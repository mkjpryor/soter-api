"""
Module providing a Soter image scanning backend for Anchore Engine.
"""

import asyncio

import httpx

from ...models import ScannerStatus, Severity
from ...exceptions import ScannerUnavailable

from .base import ImageScanner
from ..models import PackageType, PackageDetail, ImageVulnerability


class AnchoreEngine(ImageScanner):
    """
    Soter scanner implementation for Anchore Engine.
    """
    kind = "Anchore Engine"

    def __init__(self, name, url, username, password, poll_interval = 2.0):
        super().__init__(name)
        self.url = url
        self.auth = httpx.BasicAuth(username, password)
        self.poll_interval = poll_interval

    async def status(self):
        async with httpx.AsyncClient(auth = self.auth) as client:
            # Fetch system and feeds information concurrently
            system, feeds = await asyncio.gather(
                client.get(f'{self.url}/system'),
                client.get(f'{self.url}/system/feeds')
            )
        system.raise_for_status()
        feeds.raise_for_status()
        # Get the availability and version from the analyzer state
        try:
            analyzer_state = next(
                state
                for state in system.json()['service_states']
                if state['servicename'] == 'analyzer'
            )
        except StopIteration:
            raise ScannerUnavailable('could not detect status')
        version = analyzer_state['service_detail']['version']
        available = analyzer_state['status']
        message = analyzer_state['status_message']
        if available:
            properties = {
                # Use the last sync time of each group as a property
                f"{group['name']}/last-sync": group['last_sync']
                for feed in feeds.json() if feed['enabled']
                for group in feed['groups'] if group['enabled']
            }
        else:
            properties = None
        return ScannerStatus(
            name = self.name,
            kind = self.kind,
            version = version,
            available = available,
            message = message,
            properties = properties
        )

    async def scan(self, image):
        async with httpx.AsyncClient(auth = self.auth) as client:
            # First, submit the image
            response = await client.post(
                f'{self.url}/images',
                json = dict(
                    image_type = "docker",
                    source = dict(
                        digest = dict(
                            pullstring = image.full_digest,
                            tag = image.full_tag,
                            creation_timestamp_override = image.created.strftime('%Y-%m-%dT%H:%M:%SZ')
                        )
                    )
                )
            )
            response.raise_for_status()
            # Keep checking until the analysis status becomes analyzed
            while True:
                analysis_status = response.json()[0]['analysis_status']
                if analysis_status == "analyzed":
                    break
                await asyncio.sleep(self.poll_interval)
                response = await client.get(f'{self.url}/images/{image.digest}')
                response.raise_for_status()
            # Once analysis is complete, fetch the vulnerabilities
            response = await client.get(f'{self.url}/images/{image.digest}/vuln/all')
            response.raise_for_status()
        return (
            ImageVulnerability(
                title = vuln['vuln'],
                severity = Severity(vuln['severity']),
                info_url = vuln['url'],
                reported_by = [self.name],
                affected_packages = [
                    PackageDetail(
                        package_name = vuln['package_name'],
                        package_version = vuln['package_version'],
                        package_type = (
                            PackageType.OS
                            if vuln['package_path'] == "pkgdb"
                            else PackageType.NON_OS
                        ),
                        package_location = (
                            vuln['package_path']
                            if vuln['package_path'] != "pkgdb"
                            else None
                        ),
                        fix_version = vuln['fix'] if vuln['fix'] != "None" else None
                    )
                ]
            )
            for vuln in response.json()['vulnerabilities']
        )
