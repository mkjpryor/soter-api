"""
Module providing a Soter image scanning backend for Anchore Engine.
"""

import asyncio

import httpx

from .base import ImageScanner
from ..models import ScannerStatus, Severity, PackageType, ImageVulnerability
from ..exceptions import ScannerUnavailable


class AnchoreEngine(ImageScanner):
    """
    Soter scanner implementation for Anchore Engine.
    """
    kind = "Anchore Engine"

    def __init__(self, name, url, username, password):
        super().__init__(name)
        self.url = url
        self.auth = httpx.BasicAuth(username, password)

    async def status(self):
        async with httpx.AsyncClient() as client:
            # Fetch system and feeds information in parallel
            system, feeds = await asyncio.gather(
                client.get(f'{self.url}/system', auth = self.auth),
                client.get(f'{self.url}/system/feeds', auth = self.auth)
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
        if analyzer_state['status']:
            return ScannerStatus(
                name = self.name,
                kind = self.kind,
                version = analyzer_state['service_detail']['version'],
                available = True,
                message = analyzer_state['status_message'],
                properties = {
                    # Use the last sync time of each group as a property
                    f"{group['name']}/last-sync": group['last_sync']
                    for feed in feeds.json() if feed['enabled']
                    for group in feed['groups'] if group['enabled']
                }
            )
        else:
            raise ScannerUnavailable(analyzer_state['status_message'])

    async def image_submit(self, image):
        async with httpx.AsyncClient() as client:
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
                ),
                auth = self.auth
            )
        response.raise_for_status()
        return True

    async def image_report(self, image):
        """
        Return a vulnerability report for the given image.
        """
        async with httpx.AsyncClient() as client:
            vuln_url = f'{self.url}/images/{image.digest}/vuln/all'
            response = await client.get(vuln_url, auth = self.auth)
        response.raise_for_status()
        return (
            ImageVulnerability(
                id = vuln['vuln'],
                url = vuln['url'],
                package_name = vuln['package_name'],
                package_version = vuln['package_version'],
                severity = Severity(vuln['severity']),
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
            for vuln in response.json()['vulnerabilities']
        )
