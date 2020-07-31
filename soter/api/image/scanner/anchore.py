"""
Module providing a Soter image scanning backend for Anchore Engine.
"""

import asyncio

import httpx

from ...models import ScannerStatus, Severity
from ...exceptions import ScannerUnavailable

from .base import ImageScanner
from ..models import PackageType, PackageDetail, ImageVulnerability
from ..exceptions import NoVulnerabilityDataAvailable


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

    async def submit(self, image):
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

    async def report(self, image):
        """
        Return a list of vulnerabilities for the given image.
        """
        async with httpx.AsyncClient(auth = self.auth) as client:
            image_url = f'{self.url}/images/{image.digest}'
            # Fetch the vulnerabilities
            vuln_response = await client.get(f'{image_url}/vuln/all')
            # A 404 indicates no data available
            # Check if there is a scan in progress or if the image has not been submitted
            if vuln_response.status_code == 404:
                detail_response = await client.get(image_url)
                if detail_response.status_code == 200:
                    # If the response was successful, the image must be being analysed
                    raise NoVulnerabilityDataAvailable('analysis in progress')
                elif detail_response.status_code == 404:
                    # A 404 means the image was never submitted
                    raise NoVulnerabilityDataAvailable('image has not been submitted')
                # If there are any other errors with the response, raise them
                else:
                    detail_response.raise_for_status()
            # Raise any other errors with the response
            vuln_response.raise_for_status()
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
            for vuln in vuln_response.json()['vulnerabilities']
        )
