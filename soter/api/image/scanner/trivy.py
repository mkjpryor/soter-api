"""
Module providing a Soter image scanning backend for Trivy.
"""

import asyncio

from jsonrpc.client import Client
from jsonrpc.client.transport.websocket import Transport

from ...models import ScannerStatus, Severity
from ...exceptions import ScannerUnavailable

from .base import ImageScanner
from ..models import PackageType, ImageVulnerability


# The preferred references, in order of preference
PREFERRED_REFERENCES = [
    'cve.mitre.org',
    'redhat.com',
    'debian.org',
    'gentoo.org',
    'opensuse.org',
    'suse.com',
    'python.org',
    'oracle.com',
]


class Scanner(ImageScanner):
    """
    Soter scanner implementation for Trivy.
    """
    kind = "Trivy"
    vendor = "Aqua Security"

    def __init__(self, name, endpoint):
        super().__init__(name)
        self.endpoint = endpoint

    async def status(self):
        async with Client(Transport(self.endpoint)) as client:
            info = await client.call("trivy.info")
        return ScannerStatus(
            name = self.name,
            kind = self.kind,
            vendor = self.vendor,
            version = info['Version'],
            available = True,
            message = 'available',
            properties = {
                f"vulnerabilitydb/{key.lower()}": str(value)
                for key, value in info['VulnerabilityDB'].items()
            }
        )

    def select_reference(self, references):
        """
        Extracts the preferred URL from the references for a vulnerability.
        """
        if not references:
            return None
        for pref in PREFERRED_REFERENCES:
            try:
                return next(ref for ref in references if pref in ref)
            except StopIteration:
                pass
        # By default, return the first reference
        return next(iter(references), None)

    async def scan_image(self, image):
        async with Client(Transport(self.endpoint)) as client:
            result = await client.call("trivy.image_scan", image = image.full_digest)
        if result:
            return (
                ImageVulnerability(
                    title = vuln['VulnerabilityID'],
                    severity = Severity[vuln['Severity'].upper()],
                    info_url = self.select_reference(vuln.get('References')),
                    reported_by = [self.name],
                    package_name = vuln['PkgName'],
                    package_version = vuln['InstalledVersion'],
                    package_type = PackageType.OS,
                    package_location = None,
                    fix_version = vuln.get('FixedVersion')
                )
                for vuln in result[0]['Vulnerabilities']
            )
        else:
            return ()
