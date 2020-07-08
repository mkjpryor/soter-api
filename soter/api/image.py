"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio
import itertools

from jsonrpc.dispatch import dispatcher_exclude

from .conf import settings
from .docker import fetch_image
from .scanners.base import ImageScanner
from .exceptions import VulnerabilityDataUnavailable


@dispatcher_exclude
async def scanner_submit(scanner, image):
    """
    Submit the image to the given backend, dealing with exceptions.
    """
    try:
        await scanner.image_submit(image)
        return dict(scanner = scanner.name, success = True)
    except Exception as exc:
        return dict(
            scanner = scanner.name,
            success = False,
            message = str(exc)
        )


async def submit(image):
    """
    Submit an image for scanning.
    """
    # Get the list of image scanners
    image_scanners = [s for s in settings.scanners if isinstance(s, ImageScanner)]
    # Try to parse the image
    image = await fetch_image(image)
    # Submit the image to each scanner
    tasks = [scanner_submit(s, image) for s in image_scanners]
    submissions = await asyncio.gather(*tasks)
    return dict(
        image_digest = image.full_digest,
        # The submission is considered successful if at least one submission was successful
        success = any(s['success'] for s in submissions),
        scanners = submissions
    )


@dispatcher_exclude
async def scanner_report(scanner, image):
    """
    Get a list of vulnerabilities from the backend, dealing with exceptions.
    """
    try:
        return (scanner.name, await scanner.image_report(image))
    except Exception:
        # Just swallow exceptions - they are thrown away later
        pass


#: The keys used to aggregate image vulnerabilities on
AGGREGATE_KEYS = {'id', 'package_name', 'package_version', 'package_type', 'package_location'}


async def report(image):
    """
    Get a vulnerability report for the given image.
    """
    # Get the list of image scanners
    image_scanners = [s for s in settings.scanners if isinstance(s, ImageScanner)]
    # Try to parse the image
    image = await fetch_image(image)
    # Get a report from each image scanner
    tasks = [scanner_report(s, image) for s in image_scanners]
    reports = await asyncio.gather(*tasks)
    # Throw away any null results - these represent unavailability of vulnerability information
    reports = [report for report in reports if report is not None]
    # If there are no reports left, indicate a lack of data
    if not reports:
        raise VulnerabilityDataUnavailable(f'no vulnerability data for {image.full_digest}')
    # Group the vulnerabilities into those that represent the same vulnerability
    # Also collect the scanners that reported them
    grouped = dict()
    for name, vulns in reports:
        for vuln in vulns:
            key = frozenset(vuln.dict(include = AGGREGATE_KEYS).items())
            group = grouped.setdefault(key, {})
            group.setdefault('vulns', []).append(vuln)
            group.setdefault('reported_by', []).append(name)
    return dict(
        image_digest = image.full_digest,
        vulnerabilities = [
            # Produce a single aggregated record for each group
            dict(
                # Start with the properties from the first vuln in the group
                group['vulns'][0].dict(),
                # Use the maximum severity reported by any scanner
                severity = max(v.severity for v in group['vulns']),
                # Use the fix version from the first scanner that reported one
                fix_version = next((v.fix_version for v in group['vulns'] if v.fix_version), None),
                # Add the list of attributions
                reported_by = group['reported_by']
            )
            for group in grouped.values()
        ]
    )
