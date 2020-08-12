"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio

from jsonrpc.model import JsonRpcException

from ..util import default_scanners, exception_as_issue
from ..exceptions import NoSuitableScanners

from .docker import fetch_image
from .scanner.base import ImageScanner
from .models import ImageReport


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['scan']


@default_scanners
async def scan(*, image, scanners):
    """
    Get a vulnerability report for the given image.
    """
    # First, filter the scanners to just image scanners
    image_scanners = [s for s in scanners if isinstance(s, ImageScanner)]
    if not image_scanners:
        raise NoSuitableScanners('no image scanners specified')
    image = await fetch_image(image)
    # Scan the image using each image scanner
    tasks = [scanner.scan(image) for scanner in image_scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    # Aggregate the issues from each scanner
    # Use a generator to avoid building an interim list
    def issues():
        for scanner, result in zip(scanners, results):
            if isinstance(result, Exception):
                # If an exception was thrown, convert it to an issue and include it
                yield exception_as_issue(result, scanner.name)
            else:
                yield from result
    return ImageReport(image_digest = image.full_digest, issues = issues())
