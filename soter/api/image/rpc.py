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


@default_scanners(ImageScanner)
async def scan(*, image, scanners):
    """
    Get a vulnerability report for the given image.
    """
    image_obj = await fetch_image(image)
    # Scan the image using each image scanner
    tasks = [scanner.scan_image(image_obj) for scanner in scanners]
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
    return ImageReport(
        image = image,
        digest = image_obj.digest,
        issues = issues()
    )
