"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio

from jsonrpc.exceptions import JsonRpcException

from ..conf import settings
from ..util import exception_as_issue
from ..exceptions import NoSuitableScanners
from ..models import IssueSet

from .docker import fetch_image
from .scanner.base import ImageScanner
from .exceptions import ImageSubmissionFailed
from .models import ImageReport


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['submit', 'report']


async def submit(image):
    """
    Submit an image for scanning.
    """
    scanners = [s for s in settings.scanners if isinstance(s, ImageScanner)]
    if not scanners:
        raise NoSuitableScanners('no image scanners configured')
    image = await fetch_image(image)
    # Submit the image to each scanner
    tasks = [scanner.submit(image) for scanner in scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    submissions = []
    for scanner, result in zip(scanners, results):
        if isinstance(result, JsonRpcException):
            submissions.append(dict(name = scanner.name, success = False, detail = result.as_error()))
        elif isinstance(result, Exception):
            submissions.append(dict(name = scanner.name, success = False, detail = repr(result)))
        else:
            submissions.append(dict(name = scanner.name, success = True))
    result = dict(image_digest = image.full_digest, scanners = submissions)
    # If submission failed for any scanner, raise the result as an error, otherwise return it
    if all(s['success'] for s in submissions):
        return result
    else:
        raise ImageSubmissionFailed(result)


async def report(image):
    """
    Get a vulnerability report for the given image.
    """
    scanners = [s for s in settings.scanners if isinstance(s, ImageScanner)]
    if not scanners:
        raise NoSuitableScanners('no image scanners configured')
    image = await fetch_image(image)
    # Get a report from each image scanner
    tasks = [scanner.report(image) for scanner in scanners]
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
