"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio
import functools
import inspect
import itertools

import wrapt

from jsonrpc.exceptions import JsonRpcException

from ..conf import settings
from ..exceptions import NoSuitableScanners
from ..models import Issue, Severity

from .docker import fetch_image
from .scanner.base import ImageScanner
from .exceptions import ImageSubmissionFailed, NoVulnerabilityDataAvailable


__all__ = ['submit', 'report']


def injects(n):
    """
    Decorator for a decorator that injects ``n`` arguments into the wrapped function
    at the start of the argspec that ensures that the decorated function has the
    correct signature.
    """
    def modify_argspec(wrapped):
        argspec = inspect.getargspec(wrapped)
        return argspec._replace(args = argspec.args[n:])
    return wrapt.decorator(adapter = wrapt.adapter_factory(modify_argspec))


@injects(1)
def with_image_scanners(wrapped, instance, args, kwargs):
    """
    Decorator that injects the configured image scanners into the wrapped function.
    """
    scanners = [s for s in settings.scanners if isinstance(s, ImageScanner)]
    if not scanners:
        raise NoSuitableScanners('No image scanners configured')
    return wrapped(scanners, *args, **kwargs)


@with_image_scanners
async def submit(scanners, image):
    """
    Submit an image for scanning.
    """
    image = await fetch_image(image)
    # Submit the image to each scanner
    tasks = [scanner.submit(image) for scanner in scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    submissions = []
    for scanner, result in zip(scanners, results):
        if isinstance(result, Exception):
            submissions.append(dict(name = scanner.name, success = False, detail = repr(result)))
        else:
            submissions.append(dict(name = scanner.name, success = True))
    result = dict(image_digest = image.full_digest, scanners = submissions)
    # If submission failed for all scanners, raise the result as an error, otherwise return it
    if any(s['success'] for s in submissions):
        return result
    else:
        raise ImageSubmissionFailed(result)


#: The keys used to aggregate image vulnerabilities on
AGGREGATE_KEYS = {'id', 'package_name', 'package_version', 'package_type', 'package_location'}


@with_image_scanners
async def report(scanners, image):
    """
    Get a vulnerability report for the given image.
    """
    image = await fetch_image(image)
    # Get a report from each image scanner
    tasks = [scanner.report(image) for scanner in scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    # We will eventually return a list of issues, but we want to aggregate the
    # vulnerabilities first to avoid reporting the same CVE multiple times
    # Group the vulnerabilities into those that represent the same vulnerability,
    # including the scanners that reported them
    # For scanners that produced errors, record a high severity issue
    issues = []
    vulnerabilities = dict()
    for scanner, result in zip(scanners, results):
        if isinstance(result, NoVulnerabilityDataAvailable):
            issues.append(
                Issue(
                    kind = "Missing Data",
                    title = result.message,
                    severity = Severity.HIGH,
                    reported_by = [scanner.name],
                    detail = result.data
                )
            )
        elif isinstance(result, JsonRpcException):
            issues.append(
                Issue(
                    kind = "Scanner Error",
                    title = result.message,
                    severity = Severity.HIGH,
                    reported_by = [scanner.name],
                    detail = result.data
                )
            )
        elif isinstance(result, Exception):
            issues.append(
                Issue(
                    kind = "Scanner Error",
                    title = "Error retrieving vulnerability data",
                    severity = Severity.HIGH,
                    reported_by = [scanner.name],
                    detail = repr(result)
                )
            )
        else:
            for vuln in result:
                key = frozenset(vuln.dict(include = AGGREGATE_KEYS).items())
                group = vulnerabilities.setdefault(key, {})
                group.setdefault('vulns', []).append(vuln)
                group.setdefault('reported_by', []).append(scanner.name)
    # Produce a single aggregated issue for each vulnerability group
    issues.extend([
        Issue(
            kind = "Image Vulnerability",
            # Use the CVE name as the title
            title = group['vulns'][0].id,
            # Use the maximum severity reported by any scanner
            severity = max(v.severity for v in group['vulns']),
            info_url = group['vulns'][0].url,
            reported_by = group['reported_by'],
            detail = dict(
                group['vulns'][0].dict(exclude = {'id', 'severity', 'url'}),
                # Use the fix version from the first scanner that reported one
                fix_version = next((v.fix_version for v in group['vulns'] if v.fix_version), None),
            )
        )
        for group in vulnerabilities.values()
    ])
    return dict(image_digest = image.full_digest, issues = issues)
