"""
Module containing JSON-RPC methods for handling pods.
"""

import asyncio
import functools
import itertools

from jsonrpc.exceptions import JsonRpcException

from ..conf import settings
from ..util import exception_as_issue
from ..exceptions import NoSuitableScanners
from ..models import Issue, Severity

from ..image.exceptions import ImageNotFound, ImageSubmissionFailed

from .scanner.base import PodScanner
from .exceptions import PodSubmissionFailed
from .models import PodReport, PodImageIssue, Pod, ImageNotFound as ImageNotFoundIssue


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['submit', 'report']


def filter_pods(func):
    """
    Decorator that filters the incoming pods to eliminate pods that we don't
    need to consider.
    """
    @functools.wraps(func)
    async def wrapper(pods, *args, **kwargs):
        pods = [
            pod
            for pod in pods
            # The pod must have at least one running container
            if any('running' in status['state'] for status in pod['status']['containerStatuses'])
        ]
        return await func(pods, *args, **kwargs)
    return wrapper


async def submit_pod_images(pods):
    """
    Submits the images in use by the given pods for scanning and returns the scanner
    results in a format that can mesh with the other pod scanners.
    """
    # First, get the set of unique images used by the pods
    # Convert to a list as we care about the ordering when matching up with results
    images = list({
        # Kubernetes starts images with docker-pullable://, which we remove
        status['imageID'].replace('docker-pullable://', '')
        for pod in pods
        for status in pod['status']['containerStatuses']
    })
    # Submit each image using the RPC method for image submission
    from ..image import rpc as image_rpc
    tasks = [image_rpc.submit(image) for image in images]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    # Aggregate the results by scanner
    scanners = {}
    for result in results:
        # If the submission failed, extract the detail
        if isinstance(result, ImageSubmissionFailed):
            result = result.data
        for scanner in result['scanners']:
            agg = scanners.setdefault(scanner['name'], dict(success = True))
            if not scanner['success']:
                agg.update(success = False)
                agg.setdefault('detail', list()).append(dict(
                    image = result['image_digest'],
                    error = scanner['detail']
                ))
    # We return as a list
    return [dict(v, name = k) for k, v in scanners.items()]


async def submit_pods(pods):
    """
    Submit the given pods to the pod scanners and gather the results.
    """
    # Get the pod scanners
    scanners = [scanner for scanner in settings.scanners if isinstance(scanner, PodScanner)]
    # Submit the pods to each scanner
    tasks = [scanner.submit(pods) for scanner in scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    submissions = []
    for scanner, result in zip(scanners, results):
        submission = dict(name = scanner.name, success = True)
        if isinstance(result, PodSubmissionFailed):
            submission.update(success = False, detail = result.data)
        elif isinstance(result, JsonRpcException):
            submission.update(success = False, detail = result.as_error())
        elif isinstance(result, Exception):
            submission.update(success = False, detail = repr(result))
        submissions.append(submission)
    return submissions


@filter_pods
async def submit(pods):
    """
    Submit the given pods for scanning.
    """
    # Submit to image and pod scanners concurrently
    results = await asyncio.gather(submit_pod_images(pods), submit_pods(pods))
    # Chain the results from image and pod scanners
    submissions = list(itertools.chain.from_iterable(results))
    # Add information about the pods which were processed to the result
    result = dict(
        pods = [
            dict(namespace = pod['metadata']['namespace'], name = pod['metadata']['name'])
            for pod in pods
        ],
        scanners = submissions
    )
    # If submission failed for any scanner, raise the result as an error, otherwise return it
    if all(s['success'] for s in submissions):
        return result
    else:
        raise PodSubmissionFailed(result)


def image_report_to_issues(report, image, pods):
    # If there are no image scanners, just ignore that error
    if isinstance(report, NoSuitableScanners):
        return ()
    elif isinstance(report, ImageNotFound):
        # Return an error that is "reported by" the system
        return (ImageNotFoundIssue(affected_images = [image], affected_pods = pods), )
    elif isinstance(report, Exception):
        # All other exceptions are unexpected and should be re-raised
        raise report
    else:
        # Otherwise, process it as an image report by converting the issues into pod image issues
        return (PodImageIssue.from_image_issue(issue, [image], pods) for issue in report.issues)


async def pod_images_report(pods):
    """
    Returns an async generator that yields pod issues for the images in use by the given pods.
    """
    # First, get the set of unique images used by the pods and the pods that use them
    pod_images = {}
    for pod in pods:
        pod_info = Pod(namespace = pod['metadata']['namespace'], name = pod['metadata']['name'])
        for status in pod['status']['containerStatuses']:
            # Kubernetes starts images with docker-pullable://, which we remove
            image = status['imageID'].replace('docker-pullable://', '')
            pod_images.setdefault(image, set()).add(pod_info)
    # We need the images in a known order so we can match them to reports later
    images = list(pod_images.keys())
    # Get a report for each image
    from ..image import rpc as image_rpc
    tasks = [image_rpc.report(image) for image in images]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    return itertools.chain.from_iterable(
        image_report_to_issues(report, image, pod_images[image])
        for image, report in zip(images, results)
    )


@filter_pods
async def report(pods):
    """
    Get a security report for the given pods.
    """
    results = await asyncio.gather(pod_images_report(pods))
    return PodReport(
        # Add information about the pods which were processed to the report
        pods = (
            Pod(namespace = pod['metadata']['namespace'], name = pod['metadata']['name'])
            for pod in pods
        ),
        issues = itertools.chain.from_iterable(results)
    )
