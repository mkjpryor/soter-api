"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio
import itertools
import logging

from jsonrpc.model import JsonRpcException, MethodNotFound

from jsonrpc.client import Client
from jsonrpc.client.transport.websocket import Transport

from ..util import with_scanners
from ..exceptions import NoSuitableScanners

from ..image.exceptions import ImageNotFound as ImageNotFoundException

from .models import (
    Resource,
    VulnerableImage,
    ConfigurationIssue,
    ResourceError,
    ResourceReport
)


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['scan']


logger = logging.getLogger(__name__)


async def resource_images_scan(resources, scanners, force):
    """
    Returns an iterable of issues using the given scanners for:

      1. Images referenced by a pod or pod template spec
      2. Images actually running in a pod status
    """
    referenced_images = {}
    running_images = {}
    for resource in resources:
        resource_info = Resource(
            namespace = resource['metadata'].get('namespace', 'default'),
            kind = resource['kind'],
            name = resource['metadata']['name']
        )
        # Get the images referenced by the resource
        if resource['kind'] == 'Pod':
            # If the resource is a pod, see if it has information about running containers
            for cs in resource.get('status', {}).get('containerStatuses', []):
                # Only consider running containers
                if not cs['state'].get('running'):
                    continue
                # Kubernetes starts images with docker-pullable://, which we remove
                image = cs['imageID'].replace('docker-pullable://', '')
                running_images.setdefault(image, set()).add(resource_info)
            # If the pod is an "owned" pod, ignore it in terms of referenced images
            if resource['metadata'].get('ownerReferences'):
                continue
            pod_spec = resource['spec']
        elif resource['kind'] == 'Job':
            # If the job is an "owned" job, ignore it in terms of referenced images
            if resource['metadata'].get('ownerReferences'):
                continue
            pod_spec = resource['spec']['template']['spec']
        elif resource['kind'] == 'CronJob':
            pod_spec = resource['spec']['jobTemplate']['spec']['template']['spec']
        elif resource['kind'] in {'Deployment', 'DaemonSet', 'StatefulSet'}:
            pod_spec = resource['spec']['template']['spec']
        else:
            # If the resource doesn't have a pod spec there is nothing to do
            continue
        # Get the images referenced by the spec (note that this is different to running)
        for container in pod_spec['containers']:
            referenced_images.setdefault(container['image'], set()).add(resource_info)
    # We need the images in a known order so we can match them to reports later
    images = list(set(running_images.keys()).union(referenced_images.keys()))
    # Get a report for each image
    from ..image import rpc as image_rpc
    tasks = [
        image_rpc.scan(image = image, scanners = scanners.keys(), force = force)
        for image in images
    ]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    def issues():
        # For each report that has at least one issue, yield a vulnerable image issue
        for image, report in zip(images, results):
            if isinstance(report, NoSuitableScanners):
                # If there are no image scanners, just ignore that error
                continue
            elif isinstance(report, ImageNotFoundException):
                # Image not found is "reported by" the system
                yield ImageNotFoundIssue(
                    affected_images = [image],
                    affected_resources = resource_images[image]
                )
            elif isinstance(report, Exception):
                # All other exceptions are unexpected and should be re-raised
                raise report
            elif len(report.issues) < 1:
                # If the report indicates no vulnerabilites, there is nothing to yield
                continue
            else:
                # Yield running and referenced issues as appropriate
                if image in running_images:
                    yield VulnerableImage.from_image_report(
                        'Running image with known vulnerabilities',
                        report,
                        running_images[image]
                    )
                if image in referenced_images:
                    yield VulnerableImage.from_image_report(
                        'References image with known vulnerabilities',
                        report,
                        referenced_images[image]
                    )
    return issues()


async def scan_resources(resources, name, endpoint):
    """
    Scan the resources with the given scanner.
    """
    try:
        async with Client(Transport(endpoint)) as client:
            issues = await client.call("scan_resources", resources)
    except Exception as exc:
        # Convert the exception into an issue
        if isinstance(exc, JsonRpcException):
            if exc.code == MethodNotFound.code:
                # If the scanner doesn't support resource scanning, that is fine
                return []
            else:
                # Anything else should be reported
                title = exc.message
                detail = exc.data
        else:
            # Convert the exception name to words for the title
            words = re.findall(r'[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))', exc.__class__.__name__)
            title = ' '.join(words).lower().capitalize()
            detail = repr(exc)
        logger.exception(f'Error scanning resources: {name}')
        return [
            ResourceError(
                title = title,
                detail = detail,
                affected_resources = {
                    Resource(
                        namespace = r['metadata'].get('namespace', 'default'),
                        kind = r['kind'],
                        name = r['metadata']['name']
                    )
                    for r in resources
                },
                reported_by = [name]
            )
        ]
    else:
        return (
            ConfigurationIssue(
                title = issue['title'],
                severity = issue['severity'],
                suggested_remediation = issue.get('suggested_remediation'),
                affected_resources = [Resource(**r) for r in issue['affected_resources']],
                reported_by = [name]
            )
            for issue in issues
        )


async def scan_resources_all(resources, scanners):
    """
    Returns an iterable of configuration issues with the given resources.
    """
    # Scan the resources using each configured scanner
    tasks = [scan_resources(resources, *scanner) for scanner in scanners.items()]
    return itertools.chain.from_iterable(await asyncio.gather(*tasks))


@with_scanners
async def scan(*, resources, scanners, force = False):
    """
    Get a security report for the given resource configurations.
    """
    results = await asyncio.gather(
        resource_images_scan(resources, scanners, force),
        scan_resources_all(resources, scanners)
    )
    return ResourceReport(
        # Add information about the resources which were processed
        resources = (
            Resource(
                namespace = resource['metadata'].get('namespace', 'default'),
                kind = resource['kind'],
                name = resource['metadata']['name']
            )
            for resource in resources
        ),
        issues = itertools.chain.from_iterable(results)
    )
