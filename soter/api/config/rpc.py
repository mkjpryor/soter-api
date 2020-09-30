"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio
import itertools

from ..util import default_scanners
from ..exceptions import NoSuitableScanners

from ..image.exceptions import ImageNotFound as ImageNotFoundException

from .models import Resource, VulnerableImage, ResourceReport


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['scan']


async def resource_images_scan(resources, scanners):
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
        image_rpc.scan(image = image, scanners = [s.name for s in scanners])
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


@default_scanners
async def scan(*, resources, scanners):
    """
    Get a security report for the given resource configurations.
    """
    results = await asyncio.gather(resource_images_scan(resources, scanners))
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
