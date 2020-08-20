"""
Module containing JSON-RPC methods for handling pods.
"""

import asyncio
import functools
import itertools

from kubernetes_asyncio import client

from jsonrpc.model import InvalidParams

from ..util import default_scanners
from ..exceptions import NoSuitableScanners

from ..k8s_auth import authenticator_from_config

from ..image.exceptions import ImageNotFound as ImageNotFoundException

from .models import (
    PodReport,
    NamespacedPodReport,
    Pod,
    ImageNotFound as ImageNotFoundIssue,
    PodImageVulnerability,
    PodImageError
)


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['clusters', 'namespaces', 'scan']


async def clusters(*, auth):
    """
    Return the clusters available for the given auth.
    """
    return await authenticator_from_config(auth).available_clusters()


async def namespaces(*, auth, cluster = None):
    """
    Return the namespaces available for the given auth and cluster.
    """
    authenticator = authenticator_from_config(auth)
    async with authenticator.get_api_client(cluster) as api_client:
        namespaces = await client.CoreV1Api(api_client).list_namespace()
    return [ns.metadata.name for ns in namespaces.items]


def image_report_to_issues(report, image, pods):
    """
    Returns an iterable of pod issues for the given image report, image and pods
    """
    # If there are no image scanners, just ignore that error
    if isinstance(report, NoSuitableScanners):
        return
    elif isinstance(report, ImageNotFoundException):
        # Return an error that is "reported by" the system
        yield ImageNotFoundIssue(affected_images = [image], affected_pods = pods)
    elif isinstance(report, Exception):
        # All other exceptions are unexpected and should be re-raised
        raise report
    else:
        # Otherwise, process it as an image report by converting the issues into pod image issues
        for issue in report.issues:
            if issue.kind == "ImageVulnerability":
                yield PodImageVulnerability(
                    title = issue.title,
                    severity = issue.severity,
                    info_url = issue.info_url,
                    reported_by = issue.reported_by,
                    affected_pods = pods,
                    affected_packages = { image: issue.affected_packages }
                )
            else:
                yield PodImageError(
                    title = issue.title,
                    severity = issue.severity,
                    info_url = issue.info_url,
                    reported_by = issue.reported_by,
                    detail = issue.detail,
                    affected_pods = pods,
                    affected_images = [image]
                )


async def pod_images_scan(pods, scanners):
    """
    Returns an iterable of pod issues for the images in use by the given pods
    using the given scanners.
    """
    # First, get the set of unique images and the pods that use them
    pod_images = {}
    for pod in pods:
        pod_info = Pod(namespace = pod.metadata.namespace, name = pod.metadata.name)
        for status in pod.status.container_statuses:
            # Kubernetes starts images with docker-pullable://, which we remove
            image = status.image_id.replace('docker-pullable://', '')
            pod_images.setdefault(image, set()).add(pod_info)
    # We need the images in a known order so we can match them to reports later
    images = list(pod_images.keys())
    # Get a report for each image
    from ..image import rpc as image_rpc
    tasks = [
        image_rpc.scan(image = image, scanners = [s.name for s in scanners])
        for image in images
    ]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    return itertools.chain.from_iterable(
        image_report_to_issues(report, image, pod_images[image])
        for image, report in zip(images, results)
    )


@default_scanners
async def scan(*, auth,
                  scanners,
                  cluster = None,
                  all_namespaces = False,
                  namespace = None,
                  selector = None,
                  pods = None):
    """
    Get a security report for the given cluster and namespace(s).
    """
    # All namespaces and named pods cannot be specified together as the pods
    # are not uniquely identified
    if all_namespaces and pods:
        raise InvalidParams("cannot retrieve pods by name across all namespaces")
    if selector and pods:
        raise InvalidParams('pod name(s) cannot be provided when a selector is specified')
    # Fetch the pods using an API client configured with the given auth
    authenticator = authenticator_from_config(auth)
    # If no namespace is specified, use the default namespace for the cluster
    namespace = namespace or (await authenticator.default_namespace(cluster))
    async with authenticator.get_api_client(cluster) as api_client:
        # List the pods to process using the api client
        v1 = client.CoreV1Api(api_client)
        if all_namespaces:
            list_pods = v1.list_pod_for_all_namespaces
        else:
            list_pods = functools.partial(v1.list_namespaced_pod, namespace)
        # Fetch the list of pods using the given selector
        pod_list = (await list_pods(label_selector = selector)).items
        # If required, filter the pods by the given names
        if pods:
            pod_list = [pod for pod in pod_list if pod.metadata.name in pods]
    # From the pods we found, we only consider running pods
    pods = [
        pod
        for pod in pod_list
        # The pod must have at least one running container
        if any(status.state.running for status in pod.status.container_statuses)
    ]
    results = await asyncio.gather(pod_images_scan(pods, scanners))
    if all_namespaces:
        return PodReport(
            # Add information about the pods which were processed to the report
            pods = (
                Pod(namespace = pod.metadata.namespace, name = pod.metadata.name)
                for pod in pods
            ),
            issues = itertools.chain.from_iterable(results)
        )
    else:
        return NamespacedPodReport(
            namespace = namespace,
            pods = (pod.metadata.name for pod in pods),
            issues = itertools.chain.from_iterable(results)
        )
