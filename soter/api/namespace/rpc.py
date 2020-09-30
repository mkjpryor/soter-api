"""
Module containing JSON-RPC methods for handling pods.
"""

import asyncio
import itertools
from pkg_resources import iter_entry_points

from kubernetes_asyncio import client

from ..util import default_scanners

from ..k8s_auth import authenticator_from_config

from .k8s import ResourceFetcher


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['auth_kinds', 'clusters', 'namespaces', 'scan']


async def auth_kinds():
    """
    Return JSON schemas for the available auth kinds.
    """
    return {
        ep.name: ep.load().schema()
        for ep in iter_entry_points('soter.api.k8s_auth')
    }


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


DEFAULT_KINDS = (
    'pod',
    'job',
    'deployment',
    'daemonset',
    'statefulset',
    'cronjob',
    'svc',
    'ingress'
)


@default_scanners
async def scan(*, auth,
                  scanners,
                  cluster = None,
                  all_namespaces = False,
                  namespace = None,
                  kinds = DEFAULT_KINDS):
    """
    Get a security report for the given cluster and namespace(s).
    """
    # Get an authenticator for the given auth
    authenticator = authenticator_from_config(auth)
    # If no namespace is specified, use the default namespace for the cluster
    namespace = namespace or (await authenticator.default_namespace(cluster))
    # Get an API client for the given cluster
    async with authenticator.get_api_client(cluster) as api_client:
        # Fetch the specified resources asynchronously
        fetcher = ResourceFetcher(api_client)
        tasks = [fetcher.fetch_objects(k, all_namespaces, namespace) for k in kinds]
        objects = itertools.chain.from_iterable(await asyncio.gather(*tasks))
    # Scan the discovered resources using the config scanner
    from ..config import rpc as config_rpc
    return await config_rpc.scan(resources = list(objects), scanners = [s.name for s in scanners])
