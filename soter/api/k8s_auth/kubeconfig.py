"""
Module containing a Kubernetes authenticator that takes the content for a kubeconfig file.
"""

import contextlib

import yaml

from kubernetes_asyncio.client import ApiClient, Configuration
from kubernetes_asyncio.config.kube_config import KubeConfigLoader

from pydantic import constr

from .base import Authenticator as BaseAuthenticator
from .exceptions import InvalidCluster


class Authenticator(BaseAuthenticator):
    """
    Kubernetes authenticator that consumes the content of a kubeconfig file.
    """
    class Config:
        title = "Kubeconfig"

    kubeconfig: constr(min_length = 1)

    def _get_loader(self):
        return KubeConfigLoader(
            config_dict = yaml.safe_load(self.kubeconfig),
            config_base_path = None
        )

    async def available_clusters(self):
        # For kubeconfig authentication, we only allow the use of the default context
        return (await self.default_cluster(), )

    async def default_cluster(self):
        # If we get a loader without setting an active context, that is the default
        return self._get_loader().current_context['name']

    async def default_namespace(self, cluster):
        # Check that the cluster is in the available clusters
        if cluster:
            if cluster not in (await self.available_clusters()):
                raise InvalidCluster(f'"{cluster}" is not a valid cluster')
        else:
            cluster = await self.default_cluster()
        # The loader doesn't provide a method of getting the default namespace
        # So we have to parse the kubeconfig and get it ourselves
        config_dict = yaml.safe_load(self.kubeconfig)
        # Work out which cluster to use
        # Find the namespace specified for the cluster, if set
        for ctx in config_dict['contexts']:
            if ctx['name'] == cluster and 'namespace' in ctx['context']:
                return ctx['context']['namespace']
        else:
            return 'default'

    @contextlib.asynccontextmanager
    async def get_api_client(self, cluster):
        # Check that the cluster is in the available clusters
        if cluster and cluster not in (await self.available_clusters()):
            raise InvalidCluster(f'"{cluster}" is not a valid cluster')
        # Emulate the behaviour of kubernetes_asyncio.config.kube_config in order
        # to avoid writing kubeconfig to disk
        client_config = type.__call__(Configuration)
        # Load the kubeconfig as YAML and pass it to the loader
        loader = self._get_loader()
        loader.set_active_context(cluster)
        # Use the loader to populate the configuration object
        await loader.load_and_set(client_config)
        # Return an API client configured with the config object
        async with ApiClient(configuration = client_config) as api_client:
            yield api_client

    @classmethod
    def ui_schema(cls):
        return {
            "kubeconfig": {
                "ui:widget": "textarea",
                "ui:options": {
                    "rows": 10
                }
            }
        }
