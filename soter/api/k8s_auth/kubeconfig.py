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


class KubeconfigMixin:
    """
    Mixin providing the bulk of an authenticator that uses kubeconfig files.
    """
    async def get_kubeconfig(self, cluster):
        """
        Return the kubeconfig file for the given cluster.
        """
        raise NotImplementedError

    async def get_kubeconfig_loader(self, cluster):
        """
        Return a kubeconfig loader for the given cluster.
        """
        return KubeConfigLoader(
            config_dict = yaml.safe_load(await self.get_kubeconfig(cluster)),
            config_base_path = None
        )

    async def default_namespace(self, cluster):
        # If no cluster is given, use the default cluster
        cluster = cluster or (await self.default_cluster())
        # The loader doesn't provide a method of getting the default namespace
        # So we have to parse the kubeconfig and get it ourselves
        config_dict = yaml.safe_load(await self.get_kubeconfig(cluster))
        # Find the namespace specified for the cluster, if set
        for ctx in config_dict['contexts']:
            if ctx['name'] == cluster and 'namespace' in ctx['context']:
                return ctx['context']['namespace']
        else:
            return 'default'

    @contextlib.asynccontextmanager
    async def get_api_client(self, cluster):
        # Emulate the behaviour of kubernetes_asyncio.config.kube_config in order
        # to avoid writing kubeconfig to disk
        client_config = type.__call__(Configuration)
        # Get a config loader for the given cluster
        loader = await self.get_kubeconfig_loader(cluster)
        # Use the loader to populate the configuration object
        await loader.load_and_set(client_config)
        # Return an API client configured with the config object
        async with ApiClient(configuration = client_config) as api_client:
            yield api_client


class Authenticator(KubeconfigMixin, BaseAuthenticator):
    """
    Kubernetes authenticator that consumes the content of a kubeconfig file.
    """
    class Config:
        title = "Kubeconfig"

    kubeconfig: constr(min_length = 1)

    async def get_kubeconfig(self, cluster):
        """
        Return the kubeconfig file for the given cluster.
        """
        # For kubeconfig files, we only allow the use of the default context
        # So if a cluster is given, check that it matches the default one
        if cluster and cluster != (await self.default_cluster()):
            raise InvalidCluster(f'"{cluster}" is not a valid cluster')
        return self.kubeconfig

    async def available_clusters(self):
        # For kubeconfig authentication, we only allow the use of the default context
        return (await self.default_cluster(), )

    async def default_cluster(self):
        # If we get a loader without setting an active context, that is the default
        return (await self.get_kubeconfig_loader(None)).current_context['name']

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
