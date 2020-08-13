"""
Module containing a Kubernetes authenticator that takes the content for a kubeconfig file.
"""

import contextlib

import yaml

from kubernetes_asyncio.client import ApiClient, Configuration
from kubernetes_asyncio.config.kube_config import KubeConfigLoader

from .base import Authenticator as BaseAuthenticator


class Authenticator(BaseAuthenticator):
    """
    Kubernetes authenticator that consumes the content of a kubeconfig file.
    """
    def __init__(self, kubeconfig):
        self.kubeconfig = kubeconfig

    def _get_loader(self):
        return KubeConfigLoader(
            config_dict = yaml.safe_load(self.kubeconfig),
            config_base_path = None
        )

    def get_available_contexts(self):
        return tuple(ctx['name'] for ctx in self._get_loader().list_contexts())

    @property
    def default_context(self):
        # If we get a loader without setting an active context, that is the default
        return self._get_loader().current_context['name']

    def default_namespace(self, context):
        # The loader doesn't provide a method of getting the default namespace
        # So we have to parse the kubeconfig and get it ourselves
        config_dict = yaml.safe_load(self.kubeconfig)
        # Work out which context to use
        context = context or self.default_context
        # Find the namespace specified for the context, if set
        for ctx in config_dict['contexts']:
            if ctx['name'] == context and 'namespace' in ctx['context']:
                return ctx['context']['namespace']
        else:
            return 'default'

    @contextlib.asynccontextmanager
    async def get_api_client(self, context):
        # Emulate the behaviour of kubernetes_asyncio.config.kube_config in order
        # to avoid writing kubeconfig to disk
        client_config = type.__call__(Configuration)
        # Load the kubeconfig as YAML and pass it to the loader
        loader = self._get_loader()
        loader.set_active_context(context)
        # Use the loader to populate the configuration object
        await loader.load_and_set(client_config)
        # Return an API client configured with the config object
        async with ApiClient(configuration = client_config) as api_client:
            yield api_client
