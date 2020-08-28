"""
Module containing a Kubernetes authenticator that takes the content for a kubeconfig file.
"""

import contextlib

from pydantic import Field, HttpUrl, constr, validator

import httpx

from .base import Authenticator as BaseAuthenticator
from .kubeconfig import KubeconfigMixin
from .exceptions import InvalidCluster


RANCHER_API_SUFFIX = '/v3'


class Authenticator(KubeconfigMixin, BaseAuthenticator):
    """
    Authenticator that consumes clusters from a Rancher instance.
    """
    class Config:
        title = "Rancher"

    #: The Rancher endpoint URL
    endpoint: HttpUrl = Field(..., title = "Rancher server")
    #: Whether to use SSL verification
    verify_ssl: bool = Field(True, title = "Enable SSL verification?")
    #: The API token to use
    token: constr(min_length = 1) = Field(..., title = "API key")

    @validator('endpoint')
    def ensure_api_version(cls, v):
        """
        Ensures that the endpoint has the correct API version.
        """
        # First, strip any trailing slashes
        v = v.rstrip('/')
        # Then make sure it ends with /v3
        if not v.endswith(RANCHER_API_SUFFIX):
            v = v + RANCHER_API_SUFFIX
        return v

    @contextlib.asynccontextmanager
    async def get_rancher_client(self):
        """
        Yield an httpx async client configured to access Rancher.
        """
        client_kwargs = dict(
            base_url = self.endpoint,
            verify = self.verify_ssl,
            headers = {
                'Authorization': f'Bearer {self.token}',
            }
        )
        async with httpx.AsyncClient(**client_kwargs) as client:
            yield client

    async def get_kubeconfig(self, cluster):
        """
        Return the kubeconfig file for the given cluster.
        """
        cluster = cluster or (await self.default_cluster())
        async with self.get_rancher_client() as client:
            # Get the named cluster
            response = await client.get("/clusters", params = dict(name = cluster))
            response.raise_for_status()
            try:
                cluster = response.json()['data'][0]
            except IndexError:
                raise InvalidCluster(f'Could not find cluster "{cluster}".')
            response = await client.post(cluster['actions']['generateKubeconfig'])
            response.raise_for_status()
        return response.json()['config']

    async def available_clusters(self):
        # Fetch the clusters from the Rancher API
        async with self.get_rancher_client() as client:
            response = await client.get("/clusters")
            response.raise_for_status()
        return [cluster['name'] for cluster in response.json()['data']]

    async def default_cluster(self):
        # The Rancher authenticator has no default cluster
        raise InvalidCluster('Cluster must be specified for Rancher authentication.')

    @classmethod
    def ui_schema(cls):
        return {
            "endpoint": {
                "ui:help": (
                    "The address of the Rancher server to use, "
                    "including protocol and port."
                )
            },
            "verify_ssl": {
                "ui:help": (
                    "Turn off SSL verification if your Rancher server "
                    "uses a self-signed certificate."
                )
            },
            "token": {
                "ui:help": (
                    "API key to use when authenticating with Rancher."
                )
            }
        }
