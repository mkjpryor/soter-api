"""
Module containing the base class for Kubernetes authenticators.
"""

import abc

from pydantic import BaseModel


class Authenticator(BaseModel, abc.ABC):
    """
    Base class for all authenticators.
    """
    @abc.abstractmethod
    async def available_clusters(self):
        """
        Return a list or tuple of the available clusters.
        """

    @abc.abstractmethod
    async def default_cluster(self):
        """
        The default cluster if no other cluster is specified.
        """

    @abc.abstractmethod
    async def default_namespace(self, cluster):
        """
        The default namespace for the cluster if no other namespace is specified.
        """

    @abc.abstractmethod
    async def get_api_client(self, cluster):
        """
        Async context manager that yields a configured api client for the given cluster.
        """

    @classmethod
    def schema(cls, *args, **kwargs):
        # Inject the UI schema into the generated JSON schema
        schema = super().schema(*args, **kwargs)
        schema.update(ui = cls.ui_schema())
        return schema

    @classmethod
    def ui_schema(cls):
        """
        The UI schema for this authenticator.
        """
        return {}
