"""
Module containing the base class for Kubernetes authenticators.
"""

import abc


class Authenticator(abc.ABC):
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
