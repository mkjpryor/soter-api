"""
Module containing the base class for Kubernetes authenticators.
"""

import abc


class Authenticator(abc.ABC):
    """
    Base class for all authenticators.
    """
    @abc.abstractmethod
    def get_available_contexts(self):
        """
        Return a list or tuple of the available contexts.
        """

    @property
    @abc.abstractmethod
    def default_context(self):
        """
        The default context if no other context is specified.
        """

    @abc.abstractmethod
    def default_namespace(self, context):
        """
        The default namespace for the context if no other namespace is specified.
        """

    @abc.abstractmethod
    async def get_api_client(self, context):
        """
        Async context manager that yields a configured api client for the given context.
        """
