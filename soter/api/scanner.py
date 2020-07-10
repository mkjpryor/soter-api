"""
Module containing the base classes for scanners in Soter.
"""

import abc
import asyncio
import itertools


class Scanner(abc.ABC):
    """
    Base class for all scanners.
    """
    def __init__(self, name):
        self.name = name

    @abc.abstractmethod
    async def status(self):
        """
        Return information about the status of the scanner.
        """
