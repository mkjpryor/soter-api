"""
Module containing the base classes for scanners in Soter.
"""

import abc

from .models import ScannerStatus


class Scanner(abc.ABC):
    """
    Base class for all scanners.
    """
    def __init__(self, name):
        self.name = name

    @abc.abstractmethod
    async def status(self) -> ScannerStatus:
        """
        Return information about the status of the scanner.
        """
