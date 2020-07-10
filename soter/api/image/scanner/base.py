"""
Module containing the base classes for scanners in Soter.
"""

import abc
import asyncio
import itertools

from ...scanner import Scanner


class ImageScanner(Scanner):
    """
    Base class for an image scanner.
    """
    @abc.abstractmethod
    async def submit(self, image):
        """
        Submit the given image for scanning.
        """

    @abc.abstractmethod
    async def report(self, image):
        """
        Returns a list of vulnerabilities found for the given image.
        """
