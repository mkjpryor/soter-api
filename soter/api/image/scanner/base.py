"""
Module containing the base class for image scanners in Soter.
"""

import abc
import asyncio
import itertools
from typing import List

from ...scanner import Scanner

from ..docker import Image
from ..models import ImageVulnerability


class ImageScanner(Scanner):
    """
    Base class for an image scanner.
    """
    @abc.abstractmethod
    async def submit(self, image: Image) -> bool:
        """
        Submit the given image for scanning.

        Should return ``True`` if the image is successfully submitted and raise an
        exception if not.
        """

    @abc.abstractmethod
    async def report(self, image: Image) -> List[ImageVulnerability]:
        """
        Returns a list of vulnerabilities found for the given image.

        If there is no vulnerability data available for the image, as distinct from
        there being no vulnerabilities in the image, then
        py:class:`..exceptions.NoVulnerabilityDataAvailable` should be raised.

        If any other error occurs while retrieving vulnerability data, a suitable
        exception should be raised.
        """
