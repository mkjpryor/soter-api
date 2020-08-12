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
    async def scan(self, image: Image) -> List[ImageVulnerability]:
        """
        Scan the given image and return a list of vulnerabilities.

        If the scanner requires a separate submission step, this method is responsible for
        submitting the image and waiting for vulnerability data to become available.

        If an error occurs during the scan, a suitable exception should be raised.
        """
