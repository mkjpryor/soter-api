"""
Module containing the base classes for scanners in Soter.
"""

import abc


class WorkloadScanner(abc.ABC):
    """
    Base class for workload scanners.
    """
    def __init__(self, name):
        self.name = name

    @abc.abstractmethod
    async def status(self):
        """
        Return information about the status of the scanner.
        """


class ImageScanner(WorkloadScanner):
    """
    Base class for image scanners.

    An image scanner can be used to scan the images associated with a workload, but
    can also be used to scan images independently of workloads.
    """
    @abc.abstractmethod
    async def image_submit(self, image):
        """
        Submit the given image for scanning.
        """

    @abc.abstractmethod
    async def image_report(self, image):
        """
        Returns a list of vulnerabilities found for the given image.
        """
