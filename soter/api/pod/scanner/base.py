"""
Module containing the base class for pod scanners in Soter.
"""

import abc
import asyncio
import itertools
from typing import Dict, List, Any

from ...scanner import Scanner

from ..models import PodIssue
from ..exceptions import PodSubmissionFailed


class PodScanner(Scanner):
    """
    Base class for a pod scanner.
    """
    def __init__(self):
        pass

    @abc.abstractmethod
    async def submit_one(self, pod: Dict[str, Any]):
        """
        Submit the given pod configuration for scanning, raising a suitable exception
        if there is an error.
        """
        raise NotImplementedError

    async def submit(self, pods: List[Dict[str, Any]]) -> bool:
        """
        Submit the given pod configurations for scanning and return a pod submission result
        for each pod.
        """
        # Submit each pod in parallel
        tasks = [self.submit_one(pod) for pod in pods]
        results = await asyncio.gather(*tasks, return_exceptions = True)
        # If there are any errors, raise an aggregated exception
        success = True
        failed_pods = []
        for pod, result in zip(pods, results):
            if isinstance(result, Exception):
                success = False
                failed_pods.append(
                    dict(
                        namespace = pod['metadata']['namespace'],
                        name = pod['metadata']['name'],
                        error = repr(result)
                    )
                )
        if not success:
            raise PodSubmissionFailed(failed_pods)
        return True

    @abc.abstractmethod
    async def report(self, pods: List[Dict[str, Any]]) -> List[PodIssue]:
        """
        Returns a pod report for each of the given pod configurations.
        """
