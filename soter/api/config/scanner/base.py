"""
Module containing the base class for config scanners in Soter.
"""

import abc
import asyncio
import itertools
from typing import List, Dict, Any

from ...scanner import Scanner


class ConfigScanner(Scanner):
    """
    Base class for a config scanner.
    """
    @abc.abstractmethod
    async def scan_resources(self, resources: List[Dict[str, Any]]):# -> List[ImageVulnerability]:
        """
        Scan the given resources and return a list of issues.
        """
