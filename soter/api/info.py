"""
Module containing JSON-RPC methods providing information about the system.
"""

import asyncio
import functools

from jsonrpc.model import JsonRpcException

from .conf import settings
from .models import ScannerStatus


__all__ = ['scanners']


async def scanners():
    """
    Get information about the status of the scanners.
    """
    # Fetch the status of each scanner concurrently
    tasks = [scanner.status() for scanner in settings.scanners]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    statuses = []
    for scanner, result in zip(settings.scanners, results):
        ErrorStatus = functools.partial(
            ScannerStatus,
            name = scanner.name,
            kind = scanner.kind,
            vendor = scanner.vendor,
            version = 'unknown',
            available = False
        )
        if isinstance(result, JsonRpcException):
            statuses.append(ErrorStatus(message = result.message))
        elif isinstance(result, Exception):
            statuses.append(ErrorStatus(message = repr(result)))
        else:
            statuses.append(result)
    return statuses
