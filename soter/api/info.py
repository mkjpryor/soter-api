"""
Module containing JSON-RPC methods providing information about the system.
"""

import asyncio
import functools

from jsonrpc.model import JsonRpcException

from jsonrpc.client import Client
from jsonrpc.client.transport.websocket import Transport

from ..scanner.models import ScannerStatus

from .util import with_scanners


__all__ = ['scanners']


async def scanner_status(name, endpoint):
    """
    Fetch the status of a single scanner.
    """
    try:
        async with Client(Transport(endpoint)) as client:
            status = await client.call("status")
    except Exception as exc:
        ErrorStatus = functools.partial(
            ScannerStatus,
            kind = 'unknown',
            vendor = 'unknown',
            version = 'unknown',
            available = False
        )
        if isinstance(exc, JsonRpcException):
            status = ErrorStatus(message = exc.message)
        else:
            status = ErrorStatus(message = repr(exc))
    return name, status


@with_scanners
async def scanners(scanners):
    """
    Get information about the status of the scanners.
    """
    # Fetch the status of each scanner concurrently
    tasks = [scanner_status(*scanner) for scanner in scanners.items()]
    return dict(await asyncio.gather(*tasks))
