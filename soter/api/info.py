"""
Module containing JSON-RPC methods providing information about the system.
"""

import asyncio

from .conf import settings


__all__ = ['scanners']


async def get_scanner_status(scanner):
    """
    Get the status of the scanner, dealing with exceptions.
    """
    try:
        return (await scanner.status())
    except Exception as exc:
        return ScannerStatus(
            name = scanner.name,
            kind = scanner.kind,
            version = 'unknown',
            available = False,
            message = str(exc)
        )


async def scanners():
    """
    Get information about the status of the scanners.
    """
    # Fetch the status of each scanner concurrently
    tasks = [get_scanner_status(s) for s in settings.scanners]
    return (await asyncio.gather(*tasks))
