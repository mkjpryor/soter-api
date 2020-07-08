"""
Module providing the ASGI app for soter-image-scan.
"""

import asyncio

from http import HTTPStatus
from quart import Quart, request, jsonify
from quart.exceptions import HTTPException

from jsonrpc.dispatch import Dispatcher
from jsonrpc.adapter.quart import http_blueprint

from .models import ScannerStatus
from .conf import settings


dispatcher = Dispatcher()


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


@dispatcher.register
async def status():
    """
    Get information about the status of the system.
    """
    # Fetch the status of each scanner concurrently
    tasks = [get_scanner_status(s) for s in settings.scanners]
    statuses = await asyncio.gather(*tasks)
    return dict(
        # We are available if at least one backend is available
        available = any(s.available for s in statuses),
        scanners = statuses
    )


# Register the image methods with the dispatcher
from . import image
dispatcher.register_all(image, prefix = "image")


async def handle_http_exception(exc):
    """
    Handle Quart HTTP exceptions by returning a JSON response.
    """
    return dict(name = exc.name, detail = exc.description), exc.status_code


# Build the Quart app
app = Quart(__name__)
# Register the error handler
app.errorhandler(HTTPException)(handle_http_exception)
# Register the JSON-RPC blueprint
app.register_blueprint(http_blueprint(dispatcher), url_prefix = '/')
