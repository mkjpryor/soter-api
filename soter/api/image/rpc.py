"""
Module containing JSON-RPC methods for handling images.
"""

import asyncio
import itertools
import json
import logging
import re

from pydantic.json import pydantic_encoder

from quart import current_app

from jsonrpc.model import JsonRpcException, MethodNotFound

from jsonrpc.client import Client
from jsonrpc.client.transport.websocket import Transport

from ..util import with_scanners
from ..exceptions import NoSuitableScanners
from ..models import Error

from .docker import fetch_image
from .models import ImageVulnerability, ImageReport


# This defines the methods available to the JSON-RPC dispatcher
__all__ = ['scan']


logger = logging.getLogger(__name__)


async def scan_image(image, force, name, endpoint):
    """
    Scan the image with the given scanner.

    The return value is a tuple of (is image scanner, vulnerabilities).
    """
    # Use a combination of the scanner and digest as the cache key
    cache_key = "{}!{}".format(name, image.full_digest)
    # First, try to fetch vulnerabilities from the cache unless forced to scan
    vulnerabilities = None
    if not force:
        try:
            vulnerabilities = json.loads(await current_app.cache.get(cache_key))
        except KeyError:
            logger.info("No cache entry for {}".format(cache_key))
        except Exception:
            # If there is any other exception from the cache, log it and continue
            logger.exception("Error querying cache for {}".format(cache_key))
        else:
            logger.info("Using cached vulnerabilties for {}".format(cache_key))
    # On a cache miss, do a scan
    if vulnerabilities is None:
        try:
            async with Client(Transport(endpoint)) as client:
                vulnerabilities = await client.call("scan_image", image)
        except Exception as exc:
            # Convert the exception into an issue
            if isinstance(exc, JsonRpcException):
                if exc.code == MethodNotFound.code:
                    # If the scanner doesn't support image scanning, that is fine
                    return False, []
                else:
                    # Anything else should be reported
                    title = exc.message
                    detail = exc.data
            else:
                # Convert the exception name to words for the title
                words = re.findall(r'[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))', exc.__class__.__name__)
                title = ' '.join(words).lower().capitalize()
                detail = repr(exc)
            logger.exception(f'Error scanning image: {name}')
            return True, [
                Error(title = title, detail = detail, reported_by = [name])
            ]
        else:
            # On a successful scan, cache the vulnerabilities
            try:
                await current_app.cache.put(cache_key, json.dumps(vulnerabilities))
            except:
                # Log any errors using the cache, but continue to return the report
                logger.exception("Error putting cache entry for {}".format(cache_key))
    # Inject the scanner into each returned vulnerability
    return True, (
        ImageVulnerability.parse_obj(dict(vuln, reported_by = [name]))
        for vuln in vulnerabilities
    )


@with_scanners
async def scan(*, image, scanners, force = False):
    """
    Get a vulnerability report for the given image.
    """
    image_obj = await fetch_image(image)
    # Scan the image using each image scanner
    tasks = [scan_image(image_obj, force, *scanner) for scanner in scanners.items()]
    results = await asyncio.gather(*tasks)
    if not any(result[0] for result in results):
        raise NoSuitableScanners('no image scanners specified')
    return ImageReport(
        image = image,
        digest = image_obj.digest,
        # Aggregate the issues from each scanner
        issues = itertools.chain.from_iterable(result[1] for result in results)
    )
