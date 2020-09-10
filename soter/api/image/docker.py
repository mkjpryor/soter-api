"""
Utilities for working with Docker registries.
"""

import re
from urllib.parse import urlparse
from collections import namedtuple

from dateutil.parser import parse as dateutil_parse
import httpx
import httpcore

from .exceptions import ImageNotFound


class Image(namedtuple('Image', [
    'registry',
    'repository',
    'tag',
    'digest',
    'manifest',
    'authorization',
    'created'
])):
    """
    Class representing a Docker image.

    Attributes:
      registry: The registry for the image.
      repository: The repository for the image.
      tag: The tag for the image. Can be ``None`` if there is no tag.
      digest: The digest for the image.
      manifest: The manifest for the image.
      authorization: The authorization header to use to fetch layers.
      created: The datetime that the image was created.
    """
    @property
    def full_tag(self):
        tag = self.tag or 'unknown'
        return f'{self.registry}/{self.repository}:{tag}'

    @property
    def full_digest(self):
        return f'{self.registry}/{self.repository}@{self.digest}'

    def layer_uri(self, digest):
        return f"https://{self.registry}/v2/{self.repository}/blobs/{digest}"


#: Regex used to parse the www-authenticate header for auth information
WWW_AUTHENTICATE_REGEX = r'Bearer realm="(?P<realm>.*)",service="(?P<service>.*)",scope="(?P<scope>.*)"'

#: The default registry, used when no other registry is specified
DEFAULT_REGISTRY = "registry-1.docker.io"


async def fetch_image(image):
    """
    Return an `Image` for the given image string.

    The image should be of the form `[registry '/']repository['@' sha | ':' tag]`.
    """
    original_image = image
    # First, determine if we have a registry component
    # For our purposes, the first component is a registry if it contains a dot
    # (DNS name or IP address), a colon (port) or is the string "localhost"
    image, registry, *notused = image.split('/', 1)[::-1] + [None]
    if not registry:
        image = f'library/{image}'
        registry = DEFAULT_REGISTRY
    elif all(c not in registry for c in {'.', ':'}) and registry != "localhost":
        image = f'{registry}/{image}'
        registry = DEFAULT_REGISTRY
    # docker.io isn't a real registry, so use the default registry instead
    if registry == "docker.io":
        registry = DEFAULT_REGISTRY
    # Next, split the image into repository and reference
    # If the reference is a tag, then save it for later
    tag = None
    if '@' in image:
        # Images containing @ are digests
        repository, reference = image.split('@')
    elif ':' in image:
        # Images containing : are tags
        repository, reference = image.split(':')
        tag = reference
    else:
        # Otherwise, assume the latest tag
        repository, reference = (image, 'latest')
        tag = reference
    # Construct the manifest URL
    manifest_url = f'https://{registry}/v2/{repository}/manifests/{reference}'
    # Fetch the manifest
    async with httpx.AsyncClient() as client:
        # Some registries allow unauthenticated requests for public manifests, and some require a token
        # To find out, first attempt to get the manifest
        response = await client.get(
            manifest_url,
            headers = {
                # Make sure to ask for the V2 schemas
                'Accept': (
                    'application/vnd.docker.distribution.manifest.v2+json,'
                    'application/vnd.docker.distribution.manifest.list.v2+json'
                )
            }
        )
        # If the response is a 401, inspect the WWW-Authenticate header to find out where
        # to get a token, fetch one, and then fetch the manifest with it
        if response.status_code == 401:
            match = re.match(WWW_AUTHENTICATE_REGEX, response.headers['www-authenticate'])
            token_url = match.expand('\g<realm>?service=\g<service>&scope=\g<scope>')
            response = await client.get(token_url)
            response.raise_for_status()
            token = response.json()['token']
            authorization_header = f'Bearer {token}'
            # Make sure that future requests use the token
            client.headers['Authorization'] = authorization_header
            # Fetch the manifest using the token
            response = await client.get(
                manifest_url,
                headers = {
                    # Make sure to ask for the V2 schema
                    'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                }
            )
        # When a repository isn't accessible, the second response is a 401 (could exist but be private)
        if response.status_code in {401, 404}:
            raise ImageNotFound(original_image)
        response.raise_for_status()
        # If a manifest list was returned, fetch the manifest for the linux/amd64 variant
        content_type = response.headers.get('content-type')
        if content_type == 'application/vnd.docker.distribution.manifest.list.v2+json':
            try:
                digest = next(
                    m['digest']
                    for m in response.json()['manifests']
                    if m['platform']['architecture'] == 'amd64' and m['platform']['os'] == 'linux'
                )
                response = await client.get(
                    f'https://{registry}/v2/{repository}/manifests/{digest}',
                    headers = {
                        # Make sure to ask for the V2 schema
                        'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                    }
                )
                response.raise_for_status()
            except StopIteration:
                raise ImageNotFound(original_image)
        # The digest is in a response header
        manifest = response.json()
        digest = response.headers['docker-content-digest']
        # We need to make an additional request to get the created datetime
        config_url = f"https://{registry}/v2/{repository}/blobs/{manifest['config']['digest']}"
        response = await client.get(config_url)
        response.raise_for_status()
        created = dateutil_parse(response.json()['created'])
    # Return the image object
    return Image(registry, repository, tag, digest, manifest, authorization_header, created)
