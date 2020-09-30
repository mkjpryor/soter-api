"""
Kubernetes integrations for the namespace RPC group.
"""

import asyncio
import contextlib
import collections
import itertools
import ssl

import httpx

from kubernetes_asyncio import client

from .exceptions import UnsupportedKind


class KindInfo(collections.namedtuple(
    'KindInfo',
    ['api_group', 'group_version', 'name', 'kind', 'namespaced']
)):
    """
    Object for storing information about a discovered kind.
    """
    @property
    def api_group_and_version(self):
        return "{}{}".format(
            "{}/".format(self.api_group) if self.api_group else "",
            self.group_version
        )


class ResourceFetcher:
    """
    Class for fetching resources from the Kubernetes API.
    """
    def __init__(self, api_client):
        self.api_client = api_client

    @contextlib.asynccontextmanager
    async def http_client(self):
        """
        Return an HTTP client configured with the correct authentication and base URL.
        """
        # Get the connection information from the api client configuration
        config = self.api_client.configuration
        base_url = config.host
        auth_setting = config.auth_settings()['BearerToken']
        headers = { auth_setting['key']: auth_setting['value'] }
        # Work out how we are going to do SSL verification
        if not config.verify_ssl:
            # SSL verification is turned off in the configuration
            verify_ssl = False
        elif config.ssl_ca_cert:
            # If the configuration specifies CA data, use that
            verify_ssl = ssl.create_default_context(cafile = config.ssl_ca_cert)
        else:
            # Use the default certificates
            verify_ssl = True
        client = httpx.AsyncClient(base_url = base_url, headers = headers, verify = verify_ssl)
        try:
            yield client
        finally:
            await client.aclose()

    def _merge_into(self, dict1, dict2):
        # If the same key is present in both dictionaries, combine the lists
        for key, value in dict2.items():
            if key in dict1:
                dict1[key].extend(value)
            else:
                dict1[key] = value
        return dict1

    async def _discover_kinds_for_api_group(self, client, prefix, group_name, group_version):
        response = await client.get("{}{}/{}".format(
            prefix,
            "/{}".format(group_name) if group_name else "",
            group_version
        ))
        response.raise_for_status()
        supported_kinds = {}
        for resource in response.json()['resources']:
            # Discard any subresources
            if '/' in resource['name']:
                continue
            # Save the kind information against each possible alias
            kind_info = KindInfo(
                group_name,
                group_version,
                resource['name'],
                resource['kind'],
                resource['namespaced']
            )
            aliases = [
                # Use the plural name as an alias
                kind_info.name,
                # And the lower-cased kind
                kind_info.kind.lower(),
                # And the fully-qualified kind
                "{}/{}".format(kind_info.api_group_and_version, kind_info.kind)
            ]
            aliases.extend(resource.get('shortNames', []))
            self._merge_into(supported_kinds, { alias: [kind_info] for alias in aliases })
        return supported_kinds

    async def _discover_kinds(self, client):
        # Do this work in a task so we can share it between different calls to fetch_objects
        # If the task has completed, return the result now
        if hasattr(self, '_discover_kinds_task'):
            return await self._discover_kinds_task
        # If there is no task, create and await it
        async def work():
            # Start by discovering the available API groups
            # We know that the core v1 API is always there
            api_groups = [("/api", None, "v1")]
            # Discover the rest of the API groups and versions supported by the server
            response = await client.get("/apis")
            response.raise_for_status()
            api_groups.extend(
                ("/apis", group['name'], version['version'])
                for group in response.json()['groups']
                for version in group['versions']
            )
            # Then discover the kinds for each API group/version
            tasks = [self._discover_kinds_for_api_group(client, *g) for g in api_groups]
            results = await asyncio.gather(*tasks)
            # Then merge the results together
            merged = {}
            for result in results:
                self._merge_into(merged, result)
            return merged
        # Store the task before awaiting it
        self._discover_kinds_task = asyncio.create_task(work())
        return await self._discover_kinds_task

    async def _fetch_objects_for_kind_and_version(self, client, kind_info, all_namespaces, namespace):
        # Work out the URL we need to fetch the objects
        if kind_info.api_group:
            url = "/apis/{}/".format(kind_info.api_group)
        else:
            url = "/api/"
        url = url + "{}/".format(kind_info.group_version)
        if kind_info.namespaced and not all_namespaces:
            url = url + "namespaces/{}/".format(namespace)
        url = url + "{}/".format(kind_info.name)
        # Then fetch and return the objects
        response = await client.get(url)
        response.raise_for_status()
        # We need to inject the apiVersion and kind so that resources can be told apart
        return (
            dict(
                item,
                apiVersion = kind_info.api_group_and_version,
                kind = kind_info.kind
            )
            for item in response.json()['items']
        )

    async def fetch_objects(self, kind, all_namespaces, namespace):
        """
        Return an iterable of objects of the given kind for the specified namespace(s).

        The kind can be given in one of two ways:

          1. A string, which should always be lower case and can use either the plural name
             for the resource or one of the registered short names.
          2. A dictionary with the keys "apiVersion" and "kind" as when specifying a resource
             in a YAML manifest.
        """
        async with self.http_client() as client:
            # First, get the info for the kind
            if isinstance(kind, dict):
                kind_key = "{}/{}".format(kind['apiVersion'], kind['kind'])
            else:
                kind_key = kind
            # Get the discovered kinds
            # This is a map of "alias -> array of kind info objects"
            supported_kinds = await self._discover_kinds(client)
            # Extract the supported versions for the requests kind
            try:
                kind_versions = supported_kinds[kind_key]
            except KeyError:
                raise UnsupportedKind(kind)
            # Fetch the results for each version concurrently
            tasks = [
                self._fetch_objects_for_kind_and_version(client, kind_info, all_namespaces, namespace)
                for kind_info in kind_versions
            ]
            objects = itertools.chain.from_iterable(await asyncio.gather(*tasks))
            # Remove any duplicate results, defined as same namespace and name
            def results():
                seen = set()
                for obj in objects:
                    key = (obj['metadata']['namespace'], obj['metadata']['name'])
                    if key in seen:
                        continue
                    yield obj
                    seen.add(key)
            return results()
