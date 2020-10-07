"""
Module providing cache implementations.
"""

import abc
import asyncio
import os

import aioredis


class Cache(abc.ABC):
    """
    Base class for all cache implementations.
    """
    @abc.abstractmethod
    async def get(self, key):
        """
        Get the value for the given key, or raise a key error.
        """

    @abc.abstractmethod
    async def put(self, key, value):
        """
        Put the given value for the given key.
        """

    @abc.abstractmethod
    async def remove(self, key):
        """
        Remove any existing value for the given key.
        """

    @classmethod
    @abc.abstractmethod
    async def from_environment(cls):
        """
        Return an instance of this cache configured from the environment.
        """


class DummyCache(Cache):
    """
    Dummy cache implementation that fulfils the interface without doing anything.
    """
    async def get(self, key):
        raise KeyError(key)

    async def put(self, key, value):
        pass

    async def remove(self, key):
        pass

    @classmethod
    async def from_environment(cls):
        return cls()


class MemoryCache(Cache):
    """
    Cache implementation that uses an in-memory dictionary.
    """
    def __init__(self):
        self._cache = {}

    async def get(self, key):
        return self._cache[key]

    async def put(self, key, value):
        self._cache[key] = value

    async def remove(self, key):
        return self._cache.pop(key, None)

    @classmethod
    async def from_environment(cls):
        return cls()


class RedisCache(Cache):
    """
    Cache implementation for Redis.
    """
    def __init__(self, pool):
        self.pool = pool

    async def get(self, key):
        """
        Get the value for the given key, or raise a key error.
        """
        value = await self.pool.get(key)
        if value is None:
            raise KeyError(key)
        return value

    async def put(self, key, value):
        """
        Put the given value for the given key.
        """
        return await self.pool.set(key, value)

    async def remove(self, key):
        """
        Remove any existing value for the given key.
        """
        return await self.pool.delete(key)

    @classmethod
    async def from_environment(cls):
        """
        Return an instance of this cache configured from the environment.
        """
        url = os.environ['SOTER_CACHE_REDIS_URL']
        password = os.environ.get('SOTER_CACHE_REDIS_PASSWORD')
        return cls(await aioredis.create_redis_pool(url, password = password))


async def from_environment():
    """
    Create a cache from the environment variables.
    """
    cache_type = os.environ.get('SOTER_CACHE', 'dummy').lower()
    if cache_type == 'memory':
        return await MemoryCache.from_environment()
    elif cache_type == 'redis':
        return await RedisCache.from_environment()
    else:
        return await DummyCache.from_environment()
