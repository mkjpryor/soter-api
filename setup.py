#!/usr/bin/env python3

import os, re
from setuptools import setup, find_namespace_packages


here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


if __name__ == "__main__":
    setup(
        name = 'soter-api',
        setup_requires = ['setuptools_scm'],
        use_scm_version = True,
        description = 'Tool for scanning Kubernetes workloads and Docker images for security issues.',
        long_description = README,
        classifiers = [
            "Programming Language :: Python",
        ],
        author = 'Matt Pryor',
        author_email = 'matt.pryor@stfc.ac.uk',
        url = 'https://github.com/mkjpryor/soter-api',
        keywords = 'container kubernetes image scan security vulnerability configuration issue',
        packages = find_namespace_packages(include = ['soter.*']),
        include_package_data = True,
        zip_safe = False,
        install_requires = [
            'django-flexi-settings',
            'wrapt',
            'quart',
            'httpx',
            'pydantic',
            'python-dateutil',
            'jsonrpc-asyncio-server',
            'sortedcontainers',
            'kubernetes_asyncio',
            'pyyaml',
            'jsonrpc-asyncio-client[websockets]',
            'soter-scanner-model',
            'aioredis',
        ],
        entry_points = {
            # Entrypoint defining RPC modules available in the core package
            'soter.api.rpc': [
                'info = soter.api.info',
                'image = soter.api.image.rpc',
                'config = soter.api.config.rpc',
                'namespace = soter.api.namespace.rpc',
            ],
            # Entrypoint defining Kubernetes authenticators available in the core package
            'soter.api.k8s_auth': [
                'kubeconfig = soter.api.k8s_auth.kubeconfig:Authenticator',
                'rancher = soter.api.k8s_auth.rancher:Authenticator',
            ]
        }
    )
