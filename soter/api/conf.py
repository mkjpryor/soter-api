"""
Settings for the Soter unified image scanning API.
"""

import os
from typing import Any, Dict, List
from pkg_resources import iter_entry_points

from pydantic import BaseModel, validator

from flexi_settings import include


class ScannerSpec(BaseModel):
    """
    Model for a scanner specification.
    """
    #: The name of the scanner
    name: str
    #: The kind of the scanner
    #: This must correspond to an entrypoint in the soter.api.scanners group
    kind: str
    #: The parameters for the scanner
    params: Dict[str, Any]

    @validator('kind')
    def resolve_kind(cls, kind):
        """
        Resolves the given kind to a scanner class.
        """
        try:
            return next(iter_entry_points('soter.api.scanners', kind)).load()
        except StopIteration:
            raise ValueError('not a valid scanner kind')


class ApiSettings(BaseModel):
    """
    Model defining settings for the Soter API application.
    """
    #: The default registry for images without a registry
    #: Defaults to Docker hub
    default_registry: str = "registry-1.docker.io"
    #: The list of configured scanners
    scanners: List[ScannerSpec]

    @validator('scanners', each_item = True)
    def resolve_scanner(cls, spec):
        """
        Resolves the given scanner spec to a scanner instance.
        """
        return spec.kind(spec.name, **spec.params)


def from_file(config_file):
    """
    Build a settings object from a config file.
    """
    config = dict()
    include(config_file, config)
    return ApiSettings(**config)


def from_env_file(var_name, default_file):
    """
    Build a settings object from a config file specified by an environment variable.
    """
    return from_file(os.environ.get(var_name, default_file))


settings = from_env_file('SOTER_API_CONFIG', '/etc/soter/api.conf')
