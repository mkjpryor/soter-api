"""
Settings for the Soter unified image scanning API.
"""

import os
from typing import Any, Dict
from pkg_resources import iter_entry_points

from pydantic import BaseModel, validator, constr, conlist

from flexi_settings import include


class ScannerSpec(BaseModel):
    """
    Model for a scanner specification.
    """
    #: The name of the scanner
    name: constr(min_length = 1)
    #: The kind of the scanner
    #: This must correspond to an entrypoint in the soter.api.scanner group
    kind: constr(min_length = 1)
    #: The parameters for the scanner
    params: Dict[str, Any]

    @validator('kind')
    def resolve_kind(cls, kind):
        """
        Resolves the given kind to a scanner class.
        """
        try:
            return next(iter_entry_points('soter.api.scanner', kind)).load()
        except StopIteration:
            available = ', '.join(ep.name for ep in iter_entry_points('soter.api.scanner'))
            raise ValueError(f'not a valid scanner kind (available: {available})')


class ApiSettings(BaseModel):
    """
    Model defining settings for the Soter API application.
    """
    #: The default registry for images without a registry
    #: Defaults to Docker hub
    default_registry: constr(min_length = 1) = "registry-1.docker.io"
    #: The list of configured scanners
    scanners: conlist(ScannerSpec, min_items = 1)

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
