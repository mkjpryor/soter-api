"""
Module containing models for data-transfer objects (DTOs).

Used to define the interfaces between scanner implementations and the core API.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, HttpUrl, validator

from ..models import Severity


class PackageType(Enum):
    """
    Enum of possible values for the package type of an image vulnerability.
    """
    #: The vulnerability is in a package installed using the OS package manager, e.g. yum, apt
    OS = "os"
    #: The vulnerability is in a package not managed by the OS package manager
    NON_OS = "non-os"


class ImageVulnerability(BaseModel):
    """
    Model for a vulnerability in an image.
    """
    #: The id of the vulnerability, e.g. CVE-xxx or RHSA-xxx
    id: str
    #: The URL to visit for more information
    url: HttpUrl
    #: The package name that the vulnerability applies to
    package_name: str
    #: The package version that the vulnerability applies to
    package_version: str
    #: The severity of the vulnerability
    severity: Severity
    #: The type of package
    package_type: PackageType
    #: The location of the package
    package_location: Optional[str] = None
    #: The version at which the vulnerability is fixed, if it exists
    fix_version: Optional[str] = None

    @validator('package_location')
    def check_package_location(cls, v, values):
        package_type = values.get('package_type')
        if package_type:
            if package_type == PackageType.OS:
                if v is not None:
                    raise ValueError('should not be given for OS packages')
            else:
                if not v:
                    raise ValueError('required for non-OS packages')
        return v
