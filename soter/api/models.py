"""
Module containing models for data-transfer objects (DTOs).

Used to define the interfaces between scanner implementations and the core API.
"""

from functools import total_ordering
from enum import Enum
from typing import Any, List, Dict, Optional

from pydantic import BaseModel, HttpUrl, validator


class ScannerStatus(BaseModel):
    """
    Model for the status of a scanner.
    """
    #: The name of the scanner
    name: str
    #: The kind of the scanner
    kind: str
    #: The scanner version
    version: str
    #: Indicates whether the scanner is available
    available: bool
    #: Message associated with the status
    message: Optional[str] = None
    #: Additional properties associated with the scanner, e.g. time of last database update
    properties: Optional[Dict[str, Any]] = None


@total_ordering
class Severity(Enum):
    """
    Enum of possible severity levels for vulnerabilities.
    """
    NEGLIGIBLE = "Negligible"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    def __lt__(self, other):
        # Assume that the severities are defined in order
        severities = list(self.__class__)
        return severities.index(self) < severities.index(other)


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
