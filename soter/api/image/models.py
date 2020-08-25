"""
Module containing models for data-transfer objects (DTOs) for image scanners.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, HttpUrl, validator, constr, conset
from pydantic.dataclasses import dataclass

from ..models import Issue, Report


class PackageType(Enum):
    """
    Enum of possible values for the package type of an image vulnerability.
    """
    #: The vulnerability is in a package installed using the OS package manager, e.g. yum, apt
    OS = "os"
    #: The vulnerability is in a package not managed by the OS package manager
    NON_OS = "non-os"


class ImageVulnerability(Issue):
    """
    Model for a vulnerability in an image.

    The title for an image vulnerability should be the CVE id or equivalent.
    """
    #: The package name that the vulnerability applies to
    package_name: constr(min_length = 1)
    #: The package version that the vulnerability applies to
    package_version: constr(min_length = 1)
    #: The type of package
    package_type: PackageType
    #: The location of the package
    package_location: Optional[constr(min_length = 1)] = None
    #: The version at which the vulnerability is fixed, if it exists
    fix_version: Optional[constr(min_length = 1)] = None

    @validator('package_location')
    def check_package_location(cls, v, values):
        package_type = values.get('package_type')
        if package_type:
            if package_type == PackageType.OS:
                assert v is None, 'should not be given for OS packages'
            else:
                assert v is not None, 'required for non-OS packages'
        return v

    @property
    def aggregation_key(self):
        # If the issues refer to the same CVE and package, they should be aggregated
        return super().aggregation_key + (
            self.package_name,
            self.package_version,
            self.package_type,
            self.package_location
        )

    def merge(self, other):
        merged = super().merge(other)
        merged.fix_version = self.fix_version or other.fix_version
        return merged


class ImageReport(Report):
    """
    Class for a security report for an image.
    """
    #: The image as given for analysis
    image: constr(min_length = 1)
    #: The digest of the image
    digest: constr(min_length = 1)
