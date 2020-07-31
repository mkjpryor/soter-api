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


@dataclass
class PackageDetail:
    """
    Model for the details of an affected package.
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
                if v is not None:
                    raise ValueError('should not be given for OS packages')
            else:
                if not v:
                    raise ValueError('required for non-OS packages')
        return v

    def __eq__(self, other):
        # Two package details are equal if they refer to the same package
        # We don't worry about the fix version
        if not isinstance(other, PackageDetail):
            raise NotImplementedError
        return (
            self.package_name == other.package_name and
            self.package_version == other.package_version and
            self.package_type == other.package_type and
            self.package_location == other.package_location
        )

    def __hash__(self):
        # We need to make this so two package details that are equal have the same hash
        return hash((
            type(self),
            self.package_name,
            self.package_version,
            self.package_type,
            self.package_location
        ))


class ImageVulnerability(Issue):
    """
    Model for a vulnerability in an image.
    """
    affected_packages: conset(PackageDetail, min_items = 1)

    def merge(self, other):
        # Merge the affected packages
        merged = super().merge(other)
        merged.affected_packages = self.affected_packages | other.affected_packages
        return merged


class ImageReport(Report):
    """
    Class for a security report for an image.
    """
    #: The digest of the image
    image_digest: constr(min_length = 1)
