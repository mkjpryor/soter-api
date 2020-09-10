"""
Module containing models for data-transfer objects (DTOs) for image scanners.
"""

import re
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


EPOCH_REGEX = re.compile(r'^\d+:')


def strip_epoch(v):
    """
    Strips the epoch from the given version, if present.

    Some scanners include the epoch and some don't. The only consistent thing to do is to strip it.
    It is unlikely that there will be the exact same version string in two epochs.
    """
    # If the given version number has an epoch, strip it
    if v and EPOCH_REGEX.match(v):
        return EPOCH_REGEX.sub('', v, count = 1)
    else:
        return v


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

    package_version_strip_epoch = validator('package_version', allow_reuse = True)(strip_epoch)
    fix_version_strip_epoch = validator('fix_version', allow_reuse = True)(strip_epoch)

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
