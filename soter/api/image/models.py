"""
Module containing models for data-transfer objects (DTOs) for image scanners.
"""

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, HttpUrl, validator, constr, conset
from pydantic.dataclasses import dataclass

from ...scanner.models import ImageVulnerability as BaseImageVulnerability

from ..models import Issue, Report


class ImageVulnerability(BaseImageVulnerability, Issue):
    """
    Issue for a vulnerability in an image, aggregated across multiple scanners.
    """
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
