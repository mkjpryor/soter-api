"""
Module containing models for data-transfer objects (DTOs) for pod scanners.
"""

import itertools
from typing import Set, Optional

from pydantic import constr, conset
from pydantic.dataclasses import dataclass

from ..models import Issue, Error, Report


@dataclass(eq = True, frozen = True)
class Resource:
    """
    Model representing a resource.
    """
    #: The namespace of the resource
    namespace: constr(min_length = 1)
    #: The kind of the resource
    kind: constr(min_length = 1)
    #: The name of the resource
    name: constr(min_length = 1)


class ResourceIssue(Issue):
    """
    Base class for issues that affect one or more resources.
    """
    #: The affected resources
    affected_resources: conset(Resource, min_items = 1)

    def merge(self, other):
        # Merge the affected resources with the incoming issue
        merged = super().merge(other)
        merged.affected_resources = self.affected_resources | other.affected_resources
        return merged


class ResourceError(Error, ResourceIssue):
    """
    Model for a scanner error affecting one or more resources.
    """


class VulnerableImage(ResourceIssue):
    """
    Model for an issue that references a vulnerable image.
    """
    #: The image
    image: constr(min_length = 1)
    #: The digest of the image
    digest: constr(min_length = 1)

    @property
    def aggregation_key(self):
        # Add the image and digest to the aggregation key
        return super().aggregation_key + (self.image, self.digest)

    @classmethod
    def from_image_report(cls, title, report, affected_resources):
        return cls(
            title = title,
            image = report.image,
            digest = report.digest,
            # The severity is the severity of the most severe image vulnerability in the report
            severity = next(iter(report.issues)).severity,
            # Include all the scanners that contributed to the report
            reported_by = set(itertools.chain.from_iterable(i.reported_by for i in report.issues)),
            affected_resources = affected_resources
        )


class ImageNotFound(ResourceError):
    """
    Model for an issue yielded when a resource references an image that is not found.
    """
    # Set default valus for the issue properties
    title: constr(min_length = 1) = "Image not found"
    detail: constr(min_length = 1) = "Image not found in registry"
    reported_by: conset(constr(min_length = 1), min_items = 1) = {'system'}


class ConfigurationIssue(ResourceIssue):
    """
    Model for an issue that indicates a problem with a resource configuration.
    """
    #: The suggested remediation for the issue
    suggested_remediation: Optional[constr(min_length = 1)] = None


class ResourceReport(Report):
    """
    Model for a report on a set of resources.
    """
    #: The set of resources that were processed
    resources: Set[Resource]
