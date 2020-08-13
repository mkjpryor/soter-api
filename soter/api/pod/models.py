"""
Module containing models for data-transfer objects (DTOs) for pod scanners.
"""

from typing import Set, Union

from pydantic import constr, conset
from pydantic.dataclasses import dataclass

from ..models import Issue, Error, Severity, Report

from ..image.models import ImageVulnerability


@dataclass(eq = True, frozen = True)
class Pod:
    """
    Model representing a pod.
    """
    #: The namespace of the pod
    namespace: constr(min_length = 1)
    #: The name of the pod
    name: constr(min_length = 1)


class PodIssue(Issue):
    """
    Base class for issues that affect one or more pods.
    """
    #: The affected pods
    #: When the issue is in a namespaced pod report, this is a set of pod names
    #: When the issue is in a non-namespaced pod report, it is a set of pod objects
    affected_pods: Union[
        conset(Pod, min_items = 1),
        conset(constr(min_length = 1), min_items = 1)
    ]

    def merge(self, other):
        # Merge the affected pods with the incoming issue
        merged = super().merge(other)
        merged.affected_pods = self.affected_pods | other.affected_pods
        return merged


class PodError(PodIssue, Error):
    """
    Model for a scanner error affecting one or more pods.
    """


class PodImageIssue(PodIssue):
    """
    Base class for issues that affect one or more images in use by one or more pods.
    """
    #: The affected images
    affected_images: conset(constr(min_length = 1), min_items = 1)

    def merge(self, other):
        # Merge the affected images
        merged = super().merge(other)
        merged.affected_images = self.affected_images | other.affected_images
        return merged

    @classmethod
    def from_image_issue(cls, issue, affected_images, affected_pods):
        """
        Attaches image and pod information to the given issue.
        """
        # Issues from image reports are either image vulnerabilities or errors
        if isinstance(issue, ImageVulnerability):
            return PodImageVulnerability(
                title = issue.title,
                severity = issue.severity,
                info_url = issue.info_url,
                reported_by = issue.reported_by,
                affected_packages = issue.affected_packages,
                affected_pods = affected_pods,
                affected_images = affected_images
            )
        else:
            return PodImageError(
                kind = issue.kind,
                title = issue.title,
                severity = issue.severity,
                reported_by = issue.reported_by,
                detail = issue.detail,
                affected_pods = affected_pods,
                affected_images = affected_images
            )


class PodImageError(PodImageIssue, Error):
    """
    Model for a scanner error affecting one or more images in use by one or more pods.
    """


class PodImageVulnerability(PodImageIssue, ImageVulnerability):
    """
    Model for an image vulnerability affecting one or more images in use by one or more pods.
    """


class ImageNotFound(PodImageIssue):
    """
    Model for an issue representing an image that is not found.
    """
    # Set default valus for the issue properties
    title: constr(min_length = 1) = "Image not found in registry"
    severity: Severity = Severity.HIGH
    reported_by: conset(constr(min_length = 1), min_items = 1) = {'system'}


class PodReport(Report):
    """
    Model for a pod security report.
    """
    #: The set of pods that were processed
    pods: Set[Pod]


class NamespacedPodReport(Report):
    """
    Model for a pod security report for a single namespace.
    """
    #: The namespace for the report
    namespace: constr(min_length = 1)
    #: The set of pods that were processed
    pods: Set[constr(min_length = 1)]
