"""
Module containing models for data-transfer objects (DTOs) for pod scanners.
"""

import itertools
from typing import Dict, Set, Union

from pydantic import constr, conset
from pydantic.dataclasses import dataclass

from ..models import Issue, Error, Severity, Report

from ..image.models import PackageDetail


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
    affected_pods: conset(Pod, min_items = 1)

    def merge(self, other):
        # Merge the affected pods with the incoming issue
        merged = super().merge(other)
        merged.affected_pods = self.affected_pods | other.affected_pods
        return merged


class PodError(PodIssue, Error):
    """
    Model for a scanner error affecting one or more pods.
    """


class PodImageVulnerability(PodIssue):
    """
    Model for an image vulnerability affecting one or more images in use by one or more pods.
    """
    #: The affected packages, indexed by image digest
    affected_packages: Dict[str, conset(PackageDetail, min_items = 1)]

    def merge(self, other):
        merged = super().merge(other)
        # Reset the affected packages on the merged object
        merged.affected_packages = dict()
        # Combine the affected packages from the two issues by merging the sets that
        # correspond to the same image
        all_packages = itertools.chain(self.affected_packages.items(), other.affected_packages.items())
        for image, packages in all_packages:
            merged.affected_packages.setdefault(image, set()).update(packages)
        return merged


class PodImageError(PodError):
    """
    Model for a scanner error affecting one or more images in use by one or more pods.
    """
    #: The set of images affected by the error
    affected_images: conset(constr(min_length = 1), min_items = 1)

    def merge(self, other):
        # Merge the affected images
        merged = super().merge(other)
        merged.affected_images = self.affected_images | other.affected_images
        return merged


class ImageNotFound(PodImageError):
    """
    Model for an issue representing an image that is not found.
    """
    # Set default valus for the issue properties
    title: constr(min_length = 1) = "Image not found"
    detail: constr(min_length = 1) = "Image not found in registry"
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
