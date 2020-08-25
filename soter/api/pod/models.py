"""
Module containing models for data-transfer objects (DTOs) for pod scanners.
"""

import itertools
from typing import Dict, Set, Union

from pydantic import constr, conset
from pydantic.dataclasses import dataclass

from ..models import Issue, Error, Severity, Report

from ..image.models import ImageReport


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


class VulnerableImage(PodIssue):
    """
    Model indicating that one or more pods are using a vulnerable image.

    The image vulnerabilities are nested inside.
    """
    #: The image scan that triggered this issue
    image_report: ImageReport

    @property
    def aggregation_key(self):
        # Add the image and digest from the report to the aggregation key
        return super().aggregation_key + (
            self.image_report.image,
            self.image_report.digest
        )

    def merge(self, other):
        merged = super().merge(other)
        # This should probably never happen
        # However, the reports are for the same image so just merge the issues
        merged.image_report.issues.update(other.image_report.issues)
        return merged

    @classmethod
    def from_image_report(cls, report, affected_pods):
        return cls(
            title = 'Uses image with known vulnerabilities',
            # The severity is the severity of the most severe image vulnerability
            severity = next(iter(report.issues)).severity,
            # Include all the scanners that contributed to the report
            reported_by = set(itertools.chain.from_iterable(i.reported_by for i in report.issues)),
            affected_pods = affected_pods,
            image_report = report
        )


class ImageNotFound(PodIssue, Error):
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
