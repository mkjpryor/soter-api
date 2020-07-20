"""
Module containing models for data-transfer objects (DTOs).

Used to define the interfaces between scanner implementations and the core API.
"""

from functools import total_ordering
from enum import Enum
from typing import Any, List, Dict, Optional

from pydantic import BaseModel, HttpUrl, validator, constr


class ScannerStatus(BaseModel):
    """
    Model for the status of a scanner.
    """
    #: The name of the scanner
    name: constr(min_length = 1)
    #: The kind of the scanner
    kind: constr(min_length = 1)
    #: The scanner version
    version: constr(min_length = 1)
    #: Indicates whether the scanner is available
    available: bool
    #: Message associated with the status
    message: Optional[constr(min_length = 1)] = None
    #: Additional properties associated with the scanner, e.g. time of last database update
    properties: Optional[Dict[str, Any]] = None


@total_ordering
class Severity(Enum):
    """
    Enum of possible severity levels for an issue.
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


class Issue(BaseModel):
    """
    Base class for all issue types.
    """
    #: The kind of the issue
    kind: constr(min_length = 1)
    #: The title of the issue
    title: constr(min_length = 1)
    #: The severity of the issue
    severity: Severity
    #: A URL to visit for more information, if available
    info_url: Optional[HttpUrl] = None
    #: A list of scanners that reported the issue
    reported_by: List[constr(min_length = 1)]
    #: Additional scanner-specific details for the error
    detail: Any


class Report(BaseModel):
    """
    Base class for all report classes.
    """
    #: List of issues
    issues: List[Issue]

    @validator('issues')
    def sort_issues(cls, issues):
        # Ensure that the issues are sorted by severity from highest to lowest
        return sorted(issues, key = lambda i: i.severity, reverse = True)
