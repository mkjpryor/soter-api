"""
Module containing exceptions that can be raised by pod methods and scanners.
"""

from ..exceptions import ScannerError


class PodSubmissionFailed(ScannerError):
    """
    Raised when submission fails for one or more pods.
    """
    code = 301
    message = "Pod submission failed"
