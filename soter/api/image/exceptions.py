"""
Module containing exceptions that can be raised by backends.
"""

from ..exceptions import ScannerError


class ImageNotFound(ScannerError):
    """
    Raised when an image cannot be found.
    """
    code = 200
    message = "Image not found"


class ImageSubmissionFailed(ScannerError):
    """
    Raised when image submission failed for all scanners.
    """
    code = 201
    message = "Image submission failed"


class NoVulnerabilityDataAvailable(ScannerError):
    """
    Raised when vulnerability data is not available for an image.
    """
    code = 201
    message = "Vulnerability data not available"
