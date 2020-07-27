"""
Module containing exceptions that can be raised by backends.
"""

from ..exceptions import ScannerError, MissingData


class ImageNotFound(ScannerError):
    """
    Raised when an image cannot be found.
    """
    code = 200
    message = "Image not found"


class ImageSubmissionFailed(ScannerError):
    """
    Raised when image submission failed for at least one scanners.
    """
    code = 201
    message = "Image submission failed"


class NoVulnerabilityDataAvailable(MissingData):
    """
    Raised when vulnerability data is not available for an image.
    """
    code = 202
    message = "No vulnerability data available"
