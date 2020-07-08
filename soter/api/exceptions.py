"""
Module containing exceptions that can be raised by backends.
"""

from jsonrpc.exceptions import JsonRpcException


class SoterError(JsonRpcException):
    """
    Base class for all Soter errors.
    """


class ScannerError(SoterError):
    """
    Base class for all scanner errors in Soter.
    """


class ScannerUnavailable(ScannerError):
    """
    Raised when a scanner is not available.
    """
    code = 100
    message = "Scanner unavailable"


class ImageNotFound(ScannerError):
    """
    Raised when an image cannot be found.
    """
    code = 200
    message = "Image not found"


class VulnerabilityDataUnavailable(ScannerError):
    """
    Raised when vulnerability data is not available for an image.
    """
    code = 201
    message = "Vulnerability data not available"
