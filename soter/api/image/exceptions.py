"""
Module containing exceptions that can be raised by backends.
"""

from ..exceptions import ScannerError


class ImageNotFound(ScannerError):
    """
    Raised when an image cannot be found.
    """
    code = 210
    message = "Image not found"
