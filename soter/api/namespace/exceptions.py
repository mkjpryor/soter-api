"""
Module containing exceptions that can be raised by pod methods and scanners.
"""

from ..exceptions import ScannerError


class UnsupportedKind(ScannerError):
    """
    Raised when a user asks for a kind which is not supported on the cluster.
    """
    code = 230
    message = "Kind not supported"
