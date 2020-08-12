"""
Module containing exceptions that can be raised by backends.
"""

from jsonrpc.model import JsonRpcException


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
    code = 1000
    message = "Scanner unavailable"


class NoSuitableScanners(ScannerError):
    """
    Raised when there are no suitable scanners for an operation.
    """
    code = 1001
    message = "No suitable scanners"
