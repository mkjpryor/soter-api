"""
Module containing exceptions that can be raised by backends.
"""

from jsonrpc.model import JsonRpcException


class SoterError(JsonRpcException):
    """
    Base class for all Soter errors.
    """
    __seen__ = dict()

    def __init_subclass__(cls):
        # Make sure that the code has not been used for another error
        if cls.code is None:
            return
        if cls.code in SoterError.__seen__:
            message = 'code {} already in use by {}'.format(
                cls.code,
                SoterError.__seen__[cls.code].__name__
            )
            raise TypeError(message)
        SoterError.__seen__[cls.code] = cls


class ScannerError(SoterError):
    """
    Base class for all scanner errors in Soter.
    """


class ScannerUnavailable(ScannerError):
    """
    Raised when a scanner is not available.
    """
    message = "Scanner unavailable"
    code = 200


class NoSuitableScanners(ScannerError):
    """
    Raised when there are no suitable scanners for an operation.
    """
    message = "No suitable scanners"
    code = 201
