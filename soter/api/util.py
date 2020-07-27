"""
Module containing utilities for Soter API modules.
"""

import inspect

import wrapt

from jsonrpc.exceptions import JsonRpcException

from .exceptions import MissingData
from .models import Issue, Severity


def injects(n):
    """
    Decorator for a decorator that injects ``n`` arguments into the wrapped function
    at the start of the argspec that ensures that the decorated function has the
    correct signature.
    """
    def modify_argspec(wrapped):
        argspec = inspect.getargspec(wrapped)
        return argspec._replace(args = argspec.args[n:])
    return wrapt.decorator(adapter = wrapt.adapter_factory(modify_argspec))


def exception_as_issue(scanner, exc):
    """
    Convert the given exception to an issue for inclusion in reports.
    """
    if isinstance(exc, MissingData):
        kind = "Missing Data"
    else:
        kind = "Scanner Error"
    if isinstance(exc, JsonRpcException):
        title = exc.message
        detail = exc.data
    else:
        title = "Error retrieving issue data"
        detail = repr(exc)
    return Issue(
        kind = kind,
        title = title,
        severity = Severity.HIGH,
        reported_by = [scanner.name],
        detail = detail
    )
