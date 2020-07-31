"""
Module containing utilities for Soter API modules.
"""

import inspect

import wrapt

from jsonrpc.exceptions import JsonRpcException

from .exceptions import MissingData
from .models import Error


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


def exception_as_issue(exc, scanner_name):
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
        # Convert the exception name to words for the title
        words = re.findall(r'[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))', exc.__class__.__name__)
        title = ' '.join(words).lower().capitalize()
        detail = repr(exc)
    return Error(
        kind = kind,
        title = title,
        detail = detail,
        reported_by = [scanner_name]
    )
