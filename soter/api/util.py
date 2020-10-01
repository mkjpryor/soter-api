"""
Module containing utilities for Soter API modules.
"""

import inspect
import os
import re

import wrapt

from jsonrpc.model import JsonRpcException

from .exceptions import NoSuitableScanners
from .models import Error


def argspec_scanners_optional(wrapped):
    """
    Modify the signature of the given function to make the ``scanners`` argument
    optional.
    """
    argspec = inspect.getfullargspec(wrapped)
    if 'scanners' in argspec.args:
        # If scanners is in args, move it to the end and specify a default
        args = [arg for arg in argspec.args if arg != 'scanners'] + ['scanners']
        defaults = list(argspec.defaults or []) + [None]
        kwonlydefaults = argspec.kwonlydefaults
    elif 'scanners' in argspec.kwonlyargs:
        # If scanners is a keyword-only argument, give it a default value
        args = argspec.args
        defaults = argspec.defaults
        kwonlydefaults = dict(argspec.kwonlydefaults or {}, scanners = None)
    return inspect.FullArgSpec(
        args,
        argspec.varargs,
        argspec.varkw,
        defaults,
        argspec.kwonlyargs,
        kwonlydefaults,
        argspec.annotations
    )


@wrapt.decorator(adapter = wrapt.adapter_factory(argspec_scanners_optional))
def with_scanners(wrapped, instance, args, kwargs):
    """
    Decorator that filters and injects scanners into the wrapped function.

    The wrapped function should have an argument called ``scanners`` with no default value.

    The scanners come from environment variables and are optionally filtered by specifying
    scanner names in the request.
    """
    # Discover the scanners from the environment variables
    scanners = {
        var_name[14:].lower(): var_value
        for var_name, var_value in os.environ.items()
        if var_name.startswith('SOTER_SCANNER_')
    }
    requested_scanners = kwargs.pop('scanners', None)
    if requested_scanners:
        scanners = { k: v for k, v in scanners.items() if k in requested_scanners }
        if not scanners:
            raise NoSuitableScanners('no valid scanners specified')
    return wrapped(*args, scanners = scanners, **kwargs)
