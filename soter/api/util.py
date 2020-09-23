"""
Module containing utilities for Soter API modules.
"""

import inspect
import re

import wrapt

from jsonrpc.model import JsonRpcException

from .exceptions import NoSuitableScanners
from .models import Error
from .scanner import Scanner


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


def default_scanners(scanner_type = None):
    """
    Decorator that injects scanners into the wrapped function. The wrapped function
    should have an argument called ``scanners`` with no default value.

    The scanners come from settings and are optionally filtered in the request.

    The scanners can also be filtered by type by supplying a type to the decorator.
    """
    # If a scanner is given but is not a class, it will be the wrapped function
    if scanner_type and not inspect.isclass(scanner_type):
        return default_scanners()(scanner_type)
    # Otherwise, return the decorator
    @wrapt.decorator(adapter = wrapt.adapter_factory(argspec_scanners_optional))
    def wrapper(wrapped, instance, args, kwargs):
        from .conf import settings
        if 'scanners' in kwargs:
            # If scanners is given in kwargs, use it even if it is empty
            requested = kwargs.pop('scanners')
            scanners = [s for s in settings.scanners if s.name in requested]
            if not scanners:
                raise NoSuitableScanners('no valid scanners specified')
        else:
            # If no scanners were given, just use all the scanners from settings
            scanners = settings.scanners
        # Check the remaining scanners for type, if given
        if scanner_type:
            scanners = [s for s in scanners if isinstance(s, scanner_type)]
            if not scanners:
                raise NoSuitableScanners('no suitable scanners specified')
        return wrapped(*args, scanners = scanners, **kwargs)
    return wrapper


def exception_as_issue(exc, scanner_name):
    """
    Convert the given exception to an issue for inclusion in reports.
    """
    if isinstance(exc, JsonRpcException):
        title = exc.message
        detail = exc.data
    else:
        # Convert the exception name to words for the title
        words = re.findall(r'[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))', exc.__class__.__name__)
        title = ' '.join(words).lower().capitalize()
        detail = repr(exc)
    return Error(title = title, detail = detail, reported_by = [scanner_name])
