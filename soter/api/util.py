"""
Module containing utilities for Soter API modules.
"""

import inspect
import re

import wrapt

from jsonrpc.model import JsonRpcException

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
def default_scanners(wrapped, instance, args, kwargs):
    """
    Decorator that injects scanners into the wrapped function. The wrapped function
    should have an argument called ``scanners`` with no default value.

    The scanners come from settings and are optionally filtered in the request.
    """
    from .conf import settings
    requested = set(kwargs.pop('scanners', []))
    if requested:
        scanners = [s for s in settings.scanners if s.name in requested]
    else:
        scanners = settings.scanners
    return wrapped(*args, scanners = scanners, **kwargs)


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
