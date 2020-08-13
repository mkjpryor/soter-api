"""
Module containing specific exceptions raised by authenticators.
"""

from ..exceptions import SoterError


class InvalidAuthenticatorKind(SoterError):
    """
    Raised when an invalid authenticator kind is specified.
    """
    code = 100
    message = "Invalid authenticator kind"
