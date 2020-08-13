"""
Root module for the Kubernetes authenticator package.
"""

from pkg_resources import iter_entry_points

from .exceptions import InvalidAuthenticatorKind


def authenticator_from_config(config):
    """
    Returns an authenticator for the given config.
    """
    auth_kind = config.pop('kind', 'kubeconfig')
    # Use the auth kind as an entrypoint name
    try:
        auth_cls = next(iter_entry_points('soter.api.k8s_auth', auth_kind)).load()
    except StopIteration:
        available = ', '.join(ep.name for ep in iter_entry_points('soter.api.k8s_auth'))
        raise InvalidAuthenticatorKind(f'not a valid authenticator kind (available: {available})')
    # Initialise the authenticator from the rest of the config
    return auth_cls(**config)
