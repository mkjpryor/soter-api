"""
Module providing the ASGI app for soter-image-scan.
"""

from pkg_resources import iter_entry_points

from quart import Quart
from quart.exceptions import HTTPException

from jsonrpc.dispatch import Dispatcher
from jsonrpc.adapter.quart import http_blueprint


dispatcher = Dispatcher()
# Add all the configured RPC modules to the dispatcher
# Using an entrypoint allows packages to provide additional, namespaced methods
for ep in iter_entry_points('soter.api.rpc'):
    dispatcher.register_all(ep.load(), prefix = ep.name)


async def handle_http_exception(exc):
    """
    Handle Quart HTTP exceptions by returning a JSON response.
    """
    return dict(name = exc.name, detail = exc.description), exc.status_code


# Build the Quart app
app = Quart(__name__)
# Register the error handler
app.errorhandler(HTTPException)(handle_http_exception)
# Register the JSON-RPC blueprint
app.register_blueprint(http_blueprint(dispatcher), url_prefix = '/')
