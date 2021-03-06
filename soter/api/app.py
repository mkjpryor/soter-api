"""
Module providing the ASGI app for soter-image-scan.
"""

from pkg_resources import iter_entry_points

from quart import Quart

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint

from . import cache


dispatcher = Dispatcher()
# Add all the configured RPC modules to the dispatcher
# Using an entrypoint allows packages to provide additional, namespaced methods
for ep in iter_entry_points('soter.api.rpc'):
    dispatcher.register_all(ep.load(), prefix = ep.name)


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')

# Attach a cache instance to the app
@app.before_serving
async def create_cache():
    """
    Attach a cache object to the app.
    """
    app.cache = await cache.from_environment()
