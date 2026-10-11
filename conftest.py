"""Keeps every test run away from the user's real traffic database.

server.py builds its MitmController (and TrafficDB) at import time, i.e. during test
collection, so the path must be set here at module level; a fixture would run too late.
The override is unconditional on purpose: a MITMPROXY_MCP_DB exported in the shell
points at real data, and tests call clear() on whatever database they get.
"""

import os
import tempfile

os.environ["MITMPROXY_MCP_DB"] = os.path.join(
    tempfile.mkdtemp(prefix="mitmproxy-mcp-tests-"), "traffic.db"
)
