import base64
import types

import pytest
from mitmproxy.test import tflow

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.auth import AUTH_REJECTED_KEY, LanProxyAuth, is_local_peer


def _basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _flow(peer, authorization=None):
    flow = tflow.tflow()
    flow.client_conn.peername = (peer, 50000)
    if authorization is not None:
        flow.request.headers["Proxy-Authorization"] = authorization
    return flow


@pytest.fixture
def auth():
    return LanProxyAuth("mitm", "s3cret")


@pytest.mark.parametrize(
    ("peer", "local"),
    [
        ("127.0.0.1", True),
        ("127.0.0.5", True),
        ("::1", True),
        ("::ffff:127.0.0.1", True),
        ("192.168.1.20", False),
        ("10.0.0.2", False),
        ("::ffff:192.168.1.20", False),
        ("2001:db8::1", False),
    ],
)
def test_is_local_peer(peer, local):
    assert is_local_peer(peer) is local


def test_local_client_needs_no_password(auth):
    flow = _flow("127.0.0.1")

    auth.requestheaders(flow)

    assert flow.response is None
    assert AUTH_REJECTED_KEY not in flow.metadata


def test_remote_client_without_header_gets_407(auth):
    flow = _flow("192.168.1.20")

    auth.requestheaders(flow)

    assert flow.response.status_code == 407
    assert flow.response.headers["Proxy-Authenticate"].startswith("Basic")
    assert flow.metadata[AUTH_REJECTED_KEY] is True


@pytest.mark.parametrize(
    "header",
    [_basic("mitm", "wrong"), _basic("other", "s3cret"), "Basic !!!not-base64", "Bearer s3cret", ""],
)
def test_remote_client_with_bad_credentials_gets_407(auth, header):
    flow = _flow("192.168.1.20", header)

    auth.requestheaders(flow)

    assert flow.response.status_code == 407


def test_remote_client_with_good_credentials_passes_and_header_is_stripped(auth):
    flow = _flow("192.168.1.20", _basic("mitm", "s3cret"))

    auth.requestheaders(flow)

    assert flow.response is None
    assert "Proxy-Authorization" not in flow.request.headers


def test_password_may_contain_colon(auth):
    colon = LanProxyAuth("mitm", "a:b:c")
    flow = _flow("192.168.1.20", _basic("mitm", "a:b:c"))

    colon.requestheaders(flow)

    assert flow.response is None


def test_connect_authenticates_the_whole_connection(auth):
    connect = _flow("192.168.1.20", _basic("mitm", "s3cret"))
    auth.http_connect(connect)
    assert connect.response is None

    later = _flow("192.168.1.20")
    later.client_conn = connect.client_conn
    auth.requestheaders(later)

    assert later.response is None


def test_connect_without_credentials_gets_407(auth):
    connect = _flow("192.168.1.20")

    auth.http_connect(connect)

    assert connect.response.status_code == 407


def test_local_connect_is_not_challenged(auth):
    connect = _flow("127.0.0.1")

    auth.http_connect(connect)

    assert connect.response is None


def test_rejected_flows_are_not_recorded():
    flow = _flow("192.168.1.20")
    LanProxyAuth("mitm", "s3cret").requestheaders(flow)

    assert server.controller.recorder.scope.is_allowed(flow) is False


@pytest.fixture
def started(monkeypatch):
    added = []

    class FakeMaster:
        def __init__(self, opts, **kwargs):
            self.options = opts
            self.addons = types.SimpleNamespace(add=lambda addon: added.append(addon))

        async def run(self):
            return None

    monkeypatch.setattr(server, "DumpMaster", FakeMaster)
    for attr, value in {"running": False, "master": None, "proxy_task": None, "port": 8080}.items():
        monkeypatch.setattr(server.controller, attr, value)
    monkeypatch.setattr(server.controller, "host", "127.0.0.1", raising=False)
    monkeypatch.setattr(server.controller, "proxy_auth", None, raising=False)
    return added


@pytest.mark.asyncio
async def test_loopback_start_adds_no_auth_addon(started):
    message = await server.start_proxy(port=9123)

    assert not any(isinstance(a, LanProxyAuth) for a in started)
    assert "password" not in message.lower()


@pytest.mark.asyncio
async def test_lan_start_adds_auth_addon_first_and_reports_credentials(started):
    message = await server.start_proxy(port=9123, listen_host="0.0.0.0")

    assert isinstance(started[0], LanProxyAuth)
    user, password = server.controller.proxy_auth
    assert user == "mitm" and len(password) >= 16
    assert password in message
    assert "127.0.0.1" in message


@pytest.mark.asyncio
async def test_each_lan_start_gets_a_new_password(started):
    await server.start_proxy(port=9123, listen_host="0.0.0.0")
    first = server.controller.proxy_auth
    server.controller.running = False
    await server.start_proxy(port=9123, listen_host="0.0.0.0")

    assert server.controller.proxy_auth != first
