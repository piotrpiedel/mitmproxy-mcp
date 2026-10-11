import types

import pytest

from mitmproxy_mcp.core import server


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", "http://127.0.0.1:9123"),
        ("0.0.0.0", "http://127.0.0.1:9123"),
        ("", "http://127.0.0.1:9123"),
        ("::", "http://[::1]:9123"),
        ("::1", "http://[::1]:9123"),
        ("192.168.1.5", "http://192.168.1.5:9123"),
        ("localhost", "http://localhost:9123"),
    ],
)
def test_local_proxy_url_reaches_proxy_on_any_listen_host(monkeypatch, host, expected):
    monkeypatch.setattr(server.controller, "host", host, raising=False)
    monkeypatch.setattr(server.controller, "port", 9123)

    assert server.controller.local_proxy_url() == expected


@pytest.fixture
def stopped_controller(monkeypatch):
    masters = []

    class FakeMaster:
        def __init__(self, opts, **kwargs):
            self.options = opts
            self.addons = types.SimpleNamespace(add=lambda addon: None)
            masters.append(self)

        async def run(self):
            return None

    monkeypatch.setattr(server, "DumpMaster", FakeMaster)
    for attr, value in {"running": False, "master": None, "proxy_task": None, "port": 8080}.items():
        monkeypatch.setattr(server.controller, attr, value)
    monkeypatch.setattr(server.controller, "host", "127.0.0.1", raising=False)
    return masters


@pytest.mark.asyncio
async def test_start_proxy_defaults_to_loopback_without_warning(stopped_controller):
    message = await server.start_proxy(port=9123)

    assert stopped_controller[0].options.listen_host == "127.0.0.1"
    assert "Warning" not in message


@pytest.mark.asyncio
async def test_start_proxy_listens_on_requested_host_and_warns(stopped_controller):
    message = await server.start_proxy(port=9123, listen_host="0.0.0.0")

    assert stopped_controller[0].options.listen_host == "0.0.0.0"
    assert server.controller.local_proxy_url() == "http://127.0.0.1:9123"
    assert "Warning" in message
