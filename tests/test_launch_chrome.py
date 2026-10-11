import json

import pytest

from mitmproxy_mcp.core import server


class FakePopen:
    def __init__(self, cmd):
        self.cmd = cmd
        self.pid = 4242

    def poll(self):
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("listen_host", "proxy"),
    [("127.0.0.1", "http://127.0.0.1:9123"), ("::", "http://[::1]:9123")],
)
async def test_launch_chrome_routes_through_running_proxy(
    monkeypatch, tmp_path, listen_host, proxy
):
    launched = []

    def fake_popen(cmd, **kwargs):
        launched.append(FakePopen(cmd))
        return launched[-1]

    monkeypatch.setattr(server, "_find_chrome", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(server.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(server.controller, "running", True)
    monkeypatch.setattr(server.controller, "port", 9123)
    monkeypatch.setattr(server.controller, "host", listen_host, raising=False)
    monkeypatch.setattr(server.controller, "browser_process", None)
    monkeypatch.setattr(server.controller, "browser_profile_dir", None, raising=False)

    result = json.loads(await server.launch_chrome_with_proxy(profile=str(tmp_path)))

    assert f"--proxy-server={proxy}" in launched[0].cmd
    assert result["proxy"] == proxy
