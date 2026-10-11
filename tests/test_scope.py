import pytest
from mitmproxy import io
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.recorder import TrafficDB
from mitmproxy_mcp.core.scope import ScopeManager, host_in_scope
from mitmproxy_mcp.models import ScopeConfig


@pytest.mark.parametrize(
    ("host", "domains", "expected"),
    [
        ("example.com", ["example.com"], True),
        ("api.example.com", ["example.com"], True),
        ("API.Example.COM", ["example.com"], True),
        ("example.com.", ["example.com"], True),
        ("api.example.com", ["*.example.com"], True),
        ("api.example.com", [".example.com"], True),
        ("notexample.com", ["example.com"], False),
        ("example.com.evil.net", ["example.com"], False),
        ("api.example.org", ["api"], False),
        ("other.net", ["example.com", "other.net"], True),
    ],
)
def test_host_in_scope_matches_domain_or_subdomain(host, domains, expected):
    assert host_in_scope(host, domains) is expected


def flow_to(host):
    flow = tflow(resp=True)
    flow.request.host = host
    flow.request.path = "/api/items"
    return flow


def test_scope_manager_rejects_host_that_only_contains_allowed_domain():
    scope = ScopeManager(ScopeConfig(allowed_domains=["example.com"]))

    assert scope.is_allowed(flow_to("api.example.com"))
    assert not scope.is_allowed(flow_to("example.com.evil.net"))


def test_import_scope_uses_same_matching(tmp_path):
    capture = tmp_path / "capture.mitm"
    with open(capture, "wb") as f:
        writer = io.FlowWriter(f)
        writer.add(flow_to("api.example.com"))
        writer.add(flow_to("example.com.evil.net"))
    db = TrafficDB(str(tmp_path / "traffic.db"))

    stats = db.import_from_file(str(capture), scope=["*.example.com"])

    assert (stats["imported"], stats["skipped"]) == (1, 1)
