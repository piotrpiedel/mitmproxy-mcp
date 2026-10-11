import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core import server


def recorded_flow(content):
    flow = tflow(resp=True)
    flow.response.content = content
    server.controller.recorder.db.save_flow(flow)
    return flow.id


@pytest.mark.asyncio
async def test_extracts_value_beyond_preview_length(monkeypatch):
    monkeypatch.setattr(server.controller, "session_variables", {})
    flow_id = recorded_flow(b"x" * 5000 + b'"csrf_token": "abc123"')

    result = await server.extract_session_variable("csrf", flow_id, r'"csrf_token": "(\w+)"')

    assert result == "Extracted and set $csrf = abc123"
    assert server.controller.session_variables == {"csrf": "abc123"}


@pytest.mark.asyncio
async def test_unknown_flow_is_reported():
    result = await server.extract_session_variable("csrf", "no-such-flow", r"(\w+)")

    assert result == "No matching flow."


@pytest.mark.asyncio
async def test_empty_body_is_reported():
    flow_id = recorded_flow(b"")

    result = await server.extract_session_variable("csrf", flow_id, r"(\w+)")

    assert result == "Flow has no response body."
