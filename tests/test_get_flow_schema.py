import json

import pytest

from mitmproxy_mcp.core import server


def _stub_body(monkeypatch, body):
    """Make get_flow_schema see `body` as the stored response body of any flow."""
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_response_body",
        lambda fid: body,
    )


@pytest.mark.asyncio
async def test_get_flow_schema_json_object(monkeypatch):
    _stub_body(monkeypatch, '{"id": 123, "name": "test", "active": true, "tags": ["a", "b"]}')

    schema = json.loads(await server.get_flow_schema("any"))

    assert schema == {"id": "int", "name": "str", "active": "bool", "tags": "list"}


@pytest.mark.asyncio
async def test_get_flow_schema_reads_full_body(monkeypatch):
    seen = []

    def fake_get_response_body(fid):
        seen.append(fid)
        return '{"user_id": 456, "email": "user@example.com"}'

    monkeypatch.setattr(
        server.controller.recorder.db, "get_response_body", fake_get_response_body
    )

    schema = json.loads(await server.get_flow_schema("flow-db"))

    assert seen == ["flow-db"]
    assert schema == {"user_id": "int", "email": "str"}


@pytest.mark.asyncio
async def test_get_flow_schema_not_json(monkeypatch):
    _stub_body(monkeypatch, "<html><body>Hello</body></html>")

    assert await server.get_flow_schema("any") == "Response body is not valid JSON."


@pytest.mark.asyncio
async def test_get_flow_schema_json_array_of_objects(monkeypatch):
    _stub_body(monkeypatch, '[{"id": 1}, {"id": 2}]')

    schema = json.loads(await server.get_flow_schema("any"))

    assert schema == {"type": "array", "length": 2, "item_keys": {"id": "int"}}


@pytest.mark.asyncio
async def test_get_flow_schema_json_array_of_scalars(monkeypatch):
    _stub_body(monkeypatch, "[1, 2, 3]")

    schema = json.loads(await server.get_flow_schema("any"))

    assert schema == {"type": "array", "length": 3}


@pytest.mark.asyncio
async def test_get_flow_schema_json_scalar(monkeypatch):
    _stub_body(monkeypatch, "42")

    assert (
        await server.get_flow_schema("any")
        == "Response is JSON but not an object (it's int)."
    )


@pytest.mark.asyncio
async def test_get_flow_schema_flow_not_found(monkeypatch):
    _stub_body(monkeypatch, None)

    assert await server.get_flow_schema("nonexistent") == "Flow not found."


@pytest.mark.asyncio
async def test_get_flow_schema_empty_body(monkeypatch):
    _stub_body(monkeypatch, "")

    assert await server.get_flow_schema("any") == "Flow has no response body."
