import json

import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core import server


class FakeResponse:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content


def fake_session_returning(status_code, content):
    class FakeAsyncSession:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, **kwargs):
            return FakeResponse(status_code, content)

    return FakeAsyncSession


def recorded_flow(status_code, content):
    flow = tflow(resp=True)
    flow.request.url = "https://api.example.com/items?q=1"
    flow.response.status_code = status_code
    flow.response.content = content
    server.controller.recorder.db.save_flow(flow)
    return flow.id


@pytest.mark.asyncio
async def test_response_matching_recorded_baseline_is_not_an_anomaly(monkeypatch):
    flow_id = recorded_flow(404, b"x" * 100)
    monkeypatch.setattr(server, "AsyncSession", fake_session_returning(404, b"y" * 100))

    result = await server.fuzz_endpoint(flow_id, "q", "query", "xss")

    assert result == "Fuzzing complete, No significant anomalies detected."


@pytest.mark.asyncio
async def test_length_deviation_from_recorded_baseline_is_reported(monkeypatch):
    flow_id = recorded_flow(200, b"x" * 100)
    monkeypatch.setattr(server, "AsyncSession", fake_session_returning(200, b"y" * 10))

    result = await server.fuzz_endpoint(flow_id, "q", "query", "xss")

    assert result != "Fuzzing complete, No significant anomalies detected."
    report = json.loads(result)
    assert report["baseline_status"] == 200
    assert report["baseline_len"] == 100
    assert {a["anomaly"] for a in report["anomalies"]} == {"Content Length Deviation (>20%)"}
