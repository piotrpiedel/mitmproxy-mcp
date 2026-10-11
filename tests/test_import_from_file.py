import pytest
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.recorder import TrafficDB


@pytest.fixture
def db_with_one_flow(tmp_path):
    db = TrafficDB(str(tmp_path / "traffic.db"))
    db.save_flow(tflow(resp=True))
    return db


def write_flow_file(path, count):
    with open(path, "wb") as f:
        writer = io.FlowWriter(f)
        for _ in range(count):
            writer.add(tflow(resp=True))
    return path


def test_missing_file_keeps_existing_traffic(db_with_one_flow, tmp_path):
    with pytest.raises(FileNotFoundError):
        db_with_one_flow.import_from_file(str(tmp_path / "missing.har"))

    assert len(db_with_one_flow.get_summary()) == 1


def test_unsupported_extension_keeps_existing_traffic(db_with_one_flow, tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("not a flow file")

    with pytest.raises(ValueError):
        db_with_one_flow.import_from_file(str(notes))

    assert len(db_with_one_flow.get_summary()) == 1


def test_unparseable_file_keeps_existing_traffic(db_with_one_flow, tmp_path):
    broken = tmp_path / "broken.har"
    broken.write_text('{"log": {"entries": [')

    with pytest.raises(FlowReadException):
        db_with_one_flow.import_from_file(str(broken))

    assert len(db_with_one_flow.get_summary()) == 1


def test_valid_file_replaces_existing_traffic(db_with_one_flow, tmp_path):
    flows_file = write_flow_file(tmp_path / "capture.mitm", count=2)

    stats = db_with_one_flow.import_from_file(str(flows_file))

    assert stats["imported"] == 2
    assert len(db_with_one_flow.get_summary()) == 2


def test_append_keeps_existing_traffic(db_with_one_flow, tmp_path):
    flows_file = write_flow_file(tmp_path / "capture.mitm", count=2)

    db_with_one_flow.import_from_file(str(flows_file), append=True)

    assert len(db_with_one_flow.get_summary()) == 3
