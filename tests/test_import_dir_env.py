import json
import os

import pytest

from mitmproxy_mcp.core.server import load_traffic_file

EMPTY_HAR = '{"log": {"entries": []}}'


def _har(directory, name="capture.har"):
    path = directory / name
    path.write_text(EMPTY_HAR)
    return path


@pytest.fixture
def cwd_elsewhere(tmp_path, monkeypatch):
    """Server started in a directory that has nothing to do with the capture files."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("MITMPROXY_MCP_IMPORT_DIR", raising=False)
    return workdir


@pytest.mark.asyncio
async def test_env_dir_allows_file_outside_cwd(tmp_path, cwd_elsewhere, monkeypatch):
    captures = tmp_path / "captures"
    captures.mkdir()
    monkeypatch.setenv("MITMPROXY_MCP_IMPORT_DIR", str(captures))

    result = json.loads(await load_traffic_file(str(_har(captures))))

    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_env_dir_replaces_cwd(tmp_path, cwd_elsewhere, monkeypatch):
    captures = tmp_path / "captures"
    captures.mkdir()
    monkeypatch.setenv("MITMPROXY_MCP_IMPORT_DIR", str(captures))

    result = json.loads(await load_traffic_file(str(_har(cwd_elsewhere))))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_env_dir_denies_sibling_with_same_prefix(tmp_path, cwd_elsewhere, monkeypatch):
    captures = tmp_path / "captures"
    evil = tmp_path / "captures-evil"
    captures.mkdir()
    evil.mkdir()
    monkeypatch.setenv("MITMPROXY_MCP_IMPORT_DIR", str(captures))

    result = json.loads(await load_traffic_file(str(_har(evil))))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_env_accepts_several_dirs(tmp_path, cwd_elsewhere, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setenv("MITMPROXY_MCP_IMPORT_DIR", os.pathsep.join([str(first), str(second)]))

    for directory in (first, second):
        result = json.loads(await load_traffic_file(str(_har(directory))))
        assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_without_env_the_working_directory_still_applies(tmp_path, cwd_elsewhere):
    outside = tmp_path / "outside"
    outside.mkdir()

    allowed = json.loads(await load_traffic_file(str(_har(cwd_elsewhere))))
    denied = json.loads(await load_traffic_file(str(_har(outside))))

    assert allowed["status"] == "ok"
    assert denied["status"] == "error"


@pytest.mark.asyncio
async def test_blank_env_falls_back_to_working_directory(cwd_elsewhere, monkeypatch):
    monkeypatch.setenv("MITMPROXY_MCP_IMPORT_DIR", os.pathsep)

    result = json.loads(await load_traffic_file(str(_har(cwd_elsewhere))))

    assert result["status"] == "ok"
