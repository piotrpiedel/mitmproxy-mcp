import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from mitmproxy_mcp.core.recorder import TrafficDB


def test_explicit_path_creates_missing_parent_dirs(tmp_path):
    db_path = tmp_path / "nested" / "dir" / "traffic.db"

    TrafficDB(str(db_path))

    assert db_path.exists()


def test_env_var_overrides_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / "from-env.db"
    monkeypatch.setenv("MITMPROXY_MCP_DB", str(db_path))

    db = TrafficDB()

    assert Path(db.db_path) == db_path
    assert db_path.exists()


def test_env_var_expands_home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MITMPROXY_MCP_DB", "~/traffic.db")

    db = TrafficDB()

    assert Path(db.db_path) == tmp_path / "traffic.db"


def test_default_path_uses_xdg_data_home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MITMPROXY_MCP_DB", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    db = TrafficDB()

    assert Path(db.db_path) == tmp_path / "xdg" / "mitmproxy-mcp" / "traffic.db"


def test_default_path_falls_back_to_home_local_share(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MITMPROXY_MCP_DB", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    db = TrafficDB()

    assert Path(db.db_path) == tmp_path / ".local" / "share" / "mitmproxy-mcp" / "traffic.db"


def test_database_uses_wal_journal_mode(tmp_path):
    db_path = tmp_path / "traffic.db"
    TrafficDB(str(db_path))

    conn = sqlite3.connect(db_path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()

    assert mode == "wal"


def test_operations_close_their_connections(tmp_path, monkeypatch):
    opened = []
    real_connect = sqlite3.connect

    def tracking_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)
    db = TrafficDB(str(tmp_path / "traffic.db"))
    db.get_summary()
    db.clear()

    assert opened
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


def test_test_session_never_touches_user_database():
    from mitmproxy_mcp.core import server

    env_path = os.environ.get("MITMPROXY_MCP_DB")

    assert env_path, "root conftest.py must point MITMPROXY_MCP_DB at a temp file"
    assert Path(env_path).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    assert Path(server.controller.recorder.db.db_path) == Path(env_path)
