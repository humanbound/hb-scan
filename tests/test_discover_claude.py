"""Tests for Claude Code discoverer."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone

from hb_scan.discover.claude import ClaudeDiscoverer


FIXTURES = Path(__file__).parent / "fixtures"


class TestClaudeDiscoverer:

    def test_is_installed_checks_paths(self):
        d = ClaudeDiscoverer()
        # Just verify the method runs without error
        result = d.is_installed()
        assert isinstance(result, bool)

    def test_decode_project_path(self):
        d = ClaudeDiscoverer()
        assert d._decode_project_path("-Applications-MAMP-htdocs-project") == "/Applications/MAMP/htdocs/project"
        assert d._decode_project_path("-home-user-code") == "/home/user/code"

    def test_decode_project_path_no_prefix(self):
        d = ClaudeDiscoverer()
        assert d._decode_project_path("some-folder") == "some-folder"

    def test_parse_timestamp_iso(self):
        ts = ClaudeDiscoverer._parse_timestamp("2026-03-15T10:00:00Z")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 3

    def test_parse_timestamp_unix_seconds(self):
        ts = ClaudeDiscoverer._parse_timestamp(1773577200)
        assert ts is not None

    def test_parse_timestamp_unix_millis(self):
        ts = ClaudeDiscoverer._parse_timestamp(1773577200000)
        assert ts is not None

    def test_parse_timestamp_none(self):
        assert ClaudeDiscoverer._parse_timestamp(None) is None

    def test_parse_session_from_fixture(self):
        d = ClaudeDiscoverer()
        session = d._parse_session(
            FIXTURES / "claude_session.jsonl",
            "/home/dev/myproject",
            since=None,
        )
        assert session is not None
        assert session.id == "claude_session"
        assert session.tool == "claude-code"
        assert session.cwd == "/home/dev/myproject"
        assert len(session.messages) > 0

    def test_fixture_has_user_and_assistant(self):
        d = ClaudeDiscoverer()
        session = d._parse_session(
            FIXTURES / "claude_session.jsonl",
            "/test/project",
            since=None,
        )
        roles = {m.role for m in session.messages}
        assert "user" in roles
        assert "assistant" in roles

    def test_fixture_has_tool_calls(self):
        d = ClaudeDiscoverer()
        session = d._parse_session(
            FIXTURES / "claude_session.jsonl",
            "/test/project",
            since=None,
        )
        all_tool_calls = [tc for m in session.messages for tc in m.tool_calls]
        assert len(all_tool_calls) >= 2
        tool_names = {tc.name for tc in all_tool_calls}
        assert "Write" in tool_names or "Bash" in tool_names

    def test_since_filter_excludes_old_sessions(self):
        d = ClaudeDiscoverer()
        # Parse with a future since → should return None (all messages are in the past)
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        session = d._parse_session(
            FIXTURES / "claude_session.jsonl",
            "/test/project",
            since=future,
        )
        assert session is None

    def test_parse_empty_file(self, tmp_path):
        d = ClaudeDiscoverer()
        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_text("")
        session = d._parse_session(empty_file, "/test", since=None)
        assert session is None

    def test_parse_malformed_json(self, tmp_path):
        d = ClaudeDiscoverer()
        bad_file = tmp_path / "bad.jsonl"
        bad_file.write_text("not json\n{also bad\n")
        session = d._parse_session(bad_file, "/test", since=None)
        assert session is None  # no valid messages
