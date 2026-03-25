"""Tests for CLI interface."""

import pytest
from click.testing import CliRunner

from hb_scan.cli import main


class TestCLI:

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "hb-scan" in result.output
        assert "0.1.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "AI Session Security Scanner" in result.output
        assert "--since" in result.output
        assert "--tool" in result.output

    def test_discover_subcommand(self):
        runner = CliRunner()
        result = runner.invoke(main, ["discover"])
        assert result.exit_code == 0
        assert "Claude Code" in result.output

    def test_rules_subcommand(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "secret_exposure" in result.output
        assert "Rules" in result.output

    def test_invalid_since_format(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--since", "invalid"])
        assert result.exit_code != 0

    def test_since_days(self):
        runner = CliRunner()
        # Should parse without error (may find 0 sessions for very short window)
        result = runner.invoke(main, ["--since", "1d"])
        # Either completes successfully or exits 0 (no sessions)
        assert result.exit_code in (0, 1)  # 1 if critical findings
