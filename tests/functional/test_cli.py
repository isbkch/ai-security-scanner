"""Functional tests for CLI."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_security_scanner.cli.main import main


@pytest.fixture
def runner() -> CliRunner:
    """Provide CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_vulnerable_code(tmp_path: Path) -> Path:
    """Create sample vulnerable code file."""
    code_file = tmp_path / "vulnerable.py"
    code_file.write_text(
        """
import hashlib

password = "hardcoded123"
hash_val = hashlib.md5(password.encode()).hexdigest()

query = f"SELECT * FROM users WHERE id = {user_id}"
"""
    )
    return tmp_path


class TestCLIScan:
    """Test CLI scan command."""

    def test_scan_help(self, runner: CliRunner) -> None:
        """Test scan command help."""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan" in result.output or "scan" in result.output

    def test_scan_directory(self, runner: CliRunner, sample_vulnerable_code: Path) -> None:
        """Test scanning a directory."""
        result = runner.invoke(main, ["scan", str(sample_vulnerable_code), "--no-ai"])
        assert result.exit_code == 0

    def test_scan_with_json_output(
        self, runner: CliRunner, sample_vulnerable_code: Path, tmp_path: Path
    ) -> None:
        """Test scan with JSON output."""
        output_file = tmp_path / "results.json"
        result = runner.invoke(
            main,
            ["scan", str(sample_vulnerable_code), "--output", "json", "--file", str(output_file), "--no-ai"],
        )
        assert result.exit_code == 0
        if output_file.exists():
            data = json.loads(output_file.read_text())
            assert "vulnerabilities" in data or "scan_id" in data

    def test_scan_nonexistent_directory(self, runner: CliRunner) -> None:
        """Test scanning non-existent directory."""
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0


class TestCLIVersion:
    """Test CLI version command."""

    def test_version_command(self, runner: CliRunner) -> None:
        """Test version command."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "." in result.output
