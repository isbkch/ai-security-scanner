"""Tests for SARIF exporter."""

import json
from datetime import datetime

import pytest

from ai_security_scanner.core.models import (
    Confidence,
    Location,
    ScanResult,
    Severity,
    VulnerabilityResult,
)
from ai_security_scanner.integrations.sarif.exporter import SARIFExporter


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create sample scan result for testing."""
    return ScanResult(
        scan_id="test-123",
        files_scanned=2,
        total_lines_scanned=100,
        scan_duration=1.5,
        scan_timestamp=datetime(2024, 1, 1, 12, 0, 0),
        vulnerabilities=[
            VulnerabilityResult(
                vulnerability_type="SQL Injection",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Potential SQL injection",
                location=Location(file_path="app.py", line_number=42, column_number=10),
                cwe_id="CWE-89",
                owasp_category="A03:2021",
                remediation="Use parameterized queries",
            ),
            VulnerabilityResult(
                vulnerability_type="XSS",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description="Cross-site scripting vulnerability",
                location=Location(file_path="views.py", line_number=15),
                cwe_id="CWE-79",
            ),
        ],
    )


class TestSARIFExporter:
    """Test SARIF exporter functionality."""

    def test_export_creates_valid_sarif(self, sample_scan_result: ScanResult) -> None:
        """Test that export creates valid SARIF 2.1.0 document."""
        exporter = SARIFExporter()
        sarif_json = exporter.export(sample_scan_result)
        sarif = json.loads(sarif_json)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_export_includes_tool_info(self, sample_scan_result: ScanResult) -> None:
        """Test that SARIF includes tool information."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "AI Security Scanner"
        assert "version" in tool
        assert "informationUri" in tool

    def test_export_includes_all_results(self, sample_scan_result: ScanResult) -> None:
        """Test that all vulnerabilities are included as results."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_export_includes_rules(self, sample_scan_result: ScanResult) -> None:
        """Test that vulnerability patterns are exported as rules."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 2
        rule_ids = [rule["id"] for rule in rules]
        assert "CWE-89" in rule_ids
        assert "CWE-79" in rule_ids

    def test_export_maps_severity_correctly(self, sample_scan_result: ScanResult) -> None:
        """Test that severity is mapped to SARIF levels."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        results = sarif["runs"][0]["results"]
        high_result = next(r for r in results if "SQL Injection" in r["message"]["text"])
        medium_result = next(r for r in results if "XSS" in r["message"]["text"])

        assert high_result["level"] in ["error", "warning"]
        assert medium_result["level"] == "warning"

    def test_export_empty_scan_result(self) -> None:
        """Test exporting scan result with no vulnerabilities."""
        empty_result = ScanResult(
            scan_id="empty",
            files_scanned=10,
            total_lines_scanned=1000,
            scan_duration=0.5,
            scan_timestamp=datetime.now(),
            vulnerabilities=[],
        )

        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(empty_result))

        assert len(sarif["runs"][0]["results"]) == 0
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "AI Security Scanner"


@pytest.mark.unit
class TestSARIFLocationMapping:
    """Test SARIF location mapping."""

    def test_location_includes_file_path(self, sample_scan_result: ScanResult) -> None:
        """Test that file path is included in location."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        result = sarif["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]

        assert "artifactLocation" in location
        assert location["artifactLocation"]["uri"] == "app.py"

    def test_location_includes_line_and_column(self, sample_scan_result: ScanResult) -> None:
        """Test that line and column numbers are included."""
        exporter = SARIFExporter()
        sarif = json.loads(exporter.export(sample_scan_result))

        result = sarif["runs"][0]["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]

        assert region["startLine"] == 42
        assert region.get("startColumn") == 10
