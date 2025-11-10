"""Tests for service layer."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ai_security_scanner.core.config import Config, ScannerConfig
from ai_security_scanner.core.models import Confidence
from ai_security_scanner.core.patterns.base import VulnerabilityPattern
from ai_security_scanner.services.file_service import FileService
from ai_security_scanner.services.pattern_service import PatternService
from ai_security_scanner.services.scan_service import ScanService
from ai_security_scanner.services.statistics_service import StatisticsService


class TestFileService:
    """Tests for FileService."""

    def test_validate_file_success(self, tmp_path):
        """Test successful file validation."""
        config = ScannerConfig()
        service = FileService(config)

        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        assert service.validate_file(test_file) is True

    def test_validate_file_not_exists(self):
        """Test validation fails for non-existent file."""
        config = ScannerConfig()
        service = FileService(config)

        assert service.validate_file(Path("/nonexistent/file.py")) is False

    def test_validate_file_too_large(self, tmp_path):
        """Test validation fails for oversized file."""
        config = ScannerConfig(max_file_size_mb=0.001)  # Very small limit
        service = FileService(config)

        # Create a large file
        test_file = tmp_path / "large.py"
        test_file.write_text("x" * 10000)

        assert service.validate_file(test_file) is False

    def test_read_file_content(self, tmp_path):
        """Test reading file content."""
        config = ScannerConfig()
        service = FileService(config)

        test_file = tmp_path / "test.py"
        test_content = "print('hello world')"
        test_file.write_text(test_content)

        content = service.read_file_content(test_file)
        assert content == test_content

    def test_count_lines(self):
        """Test line counting."""
        config = ScannerConfig()
        service = FileService(config)

        content = "line1\nline2\nline3"
        assert service.count_lines(content) == 3


class TestPatternService:
    """Tests for PatternService."""

    def test_load_patterns(self):
        """Test pattern loading."""
        service = PatternService(["owasp-top-10"])

        assert service.get_pattern_count() > 0
        assert len(service.get_pattern_names()) > 0

    def test_add_pattern(self):
        """Test adding custom pattern."""
        service = PatternService([])
        initial_count = service.get_pattern_count()

        # Create a mock pattern
        mock_pattern = MagicMock(spec=VulnerabilityPattern)
        mock_pattern.name = "test_pattern"

        service.add_pattern(mock_pattern)

        assert service.get_pattern_count() == initial_count + 1

    def test_remove_pattern(self):
        """Test removing pattern."""
        service = PatternService(["owasp-top-10"])
        pattern_names = service.get_pattern_names()

        if pattern_names:
            first_pattern = pattern_names[0]
            assert service.remove_pattern(first_pattern) is True
            assert first_pattern not in service.get_pattern_names()

    def test_confidence_threshold(self):
        """Test confidence threshold checking."""
        service = PatternService([], confidence_threshold=0.6)

        assert service.meets_confidence_threshold(Confidence.HIGH) is True
        assert service.meets_confidence_threshold(Confidence.MEDIUM) is True
        assert service.meets_confidence_threshold(Confidence.LOW) is False

    def test_get_confidence_score(self):
        """Test confidence score conversion."""
        service = PatternService([])

        assert service.get_confidence_score(Confidence.HIGH) == 0.9
        assert service.get_confidence_score(Confidence.MEDIUM) == 0.6
        assert service.get_confidence_score(Confidence.LOW) == 0.3


class TestStatisticsService:
    """Tests for StatisticsService."""

    def test_reset(self):
        """Test statistics reset."""
        service = StatisticsService()

        service.increment_files_scanned(5)
        service.increment_lines_scanned(100)

        service.reset()

        stats = service.get_statistics()
        assert stats.files_scanned == 0
        assert stats.lines_scanned == 0

    def test_increment_files_scanned(self):
        """Test file counter increment."""
        service = StatisticsService()

        service.increment_files_scanned(3)
        service.increment_files_scanned(2)

        stats = service.get_statistics()
        assert stats.files_scanned == 5

    def test_increment_lines_scanned(self):
        """Test lines counter increment."""
        service = StatisticsService()

        service.increment_lines_scanned(100)
        service.increment_lines_scanned(50)

        stats = service.get_statistics()
        assert stats.lines_scanned == 150

    def test_increment_vulnerabilities(self):
        """Test vulnerabilities counter increment."""
        service = StatisticsService()

        service.increment_vulnerabilities(5)
        service.increment_vulnerabilities(3)

        stats = service.get_statistics()
        assert stats.vulnerabilities_found == 8

    def test_set_scan_duration(self):
        """Test setting scan duration."""
        service = StatisticsService()

        service.set_scan_duration(12.5)

        stats = service.get_statistics()
        assert stats.scan_duration == 12.5

    def test_add_custom_metric(self):
        """Test adding custom metrics."""
        service = StatisticsService()

        service.add_custom_metric("test_metric", 42)

        stats = service.get_statistics()
        assert stats.custom_metrics["test_metric"] == 42

    def test_get_statistics_dict(self):
        """Test statistics dictionary conversion."""
        service = StatisticsService()

        service.increment_files_scanned(5)
        service.increment_lines_scanned(100)
        service.add_custom_metric("custom", "value")

        stats_dict = service.get_statistics_dict()

        assert stats_dict["files_scanned"] == 5
        assert stats_dict["lines_scanned"] == 100
        assert stats_dict["custom"] == "value"


class TestScanService:
    """Tests for ScanService."""

    def test_initialization(self):
        """Test scan service initialization."""
        config = Config()
        service = ScanService(config)

        assert service.config == config
        assert service.file_service is not None
        assert service.pattern_service is not None
        assert service.statistics_service is not None
        assert service.language_detector is not None

    def test_get_supported_languages(self):
        """Test getting supported languages."""
        config = Config()
        config.scanner.languages = ["python", "javascript"]

        service = ScanService(config)

        languages = service.get_supported_languages()
        assert "python" in languages
        assert "javascript" in languages

    def test_get_loaded_pattern_names(self):
        """Test getting pattern names."""
        config = Config()
        service = ScanService(config)

        pattern_names = service.get_loaded_pattern_names()
        assert isinstance(pattern_names, list)
        assert len(pattern_names) > 0

    def test_scan_code(self):
        """Test scanning code snippet."""
        config = Config()
        service = ScanService(config)

        # Simple SQL injection example
        code = """
        query = "SELECT * FROM users WHERE id = " + user_input
        """

        vulnerabilities = service.scan_code(code, "python")

        # Should detect SQL injection
        assert isinstance(vulnerabilities, list)

    def test_scan_code_unsupported_language(self):
        """Test scanning with unsupported language raises error."""
        config = Config()
        config.scanner.languages = ["python"]

        service = ScanService(config)

        with pytest.raises(ValueError, match="Language .* not supported"):
            service.scan_code("code", "unsupported_lang")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
