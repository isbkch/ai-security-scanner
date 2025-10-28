"""Tests for GitHub integration."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from github import GithubException

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import (
    Confidence,
    Location,
    ScanResult,
    Severity,
    VulnerabilityResult,
)
from ai_security_scanner.integrations.github.integration import GitHubIntegration


@pytest.fixture
def mock_config() -> Config:
    """Create mock configuration."""
    config = Mock(spec=Config)
    config.github = Mock()
    config.github.token_env = "GITHUB_TOKEN"
    config.github.api_base_url = "https://api.github.com"
    config.github.timeout = 30
    config.github.max_file_size = 1048576  # 1MB
    config.scanner = Mock()
    config.scanner.enable_ai_analysis = False
    config.get_api_key = Mock(return_value="test_token_123")
    return config


@pytest.fixture
def mock_github_client() -> Mock:
    """Create mock GitHub client."""
    client = Mock()
    return client


class TestGitHubIntegrationInit:
    """Test GitHub integration initialization."""

    def test_init_with_valid_token(self, mock_config: Config) -> None:
        """Test initialization with valid token."""
        with patch("ai_security_scanner.integrations.github.integration.Github"):
            integration = GitHubIntegration(mock_config)
            assert integration.config == mock_config
            assert integration.github_token == "test_token_123"

    def test_init_without_token_raises_error(self, mock_config: Config) -> None:
        """Test initialization without token raises error."""
        mock_config.get_api_key = Mock(return_value=None)
        with pytest.raises(ValueError, match="GitHub token not found"):
            GitHubIntegration(mock_config)


class TestPathSanitization:
    """Test path sanitization for security."""

    @pytest.fixture
    def integration(self, mock_config: Config) -> GitHubIntegration:
        """Create integration instance."""
        with patch("ai_security_scanner.integrations.github.integration.Github"):
            return GitHubIntegration(mock_config)

    @pytest.mark.parametrize(
        "malicious_path",
        [
            "../etc/passwd",
            "../../secret",
            ".././../config",
            "dir/../../../etc/shadow",
            "./../sensitive",
        ],
    )
    def test_sanitize_path_blocks_traversal(
        self, integration: GitHubIntegration, malicious_path: str
    ) -> None:
        """Test that path traversal attempts are blocked."""
        result = integration._sanitize_path(malicious_path)
        assert result is None

    @pytest.mark.parametrize(
        "safe_path",
        [
            "src/main.py",
            "README.md",
            ".github/workflows/ci.yml",
            ".gitignore",
            "docs/api/index.md",
        ],
    )
    def test_sanitize_path_allows_safe_paths(
        self, integration: GitHubIntegration, safe_path: str
    ) -> None:
        """Test that safe paths are allowed."""
        result = integration._sanitize_path(safe_path)
        assert result is not None
        assert ".." not in result

    def test_sanitize_empty_path(self, integration: GitHubIntegration) -> None:
        """Test sanitization of empty path."""
        result = integration._sanitize_path("")
        assert result is None

    def test_sanitize_none_path(self, integration: GitHubIntegration) -> None:
        """Test sanitization of None path."""
        result = integration._sanitize_path(None)
        assert result is None


class TestCheckRunCreation:
    """Test GitHub check run creation."""

    @pytest.fixture
    def integration(self, mock_config: Config) -> GitHubIntegration:
        """Create integration instance."""
        with patch("ai_security_scanner.integrations.github.integration.Github") as mock_gh:
            integration = GitHubIntegration(mock_config)
            integration.github = mock_gh.return_value
            return integration

    @pytest.fixture
    def sample_scan_result(self) -> ScanResult:
        """Create sample scan result."""
        return ScanResult(
            scan_id="test-scan-123",
            files_scanned=10,
            total_lines_scanned=500,
            scan_duration=2.5,
            scan_timestamp=datetime.now(),
            vulnerabilities=[
                VulnerabilityResult(
                    vulnerability_type="SQL Injection",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="SQL injection vulnerability",
                    location=Location(file_path="app.py", line_number=42),
                    cwe_id="CWE-89",
                    remediation="Use parameterized queries",
                )
            ],
        )

    def test_get_check_conclusion_success(self, integration: GitHubIntegration) -> None:
        """Test check conclusion for clean scan."""
        scan_result = ScanResult(
            scan_id="test", files_scanned=5, total_lines_scanned=100, scan_duration=1.0, scan_timestamp=datetime.now(), vulnerabilities=[]
        )
        conclusion = integration._get_check_conclusion(scan_result)
        assert conclusion == "success"

    def test_get_check_conclusion_failure_critical(
        self, integration: GitHubIntegration
    ) -> None:
        """Test check conclusion for critical vulnerabilities."""
        scan_result = ScanResult(
            scan_id="test",
            files_scanned=5,
            total_lines_scanned=100,
            scan_duration=1.0,
            scan_timestamp=datetime.now(),
            vulnerabilities=[
                VulnerabilityResult(
                    vulnerability_type="RCE",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="Critical vuln",
                    location=Location(file_path="app.py", line_number=10),
                    cwe_id="CWE-78",
                )
            ],
        )
        conclusion = integration._get_check_conclusion(scan_result)
        assert conclusion == "failure"

    def test_create_check_summary_no_vulns(self, integration: GitHubIntegration) -> None:
        """Test check summary with no vulnerabilities."""
        scan_result = ScanResult(
            scan_id="test", files_scanned=5, total_lines_scanned=100, scan_duration=1.0, scan_timestamp=datetime.now(), vulnerabilities=[]
        )
        summary = integration._create_check_summary(scan_result)
        assert "No security vulnerabilities found" in summary

    def test_create_check_summary_with_vulns(
        self, integration: GitHubIntegration, sample_scan_result: ScanResult
    ) -> None:
        """Test check summary with vulnerabilities."""
        summary = integration._create_check_summary(sample_scan_result)
        assert "Found" in summary
        assert "High" in summary

    def test_create_check_details(
        self, integration: GitHubIntegration, sample_scan_result: ScanResult
    ) -> None:
        """Test check details creation."""
        details = integration._create_check_details(sample_scan_result)
        assert "Scan Results" in details
        assert "Files Scanned" in details
        assert "app.py" in details
        assert "SQL Injection" in details


class TestRepositoryInfo:
    """Test repository information retrieval."""

    @pytest.fixture
    def integration(self, mock_config: Config) -> GitHubIntegration:
        """Create integration instance."""
        with patch("ai_security_scanner.integrations.github.integration.Github") as mock_gh:
            integration = GitHubIntegration(mock_config)
            integration.github = mock_gh.return_value
            return integration

    def test_get_repository_info_success(self, integration: GitHubIntegration) -> None:
        """Test successful repository info retrieval."""
        mock_repo = Mock()
        mock_repo.name = "test-repo"
        mock_repo.full_name = "owner/test-repo"
        mock_repo.description = "Test repository"
        mock_repo.html_url = "https://github.com/owner/test-repo"
        mock_repo.clone_url = "https://github.com/owner/test-repo.git"
        mock_repo.default_branch = "main"
        mock_repo.language = "Python"
        mock_repo.get_languages.return_value = {"Python": 1000}
        mock_repo.size = 100
        mock_repo.stargazers_count = 50
        mock_repo.forks_count = 10
        mock_repo.created_at = datetime(2023, 1, 1)
        mock_repo.updated_at = datetime(2023, 12, 1)
        mock_repo.private = False

        integration.github.get_repo.return_value = mock_repo

        info = integration.get_repository_info("owner/test-repo")

        assert info["name"] == "test-repo"
        assert info["language"] == "Python"
        assert info["default_branch"] == "main"

    def test_get_repository_info_not_found(self, integration: GitHubIntegration) -> None:
        """Test repository info when repo not found."""
        integration.github.get_repo.side_effect = GithubException(404, {"message": "Not Found"})

        with pytest.raises(GithubException):
            integration.get_repository_info("owner/nonexistent")


@pytest.mark.asyncio
class TestRepositoryScanning:
    """Test repository scanning functionality."""

    @pytest.fixture
    def integration(self, mock_config: Config) -> GitHubIntegration:
        """Create integration instance."""
        with patch("ai_security_scanner.integrations.github.integration.Github") as mock_gh:
            integration = GitHubIntegration(mock_config)
            integration.github = mock_gh.return_value
            integration.scanner = Mock()
            integration.scanner.scan_directory_async = AsyncMock(
                return_value=ScanResult(
                    scan_id="test",
                    files_scanned=5,
                    total_lines_scanned=100,
                    scan_duration=1.0,
                    scan_timestamp=datetime.now(),
                    vulnerabilities=[],
                )
            )
            return integration

    async def test_scan_repository_basic(self, integration: GitHubIntegration) -> None:
        """Test basic repository scanning."""
        mock_repo = Mock()
        mock_repo.default_branch = "main"
        mock_repo.clone_url = "https://github.com/owner/repo.git"
        mock_repo.get_branch.return_value.commit.sha = "abc123"

        integration.github.get_repo.return_value = mock_repo

        with patch.object(
            integration, "_download_repository", new_callable=AsyncMock
        ) as mock_download:
            mock_download.return_value = "/tmp/test"

            with patch("shutil.rmtree"):
                result = await integration.scan_repository("owner/repo")

                assert result.repository_name == "owner/repo"
                assert result.branch == "main"
                assert result.commit_hash == "abc123"
