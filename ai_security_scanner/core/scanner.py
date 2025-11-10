"""Core security scanner implementation.

This module provides the main SecurityScanner class, which acts as a facade
for the underlying service layer following Clean Architecture principles.
"""

import logging
from typing import List, Optional

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import ScanResult, VulnerabilityResult
from ai_security_scanner.core.patterns.base import VulnerabilityPattern
from ai_security_scanner.services.scan_service import ScanService

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner facade.

    This class provides a simplified interface to the underlying service layer,
    maintaining backward compatibility while delegating to properly separated services.
    """

    def __init__(self, config: Optional[Config] = None):
        """Initialize the security scanner.

        Args:
            config: Scanner configuration. If None, loads from environment.
        """
        self.config = config or Config.from_env()

        # Initialize the scan service which orchestrates all scanning operations
        self._scan_service = ScanService(self.config)

    @property
    def stats(self) -> dict:
        """Get current scan statistics.

        Returns:
            Dictionary of scan statistics
        """
        return self._scan_service.statistics_service.get_statistics_dict()

    def scan_file(self, file_path: str) -> List[VulnerabilityResult]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of vulnerability results
        """
        return self._scan_service.scan_file(file_path)

    def scan_directory(self, directory_path: str) -> ScanResult:
        """Scan a directory for vulnerabilities.

        Args:
            directory_path: Path to directory to scan

        Returns:
            Complete scan result
        """
        return self._scan_service.scan_directory(directory_path)

    def scan_code(
        self, code: str, language: str, file_path: str = "inline"
    ) -> List[VulnerabilityResult]:
        """Scan code string for vulnerabilities.

        Args:
            code: Source code to scan
            language: Programming language
            file_path: Virtual file path for the code

        Returns:
            List of vulnerability results
        """
        return self._scan_service.scan_code(code, language, file_path)

    async def scan_directory_async(self, directory_path: str) -> ScanResult:
        """Asynchronously scan a directory for vulnerabilities.

        Args:
            directory_path: Path to directory to scan

        Returns:
            Complete scan result
        """
        return await self._scan_service.scan_directory_async(directory_path)

    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages.

        Returns:
            List of language names
        """
        return self._scan_service.get_supported_languages()

    def get_loaded_patterns(self) -> List[str]:
        """Get list of loaded vulnerability patterns.

        Returns:
            List of pattern names
        """
        return self._scan_service.get_loaded_pattern_names()

    def add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Add a custom vulnerability pattern.

        Args:
            pattern: Vulnerability pattern to add
        """
        self._scan_service.pattern_service.add_pattern(pattern)

    def remove_pattern(self, pattern_name: str) -> bool:
        """Remove a vulnerability pattern by name.

        Args:
            pattern_name: Name of pattern to remove

        Returns:
            True if pattern was removed, False if not found
        """
        return self._scan_service.pattern_service.remove_pattern(pattern_name)
