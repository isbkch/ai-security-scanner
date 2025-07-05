"""Core security scanner implementation."""

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import (
    AnalysisContext,
    Location,
    ScanResult,
    VulnerabilityResult,
)
from ai_security_scanner.core.patterns.base import VulnerabilityPattern
from ai_security_scanner.core.patterns.owasp_top10 import get_owasp_top10_patterns
from ai_security_scanner.utils.file_utils import FileScanner
from ai_security_scanner.utils.language_detector import LanguageDetector

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner class."""

    def __init__(self, config: Optional[Config] = None):
        """Initialize the security scanner.

        Args:
            config: Scanner configuration. If None, loads from environment.
        """
        self.config = config or Config.from_env()
        self.patterns: List[VulnerabilityPattern] = []
        self.file_scanner = FileScanner(self.config)
        self.language_detector = LanguageDetector()

        # Load patterns
        self._load_patterns()

        # Statistics
        self.stats = {
            "files_scanned": 0,
            "lines_scanned": 0,
            "vulnerabilities_found": 0,
            "scan_duration": 0.0,
        }

    def _load_patterns(self) -> None:
        """Load vulnerability patterns based on configuration."""
        if "owasp-top-10" in self.config.scanner.patterns:
            self.patterns.extend(get_owasp_top10_patterns())

        logger.info(f"Loaded {len(self.patterns)} vulnerability patterns")

    def scan_file(self, file_path: str) -> List[VulnerabilityResult]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of vulnerability results
        """
        try:
            file_path_obj = Path(file_path)

            # Check if file exists and is readable
            if not file_path_obj.exists() or not file_path_obj.is_file():
                logger.warning(f"File not found or not readable: {file_path}")
                return []

            # Check file size
            file_size = file_path_obj.stat().st_size
            max_size = self.config.scanner.max_file_size_mb * 1024 * 1024
            if file_size > max_size:
                logger.warning(f"File too large, skipping: {file_path} ({file_size} bytes)")
                return []

            # Read file content
            try:
                with open(file_path_obj, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                logger.warning(f"Cannot decode file as UTF-8, skipping: {file_path}")
                return []

            # Detect language
            language = self.language_detector.detect_language(file_path)
            if not language:
                logger.debug(f"Could not detect language for: {file_path}")
                return []

            # Skip if language not supported
            if language not in self.config.scanner.languages:
                logger.debug(
                    f"Language {language} not in supported languages, skipping: {file_path}"
                )
                return []

            # Create analysis context
            context = AnalysisContext(
                language=language, file_type=file_path_obj.suffix, security_context={}
            )

            # Scan with patterns
            vulnerabilities = self._scan_with_patterns(content, file_path, context)

            # Update statistics
            self.stats["files_scanned"] += 1
            self.stats["lines_scanned"] += len(content.split("\n"))
            self.stats["vulnerabilities_found"] += len(vulnerabilities)

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def _scan_with_patterns(
        self, content: str, file_path: str, context: AnalysisContext
    ) -> List[VulnerabilityResult]:
        """Scan content with loaded patterns.

        Args:
            content: File content to scan
            file_path: Path to the file being scanned
            context: Analysis context

        Returns:
            List of vulnerability results
        """
        vulnerabilities = []

        for pattern in self.patterns:
            if pattern.is_supported_language(context.language):
                try:
                    results = pattern.detect(content, file_path, context.language)

                    # Filter by confidence threshold
                    filtered_results = [
                        result
                        for result in results
                        if self._get_confidence_score(result.confidence)
                        >= self.config.scanner.confidence_threshold
                    ]

                    vulnerabilities.extend(filtered_results)

                except Exception as e:
                    logger.error(f"Error in pattern {pattern.name}: {e}")

        return vulnerabilities

    def _get_confidence_score(self, confidence) -> float:
        """Convert confidence enum to numeric score."""
        from ai_security_scanner.core.models import Confidence

        mapping = {Confidence.LOW: 0.3, Confidence.MEDIUM: 0.6, Confidence.HIGH: 0.9}
        return mapping.get(confidence, 0.5)

    def scan_directory(self, directory_path: str) -> ScanResult:
        """Scan a directory for vulnerabilities.

        Args:
            directory_path: Path to directory to scan

        Returns:
            Complete scan result
        """
        start_time = time.time()
        directory_path_obj = Path(directory_path)

        if not directory_path_obj.exists() or not directory_path_obj.is_dir():
            raise ValueError(f"Directory not found: {directory_path}")

        # Reset statistics
        self.stats = {
            "files_scanned": 0,
            "lines_scanned": 0,
            "vulnerabilities_found": 0,
            "scan_duration": 0.0,
        }

        # Get files to scan
        files_to_scan = self.file_scanner.get_files_to_scan(directory_path)

        # Limit number of files if configured
        if self.config.scanner.max_files_per_scan > 0:
            files_to_scan = files_to_scan[: self.config.scanner.max_files_per_scan]

        logger.info(f"Scanning {len(files_to_scan)} files in {directory_path}")

        # Scan files
        all_vulnerabilities = []
        for file_path in files_to_scan:
            vulnerabilities = self.scan_file(str(file_path))
            all_vulnerabilities.extend(vulnerabilities)

        # Calculate scan duration
        scan_duration = time.time() - start_time
        self.stats["scan_duration"] = scan_duration

        # Create scan result
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            repository_url=None,
            repository_name=directory_path_obj.name,
            branch=None,
            commit_hash=None,
            scan_timestamp=datetime.now(),
            vulnerabilities=all_vulnerabilities,
            scan_duration=scan_duration,
            files_scanned=self.stats["files_scanned"],
            total_lines_scanned=self.stats["lines_scanned"],
            scanner_version="0.1.0",
            configuration=self.config.__dict__,
            metrics=self.stats.copy(),
        )

        logger.info(
            f"Scan completed: {len(all_vulnerabilities)} vulnerabilities found in {scan_duration:.2f}s"
        )

        return scan_result

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
        if language not in self.config.scanner.languages:
            raise ValueError(f"Language {language} not supported")

        context = AnalysisContext(language=language, file_type=f".{language}", security_context={})

        return self._scan_with_patterns(code, file_path, context)

    async def scan_directory_async(self, directory_path: str) -> ScanResult:
        """Asynchronously scan a directory for vulnerabilities.

        Args:
            directory_path: Path to directory to scan

        Returns:
            Complete scan result
        """
        return await asyncio.get_event_loop().run_in_executor(
            None, self.scan_directory, directory_path
        )

    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages."""
        return self.config.scanner.languages.copy()

    def get_loaded_patterns(self) -> List[str]:
        """Get list of loaded vulnerability patterns."""
        return [pattern.name for pattern in self.patterns]

    def add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Add a custom vulnerability pattern.

        Args:
            pattern: Vulnerability pattern to add
        """
        self.patterns.append(pattern)
        logger.info(f"Added custom pattern: {pattern.name}")

    def remove_pattern(self, pattern_name: str) -> bool:
        """Remove a vulnerability pattern by name.

        Args:
            pattern_name: Name of pattern to remove

        Returns:
            True if pattern was removed, False if not found
        """
        for i, pattern in enumerate(self.patterns):
            if pattern.name == pattern_name:
                del self.patterns[i]
                logger.info(f"Removed pattern: {pattern_name}")
                return True
        return False
