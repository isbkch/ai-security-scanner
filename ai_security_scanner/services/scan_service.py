"""Scan service for orchestrating security scans."""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ai_security_scanner import __version__
from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import AnalysisContext, ScanResult, VulnerabilityResult
from ai_security_scanner.services.file_service import FileService
from ai_security_scanner.services.pattern_service import PatternService
from ai_security_scanner.services.statistics_service import StatisticsService
from ai_security_scanner.utils.language_detector import LanguageDetector

logger = logging.getLogger(__name__)


class ScanService:
    """Service for orchestrating security scans.

    This service coordinates between file operations, pattern matching,
    and statistics tracking to perform comprehensive security scans.
    """

    def __init__(
        self,
        config: Config,
        file_service: Optional[FileService] = None,
        pattern_service: Optional[PatternService] = None,
        statistics_service: Optional[StatisticsService] = None,
        language_detector: Optional[LanguageDetector] = None,
    ):
        """Initialize scan service.

        Args:
            config: Application configuration
            file_service: File operations service
            pattern_service: Pattern management service
            statistics_service: Statistics tracking service
            language_detector: Language detection utility
        """
        self.config = config

        # Initialize services with dependency injection
        self.file_service = file_service or FileService(config.scanner)
        self.pattern_service = pattern_service or PatternService(
            config.scanner.patterns, config.scanner.confidence_threshold
        )
        self.statistics_service = statistics_service or StatisticsService()
        self.language_detector = language_detector or LanguageDetector()

    def scan_file(self, file_path: str) -> List[VulnerabilityResult]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of vulnerability results
        """
        try:
            file_path_obj = Path(file_path)

            # Validate file
            if not self.file_service.validate_file(file_path_obj):
                return []

            # Read file content
            content = self.file_service.read_file_content(file_path_obj)
            if content is None:
                return []

            # Detect and validate language
            language = self.language_detector.detect_language(file_path)
            if not language:
                logger.debug(f"Could not detect language for: {file_path}")
                return []

            if not self._is_language_supported(language):
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
            self.statistics_service.increment_files_scanned()
            self.statistics_service.increment_lines_scanned(self.file_service.count_lines(content))
            self.statistics_service.increment_vulnerabilities(len(vulnerabilities))

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    async def scan_file_async(
        self, file_path: str, semaphore: asyncio.Semaphore
    ) -> List[VulnerabilityResult]:
        """Asynchronously scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan
            semaphore: Semaphore to limit concurrent operations

        Returns:
            List of vulnerability results
        """
        async with semaphore:
            try:
                file_path_obj = Path(file_path)

                # Validate file
                if not self.file_service.validate_file(file_path_obj):
                    return []

                # Read file content asynchronously
                content = await self.file_service.read_file_content_async(file_path_obj)
                if content is None:
                    return []

                # Detect and validate language
                language = self.language_detector.detect_language(file_path)
                if not language:
                    logger.debug(f"Could not detect language for: {file_path}")
                    return []

                if not self._is_language_supported(language):
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

                # Update statistics (thread-safe)
                self.statistics_service.increment_files_scanned()
                self.statistics_service.increment_lines_scanned(
                    self.file_service.count_lines(content)
                )
                self.statistics_service.increment_vulnerabilities(len(vulnerabilities))

                return vulnerabilities

            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {e}")
                return []

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
        self.statistics_service.reset()

        # Get files to scan
        files_to_scan = self.file_service.get_files_to_scan(directory_path)

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
        self.statistics_service.set_scan_duration(scan_duration)

        # Create scan result
        return self._create_scan_result(directory_path_obj.name, all_vulnerabilities, scan_duration)

    async def scan_directory_async(self, directory_path: str) -> ScanResult:
        """Asynchronously scan a directory for vulnerabilities.

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
        self.statistics_service.reset()

        # Get files to scan
        files_to_scan = self.file_service.get_files_to_scan(directory_path)

        # Limit number of files if configured
        if self.config.scanner.max_files_per_scan > 0:
            files_to_scan = files_to_scan[: self.config.scanner.max_files_per_scan]

        logger.info(f"Scanning {len(files_to_scan)} files in {directory_path}")

        # Scan files asynchronously
        semaphore = asyncio.Semaphore(10)  # Limit concurrent file operations
        tasks = [
            asyncio.create_task(self.scan_file_async(str(file_path), semaphore))
            for file_path in files_to_scan
        ]

        # Wait for all scans to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all vulnerabilities
        all_vulnerabilities = []
        for result in results:
            if isinstance(result, list):
                all_vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Error scanning file: {result}")

        # Calculate scan duration
        scan_duration = time.time() - start_time
        self.statistics_service.set_scan_duration(scan_duration)

        # Create scan result
        return self._create_scan_result(directory_path_obj.name, all_vulnerabilities, scan_duration)

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
        if not self._is_language_supported(language):
            raise ValueError(f"Language {language} not supported")

        context = AnalysisContext(language=language, file_type=f".{language}", security_context={})
        return self._scan_with_patterns(code, file_path, context)

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
        patterns = self.pattern_service.get_patterns_for_language(context.language)

        for pattern in patterns:
            try:
                results = pattern.detect(content, file_path, context.language)

                # Filter by confidence threshold
                filtered_results = [
                    result
                    for result in results
                    if self.pattern_service.meets_confidence_threshold(result.confidence)
                ]

                vulnerabilities.extend(filtered_results)

            except Exception as e:
                logger.error(f"Error in pattern {pattern.name}: {e}")

        return vulnerabilities

    def _is_language_supported(self, language: str) -> bool:
        """Check if language is supported.

        Args:
            language: Programming language

        Returns:
            True if language is supported
        """
        return language in self.config.scanner.languages

    def _create_scan_result(
        self, repository_name: str, vulnerabilities: List[VulnerabilityResult], scan_duration: float
    ) -> ScanResult:
        """Create scan result object.

        Args:
            repository_name: Name of repository/directory scanned
            vulnerabilities: List of vulnerabilities found
            scan_duration: Time taken to scan

        Returns:
            Complete scan result
        """
        stats = self.statistics_service.get_statistics()

        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            repository_url=None,
            repository_name=repository_name,
            branch=None,
            commit_hash=None,
            scan_timestamp=datetime.now(),
            vulnerabilities=vulnerabilities,
            scan_duration=scan_duration,
            files_scanned=stats.files_scanned,
            total_lines_scanned=stats.lines_scanned,
            scanner_version=__version__,
            configuration=self.config.to_dict_safe(),
            metrics=stats.to_dict(),
        )

        logger.info(
            f"Scan completed: {len(vulnerabilities)} vulnerabilities found in {scan_duration:.2f}s"
        )

        return scan_result

    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages.

        Returns:
            List of language names
        """
        return self.config.scanner.languages.copy()

    def get_loaded_pattern_names(self) -> List[str]:
        """Get list of loaded vulnerability pattern names.

        Returns:
            List of pattern names
        """
        return self.pattern_service.get_pattern_names()
