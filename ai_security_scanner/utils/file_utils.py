"""File system utilities for the scanner."""

import fnmatch
import logging
import os
import re
from pathlib import Path
from typing import List, Set, Pattern

from ai_security_scanner.core.config import Config

logger = logging.getLogger(__name__)


class FileScanner:
    """Utility class for scanning files in directories."""

    def __init__(self, config: Config):
        """Initialize file scanner with configuration.

        Args:
            config: Scanner configuration
        """
        self.config = config
        self.include_patterns = config.scanner.include_patterns
        self.exclude_patterns = config.scanner.exclude_patterns

        # Pre-compile patterns for better performance
        self._compiled_include_patterns = self._compile_patterns(self.include_patterns)
        self._compiled_exclude_patterns = self._compile_patterns(self.exclude_patterns)

    def get_files_to_scan(self, directory_path: str) -> List[Path]:
        """Get list of files to scan in directory.

        Args:
            directory_path: Path to directory to scan

        Returns:
            List of file paths to scan
        """
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory not found: {directory_path}")

        files_to_scan = []

        # Walk through directory tree
        for root, dirs, files in os.walk(directory):
            root_path = Path(root)

            # Filter directories based on exclude patterns
            dirs[:] = [d for d in dirs if not self._is_excluded_directory(root_path / d)]

            # Check each file
            for file in files:
                file_path = root_path / file

                # Skip if file is excluded
                if self._is_excluded_file(file_path):
                    continue

                # Check if file matches include patterns
                if self._matches_include_pattern(file_path):
                    files_to_scan.append(file_path)

        logger.info(f"Found {len(files_to_scan)} files to scan")
        return files_to_scan

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern[str]]:
        """Compile glob patterns to regex for better performance.

        Args:
            patterns: List of glob patterns

        Returns:
            List of compiled regex patterns
        """
        compiled_patterns = []
        for pattern in patterns:
            try:
                # Convert glob pattern to regex
                regex_pattern = fnmatch.translate(pattern)
                compiled_patterns.append(re.compile(regex_pattern, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid pattern '{pattern}': {e}")
        return compiled_patterns

    def _is_excluded_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning.

        Args:
            file_path: Path to file

        Returns:
            True if file should be excluded
        """
        file_str = str(file_path)

        # Check exclude patterns using compiled regex
        for compiled_pattern in self._compiled_exclude_patterns:
            if compiled_pattern.match(file_str):
                return True

        # Check if file is too large
        try:
            file_size = file_path.stat().st_size
            max_size = self.config.scanner.max_file_size_mb * 1024 * 1024
            if file_size > max_size:
                logger.debug(f"File too large, excluding: {file_path} ({file_size} bytes)")
                return True
        except OSError:
            logger.warning(f"Cannot access file stats: {file_path}")
            return True

        return False

    def _is_excluded_directory(self, dir_path: Path) -> bool:
        """Check if directory should be excluded from scanning.

        Args:
            dir_path: Path to directory

        Returns:
            True if directory should be excluded
        """
        dir_str = str(dir_path)

        # Check exclude patterns using compiled regex
        for compiled_pattern in self._compiled_exclude_patterns:
            if compiled_pattern.match(dir_str):
                return True

        # Exclude hidden directories (starting with .)
        if dir_path.name.startswith("."):
            return True

        return False

    def _matches_include_pattern(self, file_path: Path) -> bool:
        """Check if file matches include patterns.

        Args:
            file_path: Path to file

        Returns:
            True if file matches include patterns
        """
        file_str = str(file_path)

        # If no include patterns, include all files
        if not self.include_patterns:
            return True

        # Check include patterns using compiled regex
        for compiled_pattern in self._compiled_include_patterns:
            if compiled_pattern.match(file_str):
                return True

        return False

    def is_text_file(self, file_path: Path) -> bool:
        """Check if file is a text file.

        Args:
            file_path: Path to file

        Returns:
            True if file is text file
        """
        try:
            with open(file_path, "rb") as f:
                # Read first 8192 bytes to check for binary content
                chunk = f.read(8192)
                if not chunk:
                    return True  # Empty file is considered text

                # Check for null bytes (common in binary files)
                if b"\0" in chunk:
                    return False

                # Check for high ratio of non-printable characters
                printable_chars = sum(
                    1 for byte in chunk if 32 <= byte <= 126 or byte in [9, 10, 13]
                )
                if len(chunk) > 0 and printable_chars / len(chunk) < 0.75:
                    return False

                return True
        except Exception:
            return False

    def get_file_info(self, file_path: Path) -> dict:
        """Get file information.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with file information
        """
        try:
            stat = file_path.stat()
            return {
                "path": str(file_path),
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "is_text": self.is_text_file(file_path),
                "extension": file_path.suffix.lower(),
                "name": file_path.name,
            }
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return {
                "path": str(file_path),
                "size": 0,
                "modified": 0,
                "is_text": False,
                "extension": "",
                "name": file_path.name,
            }
