"""File service for handling file operations."""

import logging
from pathlib import Path
from typing import List, Optional

import aiofiles

from ai_security_scanner.core.config import ScannerConfig

logger = logging.getLogger(__name__)


class FileService:
    """Service for file-related operations.

    This service encapsulates all file system operations including
    file validation, reading, and filtering.
    """

    def __init__(self, config: ScannerConfig):
        """Initialize file service.

        Args:
            config: Scanner configuration
        """
        self.config = config
        self.max_file_size_bytes = config.max_file_size_mb * 1024 * 1024

    def validate_file(self, file_path: Path) -> bool:
        """Validate if file can be scanned.

        Args:
            file_path: Path to file

        Returns:
            True if file is valid for scanning
        """
        # Check if file exists and is readable
        if not file_path.exists() or not file_path.is_file():
            logger.warning(f"File not found or not readable: {file_path}")
            return False

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size_bytes:
            logger.warning(f"File too large, skipping: {file_path} ({file_size} bytes)")
            return False

        return True

    def read_file_content(self, file_path: Path) -> Optional[str]:
        """Read file content synchronously.

        Args:
            file_path: Path to file

        Returns:
            File content or None if read fails
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            logger.warning(f"Cannot decode file as UTF-8, skipping: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None

    async def read_file_content_async(self, file_path: Path) -> Optional[str]:
        """Read file content asynchronously.

        Args:
            file_path: Path to file

        Returns:
            File content or None if read fails
        """
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                return await f.read()
        except UnicodeDecodeError:
            logger.warning(f"Cannot decode file as UTF-8, skipping: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None

    def get_files_to_scan(
        self,
        directory_path: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[Path]:
        """Get list of files to scan in directory.

        Args:
            directory_path: Path to directory
            include_patterns: Glob patterns to include
            exclude_patterns: Glob patterns to exclude

        Returns:
            List of file paths to scan
        """
        from ai_security_scanner.core.config import Config
        from ai_security_scanner.utils.file_utils import FileScanner

        # Create a temporary config for FileScanner
        # This is a temporary solution until we fully refactor FileScanner
        temp_config = Config()
        temp_config.scanner.include_patterns = include_patterns or self.config.include_patterns
        temp_config.scanner.exclude_patterns = exclude_patterns or self.config.exclude_patterns

        file_scanner = FileScanner(temp_config)
        return file_scanner.get_files_to_scan(directory_path)

    def count_lines(self, content: str) -> int:
        """Count lines in file content.

        Args:
            content: File content

        Returns:
            Number of lines
        """
        return len(content.split("\n"))
