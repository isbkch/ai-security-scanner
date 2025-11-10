"""Statistics service for tracking scan metrics."""

import logging
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class ScanStatistics:
    """Container for scan statistics."""

    files_scanned: int = 0
    lines_scanned: int = 0
    vulnerabilities_found: int = 0
    scan_duration: float = 0.0
    custom_metrics: Dict[str, any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, any]:
        """Convert statistics to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "vulnerabilities_found": self.vulnerabilities_found,
            "scan_duration": self.scan_duration,
            **self.custom_metrics,
        }


class StatisticsService:
    """Service for managing scan statistics.

    This service provides thread-safe statistics tracking
    for scan operations.
    """

    def __init__(self):
        """Initialize statistics service."""
        self.stats = ScanStatistics()
        self.lock = Lock()

    def reset(self) -> None:
        """Reset all statistics to zero."""
        with self.lock:
            self.stats = ScanStatistics()

    def increment_files_scanned(self, count: int = 1) -> None:
        """Increment files scanned counter.

        Args:
            count: Number to increment by
        """
        with self.lock:
            self.stats.files_scanned += count

    def increment_lines_scanned(self, count: int) -> None:
        """Increment lines scanned counter.

        Args:
            count: Number of lines to add
        """
        with self.lock:
            self.stats.lines_scanned += count

    def increment_vulnerabilities(self, count: int) -> None:
        """Increment vulnerabilities found counter.

        Args:
            count: Number of vulnerabilities to add
        """
        with self.lock:
            self.stats.vulnerabilities_found += count

    def set_scan_duration(self, duration: float) -> None:
        """Set the total scan duration.

        Args:
            duration: Scan duration in seconds
        """
        with self.lock:
            self.stats.scan_duration = duration

    def add_custom_metric(self, key: str, value: any) -> None:
        """Add a custom metric.

        Args:
            key: Metric name
            value: Metric value
        """
        with self.lock:
            self.stats.custom_metrics[key] = value

    def get_statistics(self) -> ScanStatistics:
        """Get current statistics.

        Returns:
            Copy of current statistics
        """
        with self.lock:
            return ScanStatistics(
                files_scanned=self.stats.files_scanned,
                lines_scanned=self.stats.lines_scanned,
                vulnerabilities_found=self.stats.vulnerabilities_found,
                scan_duration=self.stats.scan_duration,
                custom_metrics=self.stats.custom_metrics.copy(),
            )

    def get_statistics_dict(self) -> Dict[str, any]:
        """Get statistics as dictionary.

        Returns:
            Statistics dictionary
        """
        return self.get_statistics().to_dict()
