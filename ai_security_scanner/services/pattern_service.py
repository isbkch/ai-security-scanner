"""Pattern service for managing vulnerability patterns."""

import logging
from typing import List

from ai_security_scanner.core.models import Confidence
from ai_security_scanner.core.patterns.base import VulnerabilityPattern
from ai_security_scanner.core.patterns.owasp_top10 import get_owasp_top10_patterns

logger = logging.getLogger(__name__)


class PatternService:
    """Service for managing vulnerability detection patterns.

    This service handles pattern loading, management, and provides
    methods for querying patterns.
    """

    def __init__(self, pattern_names: List[str], confidence_threshold: float = 0.5):
        """Initialize pattern service.

        Args:
            pattern_names: List of pattern collections to load
            confidence_threshold: Minimum confidence threshold for results
        """
        self.pattern_names = pattern_names
        self.confidence_threshold = confidence_threshold
        self.patterns: List[VulnerabilityPattern] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load vulnerability patterns based on configuration."""
        if "owasp-top-10" in self.pattern_names:
            self.patterns.extend(get_owasp_top10_patterns())

        # Add support for other pattern collections here
        # if "custom" in self.pattern_names:
        #     self.patterns.extend(load_custom_patterns())

        logger.info(f"Loaded {len(self.patterns)} vulnerability patterns")

    def get_patterns_for_language(self, language: str) -> List[VulnerabilityPattern]:
        """Get patterns that support a specific language.

        Args:
            language: Programming language

        Returns:
            List of applicable patterns
        """
        return [pattern for pattern in self.patterns if pattern.is_supported_language(language)]

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

    def get_pattern_names(self) -> List[str]:
        """Get list of loaded pattern names.

        Returns:
            List of pattern names
        """
        return [pattern.name for pattern in self.patterns]

    def get_confidence_score(self, confidence: Confidence) -> float:
        """Convert confidence enum to numeric score.

        Args:
            confidence: Confidence level

        Returns:
            Numeric confidence score
        """
        mapping = {Confidence.LOW: 0.3, Confidence.MEDIUM: 0.6, Confidence.HIGH: 0.9}
        return mapping.get(confidence, 0.5)

    def meets_confidence_threshold(self, confidence: Confidence) -> bool:
        """Check if confidence meets the threshold.

        Args:
            confidence: Confidence level

        Returns:
            True if confidence meets or exceeds threshold
        """
        return self.get_confidence_score(confidence) >= self.confidence_threshold

    def get_pattern_count(self) -> int:
        """Get total number of loaded patterns.

        Returns:
            Number of patterns
        """
        return len(self.patterns)
