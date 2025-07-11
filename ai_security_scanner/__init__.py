"""AI-Powered Code Security Scanner.

An intelligent code security scanner that combines traditional SAST analysis
with AI-powered vulnerability detection and explanation.
"""

__version__ = "0.1.0"
__author__ = "AI Security Scanner Contributors"
__email__ = "dev@example.com"
__license__ = "MIT"

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import ScanResult, VulnerabilityResult
from ai_security_scanner.core.scanner import SecurityScanner

__all__ = [
    "SecurityScanner",
    "VulnerabilityResult",
    "ScanResult",
    "Config",
]
