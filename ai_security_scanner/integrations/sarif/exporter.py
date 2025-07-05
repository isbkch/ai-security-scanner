"""SARIF (Static Analysis Results Interchange Format) exporter."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_security_scanner.core.models import ScanResult, VulnerabilityResult


class SARIFExporter:
    """SARIF format exporter for vulnerability scan results."""

    def __init__(self):
        """Initialize SARIF exporter."""
        self.version = "2.1.0"
        self.schema_uri = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def export(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Export scan result to SARIF format.

        Args:
            scan_result: Scan result to export

        Returns:
            SARIF document as dictionary
        """
        sarif_doc = {
            "$schema": self.schema_uri,
            "version": self.version,
            "runs": [self._create_run(scan_result)],
        }

        return sarif_doc

    def _create_run(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Create SARIF run object.

        Args:
            scan_result: Scan result

        Returns:
            SARIF run object
        """
        run = {
            "tool": self._create_tool(),
            "invocations": [self._create_invocation(scan_result)],
            "results": [
                self._create_result(vuln, scan_result) for vuln in scan_result.vulnerabilities
            ],
            "artifacts": self._create_artifacts(scan_result),
            "columnKind": "utf16CodeUnits",
        }

        # Add properties if available
        if scan_result.repository_url or scan_result.commit_hash:
            run["versionControlProvenance"] = [self._create_version_control_details(scan_result)]

        return run

    def _create_tool(self) -> Dict[str, Any]:
        """Create SARIF tool object.

        Returns:
            SARIF tool object
        """
        return {
            "driver": {
                "name": "AI Security Scanner",
                "version": "0.1.0",
                "informationUri": "https://github.com/isbkch/ai-security-scanner",
                "semanticVersion": "0.1.0",
                "organization": "AI Security Scanner Contributors",
                "rules": self._create_rules(),
            }
        }

    def _create_rules(self) -> List[Dict[str, Any]]:
        """Create SARIF rules for vulnerability types.

        Returns:
            List of SARIF rule objects
        """
        # Common vulnerability rules
        rules = [
            {
                "id": "sql_injection",
                "name": "SQLInjection",
                "shortDescription": {"text": "SQL Injection vulnerability"},
                "fullDescription": {"text": "Potential SQL injection vulnerability detected"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "injection", "sql"], "precision": "high"},
            },
            {
                "id": "xss",
                "name": "CrossSiteScripting",
                "shortDescription": {"text": "Cross-Site Scripting vulnerability"},
                "fullDescription": {"text": "Potential XSS vulnerability detected"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "injection", "xss"], "precision": "high"},
            },
            {
                "id": "weak_crypto",
                "name": "WeakCryptography",
                "shortDescription": {"text": "Weak cryptographic algorithm"},
                "fullDescription": {"text": "Use of weak or deprecated cryptographic algorithm"},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["security", "cryptography"], "precision": "high"},
            },
            {
                "id": "hardcoded_secrets",
                "name": "HardcodedSecrets",
                "shortDescription": {"text": "Hardcoded secrets"},
                "fullDescription": {"text": "Hardcoded credentials or secrets detected"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "secrets"], "precision": "medium"},
            },
            {
                "id": "insecure_deserialization",
                "name": "InsecureDeserialization",
                "shortDescription": {"text": "Insecure deserialization"},
                "fullDescription": {"text": "Insecure deserialization vulnerability detected"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "deserialization"], "precision": "high"},
            },
        ]

        return rules

    def _create_invocation(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Create SARIF invocation object.

        Args:
            scan_result: Scan result

        Returns:
            SARIF invocation object
        """
        invocation = {
            "executionSuccessful": True,
            "startTimeUtc": scan_result.scan_timestamp.isoformat() + "Z",
            "endTimeUtc": (scan_result.scan_timestamp.timestamp() + scan_result.scan_duration),
            "machine": "scanner-host",
        }

        # Convert end time back to datetime and format
        end_time = datetime.fromtimestamp(
            scan_result.scan_timestamp.timestamp() + scan_result.scan_duration
        )
        invocation["endTimeUtc"] = end_time.isoformat() + "Z"

        return invocation

    def _create_result(
        self, vulnerability: VulnerabilityResult, scan_result: ScanResult
    ) -> Dict[str, Any]:
        """Create SARIF result object for a vulnerability.

        Args:
            vulnerability: Vulnerability result
            scan_result: Scan result

        Returns:
            SARIF result object
        """
        result = {
            "ruleId": vulnerability.vulnerability_type,
            "ruleIndex": self._get_rule_index(vulnerability.vulnerability_type),
            "message": {"text": vulnerability.description},
            "level": self._severity_to_level(vulnerability.severity),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vulnerability.location.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": vulnerability.location.line_number,
                            "startColumn": vulnerability.location.column_number,
                            "endLine": vulnerability.location.end_line_number
                            or vulnerability.location.line_number,
                            "endColumn": vulnerability.location.end_column_number
                            or vulnerability.location.column_number,
                            "snippet": {
                                "text": self._extract_snippet_text(vulnerability.code_snippet)
                            },
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": self._calculate_line_hash(vulnerability)
            },
            "properties": {
                "confidence": vulnerability.confidence.value,
                "scanner_id": vulnerability.id,
            },
        }

        # Add CWE information if available
        if vulnerability.cwe_id:
            result["properties"]["cwe"] = vulnerability.cwe_id

        # Add OWASP category if available
        if vulnerability.owasp_category:
            result["properties"]["owasp_category"] = vulnerability.owasp_category

        # Add AI analysis if available (sanitized to prevent sensitive data exposure)
        if vulnerability.ai_explanation:
            result["properties"]["ai_analysis"] = self._sanitize_ai_explanation(vulnerability.ai_explanation)

        if vulnerability.false_positive_likelihood is not None:
            result["properties"][
                "false_positive_likelihood"
            ] = vulnerability.false_positive_likelihood

        # Add remediation information
        if vulnerability.remediation:
            result["fixes"] = [{"description": {"text": vulnerability.remediation}}]

        # Add related locations for similar vulnerabilities
        if "similar_vulnerabilities" in vulnerability.metadata:
            result["relatedLocations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc["file_path"]},
                        "region": {"startLine": loc["line_number"]},
                    },
                    "message": {
                        "text": f"Similar vulnerability (similarity: {loc.get('similarity', 'unknown')})"
                    },
                }
                for loc in vulnerability.metadata["similar_vulnerabilities"]
            ]

        return result

    def _create_artifacts(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Create SARIF artifacts list.

        Args:
            scan_result: Scan result

        Returns:
            List of SARIF artifact objects
        """
        # Get unique file paths from vulnerabilities
        file_paths = set()
        for vuln in scan_result.vulnerabilities:
            file_paths.add(vuln.location.file_path)

        artifacts = []
        for file_path in sorted(file_paths):
            artifacts.append(
                {
                    "location": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "mimeType": self._get_mime_type(file_path),
                    "roles": ["analysisTarget"],
                }
            )

        return artifacts

    def _create_version_control_details(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Create version control provenance details.

        Args:
            scan_result: Scan result

        Returns:
            Version control details object
        """
        details = {}

        if scan_result.repository_url:
            details["repositoryUri"] = scan_result.repository_url

        if scan_result.commit_hash:
            details["revisionId"] = scan_result.commit_hash

        if scan_result.branch:
            details["branch"] = scan_result.branch

        return details

    def _get_rule_index(self, vulnerability_type: str) -> int:
        """Get rule index for vulnerability type.

        Args:
            vulnerability_type: Vulnerability type

        Returns:
            Rule index
        """
        rule_mapping = {
            "sql_injection": 0,
            "sql_injection_python_format": 0,
            "sql_injection_python_fstring": 0,
            "sql_injection_js_concatenation": 0,
            "sql_injection_js_template": 0,
            "xss": 1,
            "xss_innerhtml": 1,
            "xss_eval": 1,
            "xss_python_render_template": 1,
            "weak_crypto": 2,
            "weak_crypto_md5": 2,
            "weak_crypto_sha1": 2,
            "weak_crypto_js_math_random": 2,
            "hardcoded_secrets": 3,
            "hardcoded_password": 3,
            "hardcoded_api_key": 3,
            "hardcoded_db_connection": 3,
            "insecure_deserialization": 4,
            "insecure_pickle": 4,
            "insecure_eval_deserialize": 4,
        }

        return rule_mapping.get(vulnerability_type, 0)

    def _severity_to_level(self, severity) -> str:
        """Convert severity enum to SARIF level.

        Args:
            severity: Severity enum

        Returns:
            SARIF level string
        """
        from ai_security_scanner.core.models import Severity

        mapping = {
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }

        return mapping.get(severity, "warning")

    def _extract_snippet_text(self, code_snippet: str) -> str:
        """Extract clean snippet text from formatted code snippet.

        Args:
            code_snippet: Formatted code snippet

        Returns:
            Clean snippet text
        """
        lines = code_snippet.split("\n")
        clean_lines = []

        for line in lines:
            # Remove line number prefix (e.g., ">>> 123: " or "    123: ")
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    clean_lines.append(parts[1])
                else:
                    clean_lines.append(line)
            else:
                clean_lines.append(line)

        return "\n".join(clean_lines)

    def _calculate_line_hash(self, vulnerability: VulnerabilityResult) -> str:
        """Calculate hash for the vulnerability location.

        Args:
            vulnerability: Vulnerability result

        Returns:
            Hash string
        """
        import hashlib

        content = f"{vulnerability.location.file_path}:{vulnerability.location.line_number}:{vulnerability.vulnerability_type}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

    def _get_mime_type(self, file_path: str) -> str:
        """Get MIME type for file.

        Args:
            file_path: File path

        Returns:
            MIME type string
        """
        extension = file_path.lower().split(".")[-1] if "." in file_path else ""

        mime_types = {
            "py": "text/x-python",
            "js": "text/javascript",
            "ts": "text/typescript",
            "jsx": "text/jsx",
            "tsx": "text/tsx",
            "java": "text/x-java-source",
            "cs": "text/x-csharp",
            "go": "text/x-go",
            "rs": "text/x-rust",
            "php": "text/x-php",
            "rb": "text/x-ruby",
            "cpp": "text/x-c++src",
            "c": "text/x-csrc",
            "h": "text/x-chdr",
            "hpp": "text/x-c++hdr",
        }

        return mime_types.get(extension, "text/plain")
    
    def _sanitize_ai_explanation(self, explanation: str) -> str:
        """Sanitize AI explanation to remove potential sensitive information.
        
        Args:
            explanation: Raw AI explanation
            
        Returns:
            Sanitized explanation
        """
        # List of patterns that might indicate sensitive information
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IP addresses
            r'\b[A-Za-z0-9+/]{20,}={0,2}\b',  # Base64 encoded data (potential keys)
            r'\b[A-Za-z0-9]{32,}\b',  # Long hex strings (potential keys/hashes)
            r'sk-[A-Za-z0-9]{48}',  # OpenAI API keys
            r'ghp_[A-Za-z0-9]{36}',  # GitHub personal access tokens
        ]
        
        sanitized = explanation
        for pattern in sensitive_patterns:
            import re
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
            
        return sanitized
