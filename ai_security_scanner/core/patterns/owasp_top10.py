"""OWASP Top 10 vulnerability patterns."""

from typing import List
from ai_security_scanner.core.patterns.base import (
    VulnerabilityPattern, RegexPattern, PatternRule, PatternType
)
from ai_security_scanner.core.models import VulnerabilityResult, Severity, Confidence


class SQLInjectionPattern(RegexPattern):
    """SQL Injection vulnerability pattern (OWASP A03:2021)."""
    
    def __init__(self):
        super().__init__(
            name="SQL Injection",
            description="Detection of potential SQL injection vulnerabilities",
            severity=Severity.HIGH,
            cwe_id="CWE-89"
        )
        self.supported_languages = ["python", "javascript", "php", "java", "csharp"]
        
        # Python SQL injection patterns
        self.add_rule(PatternRule(
            id="sql_injection_python_format",
            name="SQL Injection via String Formatting",
            pattern=r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*%\s*\(',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            description="SQL query constructed using string formatting, vulnerable to injection",
            remediation="Use parameterized queries or prepared statements",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            languages=["python"]
        ))
        
        self.add_rule(PatternRule(
            id="sql_injection_python_fstring",
            name="SQL Injection via F-String",
            pattern=r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*?\{.*?\}',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            description="SQL query constructed using f-strings, vulnerable to injection",
            remediation="Use parameterized queries or prepared statements",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            languages=["python"]
        ))
        
        # JavaScript SQL injection patterns
        self.add_rule(PatternRule(
            id="sql_injection_js_concatenation",
            name="SQL Injection via String Concatenation",
            pattern=r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*?\+\s*["\']?[a-zA-Z_][a-zA-Z0-9_]*',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            description="SQL query constructed using string concatenation, vulnerable to injection",
            remediation="Use parameterized queries or prepared statements",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            languages=["javascript"]
        ))
        
        self.add_rule(PatternRule(
            id="sql_injection_js_template",
            name="SQL Injection via Template Literals",
            pattern=r'`.*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*?\$\{.*?\}',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            description="SQL query constructed using template literals, vulnerable to injection",
            remediation="Use parameterized queries or prepared statements",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            languages=["javascript"]
        ))


class XSSPattern(RegexPattern):
    """Cross-Site Scripting (XSS) vulnerability pattern (OWASP A03:2021)."""
    
    def __init__(self):
        super().__init__(
            name="Cross-Site Scripting (XSS)",
            description="Detection of potential XSS vulnerabilities",
            severity=Severity.HIGH,
            cwe_id="CWE-79"
        )
        self.supported_languages = ["javascript", "python", "php", "java", "csharp"]
        
        # JavaScript XSS patterns
        self.add_rule(PatternRule(
            id="xss_innerhtml",
            name="XSS via innerHTML",
            pattern=r'\.innerHTML\s*=\s*["\']?[a-zA-Z_][a-zA-Z0-9_]*|\.innerHTML\s*=\s*.*?\+',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            description="Direct assignment to innerHTML with user input can lead to XSS",
            remediation="Use textContent instead of innerHTML, or sanitize input",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            languages=["javascript"]
        ))
        
        self.add_rule(PatternRule(
            id="xss_eval",
            name="XSS via eval()",
            pattern=r'eval\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*',
            pattern_type=PatternType.REGEX,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            description="Use of eval() with user input can lead to XSS and code injection",
            remediation="Avoid eval() entirely, use JSON.parse() for data parsing",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            languages=["javascript"]
        ))
        
        # Python XSS patterns
        self.add_rule(PatternRule(
            id="xss_python_render_template",
            name="XSS via Template Rendering",
            pattern=r'render_template\s*\([^)]*\|\s*safe|render_template_string\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            description="Template rendering with user input can lead to XSS",
            remediation="Escape user input properly or use auto-escaping templates",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            languages=["python"]
        ))


class WeakCryptographyPattern(RegexPattern):
    """Weak cryptography pattern (OWASP A02:2021)."""
    
    def __init__(self):
        super().__init__(
            name="Weak Cryptography",
            description="Detection of weak cryptographic practices",
            severity=Severity.MEDIUM,
            cwe_id="CWE-327"
        )
        self.supported_languages = ["python", "javascript", "java", "csharp"]
        
        # Python weak crypto patterns
        self.add_rule(PatternRule(
            id="weak_crypto_md5",
            name="Weak Hash Algorithm (MD5)",
            pattern=r'hashlib\.md5\s*\(|md5\s*\(',
            pattern_type=PatternType.REGEX,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-327",
            owasp_category="A02:2021 - Cryptographic Failures",
            description="MD5 is cryptographically broken and should not be used",
            remediation="Use SHA-256 or SHA-3 instead",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/327.html"
            ],
            languages=["python"]
        ))
        
        self.add_rule(PatternRule(
            id="weak_crypto_sha1",
            name="Weak Hash Algorithm (SHA1)",
            pattern=r'hashlib\.sha1\s*\(|sha1\s*\(',
            pattern_type=PatternType.REGEX,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-327",
            owasp_category="A02:2021 - Cryptographic Failures",
            description="SHA1 is cryptographically weak and should not be used",
            remediation="Use SHA-256 or SHA-3 instead",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/327.html"
            ],
            languages=["python"]
        ))
        
        # JavaScript weak crypto patterns
        self.add_rule(PatternRule(
            id="weak_crypto_js_math_random",
            name="Weak Random Number Generation",
            pattern=r'Math\.random\s*\(\s*\)',
            pattern_type=PatternType.REGEX,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-338",
            owasp_category="A02:2021 - Cryptographic Failures",
            description="Math.random() is not cryptographically secure",
            remediation="Use crypto.getRandomValues() for security-sensitive operations",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/338.html"
            ],
            languages=["javascript"]
        ))


class HardcodedSecretsPattern(RegexPattern):
    """Hardcoded secrets pattern (OWASP A07:2021)."""
    
    def __init__(self):
        super().__init__(
            name="Hardcoded Secrets",
            description="Detection of hardcoded secrets and credentials",
            severity=Severity.HIGH,
            cwe_id="CWE-798"
        )
        self.supported_languages = ["python", "javascript", "java", "csharp", "go"]
        
        # Generic password patterns
        self.add_rule(PatternRule(
            id="hardcoded_password",
            name="Hardcoded Password",
            pattern=r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-798",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            description="Hardcoded passwords in source code are a security risk",
            remediation="Use environment variables or secure configuration management",
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html"
            ]
        ))
        
        # API key patterns
        self.add_rule(PatternRule(
            id="hardcoded_api_key",
            name="Hardcoded API Key",
            pattern=r'(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9]{20,}["\']',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-798",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            description="Hardcoded API keys should not be stored in source code",
            remediation="Use environment variables or secure key management",
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html"
            ]
        ))
        
        # Database connection strings
        self.add_rule(PatternRule(
            id="hardcoded_db_connection",
            name="Hardcoded Database Connection",
            pattern=r'(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@[^/]+',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-798",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            description="Database connection strings with credentials should not be hardcoded",
            remediation="Use environment variables or secure configuration management",
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html"
            ]
        ))


class InsecureDeserialization(RegexPattern):
    """Insecure deserialization pattern (OWASP A08:2021)."""
    
    def __init__(self):
        super().__init__(
            name="Insecure Deserialization",
            description="Detection of insecure deserialization vulnerabilities",
            severity=Severity.HIGH,
            cwe_id="CWE-502"
        )
        self.supported_languages = ["python", "javascript", "java", "csharp"]
        
        # Python pickle patterns
        self.add_rule(PatternRule(
            id="insecure_pickle",
            name="Insecure Pickle Deserialization",
            pattern=r'pickle\.loads?\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*',
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-502",
            owasp_category="A08:2021 - Software and Data Integrity Failures",
            description="Deserializing untrusted data with pickle is dangerous",
            remediation="Use JSON or implement input validation and sanitization",
            references=[
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                "https://cwe.mitre.org/data/definitions/502.html"
            ],
            languages=["python"]
        ))
        
        # JavaScript eval patterns
        self.add_rule(PatternRule(
            id="insecure_eval_deserialize",
            name="Insecure Eval-based Deserialization",
            pattern=r'eval\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
            pattern_type=PatternType.REGEX,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-502",
            owasp_category="A08:2021 - Software and Data Integrity Failures",
            description="Using eval() to deserialize data is extremely dangerous",
            remediation="Use JSON.parse() instead of eval()",
            references=[
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                "https://cwe.mitre.org/data/definitions/502.html"
            ],
            languages=["javascript"]
        ))


def get_owasp_top10_patterns() -> List[VulnerabilityPattern]:
    """Get all OWASP Top 10 vulnerability patterns."""
    return [
        SQLInjectionPattern(),
        XSSPattern(),
        WeakCryptographyPattern(),
        HardcodedSecretsPattern(),
        InsecureDeserialization(),
    ]