"""Basic tests for the security scanner."""

import pytest
from unittest.mock import Mock, patch
from ai_security_scanner.core.scanner import SecurityScanner
from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import Severity, Confidence


class TestSecurityScanner:
    """Test cases for SecurityScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.config.scanner.enable_ai_analysis = False  # Disable AI for tests
        self.scanner = SecurityScanner(self.config)
    
    def test_scan_sql_injection_python(self):
        """Test SQL injection detection in Python code."""
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        
        vulnerabilities = self.scanner.scan_code(code, "python", "test.py")
        
        # Should detect SQL injection
        assert len(vulnerabilities) > 0
        sql_vulns = [v for v in vulnerabilities if "sql" in v.vulnerability_type.lower()]
        assert len(sql_vulns) > 0
        
        vuln = sql_vulns[0]
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]
        assert vuln.location.line_number == 3
    
    def test_scan_xss_javascript(self):
        """Test XSS detection in JavaScript code."""
        code = '''
function updateContent(userInput) {
    document.getElementById('content').innerHTML = userInput;
}
'''
        
        vulnerabilities = self.scanner.scan_code(code, "javascript", "test.js")
        
        # Should detect XSS
        assert len(vulnerabilities) > 0
        xss_vulns = [v for v in vulnerabilities if "xss" in v.vulnerability_type.lower()]
        assert len(xss_vulns) > 0
        
        vuln = xss_vulns[0]
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_scan_weak_crypto_python(self):
        """Test weak cryptography detection in Python code."""
        code = '''
import hashlib
import md5

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
        
        vulnerabilities = self.scanner.scan_code(code, "python", "test.py")
        
        # Should detect weak crypto
        assert len(vulnerabilities) > 0
        crypto_vulns = [v for v in vulnerabilities if "crypto" in v.vulnerability_type.lower() or "md5" in v.vulnerability_type.lower()]
        assert len(crypto_vulns) > 0
        
        vuln = crypto_vulns[0]
        assert vuln.severity in [Severity.MEDIUM, Severity.HIGH]
    
    def test_scan_hardcoded_secrets(self):
        """Test hardcoded secrets detection."""
        code = '''
def connect_to_db():
    password = "super_secret_password123"
    api_key = "ak_1234567890abcdef1234567890abcdef"
    return connect(password=password, api_key=api_key)
'''
        
        vulnerabilities = self.scanner.scan_code(code, "python", "test.py")
        
        # Should detect hardcoded secrets
        assert len(vulnerabilities) > 0
        secret_vulns = [v for v in vulnerabilities if "secret" in v.vulnerability_type.lower() or "password" in v.vulnerability_type.lower()]
        assert len(secret_vulns) > 0
    
    def test_scan_clean_code(self):
        """Test scanning clean code with no vulnerabilities."""
        code = '''
def safe_function(x, y):
    """A safe function with no vulnerabilities."""
    result = x + y
    return result
'''
        
        vulnerabilities = self.scanner.scan_code(code, "python", "test.py")
        
        # Should not detect any vulnerabilities
        assert len(vulnerabilities) == 0
    
    def test_unsupported_language(self):
        """Test scanning with unsupported language."""
        code = "some code"
        
        with pytest.raises(ValueError, match="Language unsupported_lang not supported"):
            self.scanner.scan_code(code, "unsupported_lang", "test.txt")
    
    def test_get_supported_languages(self):
        """Test getting supported languages."""
        languages = self.scanner.get_supported_languages()
        assert isinstance(languages, list)
        assert "python" in languages
        assert "javascript" in languages
    
    def test_get_loaded_patterns(self):
        """Test getting loaded patterns."""
        patterns = self.scanner.get_loaded_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        assert any("SQL Injection" in pattern for pattern in patterns)
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_file')
    def test_scan_nonexistent_file(self, mock_is_file, mock_exists):
        """Test scanning non-existent file."""
        mock_exists.return_value = False
        mock_is_file.return_value = False
        
        vulnerabilities = self.scanner.scan_file("nonexistent.py")
        assert len(vulnerabilities) == 0


if __name__ == "__main__":
    pytest.main([__file__])