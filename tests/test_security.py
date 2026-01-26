"""
Security Tests
Tests for injection attacks and security vulnerabilities
"""

import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.input_validation import is_valid_ipv4, sanitize_filename, sanitize_path
from src.hostname_lookup import get_hostname_from_ip


class TestCommandInjectionProtection:
    """Tests for command injection protection"""
    
    def test_ip_with_command_injection(self):
        """Test that IP validation prevents command injection"""
        malicious_inputs = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 | cat /etc/passwd",
            "192.168.1.1 && echo hacked",
            "192.168.1.1`whoami`",
            "192.168.1.1$(ls)",
            "192.168.1.1; python -c 'import os; os.system(\"rm -rf /\")'"
        ]
        
        for malicious_input in malicious_inputs:
            assert is_valid_ipv4(malicious_input) == False, \
                f"Command injection attempt should be rejected: {malicious_input}"
    
    def test_hostname_lookup_safe(self):
        """Test that hostname lookup rejects invalid IPs"""
        malicious_inputs = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 | cat /etc/passwd",
            "../../etc/passwd"
        ]
        
        for malicious_input in malicious_inputs:
            result = get_hostname_from_ip(malicious_input)
            assert result == "Unknown", \
                f"Malicious input should return Unknown: {malicious_input}"


class TestPathTraversalProtection:
    """Tests for path traversal protection"""
    
    def test_path_traversal_attempts(self):
        """Test that path traversal attempts are blocked"""
        base_dir = os.path.abspath("logs")
        traversal_attempts = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "../logs/../etc/passwd",
            "....//....//etc/passwd",
            "logs/../../etc/passwd"
        ]
        
        for attempt in traversal_attempts:
            result = sanitize_path(attempt, base_dir)
            assert result == "", \
                f"Path traversal should be blocked: {attempt}"
    
    def test_filename_traversal(self):
        """Test filename sanitization blocks traversal"""
        dangerous_filenames = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "file/../../etc/passwd"
        ]
        
        for filename in dangerous_filenames:
            result = sanitize_filename(filename)
            assert ".." not in result, \
                f"Path traversal should be removed: {filename}"
            assert "/" not in result and "\\" not in result, \
                f"Path separators should be removed: {filename}"


class TestSQLInjectionProtection:
    """Tests for SQL injection protection (if using database)"""
    
    def test_sql_injection_in_ip(self):
        """Test that SQL injection attempts in IPs are rejected"""
        sql_injection_attempts = [
            "192.168.1.1' OR '1'='1",
            "192.168.1.1'; DROP TABLE users; --",
            "192.168.1.1 UNION SELECT * FROM passwords"
        ]
        
        for attempt in sql_injection_attempts:
            assert is_valid_ipv4(attempt) == False, \
                f"SQL injection attempt should be rejected: {attempt}"


class TestXSSProtection:
    """Tests for XSS protection"""
    
    def test_xss_in_filename(self):
        """Test that XSS attempts in filenames are sanitized"""
        xss_attempts = [
            "<script>alert('XSS')</script>.csv",
            "file<script>evil</script>.txt",
            "file<img src=x onerror=alert(1)>.csv"
        ]
        
        for attempt in xss_attempts:
            result = sanitize_filename(attempt)
            assert "<" not in result and ">" not in result, \
                f"XSS attempt should be sanitized: {attempt}"


class TestInputLengthLimits:
    """Tests for input length limits"""
    
    def test_very_long_ip(self):
        """Test that very long IPs are rejected"""
        long_ip = "192.168.1." + "1" * 1000
        assert is_valid_ipv4(long_ip) == False
    
    def test_very_long_filename(self):
        """Test that very long filenames are handled"""
        long_filename = "a" * 10000 + ".csv"
        result = sanitize_filename(long_filename)
        # Should not crash, may truncate or reject
        assert isinstance(result, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
