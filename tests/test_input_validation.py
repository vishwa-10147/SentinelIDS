"""
Unit Tests for Input Validation Module
Tests security-critical input validation functions
"""

import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.input_validation import (
    is_valid_ipv4,
    is_valid_mac,
    sanitize_filename,
    sanitize_path,
    validate_port,
    validate_ticket_status,
    validate_severity,
    validate_priority
)


class TestIPv4Validation:
    """Tests for IPv4 address validation"""
    
    def test_valid_ipv4_addresses(self):
        """Test valid IPv4 addresses"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "127.0.0.1"
        ]
        for ip in valid_ips:
            assert is_valid_ipv4(ip) == True, f"{ip} should be valid"
    
    def test_invalid_ipv4_addresses(self):
        """Test invalid IPv4 addresses"""
        invalid_ips = [
            "256.1.1.1",  # Octet > 255
            "192.168.1",  # Missing octet
            "192.168.1.1.1",  # Too many octets
            "192.168.1.-1",  # Negative octet
            "192.168.1.256",  # Octet > 255
            "not.an.ip.address",
            "192.168.1",
            "",
            None,
            12345,  # Not a string
            "192.168.1.1.2.3"
        ]
        for ip in invalid_ips:
            assert is_valid_ipv4(ip) == False, f"{ip} should be invalid"
    
    def test_ipv4_with_whitespace(self):
        """Test IPv4 addresses with whitespace"""
        assert is_valid_ipv4("  192.168.1.1  ") == True
        assert is_valid_ipv4("192.168.1.1\n") == True


class TestMACValidation:
    """Tests for MAC address validation"""
    
    def test_valid_mac_addresses(self):
        """Test valid MAC addresses"""
        valid_macs = [
            "00:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF",
            "00-11-22-33-44-55",
            "aa:bb:cc:dd:ee:ff",
            "00:11:22:33:44:55"
        ]
        for mac in valid_macs:
            assert is_valid_mac(mac) == True, f"{mac} should be valid"
    
    def test_invalid_mac_addresses(self):
        """Test invalid MAC addresses"""
        invalid_macs = [
            "00:11:22:33:44",  # Too short
            "00:11:22:33:44:55:66",  # Too long
            "00:11:22:33:44:GG",  # Invalid hex
            "00.11.22.33.44.55",  # Wrong separator
            "",
            None,
            12345,
            "not-a-mac"
        ]
        for mac in invalid_macs:
            assert is_valid_mac(mac) == False, f"{mac} should be invalid"


class TestFilenameSanitization:
    """Tests for filename sanitization"""
    
    def test_safe_filenames(self):
        """Test safe filenames"""
        safe_names = [
            "test.csv",
            "my_file.txt",
            "data_2026.csv",
            "report-123.pdf"
        ]
        for name in safe_names:
            result = sanitize_filename(name)
            assert result == name, f"{name} should remain unchanged"
    
    def test_dangerous_filenames(self):
        """Test dangerous filenames"""
        dangerous = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "file<script>.txt",
            "file|command.txt",
            "/etc/passwd",
            "C:\\Windows\\System32"
        ]
        for name in dangerous:
            result = sanitize_filename(name)
            assert ".." not in result, f"Path traversal should be removed from {name}"
            assert "/" not in result and "\\" not in result, f"Path separators should be removed"
    
    def test_empty_filename(self):
        """Test empty filename"""
        assert sanitize_filename("") == ""
        assert sanitize_filename(None) == ""


class TestPathSanitization:
    """Tests for path sanitization"""
    
    def test_valid_paths(self):
        """Test valid paths"""
        base_dir = os.path.abspath("logs")
        valid_paths = [
            "logs/test.csv",
            "logs/data.txt"
        ]
        for path in valid_paths:
            result = sanitize_path(path, base_dir)
            assert result != "", f"{path} should be valid"
            assert result.startswith(base_dir), f"Path should be within base_dir"
    
    def test_path_traversal_attempts(self):
        """Test path traversal attempts"""
        base_dir = os.path.abspath("logs")
        dangerous_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "../logs/../etc/passwd"
        ]
        for path in dangerous_paths:
            result = sanitize_path(path, base_dir)
            assert result == "", f"Path traversal should be blocked: {path}"
    
    def test_path_without_base_dir(self):
        """Test path without base directory restriction"""
        path = "logs/test.csv"
        result = sanitize_path(path)
        assert result != "", "Path should be valid without base_dir"
        assert os.path.isabs(result), "Result should be absolute path"


class TestPortValidation:
    """Tests for port validation"""
    
    def test_valid_ports(self):
        """Test valid ports"""
        valid_ports = [1, 80, 443, 8080, 65535]
        for port in valid_ports:
            assert validate_port(port) == True, f"Port {port} should be valid"
    
    def test_valid_ports_as_strings(self):
        """Test that string ports are converted and validated"""
        valid_string_ports = ["80", "443", "8080", "65535"]
        for port in valid_string_ports:
            assert validate_port(port) == True, f"String port '{port}' should be valid (converted to int)"
    
    def test_invalid_ports(self):
        """Test invalid ports"""
        # Note: "80" as string is valid because validate_port converts it to int
        invalid_ports = [0, -1, 65536, 70000, None, "not_a_port", "abc"]
        for port in invalid_ports:
            assert validate_port(port) == False, f"Port {port} should be invalid"


class TestTicketStatusValidation:
    """Tests for ticket status validation"""
    
    def test_valid_statuses(self):
        """Test valid ticket statuses"""
        valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        for status in valid_statuses:
            assert validate_ticket_status(status) == True
            assert validate_ticket_status(status.lower()) == True  # Case insensitive
    
    def test_invalid_statuses(self):
        """Test invalid ticket statuses"""
        invalid_statuses = ["CLOSED", "PENDING", "INVALID", "", None]
        for status in invalid_statuses:
            assert validate_ticket_status(status) == False


class TestSeverityValidation:
    """Tests for severity validation"""
    
    def test_valid_severities(self):
        """Test valid severities"""
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for severity in valid_severities:
            assert validate_severity(severity) == True
            assert validate_severity(severity.lower()) == True  # Case insensitive
    
    def test_invalid_severities(self):
        """Test invalid severities"""
        invalid_severities = ["MINOR", "MAJOR", "UNKNOWN", "", None]
        for severity in invalid_severities:
            assert validate_severity(severity) == False


class TestPriorityValidation:
    """Tests for priority validation"""
    
    def test_valid_priorities(self):
        """Test valid priorities"""
        valid_priorities = ["P1", "P2", "P3"]
        for priority in valid_priorities:
            assert validate_priority(priority) == True
            assert validate_priority(priority.lower()) == True  # Case insensitive
    
    def test_invalid_priorities(self):
        """Test invalid priorities"""
        invalid_priorities = ["P0", "P4", "HIGH", "", None]
        for priority in invalid_priorities:
            assert validate_priority(priority) == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
