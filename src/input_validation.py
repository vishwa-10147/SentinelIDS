"""
Input Validation Utilities
Security module for validating user inputs to prevent injection attacks
"""

import re
import os
from pathlib import Path


def is_valid_ipv4(ip: str) -> bool:
    """
    Validate IPv4 address format.
    Returns True if valid IPv4, False otherwise.
    """
    if not ip or not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    # IPv4 regex pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip):
        return False
    
    # Check each octet is 0-255
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
    except ValueError:
        return False
    
    return True


def is_valid_mac(mac: str) -> bool:
    """
    Validate MAC address format.
    Accepts formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    """
    if not mac or not isinstance(mac, str):
        return False
    
    mac = mac.strip()
    # MAC address regex pattern
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.
    Removes dangerous characters and path components.
    """
    if not filename or not isinstance(filename, str):
        return ""
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove dangerous characters
    dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
    for char in dangerous_chars:
        filename = filename.replace(char, '')
    
    return filename.strip()


def sanitize_path(filepath: str, base_dir: str = None) -> str:
    """
    Sanitize file path to prevent path traversal attacks.
    Ensures path is within allowed base directory.
    
    Args:
        filepath: Path to sanitize
        base_dir: Base directory to restrict paths to (optional)
    
    Returns:
        Sanitized absolute path, or empty string if invalid
    """
    if not filepath or not isinstance(filepath, str):
        return ""
    
    try:
        # Resolve to absolute path
        abs_path = os.path.abspath(filepath)
        
        # If base_dir specified, ensure path is within it
        if base_dir:
            base_abs = os.path.abspath(base_dir)
            if not abs_path.startswith(base_abs):
                return ""
        
        return abs_path
    except Exception:
        return ""


def validate_port(port: int) -> bool:
    """
    Validate port number (1-65535).
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_ticket_status(status: str) -> bool:
    """
    Validate SOC ticket status.
    Only allows predefined status values.
    """
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    return str(status).upper() in valid_statuses


def validate_severity(severity: str) -> bool:
    """
    Validate severity level.
    """
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return str(severity).upper() in valid_severities


def validate_priority(priority: str) -> bool:
    """
    Validate priority level.
    """
    valid_priorities = ["P1", "P2", "P3"]
    return str(priority).upper() in valid_priorities
