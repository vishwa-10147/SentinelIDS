import subprocess
import re


def is_valid_ip(ip: str) -> bool:
    """
    Validate IP address format to prevent command injection.
    Only allows IPv4 addresses in format: xxx.xxx.xxx.xxx
    """
    ip = str(ip).strip()
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


def get_hostname_from_ip(ip: str) -> str:
    """
    Try to resolve hostname using Windows/Kali commands.
    Works best inside local LAN.
    Silently returns "Unknown" if DNS lookup fails.
    
    SECURITY: Validates IP address to prevent command injection.
    """

    ip = str(ip).strip()
    
    # SECURITY FIX: Validate IP address before using in commands
    if not is_valid_ip(ip):
        return "Unknown"

    # Method 1: nslookup (SECURITY FIX: Use list instead of shell=True)
    try:
        # Use list format to prevent shell injection
        result = subprocess.check_output(
            ["nslookup", ip],
            text=True,
            timeout=4,
            stderr=subprocess.DEVNULL
        )

        for line in result.splitlines():
            line = line.strip()
            if "name =" in line.lower():
                return line.split("=")[-1].strip().rstrip(".")
    except Exception:
        pass

    # Method 2: ping reverse lookup (SECURITY FIX: Use list instead of shell=True)
    try:
        # Windows: ping -a -n 1
        # Linux: ping -a -c 1
        import platform
        if platform.system().lower() == "windows":
            result = subprocess.check_output(
                ["ping", "-a", "-n", "1", ip],
                text=True,
                timeout=4,
                stderr=subprocess.DEVNULL
            )
        else:
            result = subprocess.check_output(
                ["ping", "-a", "-c", "1", ip],
                text=True,
                timeout=4,
                stderr=subprocess.DEVNULL
            )

        for line in result.splitlines():
            line = line.strip()
            if "pinging" in line.lower() or "ping " in line.lower():
                # Example: Pinging DESKTOP-XXXX [192.168.29.1]
                parts = line.split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    # Remove brackets if present
                    hostname = hostname.strip("[]")
                    return hostname
    except Exception:
        pass

    return "Unknown"

