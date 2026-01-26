"""
Pytest configuration and fixtures
"""

import pytest
import os
import sys
import pandas as pd
import tempfile
import shutil

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def sample_flow_data():
    """Sample flow data for testing"""
    return pd.DataFrame({
        "flow_id": ["flow1", "flow2", "flow3"],
        "src_ip": ["192.168.1.100", "192.168.1.101", "192.168.1.102"],
        "dst_ip": ["192.168.1.200", "192.168.1.200", "192.168.1.200"],
        "proto": ["6", "6", "17"],
        "total_packets": [250, 50, 150],
        "unique_dst_ports": [2, 1, 1],
        "packets_per_sec": [12.5, 5.0, 5.0],
        "total_bytes": [50000, 5000, 50000],
        "duration_sec": [20, 10, 30]
    })


@pytest.fixture
def sample_device_inventory():
    """Sample device inventory for testing"""
    return pd.DataFrame({
        "ip": ["192.168.1.100", "192.168.1.200"],
        "mac": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
        "hostname": ["Device1", "Device2"],
        "vendor": ["Vendor1", "Vendor2"]
    })


@pytest.fixture
def sample_ticket_data():
    """Sample ticket data for testing"""
    return {
        "ticket_id": "TICKET-20260126-001",
        "timestamp": "2026-01-26 10:00:00",
        "severity": "HIGH",
        "priority": "P2",
        "attacker_ip": "192.168.1.100",
        "victim_ip": "192.168.1.200",
        "attack_category": "BRUTEFORCE",
        "status": "OPEN"
    }
