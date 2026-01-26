"""
Unit Tests for Advanced Flow Labeling
Tests Level 5 attack detection rules
"""

import pytest
import pandas as pd
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.label_advanced_flows import label_advanced_flow


class TestBruteforceDetection:
    """Tests for BRUTEFORCE detection"""
    
    def test_tcp_bruteforce_detection(self):
        """Test TCP bruteforce detection"""
        row = {
            "proto": "6",  # TCP
            "total_packets": 250,
            "duration_sec": 20,
            "unique_dst_ports": 2,
            "packets_per_sec": 12.5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label == "BRUTEFORCE"
        assert score == 85
    
    def test_tcp_bruteforce_not_detected_icmp(self):
        """Test that ICMP is not detected as bruteforce"""
        row = {
            "proto": "1",  # ICMP
            "total_packets": 250,
            "duration_sec": 20,
            "unique_dst_ports": 2,
            "packets_per_sec": 12.5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label != "BRUTEFORCE", "ICMP should not trigger bruteforce"
    
    def test_tcp_bruteforce_not_detected_udp(self):
        """Test that UDP is not detected as bruteforce"""
        row = {
            "proto": "17",  # UDP
            "total_packets": 250,
            "duration_sec": 20,
            "unique_dst_ports": 2,
            "packets_per_sec": 12.5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label != "BRUTEFORCE", "UDP should not trigger bruteforce"
    
    def test_tcp_bruteforce_too_many_ports(self):
        """Test that too many ports don't trigger bruteforce"""
        row = {
            "proto": "6",
            "total_packets": 250,
            "duration_sec": 20,
            "unique_dst_ports": 10,  # Too many ports
            "packets_per_sec": 12.5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label != "BRUTEFORCE", "Too many ports should not trigger bruteforce"
    
    def test_tcp_bruteforce_too_few_packets(self):
        """Test that too few packets don't trigger bruteforce"""
        row = {
            "proto": "6",
            "total_packets": 100,  # Too few
            "duration_sec": 20,
            "unique_dst_ports": 2,
            "packets_per_sec": 5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label != "BRUTEFORCE", "Too few packets should not trigger bruteforce"


class TestPortscanDetection:
    """Tests for PORTSCAN detection"""
    
    def test_portscan_detection(self):
        """Test portscan detection"""
        row = {
            "proto": "6",
            "total_packets": 500,
            "duration_sec": 60,
            "unique_dst_ports": 250,  # Many ports
            "packets_per_sec": 8.3,
            "total_bytes": 100000
        }
        label, score = label_advanced_flow(row)
        assert label == "PORTSCAN"
        assert score == 100
    
    def test_portscan_not_detected_few_ports(self):
        """Test that few ports don't trigger portscan"""
        row = {
            "proto": "6",
            "total_packets": 500,
            "duration_sec": 60,
            "unique_dst_ports": 50,  # Not enough ports
            "packets_per_sec": 8.3,
            "total_bytes": 100000
        }
        label, score = label_advanced_flow(row)
        assert label != "PORTSCAN", "Too few ports should not trigger portscan"


class TestDNSTunnelingDetection:
    """Tests for DNS_TUNNELING detection"""
    
    def test_dns_tunneling_detection(self):
        """Test DNS tunneling detection"""
        row = {
            "proto": "17.0",  # UDP
            "total_packets": 150,
            "duration_sec": 30,
            "unique_dst_ports": 1,
            "packets_per_sec": 5,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label == "DNS_TUNNELING"
        assert score == 90
    
    def test_dns_tunneling_not_detected_short_duration(self):
        """Test that short duration doesn't trigger DNS tunneling"""
        row = {
            "proto": "17.0",
            "total_packets": 150,
            "duration_sec": 10,  # Too short
            "unique_dst_ports": 1,
            "packets_per_sec": 15,
            "total_bytes": 50000
        }
        label, score = label_advanced_flow(row)
        assert label != "DNS_TUNNELING", "Short duration should not trigger DNS tunneling"


class TestDataExfiltrationDetection:
    """Tests for DATA_EXFILTRATION detection"""
    
    def test_data_exfiltration_detection(self):
        """Test data exfiltration detection"""
        # Note: Must not match BRUTEFORCE first (BRUTEFORCE requires duration < 30)
        # So we use duration >= 30 to avoid BRUTEFORCE match
        row = {
            "proto": "6",
            "total_packets": 1000,
            "duration_sec": 35,  # >= 30 so doesn't match BRUTEFORCE (requires < 30)
            "unique_dst_ports": 1,
            "packets_per_sec": 28.6,
            "total_bytes": 3000000  # Large data transfer (> 2MB) and duration > 10
        }
        label, score = label_advanced_flow(row)
        assert label == "DATA_EXFILTRATION", f"Expected DATA_EXFILTRATION but got {label}. Flow matches: proto={row['proto']}, packets={row['total_packets']}, duration={row['duration_sec']}, ports={row['unique_dst_ports']}, bytes={row['total_bytes']}"
        assert score == 95
    
    def test_data_exfiltration_not_detected_small_data(self):
        """Test that small data doesn't trigger exfiltration"""
        row = {
            "proto": "6",
            "total_packets": 1000,
            "duration_sec": 20,
            "unique_dst_ports": 1,
            "packets_per_sec": 50,
            "total_bytes": 1000000  # Not enough bytes
        }
        label, score = label_advanced_flow(row)
        assert label != "DATA_EXFILTRATION", "Small data should not trigger exfiltration"


class TestMalwareBeaconingDetection:
    """Tests for MALWARE_BEACONING detection"""
    
    def test_malware_beaconing_detection(self):
        """Test malware beaconing detection"""
        row = {
            "proto": "6",
            "total_packets": 200,
            "duration_sec": 120,  # Long duration
            "unique_dst_ports": 1,
            "packets_per_sec": 1.67,  # Low rate
            "total_bytes": 10000
        }
        label, score = label_advanced_flow(row)
        assert label == "MALWARE_BEACONING"
        assert score == 70


class TestBotnetC2Detection:
    """Tests for BOTNET_C2 detection"""
    
    def test_botnet_c2_detection(self):
        """Test botnet C2 detection"""
        row = {
            "proto": "6",
            "total_packets": 50,
            "duration_sec": 60,
            "unique_dst_ports": 1,
            "packets_per_sec": 0.83,  # Very low rate
            "total_bytes": 5000
        }
        label, score = label_advanced_flow(row)
        assert label == "BOTNET_C2"
        assert score == 75


class TestMITMDetection:
    """Tests for MITM_ARP_SPOOF detection"""
    
    def test_mitm_detection(self):
        """Test MITM detection"""
        row = {
            "proto": "1.0",  # ICMP
            "total_packets": 300,
            "duration_sec": 10,
            "unique_dst_ports": 0,
            "packets_per_sec": 30,
            "total_bytes": 30000
        }
        label, score = label_advanced_flow(row)
        assert label == "MITM_ARP_SPOOF"
        assert score == 80


class TestNormalFlow:
    """Tests for normal flow detection"""
    
    def test_normal_flow(self):
        """Test normal flow (no attack)"""
        row = {
            "proto": "6",
            "total_packets": 50,
            "duration_sec": 10,
            "unique_dst_ports": 1,
            "packets_per_sec": 5,
            "total_bytes": 5000
        }
        label, score = label_advanced_flow(row)
        assert label == "NORMAL"
        assert score == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
