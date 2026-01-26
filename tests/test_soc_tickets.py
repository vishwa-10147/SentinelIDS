"""
Unit Tests for SOC Ticket Generator
Tests ticket generation and validation functions
"""

import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.soc_ticket_generator import (
    build_ticket_key,
    get_priority_from_severity,
    recommend_action
)


class TestTicketKeyGeneration:
    """Tests for ticket key generation"""
    
    def test_build_ticket_key(self):
        """Test ticket key generation"""
        attacker = "192.168.1.100"
        victim = "192.168.1.200"
        category = "BRUTEFORCE"
        
        key = build_ticket_key(attacker, victim, category)
        expected = "192.168.1.100|192.168.1.200|BRUTEFORCE"
        assert key == expected
    
    def test_ticket_key_uniqueness(self):
        """Test that different tickets have different keys"""
        key1 = build_ticket_key("192.168.1.100", "192.168.1.200", "BRUTEFORCE")
        key2 = build_ticket_key("192.168.1.100", "192.168.1.200", "PORTSCAN")
        key3 = build_ticket_key("192.168.1.101", "192.168.1.200", "BRUTEFORCE")
        
        assert key1 != key2, "Different categories should have different keys"
        assert key1 != key3, "Different attackers should have different keys"
    
    def test_ticket_key_with_none_values(self):
        """Test ticket key with None values"""
        key = build_ticket_key(None, None, None)
        assert "None" in key or key == "None|None|None"


class TestPriorityFromSeverity:
    """Tests for priority conversion from severity"""
    
    def test_critical_to_p1(self):
        """Test CRITICAL severity maps to P1"""
        assert get_priority_from_severity("CRITICAL") == "P1"
        assert get_priority_from_severity("critical") == "P1"  # Case insensitive
    
    def test_high_to_p2(self):
        """Test HIGH severity maps to P2"""
        assert get_priority_from_severity("HIGH") == "P2"
        assert get_priority_from_severity("high") == "P2"
    
    def test_medium_to_p3(self):
        """Test MEDIUM severity maps to P3"""
        assert get_priority_from_severity("MEDIUM") == "P3"
        assert get_priority_from_severity("medium") == "P3"
    
    def test_low_to_p3(self):
        """Test LOW severity maps to P3"""
        assert get_priority_from_severity("LOW") == "P3"
        assert get_priority_from_severity("low") == "P3"
    
    def test_unknown_severity_to_p3(self):
        """Test unknown severity defaults to P3"""
        assert get_priority_from_severity("UNKNOWN") == "P3"
        assert get_priority_from_severity("") == "P3"
        assert get_priority_from_severity(None) == "P3"


class TestRecommendAction:
    """Tests for recommendation generation"""
    
    def test_critical_recommendation(self):
        """Test CRITICAL severity recommendation"""
        action = recommend_action("CRITICAL")
        assert "Immediate" in action or "isolation" in action.lower()
        assert len(action) > 0
    
    def test_high_recommendation(self):
        """Test HIGH severity recommendation"""
        action = recommend_action("HIGH")
        assert len(action) > 0
        assert action != "No action needed"
    
    def test_medium_recommendation(self):
        """Test MEDIUM severity recommendation"""
        action = recommend_action("MEDIUM")
        assert len(action) > 0
    
    def test_low_recommendation(self):
        """Test LOW severity recommendation"""
        action = recommend_action("LOW")
        assert action == "No action needed"
    
    def test_case_insensitive(self):
        """Test that severity is case insensitive"""
        action1 = recommend_action("CRITICAL")
        action2 = recommend_action("critical")
        assert action1 == action2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
