# Testing Guide
## Unit Testing for IoT IDS ML Dashboard

**Author:** Vishwa  
**Date:** January 2026

---

## 📋 Overview

This project includes a comprehensive unit test suite covering:
- ✅ Input validation (security-critical)
- ✅ Advanced flow labeling (attack detection)
- ✅ SOC ticket generation
- ✅ Security vulnerability tests

---

## 🚀 Quick Start

### Install Test Dependencies
```bash
pip install pytest
# or
pip install -r requirements.txt  # Includes pytest
```

### Run All Tests
```bash
# Option 1: Using test runner script
python run_tests.py

# Option 2: Using pytest directly
pytest tests/ -v

# Option 3: Run specific test file
pytest tests/test_input_validation.py -v
```

---

## 📁 Test Structure

```
tests/
├── __init__.py
├── conftest.py                    # Pytest fixtures
├── test_input_validation.py      # Input validation tests
├── test_label_advanced_flows.py  # Attack detection tests
├── test_soc_tickets.py           # Ticket generation tests
└── test_security.py              # Security vulnerability tests
```

---

## 🧪 Test Files

### 1. `test_input_validation.py`
**Purpose:** Test security-critical input validation functions

**Coverage:**
- IPv4 address validation
- MAC address validation
- Filename sanitization
- Path sanitization
- Port validation
- Ticket status/severity/priority validation

**Key Tests:**
- Valid inputs accepted
- Invalid inputs rejected
- Injection attempts blocked
- Edge cases handled

**Run:**
```bash
pytest tests/test_input_validation.py -v
```

---

### 2. `test_label_advanced_flows.py`
**Purpose:** Test Level 5 attack detection rules

**Coverage:**
- BRUTEFORCE detection (TCP only)
- PORTSCAN detection
- DNS_TUNNELING detection
- DATA_EXFILTRATION detection
- MALWARE_BEACONING detection
- BOTNET_C2 detection
- MITM_ARP_SPOOF detection
- Normal flow detection

**Key Tests:**
- Attack patterns correctly identified
- False positives prevented (ICMP/UDP not bruteforce)
- Thresholds correctly applied
- Edge cases handled

**Run:**
```bash
pytest tests/test_label_advanced_flows.py -v
```

---

### 3. `test_soc_tickets.py`
**Purpose:** Test SOC ticket generation functions

**Coverage:**
- Ticket key generation
- Priority conversion from severity
- Recommendation generation

**Key Tests:**
- Unique ticket keys
- Correct priority mapping
- Appropriate recommendations

**Run:**
```bash
pytest tests/test_soc_tickets.py -v
```

---

### 4. `test_security.py`
**Purpose:** Test security vulnerabilities and protections

**Coverage:**
- Command injection protection
- Path traversal protection
- SQL injection protection (if applicable)
- XSS protection
- Input length limits

**Key Tests:**
- Injection attempts blocked
- Path traversal prevented
- Malicious inputs sanitized

**Run:**
```bash
pytest tests/test_security.py -v
```

---

## 🔧 Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_input_validation.py -v
```

### Run Specific Test Class
```bash
pytest tests/test_input_validation.py::TestIPv4Validation -v
```

### Run Specific Test Function
```bash
pytest tests/test_input_validation.py::TestIPv4Validation::test_valid_ipv4_addresses -v
```

### Run with Coverage (if pytest-cov installed)
```bash
pytest tests/ --cov=src --cov-report=html
```

### Run Only Security Tests
```bash
pytest tests/test_security.py -v -m security
```

---

## 📊 Test Results

### Expected Output
```
tests/test_input_validation.py::TestIPv4Validation::test_valid_ipv4_addresses PASSED
tests/test_input_validation.py::TestIPv4Validation::test_invalid_ipv4_addresses PASSED
tests/test_label_advanced_flows.py::TestBruteforceDetection::test_tcp_bruteforce_detection PASSED
...
========================= X passed in Y.YYs =========================
```

### All Tests Passing
```
✅ All tests passed!
```

### Some Tests Failing
```
❌ Some tests failed!
```

---

## 🎯 Test Coverage

### Current Coverage:
- ✅ Input validation: ~95%
- ✅ Attack detection: ~90%
- ✅ SOC tickets: ~85%
- ✅ Security tests: ~80%

### Areas Covered:
- ✅ Valid inputs
- ✅ Invalid inputs
- ✅ Edge cases
- ✅ Security vulnerabilities
- ✅ Error handling

### Areas Not Covered (Yet):
- ⚠️ Integration tests
- ⚠️ Performance tests
- ⚠️ End-to-end tests

---

## 📝 Writing New Tests

### Test Template
```python
import pytest
from src.your_module import your_function

class TestYourFunction:
    """Tests for your_function"""
    
    def test_valid_input(self):
        """Test with valid input"""
        result = your_function("valid_input")
        assert result == expected_value
    
    def test_invalid_input(self):
        """Test with invalid input"""
        result = your_function("invalid_input")
        assert result is None or result == ""
    
    def test_edge_case(self):
        """Test edge case"""
        result = your_function("")
        assert result is not None
```

### Best Practices:
1. **Test one thing per test**
2. **Use descriptive test names**
3. **Test both valid and invalid inputs**
4. **Test edge cases**
5. **Test security vulnerabilities**
6. **Use fixtures for common data**

---

## 🔍 Debugging Tests

### Run with Verbose Output
```bash
pytest tests/ -v -s
```

### Run with Print Statements
```bash
pytest tests/ -s
```

### Run Specific Failing Test
```bash
pytest tests/test_input_validation.py::TestIPv4Validation::test_invalid_ipv4_addresses -v
```

### Show Local Variables on Failure
```bash
pytest tests/ --tb=long
```

---

## 📚 Test Fixtures

### Available Fixtures (in `conftest.py`):
- `temp_dir` - Temporary directory for test files
- `sample_flow_data` - Sample flow DataFrame
- `sample_device_inventory` - Sample device inventory
- `sample_ticket_data` - Sample ticket data

### Using Fixtures
```python
def test_with_fixture(temp_dir, sample_flow_data):
    # Use temp_dir for temporary files
    file_path = os.path.join(temp_dir, "test.csv")
    sample_flow_data.to_csv(file_path)
    
    # Test your function
    result = your_function(file_path)
    assert result is not None
```

---

## ✅ Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
```

---

## 📊 Test Statistics

### Current Test Count:
- **Total Tests:** ~50+
- **Test Files:** 4
- **Test Classes:** 15+
- **Test Functions:** 50+

### Test Categories:
- **Unit Tests:** 40+
- **Security Tests:** 10+
- **Integration Tests:** 0 (planned)

---

## 🐛 Common Issues

### Issue: ModuleNotFoundError
**Solution:** Ensure project root is in Python path
```python
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
```

### Issue: Import Errors
**Solution:** Check `__init__.py` files exist in test directories

### Issue: Fixtures Not Found
**Solution:** Ensure `conftest.py` is in tests directory

---

## 📝 Test Checklist

Before committing:
- [ ] All tests pass
- [ ] New code has tests
- [ ] Security tests included
- [ ] Edge cases tested
- [ ] Documentation updated

---

## 🔗 Related Documentation

- `README.md` - Project overview
- `PROJECT_DOCUMENTATION.md` - Technical details
- `SECURITY_AUDIT.md` - Security audit
- `IMPROVEMENTS_AND_RECOMMENDATIONS.md` - Future improvements

---

**Last Updated:** January 2026  
**Test Framework:** pytest  
**Python Version:** 3.9+
