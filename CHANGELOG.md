# Changelog
## IoT IDS ML Dashboard - Version History

All notable changes to this project will be documented in this file.

---

## [1.0.0] - January 2026

### ✅ Added
- **Complete Documentation Suite:**
  - README.md - Complete project guide
  - PROJECT_DOCUMENTATION.md - Technical documentation
  - QUICK_START.md - Quick setup guide
  - SECURITY_GUIDE.md - Security best practices
  - TESTING_GUIDE.md - Testing documentation
  - DOCUMENTATION_INDEX.md - Documentation navigation

- **Security Improvements:**
  - Input validation module (`src/input_validation.py`)
  - Command injection fixes
  - Shell injection fixes
  - Path traversal protection
  - Secure subprocess calls

- **Unit Test Suite:**
  - 55+ unit tests across 4 test files
  - Input validation tests
  - Attack detection tests
  - SOC ticket tests
  - Security vulnerability tests
  - Test runners (Python and PowerShell)

- **Project Features:**
  - Dataset IDS (Level 1)
  - Live Packet IDS (Level 2)
  - Flow Generator (Level 3)
  - Flow ML Prediction + Fusion (Level 4)
  - Advanced Threat Detection (Level 5)
  - SOC Ticket System
  - Device Discovery

### 🔧 Fixed
- BRUTEFORCE false alerts (TCP only, ignores ICMP/UDP)
- Command injection vulnerabilities
- Shell injection vulnerabilities
- Requirements.txt encoding issues
- Test failures (port validation, data exfiltration)

### 🔒 Security
- Added IP address validation
- Added MAC address validation
- Added filename/path sanitization
- Replaced all `os.system()` calls with secure `subprocess.run()`
- Added timeout protection on all commands

### 📝 Documentation
- Complete README with all commands
- Professional project documentation
- Security audit report
- Testing guide
- Quick start guide

### 🧪 Testing
- Comprehensive unit test suite
- Security test coverage
- Test fixtures and configuration
- Test runners for easy execution

---

## [0.9.0] - Pre-Release

### Added
- Initial project structure
- Basic IDS functionality
- Streamlit dashboard
- ML models integration

---

**Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)**
