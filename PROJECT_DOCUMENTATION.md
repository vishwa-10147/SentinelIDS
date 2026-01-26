# IoT Intrusion Detection System (ML-Based) with SOC Dashboard
## Project Documentation

**Author:** Vishwa  
**Department:** Computer Science / Cybersecurity  
**Date:** January 2026  
**Version:** 1.0

---

## 1. Introduction

### 1.1 Overview

The proliferation of Internet of Things (IoT) devices has significantly expanded the attack surface for cybercriminals. Traditional security measures are often insufficient to detect sophisticated attacks in real-time. This project presents a **Machine Learning-based Intrusion Detection System (IDS)** integrated with a **Security Operations Center (SOC) style dashboard** for comprehensive network security monitoring.

The system combines multiple detection layers:
- **Dataset-based IDS** for research and validation
- **Live Packet IDS** for real-time traffic analysis
- **Flow-based IDS** with advanced threat categorization
- **SOC ticket generation** for incident management

### 1.2 Motivation

With the exponential growth of IoT devices and network traffic, organizations need:
- Real-time threat detection capabilities
- Automated incident response workflows
- Comprehensive visibility into network behavior
- Machine learning-powered anomaly detection
- SOC-ready incident management system

This project addresses these needs by providing an integrated solution that combines ML-based detection with operational SOC workflows.

---

## 2. Problem Statement

### 2.1 Current Challenges

1. **Limited Real-Time Detection:**
   - Traditional IDS systems rely on signature-based detection
   - Cannot detect zero-day attacks or novel attack patterns
   - High false positive rates

2. **Lack of Integration:**
   - Packet-level detection lacks context
   - No unified view of network threats
   - Manual incident management processes

3. **Scalability Issues:**
   - Cannot handle high-volume network traffic
   - Limited device identification capabilities
   - No automated threat categorization

### 2.2 Research Questions

1. How can Machine Learning improve intrusion detection accuracy?
2. Can flow-based analysis provide better threat context than packet-level analysis?
3. How can SOC workflows be automated for faster incident response?
4. What is the optimal fusion strategy for combining multiple detection methods?

---

## 3. Objectives

### 3.1 Primary Objectives

1. **Develop ML-based IDS:**
   - Train models for packet and flow classification
   - Achieve high accuracy in attack detection
   - Minimize false positive rates

2. **Implement Real-Time Monitoring:**
   - Capture live network traffic
   - Process packets in real-time
   - Generate alerts for suspicious activities

3. **Create SOC Dashboard:**
   - Unified view of all security events
   - Automated ticket generation
   - Device identification and mapping

4. **Advanced Threat Detection:**
   - Implement Level 5 advanced attack categories
   - Fusion scoring for comprehensive threat assessment
   - Priority-based incident management

### 3.2 Secondary Objectives

1. Device discovery and hostname resolution
2. Vendor identification from MAC addresses
3. Flow-based behavior analysis
4. Historical incident logging and reporting

---

## 4. Proposed System

### 4.1 System Architecture

The system follows a **multi-layered detection architecture**:

```
┌─────────────────────────────────────────────────────────┐
│                    Streamlit Dashboard                   │
│              (SOC-Style User Interface)                  │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
│  Dataset IDS │  │ Live Packet  │  │  Flow IDS    │
│   (Level 1)  │  │ IDS (Level 2)│  │ (Level 4/5)  │
└───────┬──────┘  └───────┬──────┘  └───────┬──────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
│ ML Models    │  │ Rule Engine  │  │ Fusion Engine│
│ (RF/SVM)     │  │ (Level 3)    │  │ (Level 4)   │
└──────────────┘  └──────────────┘  └──────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
│ Data Sources │  │ Device Disc. │  │ SOC Tickets  │
│ (Kali/CSV)   │  │ (ARP/DNS)    │  │ (Auto Gen)   │
└──────────────┘  └──────────────┘  └──────────────┘
```

### 4.2 System Components

#### **4.2.1 Dataset IDS (Level 1)**
- **Purpose:** Research and validation using TON_IoT dataset
- **Components:**
  - Binary classifier (Normal/Attack)
  - Attack type classifier (Multi-class)
  - Prediction logging system
- **Output:** `logs/detections.csv`

#### **4.2.2 Live Packet IDS (Level 2)**
- **Purpose:** Real-time packet-level threat detection
- **Components:**
  - Packet capture integration (Kali tshark)
  - ML-based packet classifier
  - Risk scoring engine
  - Device identification
- **Output:** `logs/live_detections.csv`

#### **4.2.3 Flow Generator (Level 3)**
- **Purpose:** Convert packets to flows for behavior analysis
- **Components:**
  - Packet aggregation engine
  - Flow feature extraction
  - Flow metadata generation
- **Output:** `logs/live_flows.csv`

#### **4.2.4 Flow ML Prediction + Fusion (Level 4)**
- **Purpose:** Comprehensive flow-based threat assessment
- **Components:**
  - Flow ML classifier
  - Rule-based scoring
  - Fusion scoring engine
  - Severity calculation
- **Output:** `logs/live_flows_final.csv`

#### **4.2.5 Advanced Threat Detection (Level 5)**
- **Purpose:** Detect sophisticated attack patterns
- **Attack Categories:**
  - **BRUTEFORCE:** TCP-based brute force attacks (TCP only, ignores ICMP/UDP)
  - **PORTSCAN:** Port scanning activities
  - **DNS_TUNNELING:** DNS-based data exfiltration
  - **DATA_EXFILTRATION:** Large data transfers
  - **MALWARE_BEACONING:** Periodic malware communication
  - **BOTNET_C2:** Botnet command and control
  - **MITM_ARP_SPOOF:** Man-in-the-middle attacks
- **Output:** `logs/live_flows_advanced_labeled.csv`

#### **4.2.6 SOC Ticket System**
- **Purpose:** Automated incident management
- **Components:**
  - Ticket auto-generation
  - Priority assignment (P1/P2/P3)
  - Status tracking (OPEN/INVESTIGATING/RESOLVED/FALSE_POSITIVE)
  - Notes management
  - Duplicate prevention
- **Output:** `logs/soc_tickets.csv`

#### **4.2.7 Device Discovery**
- **Purpose:** Network device identification and mapping
- **Components:**
  - ARP table parsing
  - DNS hostname resolution
  - MAC vendor lookup (OUI database)
  - IPv4 filtering (IPv6 excluded)
- **Output:** `logs/device_inventory.csv`

---

## 5. System Architecture

### 5.1 Technology Stack

| Component | Technology |
|-----------|-----------|
| **Frontend** | Streamlit (Python web framework) |
| **Backend** | Python 3.9+ |
| **ML Framework** | Scikit-learn |
| **Data Processing** | Pandas, NumPy |
| **Model Storage** | Joblib (PKL files) |
| **Network Capture** | Tshark (Wireshark CLI) |
| **Visualization** | Streamlit native charts |

### 5.2 Data Flow

```
1. Packet Capture (Kali)
   └─> live_data/live_capture.csv

2. Live Packet IDS
   └─> logs/live_detections.csv

3. Flow Generator
   └─> logs/live_flows.csv

4. Flow Labeling (Rules)
   └─> logs/live_flows_labeled.csv

5. Flow ML Prediction
   └─> logs/live_flows_predicted.csv

6. Advanced Labeling (Level 5)
   └─> logs/live_flows_advanced_labeled.csv

7. Fusion Engine
   └─> logs/live_flows_final.csv

8. SOC Ticket Generation
   └─> logs/soc_tickets.csv
```

### 5.3 Machine Learning Models

#### **5.3.1 Dataset Binary Classifier**
- **Algorithm:** Random Forest
- **Input:** TON_IoT dataset features
- **Output:** Binary classification (0=Normal, 1=Attack)
- **Model File:** `models/ids_random_forest.pkl`

#### **5.3.2 Attack Type Classifier**
- **Algorithm:** Random Forest / SVM
- **Input:** TON_IoT dataset features
- **Output:** Multi-class classification (attack types)
- **Model File:** `models/attack_type_model.pkl`

#### **5.3.3 Live Packet Classifier**
- **Algorithm:** Random Forest
- **Input:** Packet features (IP, ports, protocol, frame length)
- **Output:** Binary classification (Normal/Suspicious)
- **Model File:** `models/live_ids_model.pkl`

#### **5.3.4 Flow Classifier**
- **Algorithm:** Random Forest
- **Input:** Flow features (packets, ports, duration, bytes)
- **Output:** Flow classification
- **Model File:** `models/flow_ids_model.pkl`

---

## 6. Modules Description

### 6.1 Dashboard Module (`app/dashboard.py`)

**Purpose:** Main user interface for SOC operations

**Features:**
- Three-tab interface (Dataset IDS, Live Packet IDS, Flow IDS)
- Real-time auto-refresh
- Device inventory management
- SOC ticket editor
- Download reports functionality

**Key Functions:**
- `load_device_name_map()` - Device IP to hostname mapping
- `save_tickets_df()` - Ticket save with data validation
- `auto_update_device_inventory()` - Auto device discovery
- `can_run_pipeline()` - Pipeline lock mechanism

### 6.2 Flow Generator (`src/flow_generator.py`)

**Purpose:** Convert packets to flows

**Process:**
1. Read packet CSV
2. Group packets by (src_ip, dst_ip, protocol)
3. Calculate flow features:
   - Total packets
   - Unique destination ports
   - Packets per second
   - Duration
   - Total bytes
4. Generate flow IDs

**Output:** `logs/live_flows.csv`

### 6.3 Advanced Flow Labeling (`src/label_advanced_flows.py`)

**Purpose:** Level 5 advanced attack detection

**Rules:**
- **BRUTEFORCE:** TCP only, >200 packets, <30s duration, 1-3 ports
- **PORTSCAN:** >=200 unique destination ports
- **DNS_TUNNELING:** UDP, >100 packets, >20s duration
- **DATA_EXFILTRATION:** >2MB bytes, >10s duration
- **MALWARE_BEACONING:** 0.2-5 pps, >60s duration
- **BOTNET_C2:** <2 pps, >40s duration, >30 packets
- **MITM_ARP_SPOOF:** ICMP floods, >200 packets

**Output:** `logs/live_flows_advanced_labeled.csv`

### 6.4 Flow Fusion Engine (`src/apply_flow_fusion.py`)

**Purpose:** Combine ML, rule, and advanced scores

**Fusion Formula:**
```
ml_score = (ML_confidence / 100) * 40
rule_score = (Rule_threat_score / 100) * 30
advanced_score = (Advanced_threat_score / 100) * 40

final_flow_score = ml_score + rule_score + advanced_score
```

**Severity Mapping:**
- CRITICAL: >= 85
- HIGH: >= 65
- MEDIUM: >= 40
- LOW: < 40

**Output:** `logs/live_flows_final.csv`

### 6.5 SOC Ticket Generator (`src/soc_ticket_generator.py`)

**Purpose:** Auto-generate SOC tickets for incidents

**Ticket Fields:**
- `ticket_id` - Unique ticket identifier
- `timestamp` - Creation time
- `severity` - CRITICAL/HIGH/MEDIUM/LOW
- `priority` - P1/P2/P3 (derived from severity)
- `attacker_ip` / `victim_ip` - IP addresses
- `attacker_device` / `victim_device` - Device names
- `advanced_flow_label` - Attack category
- `advanced_flow_threat_score` - Threat score
- `top_ports` - Scanning ports
- `final_flow_score` - Fusion score
- `recommendation` - Suggested action
- `status` - OPEN/INVESTIGATING/RESOLVED/FALSE_POSITIVE
- `notes` - Analyst notes
- `ticket_key` - Duplicate prevention key

**Duplicate Prevention:**
- Uses `ticket_key = f"{attacker_ip}|{victim_ip}|{category}"`
- Skips tickets with existing keys

**Output:** `logs/soc_tickets.csv`

### 6.6 Device Discovery (`src/device_discovery.py`)

**Purpose:** Identify network devices

**Process:**
1. Read ARP table from Kali
2. Filter IPv4 addresses (exclude IPv6)
3. Lookup hostnames (DNS)
4. Lookup MAC vendors (OUI database)
5. Merge with existing inventory
6. Update timestamps

**Output:** `logs/device_inventory.csv`

---

## 7. Results

### 7.1 Detection Capabilities

The system successfully detects:

✅ **Packet-Level Threats:**
- Suspicious port scanning
- Unusual packet sizes
- Protocol anomalies

✅ **Flow-Level Threats:**
- Brute force attacks (TCP-based)
- Port scanning activities
- DNS tunneling attempts
- Data exfiltration patterns
- Malware beaconing
- Botnet C2 communication
- MITM/ARP spoofing

### 7.2 Performance Metrics

**Dataset IDS:**
- Binary classification accuracy: High (model-dependent)
- Attack type classification: Multi-class support

**Live Packet IDS:**
- Real-time processing: Yes
- Risk scoring: 0-100% probability
- Device identification: Automatic

**Flow IDS:**
- Flow generation: Real-time
- Fusion scoring: Weighted combination
- Severity classification: 4 levels (LOW/MEDIUM/HIGH/CRITICAL)

### 7.3 SOC Workflow Automation

✅ **Automated Processes:**
- Ticket generation from high-severity flows
- Priority assignment based on severity
- Device name mapping
- Duplicate ticket prevention
- Status tracking

✅ **Manual Processes:**
- Ticket status updates
- Notes addition
- False positive marking

### 7.4 System Outputs

All outputs are stored in `logs/` directory:

| Output File | Records | Update Frequency |
|-------------|---------|------------------|
| `detections.csv` | Dataset predictions | On-demand |
| `live_detections.csv` | Packet predictions | Real-time |
| `live_flows.csv` | Generated flows | Pipeline run |
| `live_flows_final.csv` | Fused flows | Pipeline run |
| `soc_tickets.csv` | SOC tickets | Pipeline run |
| `device_inventory.csv` | Device list | Auto (60s) |

---

## 8. Screenshots & Usage

### 8.1 Dashboard Overview

The dashboard provides three main tabs:

1. **Tab 1: Dataset IDS**
   - Dataset prediction interface
   - Attack type classification
   - Log analytics

2. **Tab 2: Live Packet IDS**
   - Real-time packet monitoring
   - Risk scoring
   - Device identification
   - High-risk packet alerts

3. **Tab 3: Flow IDS Monitoring**
   - Flow SOC pipeline controls
   - Top attackers/victims
   - Scanning ports
   - Advanced threat categories
   - SOC ticket management

### 8.2 Key Features Demonstrated

✅ **Real-Time Monitoring:**
- Auto-refresh every 5 seconds
- Live packet analysis
- Flow pipeline automation

✅ **Device Identification:**
- IP to hostname mapping
- MAC vendor lookup
- Device inventory management

✅ **SOC Ticket Management:**
- Auto ticket generation
- Status updates
- Notes editing
- Priority assignment

---

## 9. Conclusion

### 9.1 Achievements

This project successfully implements:

1. ✅ **Multi-layered IDS System:**
   - Dataset-based validation
   - Real-time packet analysis
   - Flow-based behavior detection
   - Advanced threat categorization

2. ✅ **ML-Powered Detection:**
   - Multiple ML models for different detection levels
   - High accuracy classification
   - Real-time prediction capabilities

3. ✅ **SOC-Ready Dashboard:**
   - Unified security monitoring interface
   - Automated ticket generation
   - Device identification
   - Incident management

4. ✅ **Advanced Threat Detection:**
   - 7 attack categories detected
   - Fusion scoring for comprehensive assessment
   - Priority-based incident handling

### 9.2 Key Contributions

- **Integrated Approach:** Combines packet, flow, and ML-based detection
- **SOC Automation:** Reduces manual incident management workload
- **Device Intelligence:** Automatic device identification and mapping
- **False Positive Reduction:** Advanced rules prevent ICMP/UDP false alerts

### 9.3 Limitations

1. **Network Visibility:**
   - Limited to traffic visible to capture interface
   - Requires port mirroring for full network visibility

2. **Model Training:**
   - Requires labeled datasets for training
   - Model accuracy depends on training data quality

3. **Demo Environment:**
   - Blocking is simulated (not real firewall)
   - SOC tickets are for demonstration

4. **Security:**
   - Dashboard lacks authentication (add before production)
   - No rate limiting implemented
   - Logs may contain sensitive information

---

## 9.4 Security Implementation

### Security Features Implemented:

1. **Input Validation:**
   - IP address validation (`src/input_validation.py`)
   - MAC address format validation
   - File path sanitization
   - Port number validation

2. **Secure Command Execution:**
   - Replaced `os.system()` with secure `subprocess.run()`
   - List-based subprocess arguments (prevents shell injection)
   - Timeout protection on all external commands

3. **Code Security:**
   - Command injection vulnerabilities fixed
   - Shell injection vulnerabilities fixed
   - Path traversal protection added

### Security Recommendations:

1. **Authentication:** Add Streamlit authentication before production deployment
2. **Rate Limiting:** Implement to prevent DoS attacks
3. **Log Encryption:** Encrypt sensitive log files
4. **HTTPS:** Use HTTPS if exposing dashboard externally
5. **Access Control:** Implement role-based access control

**See:** `SECURITY_AUDIT.md` and `IMPROVEMENTS_AND_RECOMMENDATIONS.md` for details.

---

## 10. Future Scope

### 10.1 Short-Term Enhancements

1. **Enhanced Alerting:**
   - Email notifications for critical incidents
   - Telegram/Slack integration
   - SMS alerts for P1 incidents

2. **Real-Time Blocking:**
   - iptables integration for Linux
   - Windows Firewall integration
   - Router API integration

3. **Advanced Visualization:**
   - Network topology maps
   - Attack timeline visualization
   - Geographic IP mapping

### 10.2 Long-Term Enhancements

1. **Distributed Architecture:**
   - Multi-sensor deployment
   - Centralized correlation engine
   - Cloud-based storage

2. **Deep Learning Integration:**
   - LSTM for sequence analysis
   - Autoencoder for anomaly detection
   - Transfer learning for model improvement

3. **Threat Intelligence:**
   - Integration with threat feeds
   - IOC (Indicators of Compromise) matching
   - Reputation scoring

4. **Compliance & Reporting:**
   - Regulatory compliance reports
   - Executive dashboards
   - Automated compliance checking

---

## 11. Security Implementation

### 11.1 Security Features

The system includes several security measures:

1. **Input Validation:**
   - All user inputs are validated before processing
   - IP addresses, MAC addresses, and file paths are sanitized
   - Prevents injection attacks

2. **Secure Command Execution:**
   - All system commands use secure subprocess calls
   - Timeout protection prevents hanging processes
   - Error handling prevents information disclosure

3. **Code Security:**
   - Command injection vulnerabilities fixed
   - Shell injection vulnerabilities fixed
   - Path traversal protection implemented

### 11.2 Security Documentation

- **SECURITY_AUDIT.md** - Complete security audit report
- **SECURITY_GUIDE.md** - Security best practices and deployment guide
- **ERRORS_AND_FIXES_SUMMARY.md** - Security fixes applied
- **IMPROVEMENTS_AND_RECOMMENDATIONS.md** - Future security enhancements

### 11.3 Security Recommendations

For production deployment:
1. Add authentication to dashboard
2. Implement rate limiting
3. Use HTTPS for external access
4. Encrypt sensitive log files
5. Regular security audits

---

## 12. Testing Implementation ✅

### 12.1 Unit Test Suite

**Status:** Comprehensive unit test suite implemented

**Test Structure:**
```
tests/
├── __init__.py
├── conftest.py                    # Pytest fixtures
├── test_input_validation.py      # Input validation tests
├── test_label_advanced_flows.py  # Attack detection tests
├── test_soc_tickets.py           # SOC ticket tests
└── test_security.py              # Security vulnerability tests
```

**Test Coverage:**
- Input validation: ~95%
- Attack detection: ~90%
- SOC tickets: ~85%
- Security tests: ~80%

**Total Tests:** 50+ test functions across 15+ test classes

### 12.2 Running Tests

**Installation:**
```bash
pip install pytest
```

**Run Tests:**
```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_input_validation.py -v

# Using test runner
python run_tests.py
```

### 12.3 Test Categories

1. **Input Validation Tests:**
   - IPv4/MAC address validation
   - Filename/path sanitization
   - Port/ticket validation

2. **Attack Detection Tests:**
   - BRUTEFORCE detection (TCP only)
   - PORTSCAN detection
   - DNS_TUNNELING detection
   - Other attack categories

3. **SOC Ticket Tests:**
   - Ticket key generation
   - Priority conversion
   - Recommendation generation

4. **Security Tests:**
   - Command injection protection
   - Path traversal protection
   - XSS protection

**See:** `TESTING_GUIDE.md` for complete testing documentation

---

## 13. References

1. TON_IoT Dataset - IoT Network Traffic Dataset
2. Scikit-learn Documentation - Machine Learning Library
3. Streamlit Documentation - Web Framework
4. Wireshark/Tshark Documentation - Network Protocol Analyzer
5. OUI Database - MAC Address Vendor Lookup
6. OWASP Top 10 - Web Application Security Risks
7. CWE Top 25 - Common Weakness Enumeration

---

## 12. Appendix

### 12.1 Installation Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Activate virtual environment (Windows)
.\venv\Scripts\activate

# Run dashboard
streamlit run app/dashboard.py
```

### 12.2 Kali Capture Commands

```bash
# Live capture to CSV
sudo tshark -i eth0 -a duration:60 -T fields \
-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
-e tcp.srcport -e tcp.dstport \
-e udp.srcport -e udp.dstport \
-e frame.len \
-E header=y -E separator=, \
> /mnt/hgfs/live_data/live_capture.csv

# ARP scan
sudo arp-scan --localnet | awk '/^192\./ {print $1","$2}' > /tmp/arp_table_kali.csv
cp /tmp/arp_table_kali.csv /mnt/hgfs/live_data/arp_table_kali.csv
```

### 12.3 Pipeline Commands

```bash
# Run complete SOC pipeline
python src/run_flow_soc_pipeline.py

# Individual steps
python src/flow_generator.py
python src/label_live_flows.py
python src/predict_flow_live.py
python src/label_advanced_flows.py
python src/apply_flow_fusion.py
python src/flow_incident_logger.py
python src/soc_ticket_generator.py
```

### 12.4 Testing Commands

```bash
# Install pytest
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_input_validation.py -v

# Run using test runner
python run_tests.py
```

---

**Document Version:** 1.0  
**Last Updated:** January 2026  
**Author:** Vishwa
