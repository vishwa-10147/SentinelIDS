# IoT IDS + SOC Dashboard (ML-Based)  
### Real-Time Packet + Flow IDS Monitoring with SOC Tickets + Device Identification

This project is a **A Multi-Level Machine Learning–Based Intrusion Detection System for IoT Networks**.  
It supports:

✅ Dataset-based IDS (TON_IoT)  
✅ Live Packet IDS (Real-time traffic capture)  
✅ Flow-Based IDS (SOC pipeline + Fusion scoring)  
✅ Advanced Attack Category Labeling (Level 5 rules)  
✅ Device Identification (IP → Hostname)  
✅ SOC Tickets Auto-Generation (Incident tracking)

---

## 🚀 Features

### ✅ Tab 1: Dataset IDS (TON_IoT)
- Runs ML prediction on TON_IoT dataset samples
- Two-level detection:
  - Binary classification (Normal / Attack)
  - Attack Type classification
- Auto logging of predictions in `logs/detections.csv`

---

### ✅ Tab 2: Live Packet IDS (Real-Time)
- Captures live traffic using Kali `tshark`
- CSV transfer to Windows shared folder
- ML model predicts packets as:
  - NORMAL
  - SUSPICIOUS
- Shows risk probability score
- Shows device names:
  - `src_device` and `dst_device` from Device Discovery

Output generated:
- `logs/live_detections.csv`

---

### ✅ Tab 3: Flow IDS Monitoring (Level 4/5 SOC View)
- Converts live packets into flows
- Flow ML prediction + Rule scoring + Fusion scoring
- Shows:
  - Top attackers
  - Top victims
  - Scanning ports
  - High severity flows
  - Severity distribution chart

Advanced detection (Level 5):
- BRUTEFORCE (TCP only, ignores ICMP/UDP)
- PORTSCAN
- DNS_TUNNELING
- DATA_EXFILTRATION
- MALWARE_BEACONING
- BOTNET_C2
- MITM_ARP_SPOOF

Outputs generated:
- `logs/live_flows.csv`
- `logs/live_flows_labeled.csv`
- `logs/live_flows_predicted.csv`
- `logs/live_flows_advanced_labeled.csv`
- `logs/live_flows_final.csv`
- `logs/flow_incidents.csv`

---

### ✅ SOC Tickets (Auto Generated)
Creates SOC tickets based on suspicious/high severity flows.

Output:
- `logs/soc_tickets.csv`

Ticket contains:
- `ticket_id`, `timestamp`, `severity`, `priority` (P1/P2/P3)
- `attacker_ip` / `victim_ip`
- `attacker_device` / `victim_device`
- `advanced_flow_label` + `advanced_flow_threat_score`
- `top_ports` (scanning ports)
- `final_flow_score`
- `recommendation`
- `status` (OPEN/INVESTIGATING/RESOLVED/FALSE_POSITIVE)
- `notes` (editable)
- `ticket_key` (prevents duplicates)

---

## 📁 Project Structure

```
iot-ids-ml-dashboard/
│
├── app/
│   └── dashboard.py                    # Main Streamlit dashboard
│
├── src/
│   ├── flow_generator.py              # Converts packets to flows
│   ├── label_live_flows.py            # Rule-based flow labeling
│   ├── predict_flow_live.py           # Flow ML prediction
│   ├── label_advanced_flows.py        # Level 5 advanced rules
│   ├── apply_flow_fusion.py           # Fusion scoring engine
│   ├── flow_incident_logger.py        # Flow incident logging
│   ├── soc_ticket_generator.py        # Auto SOC ticket generation
│   ├── device_discovery.py            # Device identification
│   ├── hostname_lookup.py             # DNS hostname resolution
│   ├── vendor_lookup.py               # MAC vendor lookup
│   ├── run_flow_soc_pipeline.py       # Complete SOC pipeline runner
│   └── ...                            # Other utility scripts
│
├── models/
│   ├── ids_random_forest.pkl          # Dataset binary classifier
│   ├── attack_type_model.pkl          # Attack type classifier
│   ├── live_ids_model.pkl             # Live packet classifier
│   └── flow_ids_model.pkl              # Flow classifier
│
├── datasets/
│   └── raw/
│       └── train_test_network.csv     # TON_IoT dataset
│
├── logs/
│   ├── detections.csv                 # Dataset IDS logs
│   ├── live_detections.csv            # Live packet predictions
│   ├── incidents.csv                  # Packet incidents
│   ├── flow_incidents.csv             # Flow incidents
│   ├── soc_tickets.csv                # SOC tickets
│   ├── device_inventory.csv           # Device discovery inventory
│   └── ...                            # Flow processing outputs
│
├── live_data/
│   ├── live_capture.csv                # Live packet capture (from Kali)
│   └── arp_table_kali.csv             # ARP table (from Kali)
│
├── requirements.txt                    # Python dependencies
├── run_dashboard.ps1                  # One-click dashboard launcher
├── auto_update_devices.ps1             # Auto device discovery script
├── LICENSE                            # MIT License
└── README.md                          # This file
```

---

## ✅ Requirements

### Software
- **Python 3.9+** (recommended: Python 3.10+)
- **Streamlit** (web dashboard framework)
- **Scikit-learn** (ML models)
- **Pandas** (data processing)
- **Joblib** (model serialization)
- **Tshark** (Wireshark CLI) on Kali Linux
- **VMware Shared Folder** support (Kali ↔ Windows)

### Install Dependencies

```bash
# Activate virtual environment (Windows)
.\venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

---

## ✅ How To Run

### **Option 1: One-Click Launch (Recommended)**

```powershell
# Windows PowerShell
.\run_dashboard.ps1
```

This script will:
1. Activate virtual environment
2. Start Streamlit dashboard
3. Open browser automatically

### **Option 2: Manual Launch**

```bash
# Step 1: Activate Virtual Environment (Windows)
cd D:\MiniProject\iot-ids-ml-dashboard
.\venv\Scripts\activate

# Step 2: Start Streamlit Dashboard
streamlit run app/dashboard.py
```

Dashboard will open at:
```
http://localhost:8501
```

---

## ✅ Live Packet Capture Setup (Kali Linux)

### **Step 1: Start Capture (Kali Linux)**

**Method 1: Direct CSV Export (Recommended)**
```bash
# Capture for 60 seconds and export directly to CSV
sudo tshark -i eth0 -a duration:60 -T fields \
-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
-e tcp.srcport -e tcp.dstport \
-e udp.srcport -e udp.dstport \
-e frame.len \
-E header=y -E separator=, \
> /mnt/hgfs/live_data/live_capture.csv
```

**Method 2: PCAP then CSV**
```bash
# Capture to PCAP file
sudo tshark -i eth0 -a duration:60 -w /tmp/traffic.pcap

# Export PCAP to CSV
sudo chmod 644 /tmp/traffic.pcap
tshark -r /tmp/traffic.pcap -T fields \
-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
-e tcp.srcport -e tcp.dstport \
-e udp.srcport -e udp.dstport \
-e frame.len \
-E header=y -E separator=, \
> /mnt/hgfs/live_data/live_capture.csv

# Verify capture
wc -l /mnt/hgfs/live_data/live_capture.csv
```

**Note:** Replace `eth0` with your network interface (use `ip a` to check)

---

## ✅ Device Discovery Setup (Auto Device Identification)

### **Step 1: Export ARP Table (Kali Linux)**

```bash
# Scan local network and save ARP table
sudo arp-scan --localnet | awk '/^192\./ {print $1","$2}' > /tmp/arp_table_kali.csv

# Verify ARP table
cat /tmp/arp_table_kali.csv

# Copy to Windows shared folder
cp /tmp/arp_table_kali.csv /mnt/hgfs/live_data/arp_table_kali.csv
```

**Manual ARP Table Format:**
```csv
ip,mac
192.168.29.1,04:70:56:ea:24:89
192.168.29.190,90:09:df:08:63:12
192.168.29.152,00:11:22:33:44:55
```

### **Step 2: Run Device Discovery (Windows)**

**Manual Run:**
```bash
python -m src.device_discovery
```

**Auto Update (Background Script):**
```powershell
# Run in separate PowerShell window
.\auto_update_devices.ps1
```

This updates:
- ✅ `logs/device_inventory.csv` (with hostname, vendor, IP, MAC)

**Device Discovery Features:**
- ✅ IPv4 only (IPv6 filtered automatically)
- ✅ DNS hostname lookup (skips invalid DNS gracefully)
- ✅ MAC vendor lookup (OUI database)
- ✅ Auto-updates every 60 seconds (if using auto script)

---

## ✅ Running Flow SOC Pipeline

### **Method 1: Dashboard Button (Recommended)**
1. Open dashboard → Tab 3: Flow IDS Monitoring
2. Click **"🚀 Run Flow SOC Pipeline Now"**
3. Wait for completion message

### **Method 2: Command Line**
```bash
python src/run_flow_soc_pipeline.py
```

**Pipeline Steps:**
1. `flow_generator.py` - Converts packets to flows
2. `label_live_flows.py` - Rule-based labeling
3. `predict_flow_live.py` - ML prediction
4. `label_advanced_flows.py` - Level 5 advanced rules
5. `apply_flow_fusion.py` - Fusion scoring
6. `flow_incident_logger.py` - Incident logging

---

## ✅ Outputs Generated

| File | Description |
|------|-------------|
| `logs/detections.csv` | Dataset IDS predictions |
| `logs/live_detections.csv` | Live packet IDS predictions |
| `logs/incidents.csv` | Packet-level incidents |
| `logs/live_flows.csv` | Generated flows from packets |
| `logs/live_flows_labeled.csv` | Rule-based flow labels |
| `logs/live_flows_predicted.csv` | ML flow predictions |
| `logs/live_flows_advanced_labeled.csv` | Level 5 advanced attack categories |
| `logs/live_flows_final.csv` | **Final fused flow severity output** |
| `logs/flow_incidents.csv` | Flow-level incidents |
| `logs/device_inventory.csv` | Device discovery inventory |
| `logs/soc_tickets.csv` | **Auto-generated SOC tickets** |

---

## ✅ Project Levels Implemented

### **Level 1: Dataset IDS**
- TON_IoT dataset classification
- Binary + Attack Type prediction
- Logging and analytics

### **Level 2: Live Packet IDS**
- Real-time packet capture (Kali)
- ML-based packet classification
- Risk scoring and device identification

### **Level 3: Flow Generator**
- Packet-to-flow conversion
- Flow feature extraction
- Flow aggregation

### **Level 4: Flow ML Prediction + Fusion**
- Flow ML classification
- Rule-based scoring
- Fusion scoring engine
- Severity calculation (LOW/MEDIUM/HIGH/CRITICAL)

### **Level 5: Advanced Threat Categories + SOC Tickets**
- Advanced attack detection:
  - BRUTEFORCE (TCP only)
  - PORTSCAN
  - DNS_TUNNELING
  - DATA_EXFILTRATION
  - MALWARE_BEACONING
  - BOTNET_C2
  - MITM_ARP_SPOOF
- SOC ticket auto-generation
- Ticket management (status, notes)

---

## 🔒 Security Features

### ✅ Security Improvements Implemented

1. **Input Validation:**
   - IP address validation to prevent command injection
   - MAC address format validation
   - File path sanitization
   - Port number validation

2. **Secure Command Execution:**
   - All subprocess calls use list-based arguments (no shell injection)
   - Timeout protection on all external commands
   - Error handling for failed operations

3. **Security Modules:**
   - `src/input_validation.py` - Comprehensive input validation utilities
   - Secure file operations
   - Path traversal protection

### ⚠️ Security Recommendations

**For Production Deployment:**
1. **Add Authentication:** Dashboard currently has no authentication
   - See `IMPROVEMENTS_AND_RECOMMENDATIONS.md` for implementation guide
   - Use environment variables for credentials
   - Implement session timeout

2. **Network Security:**
   - Use HTTPS if exposing dashboard externally
   - Implement firewall rules
   - Restrict access to authorized users only

3. **Data Protection:**
   - Encrypt sensitive log files
   - Implement log rotation
   - Regular security audits

**Security Documentation:**
- `SECURITY_AUDIT.md` - Complete security audit report
- `ERRORS_AND_FIXES_SUMMARY.md` - Security fixes applied
- `IMPROVEMENTS_AND_RECOMMENDATIONS.md` - Future security enhancements

---

## 🔐 Data Privacy & Ethics

### **Important Notes:**
- This project is designed for **controlled lab environments** only
- All sample captures are from **isolated test networks**
- No real production network data is included in this repository
- Captures contain **no personally identifiable information (PII)**

### **Ethical Use:**
- ⚠️ **Network monitoring requires proper authorization**
- Only use on networks you own or have explicit permission to monitor
- Comply with local laws regarding network monitoring (e.g., GDPR, CCPA, Computer Fraud and Abuse Act)
- This tool is for **educational and research purposes only**

### **For Production/Real-World Use:**
- Implement proper data anonymization techniques
- Add user authentication and role-based access controls
- Encrypt sensitive log files and network captures
- Follow your organization's security and privacy policies
- Obtain necessary approvals from network administrators
- Consider legal implications of packet inspection in your jurisdiction

### **Researcher Responsibilities:**
- Use only on authorized test networks
- Anonymize any data before sharing or publication
- Respect privacy of network users
- Follow institutional review board (IRB) guidelines if applicable

---

## ⚠️ Limitations (Important)

1. **Network Visibility:**
   - This project captures packets only from the system running Kali capture
   - In a college lab network, attacks between other PCs may not be visible unless:
     - ✅ Port mirroring configured
     - ✅ Monitor mode enabled
     - ✅ SPAN configuration on switch
     - ✅ Router-level capture

2. **Demo Environment:**
   - Blocking is simulated (not real firewall blocking)
   - SOC tickets are for demonstration purposes
   - Device discovery requires ARP scan access
   - **⚠️ No authentication** (add before production use)

3. **Model Training:**
   - Models need to be trained before first use
   - Training scripts available in `src/` directory

---

## ✅ Future Enhancements

- [ ] Live PCAP logging + investigation download
- [ ] Email/Telegram SOC alerting
- [ ] Real firewall blocking (iptables integration)
- [ ] GeoIP attacker mapping
- [ ] Advanced visualization dashboard
- [ ] Multi-interface capture support
- [ ] Distributed IDS architecture
- [ ] Real-time streaming analysis

---

## 👨‍💻 Author

**Vishwa**  
Department of Computer Science / Cybersecurity

This project was developed as part of academic research in network security and machine learning applications for intrusion detection systems.

---

## 📌 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### What this means:
- ✅ Free to use, modify, and distribute
- ✅ Can be used in commercial projects
- ✅ Must include copyright notice and license
- ✅ Provided "as-is" without warranty

**Copyright (c) 2025 Vishwa**

---

## 📝 Quick Reference Commands

### **Windows (Dashboard)**
```powershell
# One-click launch
.\run_dashboard.ps1

# Manual launch
.\venv\Scripts\activate
streamlit run app/dashboard.py

# Run SOC pipeline
python src/run_flow_soc_pipeline.py

# Device discovery
python -m src.device_discovery

# Run unit tests
.\run_tests.ps1
# or
python run_tests.py
```

### **Kali Linux (Capture)**
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

---

## 🐛 Troubleshooting

### **Dashboard not starting?**
- Check if virtual environment is activated
- Verify `requirements.txt` packages are installed
- Check if port 8501 is available

### **No live packets detected?**
- Verify `live_data/live_capture.csv` exists
- Check CSV has valid IP packets (not empty)
- Ensure Kali capture completed successfully

### **Device discovery not working?**
- Verify `live_data/arp_table_kali.csv` exists
- Check ARP table format (ip,mac)
- Ensure IPv4 addresses only (IPv6 filtered automatically)

### **SOC pipeline errors?**
- Check all input files exist:
  - `live_data/live_capture.csv`
  - `models/flow_ids_model.pkl`
- Verify logs directory exists
- Check Python version (3.9+)

---

## 🧪 Testing

### Run Unit Tests

**Windows PowerShell:**
```powershell
.\run_tests.ps1
```

**Python:**
```bash
# Option 1: Using test runner
python run_tests.py

# Option 2: Using pytest directly
pytest tests/ -v
```

**Test Coverage:**
- ✅ Input validation (security-critical)
- ✅ Attack detection rules
- ✅ SOC ticket generation
- ✅ Security vulnerability tests

**See:** `TESTING_GUIDE.md` for complete testing documentation

---

## 📚 Additional Documentation

### Getting Started:
- **`QUICK_START.md`** - 5-minute quick setup guide ⚡
- **`DOCUMENTATION_INDEX.md`** - Complete documentation index 📚

### Technical Documentation:
- **`PROJECT_DOCUMENTATION.md`** - Complete project documentation 📘
- **`DOCUMENTATION_SUMMARY.md`** - Documentation overview 📋

### Security Documentation:
- **`SECURITY_AUDIT.md`** - Security audit report 🔍
- **`SECURITY_GUIDE.md`** - Security best practices guide 🛡️
- **`ERRORS_AND_FIXES_SUMMARY.md`** - Security fixes summary ✅

### Testing Documentation:
- **`TESTING_GUIDE.md`** - Complete testing guide 🧪

### Future Development:
- **`IMPROVEMENTS_AND_RECOMMENDATIONS.md`** - Future improvements 💡

---

## 📦 Project Files

### Essential Files:
- `README.md` - This file (start here)
- `requirements.txt` - Python dependencies
- `run_dashboard.ps1` - One-click launcher
- `run_tests.ps1` - Test runner
- `LICENSE` - MIT License

### Documentation:
- See `DOCUMENTATION_INDEX.md` for complete list

### Configuration:
- `.gitignore` - Git ignore rules
- `pytest.ini` - Test configuration

---

## 🔗 GitHub Repository

**Repository:** [https://github.com/vishwa-10147/iot-ids-ml-dashboard](https://github.com/vishwa-10147/iot-ids-ml-dashboard)

**Setup Instructions:** See `GITHUB_PUSH_INSTRUCTIONS.md` or `QUICK_GIT_COMMANDS.md`

---

## 📖 Citation

If you use this project in your research, please cite:

```bibtex
@software{vishwa2025iot_ids,
  author = {Vishwa},
  title = {IoT IDS + SOC Dashboard: ML-Based Real-Time Intrusion Detection System},
  year = {2025},
  url = {https://github.com/vishwa-10147/iot-ids-ml-dashboard},
  note = {Research project with paper submission pending}
}
```

*Note: Citation details will be updated upon paper publication.*

---

## 🙏 Acknowledgments

This project uses the following open-source tools and datasets:
- **TON_IoT Dataset** - University of New South Wales (UNSW)
- **Scikit-learn** - Machine learning library
- **Streamlit** - Dashboard framework
- **Wireshark/Tshark** - Network analysis tools

---

**Last Updated:** January 2025  
**Version:** 1.0.0  
**Status:** ✅ Active Research Project

---

## 📧 Contact

For questions, suggestions, or collaboration inquiries related to this research:
- Open an issue on GitHub
- Check the documentation in the `docs/` folder

---

**⚠️ Disclaimer:** This software is provided for educational and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations regarding network monitoring and data collection in their jurisdiction.
