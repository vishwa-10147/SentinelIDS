# Quick Start Guide
## IoT IDS ML Dashboard - Getting Started

**Author:** Vishwa  
**Date:** January 2026

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Install Dependencies
```bash
# Activate virtual environment
.\venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Linux/Mac

# Install packages
pip install -r requirements.txt
```

### Step 2: Start Dashboard
```bash
# Option 1: One-click launch (Windows)
.\run_dashboard.ps1

# Option 2: Manual launch
streamlit run app/dashboard.py
```

Dashboard opens at: `http://localhost:8501`

---

## 📡 Setup Live Packet Capture (Kali Linux)

### Step 1: Capture Traffic
```bash
# Capture for 60 seconds
sudo tshark -i eth0 -a duration:60 -T fields \
-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
-e tcp.srcport -e tcp.dstport \
-e udp.srcport -e udp.dstport \
-e frame.len \
-E header=y -E separator=, \
> /mnt/hgfs/live_data/live_capture.csv
```

### Step 2: Export ARP Table
```bash
# Scan network
sudo arp-scan --localnet | awk '/^192\./ {print $1","$2}' > /tmp/arp_table_kali.csv

# Copy to shared folder
cp /tmp/arp_table_kali.csv /mnt/hgfs/live_data/arp_table_kali.csv
```

---

## 🪟 Setup Live Packet Capture (Windows VMnet + Scapy)

Use this mode when traffic is between **Kali VM → Metasploitable VM** and you want Windows IDS to capture directly from VMware virtual adapters.

### Step 1: Install Npcap
- Download: https://nmap.org/npcap/
- During install, enable:
   - Install Npcap in WinPcap API-compatible mode
   - Support raw 802.11 traffic
   - Install Npcap loopback adapter

### Step 2: Find VMware adapter
```powershell
ipconfig
```
Look for adapter names like `VMware Network Adapter VMnet1`.

### Step 3: Install Scapy
```powershell
pip install scapy
```

### Step 4: List interfaces from Python
```powershell
python src/capture_live_vmnet.py --list-ifaces
```

### Step 5: Start live capture to pipeline CSV
```powershell
# Run PowerShell as Administrator
python src/capture_live_vmnet.py --iface-hint "VMware Network Adapter VMnet1"
```

This writes packet features to `live_data/live_capture.csv` using the same columns required by:
- `src/predict_live_traffic.py`
- `src/flow_generator.py`

### Step 6 (Optional): Real-time packet ML alerts
```powershell
python src/capture_live_vmnet.py --iface-hint "VMware Network Adapter VMnet1" --model models/live_ids_model.pkl
```
When model output is `1`, the script prints `🚨 ATTACK DETECTED` and appends to `logs/live_detections.csv`.

### Step 7: Run your SOC pipeline
```powershell
python src/run_flow_soc_pipeline.py
```

Fusion scoring now uses:
- `0.4 × packet_ml_confidence_%` (from `logs/live_scored_packets.csv`)
- `0.4 × flow_ml_confidence_%` (from flow model)
- `0.2 × rule_engine_score` (max of base + advanced rule scores)

Final output is saved in `logs/live_flows_final.csv`.

### Quick troubleshooting
- No packets: run terminal as Administrator, verify Npcap is installed, and confirm both VMs are on the same VMnet.
- Wrong adapter: run `python src/capture_live_vmnet.py --list-ifaces` and pass exact name with `--iface`.
- Empty capture: generate traffic from Kali (`ping`, `nmap -sS`, `telnet`) to Metasploitable while capture is running.

---

## 🎯 Using the Dashboard

### Tab 1: Dataset IDS
- Click "Run Dataset Detection" to test ML models
- View predictions and attack types
- Check logs in `logs/detections.csv`

### Tab 2: Live Packet IDS
- View real-time packet analysis
- See suspicious packets highlighted
- Check device names and risk scores
- Download detection reports

### Tab 3: Flow IDS Monitoring
- Click "🚀 Run Flow SOC Pipeline Now" to analyze flows
- View top attackers and victims
- Check advanced threat categories
- Generate SOC tickets

---

## 🔒 Security Setup (Recommended)

### Add Password Protection
```python
# Add to start of app/dashboard.py
import os

if not st.session_state.get("authenticated"):
    password = st.text_input("Enter Password", type="password")
    if password == os.getenv("DASHBOARD_PASSWORD", "changeme"):
        st.session_state.authenticated = True
    else:
        st.error("Invalid password")
        st.stop()
```

Set password via environment variable:
```bash
# Windows PowerShell
$env:DASHBOARD_PASSWORD="your_secure_password"

# Linux/Mac
export DASHBOARD_PASSWORD="your_secure_password"
```

---

## 📊 Understanding Outputs

### Key Files Generated:

| File | Description | Location |
|------|-------------|----------|
| `live_detections.csv` | Packet-level predictions | `logs/` |
| `live_flows_final.csv` | Final flow analysis | `logs/` |
| `soc_tickets.csv` | Auto-generated tickets | `logs/` |
| `device_inventory.csv` | Device discovery results | `logs/` |

### Understanding Severity Levels:
- **CRITICAL** - Immediate action required (P1)
- **HIGH** - Investigate soon (P2)
- **MEDIUM** - Monitor and review (P3)
- **LOW** - Normal traffic

---

## 🐛 Troubleshooting

### Dashboard won't start?
```bash
# Check if port 8501 is available
netstat -an | findstr 8501  # Windows
lsof -i :8501  # Linux/Mac

# Try different port
streamlit run app/dashboard.py --server.port 8502
```

### No packets detected?
- Verify `live_data/live_capture.csv` exists
- Check CSV has valid IP packets
- Ensure Kali capture completed successfully

### Device discovery not working?
- Verify `live_data/arp_table_kali.csv` exists
- Check ARP table format (ip,mac)
- Ensure IPv4 addresses only

### SOC pipeline errors?
- Check all input files exist
- Verify models are trained (`models/*.pkl`)
- Check Python version (3.9+)

---

## 📚 Next Steps

1. **Read Full Documentation:**
   - `README.md` - Complete guide
   - `PROJECT_DOCUMENTATION.md` - Technical details

2. **Security Setup:**
   - `SECURITY_GUIDE.md` - Security best practices
   - `SECURITY_AUDIT.md` - Security audit

3. **Improvements:**
   - `IMPROVEMENTS_AND_RECOMMENDATIONS.md` - Future enhancements

---

## 🧪 Running Tests

### Install Test Dependencies:
```bash
pip install pytest
```

### Run Tests:
```powershell
# Windows PowerShell
.\run_tests.ps1

# Python
python run_tests.py
```

**See:** `TESTING_GUIDE.md` for complete testing documentation

---

## ✅ Checklist

- [ ] Dependencies installed
- [ ] Dashboard running
- [ ] Kali capture configured
- [ ] Device discovery working
- [ ] SOC pipeline tested
- [ ] Security configured (optional but recommended)
- [ ] Tests passing (run `python run_tests.py`)

---

## 🧪 Single-PC VMware Lab: Full Test Procedure

This setup matches your environment:
- Windows host = IDS + Dashboard
- Kali VM = attacker
- Metasploitable VM = target server
- All on same PC, same VMware virtual network

### 1) One-time setup on Windows
```powershell
# Run PowerShell as Administrator
.\setup_windows_vmnet_lab.ps1
```

### 2) Terminal A (Windows): Start packet capture
```powershell
# Capture + real-time packet ML alerts
.\start_vmnet_capture.ps1 -InterfaceHint "VMware Network Adapter VMnet1" -UseModel
```

### 3) Terminal B (Windows): Start flow SOC fusion loop
```powershell
.\start_soc_pipeline_loop.ps1 -IntervalSeconds 8
```

### 4) (Optional) Terminal C (Windows): Start dashboard
```powershell
.\run_dashboard.ps1
```

### 5) Kali VM: Launch attack simulation against Metasploitable
```bash
# Replace with Metasploitable IP
ping <metasploitable_ip>
nmap -sS <metasploitable_ip>
telnet <metasploitable_ip> 23
```

### 6) Verify detections on Windows
Check these outputs:
- `live_data/live_capture.csv` (incoming packets)
- `logs/live_scored_packets.csv` (packet ML + risk)
- `logs/live_flows_final.csv` (0.4/0.4/0.2 fusion score)
- `logs/flow_incidents.csv` (SOC incident records)

### 7) Stop test
- Stop all Windows terminals with `Ctrl+C`
- Stop attack commands in Kali

---

**Need Help?** Check `README.md` for detailed instructions.
