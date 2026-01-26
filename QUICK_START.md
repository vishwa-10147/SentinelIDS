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

**Need Help?** Check `README.md` for detailed instructions.
