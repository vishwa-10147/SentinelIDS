# Deployment Guide
## IoT IDS ML Dashboard - Production Deployment

**Author:** Vishwa  
**Date:** January 2026

---

## 🚀 Deployment Overview

This guide covers deploying the IoT IDS ML Dashboard for production use.

---

## 📋 Pre-Deployment Checklist

### 1. Code Review
- [x] All tests passing
- [x] Security fixes applied
- [x] Code reviewed
- [x] Documentation complete

### 2. Security Setup
- [ ] Authentication implemented
- [ ] HTTPS configured
- [ ] Firewall rules set
- [ ] Access controls configured

### 3. Environment Setup
- [ ] Python 3.9+ installed
- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] Models trained/available

---

## 🔧 Installation Steps

### Step 1: Clone/Download Project
```bash
git clone <repository-url>
cd iot-ids-ml-dashboard
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation
```bash
# Run tests
python run_tests.py

# Check models exist
ls models/*.pkl
```

---

## 🔒 Security Configuration

### 1. Add Authentication

**Option A: Simple Password (Quick)**
```python
# Add to start of app/dashboard.py
import os

if not st.session_state.get("authenticated"):
    password = st.text_input("Enter Password", type="password")
    if password == os.getenv("DASHBOARD_PASSWORD", "changeme"):
        st.session_state.authenticated = True
        st.rerun()
    else:
        st.error("Invalid password")
        st.stop()
```

**Option B: Streamlit Authenticator (Recommended)**
```bash
pip install streamlit-authenticator
```

See `SECURITY_GUIDE.md` for complete authentication setup.

### 2. Set Environment Variables
```bash
# Windows PowerShell
$env:DASHBOARD_PASSWORD="your_secure_password"

# Linux/Mac
export DASHBOARD_PASSWORD="your_secure_password"
```

### 3. Configure Firewall
```bash
# Linux example
sudo ufw allow 8501/tcp from 192.168.1.0/24
```

---

## 🌐 Network Configuration

### Internal Network Only (Recommended)
- Run dashboard on internal network
- Use firewall to restrict access
- Don't expose to internet

### External Access (If Needed)
- Use HTTPS (reverse proxy with SSL)
- Strong authentication required
- Rate limiting recommended
- VPN access preferred

---

## 📊 Running the Dashboard

### Development Mode
```bash
streamlit run app/dashboard.py
```

### Production Mode
```bash
# With authentication
streamlit run app/dashboard.py --server.headless true

# With custom port
streamlit run app/dashboard.py --server.port 8501
```

### As a Service (Linux)
```bash
# Create systemd service
sudo nano /etc/systemd/system/iot-ids-dashboard.service
```

Service file:
```ini
[Unit]
Description=IoT IDS ML Dashboard
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/iot-ids-ml-dashboard
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/streamlit run app/dashboard.py --server.headless true
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable service:
```bash
sudo systemctl enable iot-ids-dashboard
sudo systemctl start iot-ids-dashboard
```

---

## 🔄 Updates and Maintenance

### Regular Tasks:
1. **Weekly:**
   - Review logs
   - Check for failed authentications
   - Monitor system resources

2. **Monthly:**
   - Update dependencies
   - Review security logs
   - Check for security advisories

3. **Quarterly:**
   - Full security audit
   - Review and update policies
   - Test incident response

### Updating the System:
```bash
# Pull latest code
git pull

# Update dependencies
pip install -r requirements.txt --upgrade

# Run tests
python run_tests.py

# Restart service
sudo systemctl restart iot-ids-dashboard
```

---

## 📝 Configuration

### Environment Variables
Create `.env` file:
```env
DASHBOARD_PASSWORD=your_secure_password
DASHBOARD_PORT=8501
LOG_LEVEL=INFO
```

### Configuration File (Future)
Create `config.yaml`:
```yaml
paths:
  logs: "logs/"
  models: "models/"
  
security:
  auth_enabled: true
  session_timeout: 3600
  
ml:
  confidence_threshold: 0.8
```

---

## 🐛 Troubleshooting

### Dashboard Won't Start
- Check Python version (3.9+)
- Verify dependencies installed
- Check port availability
- Review error logs

### Tests Failing
- Verify pytest installed
- Check Python path
- Review test output

### Security Issues
- Review SECURITY_AUDIT.md
- Check authentication
- Verify firewall rules

---

## 📚 Additional Resources

- `README.md` - Complete project guide
- `SECURITY_GUIDE.md` - Security best practices
- `QUICK_START.md` - Quick setup
- `TESTING_GUIDE.md` - Testing documentation

---

**Last Updated:** January 2026  
**Status:** Ready for Deployment
