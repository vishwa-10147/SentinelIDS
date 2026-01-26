# Security Guide
## IoT IDS ML Dashboard - Security Best Practices

**Date:** January 2026  
**Author:** Security Team  
**Version:** 1.0

---

## 🔒 Security Overview

This guide provides security best practices for deploying and operating the IoT IDS ML Dashboard.

---

## ✅ Security Features Implemented

### 1. Input Validation ✅
- **Module:** `src/input_validation.py`
- **Features:**
  - IPv4 address validation
  - MAC address validation
  - Filename sanitization
  - Path sanitization
  - Port validation
  - Ticket status/severity/priority validation

**Usage:**
```python
from src.input_validation import is_valid_ipv4, sanitize_path

# Validate IP before use
if is_valid_ipv4(ip_address):
    # Safe to use
    pass

# Sanitize file paths
safe_path = sanitize_path(user_input, base_dir="logs/")
```

### 2. Secure Command Execution ✅
- **Fixed:** All `os.system()` calls replaced with `subprocess.run()`
- **Protection:** List-based arguments prevent shell injection
- **Added:** Timeout protection on all commands

**Before (Vulnerable):**
```python
os.system(f"nslookup {ip}")  # Command injection risk
```

**After (Secure):**
```python
subprocess.run(["nslookup", ip], timeout=4)  # Safe
```

### 3. Command Injection Protection ✅
- **Fixed:** `src/hostname_lookup.py`
- **Protection:** IP validation before command execution
- **Method:** List-based subprocess calls

---

## ⚠️ Security Considerations

### 1. Authentication (REQUIRED for Production)

**Current Status:** ❌ No authentication implemented

**Risk:** Anyone with network access can:
- View sensitive network data
- Modify SOC tickets
- Access device inventory
- Run system commands

**Solution Options:**

#### Option A: Simple Password Protection
```python
# Add to dashboard.py at the start
import os

if not st.session_state.get("authenticated"):
    password = st.text_input("Enter Dashboard Password", type="password")
    if password == os.getenv("DASHBOARD_PASSWORD", "changeme"):
        st.session_state.authenticated = True
        st.rerun()
    else:
        st.error("Invalid password")
        st.stop()
```

#### Option B: Streamlit Authenticator
```bash
pip install streamlit-authenticator
```

```python
import streamlit_authenticator as stauth

# Configure users
users = {
    "admin": {
        "name": "Admin User",
        "password": stauth.Hasher(["admin123"]).generate()[0]
    }
}

authenticator = stauth.Authenticate(
    users, "dashboard_cookie", "dashboard_key", 30
)

name, authentication_status, username = authenticator.login("Login", "main")

if not authentication_status:
    st.stop()
```

**Implementation Steps:**
1. Choose authentication method
2. Add authentication check at start of `dashboard.py`
3. Set password via environment variable
4. Implement session timeout
5. Add logout functionality

---

### 2. Network Security

**Recommendations:**

1. **Firewall Rules:**
   ```bash
   # Linux firewall example
   sudo ufw allow 8501/tcp from 192.168.1.0/24
   sudo ufw deny 8501/tcp
   ```

2. **HTTPS (if exposing externally):**
   ```bash
   # Use reverse proxy (nginx) with SSL
   # Or use Streamlit's built-in SSL support
   streamlit run app/dashboard.py --server.sslCertFile cert.pem --server.sslKeyFile key.pem
   ```

3. **Access Control:**
   - Restrict dashboard to internal network only
   - Use VPN for remote access
   - Implement IP whitelisting

---

### 3. Data Protection

**Log Files:**
- Logs may contain sensitive network information
- Implement log encryption for production
- Restrict log file permissions

**Example:**
```python
import os

# Set restrictive permissions
os.chmod("logs/soc_tickets.csv", 0o600)  # Owner read/write only
```

**Data Encryption:**
- Consider encrypting sensitive CSV files
- Use environment variables for credentials
- Never commit passwords to git

---

### 4. Rate Limiting

**Current Status:** ❌ No rate limiting

**Risk:** DoS attacks can overwhelm the system

**Implementation:**
```python
from functools import wraps
import time

def rate_limit(max_calls=10, period=60):
    calls = {}
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            key = 'global'  # Or use IP address
            if key not in calls:
                calls[key] = []
            calls[key] = [t for t in calls[key] if now - t < period]
            if len(calls[key]) >= max_calls:
                st.error("Rate limit exceeded. Please wait.")
                st.stop()
            calls[key].append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

---

### 5. Error Handling

**Best Practices:**
- Don't expose internal paths in error messages
- Log errors securely
- Use generic error messages for users

**Example:**
```python
try:
    df = pd.read_csv(path)
except Exception as e:
    logger.error(f"Failed to read {path}: {e}")  # Log internally
    st.error("Failed to load data. Please try again.")  # Generic user message
```

---

## 🔐 Deployment Security Checklist

### Pre-Deployment:
- [ ] Add authentication
- [ ] Set secure passwords (use environment variables)
- [ ] Configure firewall rules
- [ ] Enable HTTPS (if external access)
- [ ] Review and restrict file permissions
- [ ] Set up log rotation
- [ ] Configure rate limiting
- [ ] Review security audit (`SECURITY_AUDIT.md`)

### Post-Deployment:
- [ ] Monitor logs for suspicious activity
- [ ] Regular security updates
- [ ] Backup sensitive data
- [ ] Review access logs
- [ ] Update dependencies regularly

---

## 🛡️ Security Monitoring

### What to Monitor:

1. **Failed Authentication Attempts:**
   - Multiple failed login attempts
   - Unusual access patterns

2. **System Resources:**
   - High CPU/memory usage
   - Disk space
   - Network bandwidth

3. **Application Logs:**
   - Error rates
   - Unusual patterns
   - Security events

### Log Locations:
- `logs/` - Application logs
- System logs (var/log/)
- Streamlit logs

---

## 🚨 Incident Response

### If Security Breach Detected:

1. **Immediate Actions:**
   - Disable dashboard access
   - Review access logs
   - Check for unauthorized changes
   - Notify security team

2. **Investigation:**
   - Review all logs
   - Check for data exfiltration
   - Identify attack vector
   - Document findings

3. **Recovery:**
   - Fix vulnerabilities
   - Restore from backup if needed
   - Update security measures
   - Re-enable with enhanced security

---

## 📚 Security Resources

### Documentation:
- `SECURITY_AUDIT.md` - Security audit report
- `ERRORS_AND_FIXES_SUMMARY.md` - Security fixes applied
- `IMPROVEMENTS_AND_RECOMMENDATIONS.md` - Future improvements

### External Resources:
- OWASP Top 10
- CWE Top 25
- Python Security Best Practices

---

## 🔄 Regular Security Tasks

### Weekly:
- Review access logs
- Check for failed authentication attempts
- Monitor system resources

### Monthly:
- Update dependencies
- Review security logs
- Check for security advisories

### Quarterly:
- Full security audit
- Review and update security policies
- Test incident response procedures

---

## 📝 Security Notes

- **Never commit credentials** to version control
- **Use environment variables** for sensitive data
- **Keep dependencies updated** to patch vulnerabilities
- **Regular backups** of critical data
- **Monitor logs** for suspicious activity

---

**Last Updated:** January 2026  
**Next Review:** Quarterly
