# Realtime IDS Runbook (Windows + Kali + Metasploitable)

Use this guide to run everything end-to-end on one PC:
- Windows host: IDS + Dashboard
- Kali VM: attacker
- Metasploitable VM: victim server

---

## 0) Prerequisites

- VMware VMs are on the same VM network (recommended: VMnet1)
- Npcap installed on Windows (WinPcap-compatible mode enabled)
- Open PowerShell as **Administrator** for capture

---

## 1) One-Time Setup (Windows)

```powershell
cd D:\MiniProject\iot-ids-ml-dashboard
.\venv\Scripts\Activate.ps1
.\setup_windows_vmnet_lab.ps1
```

Optional interface check:
```powershell
python src/capture_live_vmnet.py --list-ifaces
```

---

## 2) Start Terminal A (Packet Capture)

```powershell
cd D:\MiniProject\iot-ids-ml-dashboard
.\venv\Scripts\Activate.ps1
.\start_vmnet_capture.ps1 -InterfaceHint "VMware Network Adapter VMnet1" -UseModel -AlertThreshold 0.90
```

Expected behavior:
- Continuous packet lines in terminal
- `✅ NORMAL` for normal traffic
- `⚠️ SUSPICIOUS` for low-confidence anomalies
- `🚨 CONFIRMED ALERT` for high-confidence anomalies

To reduce alert noise, increase threshold (example):
```powershell
.\start_vmnet_capture.ps1 -InterfaceHint "VMware Network Adapter VMnet1" -UseModel -AlertThreshold 0.95
```

To focus only on victim traffic (recommended during demo):
```powershell
.\start_vmnet_capture.ps1 -InterfaceHint "VMware Network Adapter VMnet1" -UseModel -AlertThreshold 0.90 -Filter "ip and host <TARGET_IP>"
```

---

## 3) Start Terminal B (Flow SOC Fusion Loop)

```powershell
cd D:\MiniProject\iot-ids-ml-dashboard
.\venv\Scripts\Activate.ps1
.\start_soc_pipeline_loop.ps1 -IntervalSeconds 8
```

Expected behavior:
- Repeated pipeline runs every 8 seconds
- Updates `logs/live_flows_final.csv` and `logs/flow_incidents.csv`

---

## 4) Start Terminal C (Dashboard)

```powershell
cd D:\MiniProject\iot-ids-ml-dashboard
.\venv\Scripts\Activate.ps1
.\run_dashboard.ps1
```

Open:
- http://localhost:8501

---

## 5) Run Attacks from Kali (while Windows terminals are running)

Replace `<TARGET_IP>` with Metasploitable IP.

```bash
ping -c 20 <TARGET_IP>
nmap -sS -Pn <TARGET_IP>
telnet <TARGET_IP> 23
```

Optional additional tests:
```bash
nmap -p- -Pn <TARGET_IP>
sudo nmap -sU --top-ports 100 -Pn <TARGET_IP>
nikto -h http://<TARGET_IP>
```

---

## 6) What to Watch in Dashboard

### Tab 2: Live Packet IDS
- Use **Refresh Packet View Now** when needed
- Watch:
  - `Last Packet Age (sec)` (should stay low)
  - `Last Packet Time`
  - `packet_entered_at` column

### Tab 3: Flow IDS Monitoring
- Click **Run Flow SOC Pipeline Now** when needed
- Use **Refresh Flow View Now** to refresh table/cards
- Watch:
  - Severity counts (LOW/MEDIUM/HIGH/CRITICAL)
  - Top attacker/victim tables
  - Flow incidents and SOC tickets

---

## 7) Quick Log Verification (Windows)

```powershell
Get-Content .\live_data\live_capture.csv -Tail 20
Get-Content .\logs\live_scored_packets.csv -Tail 20
Get-Content .\logs\live_flows_final.csv -Tail 20
Get-Content .\logs\flow_incidents.csv -Tail 20
```

---

## 8) Stop Everything

- Press `Ctrl+C` in Terminal A, B, and C
- Stop attack commands in Kali

---

## Troubleshooting

### No live packets
- Ensure Terminal A is Administrator
- Re-check adapter:
  ```powershell
  python src/capture_live_vmnet.py --list-ifaces
  ```
- Retry with exact interface:
  ```powershell
  python src/capture_live_vmnet.py --iface "VMware Network Adapter VMnet1" --model models/live_ids_model.pkl --alert-threshold 0.90
  ```

### Packet data not updating in dashboard
- Confirm `live_data/live_capture.csv` is growing
- Use `Refresh Packet View Now` button or browser refresh

### Flow tab empty
- Ensure Terminal B is running
- Run once manually:
  ```powershell
  python src/run_flow_soc_pipeline.py
  ```
