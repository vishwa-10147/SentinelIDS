# Setup script for Windows host IDS with VMware Kali + Metasploitable lab
# Run once before starting capture/testing

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows VMnet IDS Lab Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location -Path $PSScriptRoot

if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "[OK] Activating virtual environment..." -ForegroundColor Green
    & "venv\Scripts\Activate.ps1"
} else {
    Write-Host "[WARN] venv not found. Continuing with system Python." -ForegroundColor Yellow
}

Write-Host "[INFO] Installing project requirements..." -ForegroundColor Yellow
python -m pip install -r requirements.txt

Write-Host "[INFO] Ensuring Scapy is installed..." -ForegroundColor Yellow
python -m pip install scapy

Write-Host "[INFO] Ensuring runtime folders..." -ForegroundColor Yellow
foreach ($dir in @("live_data", "logs", "models")) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

Write-Host ""
Write-Host "[INFO] VMware interface list from Scapy:" -ForegroundColor Cyan
python src/capture_live_vmnet.py --list-ifaces

Write-Host ""
Write-Host "[NOTE] If no VMware interface appears:" -ForegroundColor Yellow
Write-Host " - Install/repair Npcap (WinPcap compatibility ON)" -ForegroundColor Yellow
Write-Host " - Run PowerShell as Administrator" -ForegroundColor Yellow
Write-Host " - Verify Kali + Metasploitable are on same VMnet (Host-only/Internal)" -ForegroundColor Yellow
Write-Host ""
Write-Host "✅ Setup completed." -ForegroundColor Green
