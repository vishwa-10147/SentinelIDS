param(
    [string]$InterfaceHint = "VMware Network Adapter VMnet1",
    [switch]$UseModel,
    [string]$ModelPath = "models/live_ids_model.pkl",
    [string]$Filter = "ip",
    [double]$AlertThreshold = 0.90
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Start VMnet Packet Capture" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Set-Location -Path $PSScriptRoot

if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
}

if ($UseModel) {
    if (-not (Test-Path $ModelPath)) {
        Write-Host "[ERROR] Model not found: $ModelPath" -ForegroundColor Red
        Write-Host "Train first: python src/train_live_ids_model.py" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[INFO] Starting capture + packet ML scoring..." -ForegroundColor Yellow
    python src/capture_live_vmnet.py --iface-hint "$InterfaceHint" --filter "$Filter" --model "$ModelPath" --alert-threshold "$AlertThreshold"
} else {
    Write-Host "[INFO] Starting capture only..." -ForegroundColor Yellow
    python src/capture_live_vmnet.py --iface-hint "$InterfaceHint" --filter "$Filter"
}
