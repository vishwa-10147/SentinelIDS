# One-Click Demo Run Script for IoT IDS ML Dashboard
# This script activates the virtual environment and runs the Streamlit dashboard

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "IoT IDS ML Dashboard - Starting..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if venv exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "[OK] Virtual environment found" -ForegroundColor Green
    Write-Host "[INFO] Activating virtual environment..." -ForegroundColor Yellow
    
    # Activate virtual environment
    & "venv\Scripts\Activate.ps1"
    
    Write-Host "[OK] Virtual environment activated" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Virtual environment not found at venv\Scripts\Activate.ps1" -ForegroundColor Yellow
    Write-Host "[INFO] Attempting to run without venv activation..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[INFO] Starting Streamlit Dashboard..." -ForegroundColor Yellow
Write-Host "[INFO] Dashboard will open in your default browser" -ForegroundColor Yellow
Write-Host "[INFO] Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host ""

# Run Streamlit dashboard
streamlit run app/dashboard.py
