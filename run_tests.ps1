# Test Runner Script for Windows PowerShell
# Run all unit tests for IoT IDS ML Dashboard

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "IoT IDS ML Dashboard - Unit Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if pytest is installed
try {
    $pytestVersion = python -m pytest --version 2>&1
    Write-Host "[OK] pytest found" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] pytest not found. Installing..." -ForegroundColor Yellow
    pip install pytest
}

Write-Host ""
Write-Host "[INFO] Running unit tests..." -ForegroundColor Yellow
Write-Host ""

# Run pytest
python -m pytest tests/ -v --tb=short

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✅ All tests passed!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "❌ Some tests failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

Write-Host ""
Write-Host "[INFO] Test run completed" -ForegroundColor Cyan
