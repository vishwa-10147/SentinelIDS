param(
    [int]$IntervalSeconds = 8
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Start SOC Fusion Pipeline Loop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Set-Location -Path $PSScriptRoot

if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
}

Write-Host "[INFO] Running every $IntervalSeconds seconds. Press Ctrl+C to stop." -ForegroundColor Yellow

while ($true) {
    try {
        python src/run_flow_soc_pipeline.py
    } catch {
        Write-Host "[WARN] Pipeline run failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds $IntervalSeconds
}
