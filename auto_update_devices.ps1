# Auto Update Device Inventory Script
# Updates device inventory every 60 seconds
# - Removes IPv6 addresses (only keeps IPv4)
# - Skips invalid DNS lookups (handled gracefully by Python module)
# - Saves clean CSV with valid devices only

while ($true) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Updating Device Inventory..." -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Check for ARP table file in live_data directory
    $arpSourcePath = "live_data\arp_table_kali.csv"
    $arpDestPath = "logs\arp_table_kali.csv"
    
    if (Test-Path $arpSourcePath) {
        # Ensure logs directory exists
        if (-not (Test-Path "logs")) {
            New-Item -ItemType Directory -Path "logs" | Out-Null
        }
        
        # Copy ARP table file
        Copy-Item $arpSourcePath $arpDestPath -Force
        Write-Host "[OK] Copied ARP table to logs/" -ForegroundColor Green
        
        # Run device discovery (Python module handles IPv6 filtering and DNS lookup)
        # The Python module will:
        # - Filter out IPv6 addresses (only keep IPv4)
        # - Skip invalid DNS lookups (returns "Unknown" for failures)
        # - Save clean device_inventory.csv
        python -m src.device_discovery
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Device inventory updated successfully" -ForegroundColor Green
            Write-Host "[INFO] Only valid IPv4 devices are saved" -ForegroundColor Yellow
        } else {
            Write-Host "[ERROR] Device discovery failed" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[WARNING] arp_table_kali.csv not found at: $arpSourcePath" -ForegroundColor Yellow
        Write-Host "[INFO] Waiting for ARP table file..." -ForegroundColor Yellow
    }

    Write-Host "[INFO] Next update in 60 seconds..." -ForegroundColor Cyan
    Write-Host ""
    Start-Sleep -Seconds 60
}
