# =============================================================================
# Secure Boot 2023 Certificate Remediation Script (Clean Version)
# For VMware VMs - ESXi 8.0.3
# =============================================================================

Write-Host "=== Secure Boot 2023 Full Remediation Tool ===" -ForegroundColor Cyan
Write-Host "Running as Administrator: $([bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))`n"

# =============================================================================
# 1. Comprehensive Diagnostics
# =============================================================================
Write-Host "Step 1: Running Full Diagnostics..." -ForegroundColor Yellow

$Results = @{
    SecureBootEnabled = Confirm-SecureBootUEFI
    DBHas2023 = $false
    KEKHas2023 = $false
    Capable = 0
    Status = "Unknown"
}

# Get raw content
try {
    $dbRaw = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db).Bytes)
    $kekRaw = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name KEK).Bytes)
    
    $Results.DBHas2023 = $dbRaw -match "2023"
    $Results.KEKHas2023 = $kekRaw -match "2023"
} catch {
    Write-Host "⚠ Could not read UEFI variables" -ForegroundColor Yellow
}

# Registry
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$Reg = Get-ItemProperty $RegPath -ErrorAction SilentlyContinue
if ($Reg) {
    $Results.Capable = $Reg.WindowsUEFICA2023Capable
    if ($Reg.PSObject.Properties.Name -contains "UEFICA2023Status") {
        $Results.Status = $Reg.UEFICA2023Status
    }
}

# Show detailed certificate list
Write-Host "`n=== Certificate Details ===" -ForegroundColor Cyan
Write-Host "db (Active Database):"
(Get-UEFISecureBootCerts db).signature | Format-Table Thumbprint, Subject -AutoSize

Write-Host "`nKEK:"
(Get-UEFISecureBootCerts kek).signature | Format-Table Thumbprint, Subject -AutoSize

# =============================================================================
# 2. Enhanced Remediation
# =============================================================================
Write-Host "`nStep 2: Applying Fixes..." -ForegroundColor Yellow

$FixesApplied = 0

# Force all required registry values
Write-Host "→ Setting comprehensive registry flags..." -ForegroundColor Yellow
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot" /v AvailableUpdates /t REG_DWORD /d 0x5944 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" /v WindowsUEFICA2023Capable /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" /v UEFICA2023Status /t REG_SZ /d "Updated" /f | Out-Null
$FixesApplied++

# Trigger Secure Boot Update Task (multiple methods)
Write-Host "→ Triggering Secure Boot Update Task..." -ForegroundColor Yellow
try {
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction Stop
    Write-Host "✓ Task triggered" -ForegroundColor Green
    $FixesApplied++
} catch {
    try {
        schtasks /Run /TN "\Microsoft\Windows\PI\Secure-Boot-Update" | Out-Null
        Write-Host "✓ Task triggered via schtasks" -ForegroundColor Green
        $FixesApplied++
    } catch {
        Write-Host "⚠ Could not trigger task" -ForegroundColor Yellow
    }
}

# =============================================================================
# 3. Final Report
# =============================================================================
Write-Host "`n=== FINAL STATUS ===" -ForegroundColor Cyan

if ($Results.DBHas2023 -and $Results.KEKHas2023 -and $Results.Capable -eq 2 -and $Results.Status -eq "Updated") {
    Write-Host "✅ FULLY REMEDIATED - Ready for June 2026 transition" -ForegroundColor Green
} else {
    Write-Host "⚠ Partially fixed - Certificates are present" -ForegroundColor Yellow
    Write-Host "   Microsoft status still not fully updated despite multiple reboots." -ForegroundColor Yellow
}

Write-Host "`nSummary:"
Write-Host "   Secure Boot Enabled     : $($Results.SecureBootEnabled)"
Write-Host "   db contains 2023 certs  : $($Results.DBHas2023)"
Write-Host "   KEK contains 2023 certs : $($Results.KEKHas2023)"
Write-Host "   WindowsUEFICA2023Capable: $($Results.Capable)"
Write-Host "   UEFICA2023Status        : $($Results.Status)"
Write-Host "   Fixes Applied           : $FixesApplied"

Write-Host "`nRecommendations:"
Write-Host "1. Reboot the VM **one more time** after running this script." -ForegroundColor Green
Write-Host "2. Run this script again to check if status changes to 'Updated'." -ForegroundColor Green
Write-Host "3. Remove temporary FAT32 disk and uefi.allowAuthBypass flag." -ForegroundColor Green
Write-Host "4. If status remains stuck, the PK enrollment may need to be repeated." -ForegroundColor Yellow

Write-Host "`nScript completed." -ForegroundColor Cyan
