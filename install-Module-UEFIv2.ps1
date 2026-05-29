#Requires -Version 5.1
<#
.SYNOPSIS
    Installs a PowerShell module offline from a local .zip file.

.DESCRIPTION
    Handles three zip layouts automatically:
      - Raw module files (.psm1/.psd1 at zip root)
      - Versioned subfolder  (ModuleName\1.0.0\*.psm1)
      - NuGet package        (.nupkg inside the zip)

    Writes logs to C:\Temp\Logs\.
    Must be run as Administrator when using -Scope AllUsers.

.PARAMETER ZipPath
    Full path to the module zip. Default: C:\Temp\UEFIv2\UEFIv2.zip

.PARAMETER ModuleName
    Name of the module to install. Default: UEFIv2

.PARAMETER Scope
    AllUsers (requires admin) or CurrentUser. Default: AllUsers

.EXAMPLE
    .\Install-OfflineModule.ps1
    .\Install-OfflineModule.ps1 -ZipPath "C:\Temp\OtherMod\OtherMod.zip" -ModuleName "OtherMod"
    .\Install-OfflineModule.ps1 -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [string]$ZipPath    = "C:\Temp\UEFIv2.zip",
    [string]$ModuleName = "UEFIv2",
    [ValidateSet("AllUsers","CurrentUser")]
    [string]$Scope      = "AllUsers"
)

# --- Logging ------------------------------------------------------------------
$LogDir  = "C:\Temp\Logs"
$LogFile = Join-Path $LogDir ("Install-OfflineModule_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".log")

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $entry = "[" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "] [" + $Level + "] " + $Message
    Add-Content -Path $LogFile -Value $entry
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red    }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        default { Write-Host $entry }
    }
}

# --- Admin check (required for AllUsers scope) --------------------------------
if ($Scope -eq "AllUsers") {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "AllUsers scope requires elevation. Re-launch PowerShell as Administrator." "ERROR"
        exit 1
    }
}

# --- Module base path ---------------------------------------------------------
if ($Scope -eq "AllUsers") {
    $ModuleBase = "C:\Program Files\WindowsPowerShell\Modules"
} else {
    $ModuleBase = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
}

# --- Temp extraction directory (unique per run) --------------------------------
$ExtractDir = "C:\Temp\_ModuleInstall_" + (Get-Date -Format 'yyyyMMddHHmmss')

# --- Helper: find .psd1 matching module name ----------------------------------
function Find-ModuleManifest {
    param([string]$SearchRoot)

    $manifests = Get-ChildItem -Path $SearchRoot -Recurse -Filter "*.psd1" -ErrorAction SilentlyContinue

    $match = $manifests | Where-Object { $_.BaseName -eq $ModuleName } | Select-Object -First 1
    if ($match) {
        return $match
    }

    if ($manifests.Count -gt 0) {
        Write-Log "No .psd1 named '$ModuleName' found -- using: $($manifests[0].FullName)" "WARN"
        return $manifests[0]
    }

    return $null
}

# ==============================================================================
try {
    Write-Log "---------------------------------------------------"
    Write-Log "Offline Module Installer -- $ModuleName"
    Write-Log "Source : $ZipPath"
    Write-Log "Scope  : $Scope -> $ModuleBase"
    Write-Log "---------------------------------------------------"

    # 1. Validate zip exists
    if (-not (Test-Path $ZipPath)) {
        Write-Log "Zip not found: $ZipPath" "ERROR"
        exit 1
    }

    # 2. Extract outer zip
    Write-Log "Extracting zip to: $ExtractDir"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
    Write-Log "Extraction complete"

    # 3. Unblock all extracted files immediately
    Write-Log "Unblocking extracted files (removing Zone.Identifier ADS)..."
    Get-ChildItem -Path $ExtractDir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Write-Log "Unblock complete"

    # 4. Detect layout: raw files, versioned folder, or nupkg
    $ModuleSourceDir = $null
    $psd1 = Find-ModuleManifest -SearchRoot $ExtractDir

    if (-not $psd1) {
        $nupkg = Get-ChildItem -Path $ExtractDir -Recurse -Filter "*.nupkg" | Select-Object -First 1

        if ($nupkg) {
            Write-Log "No .psd1 found -- detected .nupkg: $($nupkg.FullName)"
            Write-Log "Extracting .nupkg as zip..."

            $nupkgZip  = [System.IO.Path]::ChangeExtension($nupkg.FullName, ".zip")
            $nupkgDest = Join-Path $ExtractDir "nupkg_extracted"

            Copy-Item -Path $nupkg.FullName -Destination $nupkgZip -Force
            Expand-Archive -Path $nupkgZip -DestinationPath $nupkgDest -Force

            Get-ChildItem -Path $nupkgDest -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

            $psd1 = Find-ModuleManifest -SearchRoot $nupkgDest
        }
    }

    if (-not $psd1) {
        Write-Log "Cannot locate a .psd1 manifest in the zip contents. Verify the zip is a valid module package." "ERROR"
        exit 1
    }

    $ModuleSourceDir = $psd1.DirectoryName
    Write-Log "Module root detected : $ModuleSourceDir"
    Write-Log "Manifest             : $($psd1.FullName)"

    # 5. Read version from manifest
    $manifest = Import-PowerShellDataFile -Path $psd1.FullName
    $version  = $manifest.ModuleVersion

    if (-not $version) {
        Write-Log "ModuleVersion missing from manifest -- defaulting to 1.0.0" "WARN"
        $version = "1.0.0"
    }
    Write-Log "Module version: $version"

    # 6. Build versioned destination path
    $DestPath = Join-Path $ModuleBase ($ModuleName + "\" + $version)
    Write-Log "Install destination: $DestPath"

    # 7. Remove stale install if present
    if (Test-Path $DestPath) {
        Write-Log "Existing install found at $DestPath -- removing stale version..." "WARN"
        Remove-Item -Path $DestPath -Recurse -Force
        Write-Log "Stale version removed"
    }

    New-Item -Path $DestPath -ItemType Directory -Force | Out-Null

    # 8. Copy module files
    Copy-Item -Path "$ModuleSourceDir\*" -Destination $DestPath -Recurse -Force
    Write-Log "Module files copied to: $DestPath"

    # 9. Verify manifest landed correctly
    $installedPsd1 = Join-Path $DestPath ($ModuleName + ".psd1")
    if (-not (Test-Path $installedPsd1)) {
        $presentFiles = (Get-ChildItem $DestPath | Select-Object -ExpandProperty Name) -join ", "
        Write-Log "Expected manifest not found at: $installedPsd1" "WARN"
        Write-Log "Files present in destination: $presentFiles" "WARN"
    } else {
        Write-Log "Manifest confirmed at: $installedPsd1"
    }

    # 10. Execution policy check
    $effectivePolicy = Get-ExecutionPolicy -Scope LocalMachine
    Write-Log "ExecutionPolicy (LocalMachine): $effectivePolicy"

    if ($effectivePolicy -in @("Restricted", "AllSigned")) {
        Write-Log "Policy is restrictive -- setting LocalMachine to RemoteSigned" "WARN"
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Log "ExecutionPolicy updated to RemoteSigned"
    }

    # 11. Unload existing session module if already imported
    if (Get-Module -Name $ModuleName) {
        Write-Log "Module '$ModuleName' already loaded in session -- removing before re-import"
        Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue
    }

    # 12. Import and verify
    Write-Log "Importing module..."
    Import-Module $ModuleName -Force -ErrorAction Stop

    $loaded = Get-Module -Name $ModuleName
    if ($loaded) {
        Write-Log "---------------------------------------------------"
        Write-Log "SUCCESS"
        Write-Log "Module  : $($loaded.Name)"
        Write-Log "Version : $($loaded.Version)"
        Write-Log "Path    : $($loaded.ModuleBase)"
        if ($loaded.ExportedCommands.Count -gt 0) {
            $cmdList = ($loaded.ExportedCommands.Keys | Sort-Object) -join ", "
            Write-Log "Exports : $cmdList"
        }
        Write-Log "---------------------------------------------------"
    } else {
        Write-Log "Import completed but module not visible in session -- check output above" "WARN"
    }

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log "At   : $($_.InvocationInfo.PositionMessage)" "ERROR"
    Write-Log "Stack: $($_.ScriptStackTrace)" "ERROR"
    exit 1

} finally {
    if (Test-Path $ExtractDir) {
        Remove-Item -Path $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Temp directory cleaned up: $ExtractDir"
    }
    Write-Log "Log: $LogFile"
}
