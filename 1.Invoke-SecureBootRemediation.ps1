#Requires -Version 5.1
<#
.SYNOPSIS
    Bulk Secure Boot 2023 certificate remediation for Windows Server VMs on vSphere 8.
    Eliminates manual FAT32 disk attachment by using ESXi SetupMode VMX trick for PK enrollment.

.DESCRIPTION
    MODES
      Default  : Full remediation per VM (NVRAM rename, cert update, registry fix, PK enrollment).
      -PreflightOnly  : Run preflight checks only, no changes made.
      -CleanupSnapshots : Remove Pre-SecureBoot-Fix snapshots from target VMs.
      -CleanupNvram   : Remove .nvram_old files from target VM datastores.
      -Rollback       : Restore original NVRAM and revert snapshot.

    PROCESS PER VM (default mode)
      [0] Preflight  - ESXi 8.0.2+, HW v13+, Tools OK, not a DC, BitLocker check
      [1] Snapshot   - taken before any changes (unless -NoSnapshot)
      [2] Power off
      [3] Rename NVRAM  - vmname.nvram -> vmname.nvram_old on datastore
      [4] Power on   - ESXi regenerates NVRAM with 2023 KEK/DB certs
      [5] Registry fix - set AvailableUpdates = 0x5944, trigger Secure-Boot-Update task
      [6] Reboot     - task runs again on boot
      [7] Verify     - check KEK 2023, DB 2023, UEFICA2023Status = Updated
      [8] PK check   - Valid_WindowsOEM/Valid_Microsoft = OK, Valid_Other/NULL = enroll
      [9] PK enroll  - set uefi.secureBootMode.overrideOnce=SetupMode, copy .der, run cmdlet

    REQUIREMENTS
      - Run from jump box / admin workstation (not on the VMs)
      - VMware PowerCLI installed locally
      - ESXi 8.0.2+ on all target VM hosts
      - VMware Tools running on all target VMs
      - VM hardware version 13+
      - Admin credential with local admin rights on target VMs
      - WindowsOEMDevicesPK.der in same folder as script (for PK enrollment)
        Download: https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der

.PARAMETER VCenter
    vCenter FQDN or IP. Default: aussdc1vcn001.corp.pri

.PARAMETER VMName
    One or more VM display names. Wildcards supported. Omit to target all eligible VMs.

.PARAMETER VMListCsv
    Path to a CSV with a VMName column. Combined with -VMName if both provided.

.PARAMETER GuestCredential
    PSCredential for guest OS (local/domain admin with local admin rights on VMs).
    Required for default mode. Not required for -CleanupSnapshots, -CleanupNvram, -Rollback.

.PARAMETER PKDerPath
    Path to WindowsOEMDevicesPK.der. Required for PK enrollment (step 9).
    If not provided, script stops after step 7 (cert update only, no PK fix).

.PARAMETER NoSnapshot
    Skip snapshot creation. Cannot combine with -RetainSnapshots.

.PARAMETER RetainSnapshots
    Keep snapshots after successful remediation. Remove later with -CleanupSnapshots.

.PARAMETER PreflightOnly
    Run preflight checks only. No changes made. Does not require -GuestCredential.

.PARAMETER CleanupSnapshots
    Remove all Pre-SecureBoot-Fix snapshots on target VMs. No -GuestCredential needed.

.PARAMETER CleanupNvram
    Remove .nvram_old files from datastores of target VMs. No -GuestCredential needed.
    Always run -CleanupSnapshots BEFORE -CleanupNvram (snapshot is the rollback path).

.PARAMETER Rollback
    Restore .nvram_old -> .nvram and revert Pre-SecureBoot-Fix snapshot. Power VM on.

.PARAMETER WaitSeconds
    Seconds to wait after reboot before polling VMware Tools. Default: 90.

.EXAMPLE
    # Preflight check all eligible VMs first
    .\Invoke-SecureBootRemediation.ps1 -PreflightOnly

    # Single VM test run
    $cred = Get-Credential
    .\Invoke-SecureBootRemediation.ps1 -VMName "TESTVM01" -GuestCredential $cred -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

    # Bulk run via CSV
    .\Invoke-SecureBootRemediation.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

    # Cleanup after validation
    .\Invoke-SecureBootRemediation.ps1 -VMListCsv ".\SecureBoot_Remediation_20260527_120000.csv" -CleanupSnapshots
    .\Invoke-SecureBootRemediation.ps1 -VMListCsv ".\SecureBoot_Remediation_20260527_120000.csv" -CleanupNvram

    # Rollback
    .\Invoke-SecureBootRemediation.ps1 -VMName "TESTVM01" -Rollback
#>

[CmdletBinding(DefaultParameterSetName = "Remediate")]
param(
    [string]$VCenter = "aussdc1vcn001.corp.pri",

    [Parameter(ParameterSetName = "Remediate")]
    [Parameter(ParameterSetName = "Preflight")]
    [Parameter(ParameterSetName = "Cleanup")]
    [Parameter(ParameterSetName = "Rollback")]
    [string[]]$VMName,

    [Parameter(ParameterSetName = "Remediate")]
    [Parameter(ParameterSetName = "Preflight")]
    [Parameter(ParameterSetName = "Cleanup")]
    [Parameter(ParameterSetName = "Rollback")]
    [string]$VMListCsv,

    [Parameter(ParameterSetName = "Remediate", Mandatory = $true)]
    [System.Management.Automation.PSCredential]$GuestCredential,

    [Parameter(ParameterSetName = "Remediate")]
    [string]$PKDerPath,

    [Parameter(ParameterSetName = "Remediate")]
    [switch]$NoSnapshot,

    [Parameter(ParameterSetName = "Remediate")]
    [switch]$RetainSnapshots,

    [Parameter(ParameterSetName = "Preflight")]
    [switch]$PreflightOnly,

    [Parameter(ParameterSetName = "Cleanup")]
    [switch]$CleanupSnapshots,

    [Parameter(ParameterSetName = "Cleanup")]
    [switch]$CleanupNvram,

    [Parameter(ParameterSetName = "Remediate")]
    [switch]$Rollback,

    # Skip the per-VM confirmation prompt. Useful for bulk CSV runs.
    # Without -Force the script shows a plan summary and asks Y/N before touching each VM.
    [Parameter(ParameterSetName = "Remediate")]
    [switch]$Force,

    [int]$WaitSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ==============================================================================
# LOGGING
# ==============================================================================
$LogDir  = "C:\Temp\Logs"
$RunTs   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $LogDir ("SecureBoot_Remediation_" + $RunTs + ".log")

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","OK","HEAD")]
        [string]$Level = "INFO"
    )
    $entry = "[" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "] [" + $Level.PadRight(5) + "] " + $Message
    Add-Content -Path $LogFile -Value $entry
    switch ($Level) {
        "OK"    { Write-Host $entry -ForegroundColor Green  }
        "ERROR" { Write-Host $entry -ForegroundColor Red    }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "HEAD"  { Write-Host $entry -ForegroundColor Cyan   }
        default { Write-Host $entry }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Log ("-" * 60) "HEAD"
    Write-Log "  $Title" "HEAD"
    Write-Log ("-" * 60) "HEAD"
}

# ==============================================================================
# ADMIN CHECK (local script must run as admin for PowerCLI)
# ==============================================================================
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script must be run as Administrator (on the machine running PowerCLI)." "ERROR"
    exit 1
}

# ==============================================================================
# VALIDATE PARAMS
# ==============================================================================
if ($NoSnapshot -and $RetainSnapshots) {
    Write-Log "-NoSnapshot and -RetainSnapshots cannot be combined." "ERROR"
    exit 1
}

if ($PKDerPath -and -not (Test-Path $PKDerPath)) {
    Write-Log "PKDerPath not found: $PKDerPath" "ERROR"
    exit 1
}

# ==============================================================================
# OUTPUT CSV PATH
# ==============================================================================
$CsvMode = "Remediation"
if ($PreflightOnly)     { $CsvMode = "Preflight" }
if ($CleanupSnapshots)  { $CsvMode = "SnapshotCleanup" }
if ($CleanupNvram)      { $CsvMode = "NvramCleanup" }
if ($Rollback)          { $CsvMode = "Rollback" }

$OutputCsv = Join-Path (Split-Path $PSCommandPath -Parent) ("SecureBoot_" + $CsvMode + "_" + $RunTs + ".csv")

# ==============================================================================
# POWERCLI SETUP
# ==============================================================================
function Initialize-PowerCLI {
    if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI) -and
        -not (Get-Module -ListAvailable -Name VMware.VimAutomation.Core)) {
        Write-Log "VMware PowerCLI is not installed. Install it with: Install-Module VMware.PowerCLI -Scope AllUsers" "ERROR"
        exit 1
    }
    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -ParticipateInCEIP $false -Scope Session -Confirm:$false | Out-Null
    } catch { }
}

# ==============================================================================
# VCENTER CONNECTION
# ==============================================================================
function Connect-ToVCenter {
    $existing = $global:DefaultVIServers | Where-Object { $_.Name -eq $VCenter -and $_.IsConnected }
    if ($existing) {
        Write-Log "Using existing vCenter session: $VCenter" "OK"
        return
    }
    Write-Log "Connecting to vCenter: $VCenter ..."
    Connect-VIServer -Server $VCenter -ErrorAction Stop | Out-Null
    Write-Log "Connected to $VCenter" "OK"
}

# ==============================================================================
# VM TARGETING
# ==============================================================================
function Get-TargetVMs {
    $names = @()

    if ($VMListCsv -and (Test-Path $VMListCsv)) {
        $csv = Import-Csv -Path $VMListCsv
        if ($csv | Get-Member -Name VMName -ErrorAction SilentlyContinue) {
            $names += $csv.VMName | Where-Object { $_ -ne "" }
        } else {
            Write-Log "CSV at '$VMListCsv' does not have a VMName column." "WARN"
        }
    }

    if ($VMName) { $names += $VMName }

    $names = @($names | Select-Object -Unique)

    if ($names.Count -gt 0) {
        $vms = @()
        foreach ($n in $names) {
            $found = @(Get-VM -Name $n -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) { $vms += $found }
            else { Write-Log "VM not found in vCenter: $n" "WARN" }
        }
        return @($vms)
    }

    # No names specified -- enumerate all eligible VMs (EFI + Secure Boot enabled + Windows)
    Write-Log "No VM names specified -- enumerating all eligible VMs..."
    $allVMs = @(Get-VM | Where-Object { $_.PowerState -ne "Suspended" })
    $eligible = @()
    foreach ($v in $allVMs) {
        $ext = $v.ExtensionData
        $firmware = $ext.Config.Firmware
        $sbEnabled = $ext.Config.BootOptions.EfiSecureBootEnabled
        $guestId   = $ext.Config.GuestId
        if ($firmware -eq "efi" -and $sbEnabled -eq $true -and $guestId -match "windows") {
            $eligible += $v
        }
    }
    Write-Log "Found $($eligible.Count) eligible VMs (EFI + Secure Boot + Windows)"
    return @($eligible)
}

# ==============================================================================
# HELPERS: WAIT FOR TOOLS
# ==============================================================================
function Wait-VMTools {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [int]$TimeoutSeconds = 150
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Log "  Waiting for VMware Tools on '$($VM.Name)' (timeout: ${TimeoutSeconds}s)..."
    do {
        Start-Sleep -Seconds 20
        $refreshed = Get-VM -Name $VM.Name
        $status = $refreshed.Guest.ExtensionData.ToolsStatus
        Write-Log "  Tools status: $status"
        if ($status -eq "toolsOk" -or $status -eq "toolsOld") { return $true }
    } while ((Get-Date) -lt $deadline)
    Write-Log "  Timed out waiting for VMware Tools on '$($VM.Name)'" "WARN"
    return $false
}

# ==============================================================================
# HELPERS: WAIT FOR GUEST OPERATIONS AGENT
# ==============================================================================
# Tools status = toolsOk/toolsOld means the Tools SERVICE is running, but the
# guest operations agent (VMware VGAUTH) can still be initialising. Invoke-VMScript
# will throw "guest operations agent could not be contacted" if called too early.
# This function probes with a trivial command until the agent actually responds.
function Wait-GuestOpsAgent {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$TimeoutSeconds    = 200,
        [int]$RetryIntervalSecs = 20
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Log "  Waiting for guest operations agent on '$($VM.Name)' (timeout: ${TimeoutSeconds}s)..."

    # IMPORTANT: probe with ScriptType PowerShell, NOT Bat.
    # VMware Tools has separate execution engines for Bat vs PowerShell.
    # All real remediation scripts use PowerShell mode -- probing with Bat
    # can return "ready" while the PowerShell engine is still initialising,
    # causing the very next PowerShell Invoke-VMScript call to fail with
    # "guest operations agent could not be contacted".
    do {
        try {
            $probe = Invoke-VMScript -VM $VM `
                        -ScriptText 'Write-Output "agent_ready"' `
                        -GuestCredential $Credential `
                        -ScriptType PowerShell `
                        -ErrorAction Stop
            if ($probe.ScriptOutput -match 'agent_ready') {
                Write-Log "  Guest operations agent (PowerShell engine) is ready" "OK"
                return $true
            }
        } catch {
            Write-Log "  Agent not yet contactable -- retrying in ${RetryIntervalSecs}s ($($_.Exception.Message -replace '\r?\n',' '))"
        }
        Start-Sleep -Seconds $RetryIntervalSecs
    } while ((Get-Date) -lt $deadline)

    Write-Log "  Timed out waiting for guest operations agent" "WARN"
    return $false
}

# ==============================================================================
# HELPERS: GRACEFUL SHUTDOWN WITH HARD POWER-OFF FALLBACK
# ==============================================================================
# Sends an OS-level shutdown via VMware Tools (Shutdown-VMGuest), waits up to
# $GracefulTimeoutSeconds, then falls back to hard Stop-VM if the guest does not
# power off cleanly. This is safer than Stop-VM alone, which is always a hard
# power-off regardless of OS state.
function Invoke-GracefulShutdown {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [int]$GracefulTimeoutSeconds = 200,
        [int]$HardTimeoutSeconds     = 150,
        [int]$PollIntervalSeconds    = 20
    )

    # Refresh VM state
    $VM = Get-VM -Name $VM.Name
    if ($VM.PowerState -eq "PoweredOff") {
        Write-Log "  VM is already powered off -- skipping shutdown" "OK"
        return "AlreadyOff"
    }

    # Attempt graceful OS shutdown via VMware Tools
    Write-Log "  Sending graceful shutdown request (OS-level via VMware Tools)..."
    try {
        Shutdown-VMGuest -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Log "  Graceful shutdown signal sent -- waiting up to ${GracefulTimeoutSeconds}s..."
    } catch {
        Write-Log "  Graceful shutdown request failed: $($_.Exception.Message)" "WARN"
        Write-Log "  VMware Tools may not be responding -- falling back to hard power-off" "WARN"
        Stop-VM -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null
        $deadline = (Get-Date).AddSeconds($HardTimeoutSeconds)
        do { Start-Sleep -Seconds 10; $VM = Get-VM -Name $VM.Name }
        while ($VM.PowerState -ne "PoweredOff" -and (Get-Date) -lt $deadline)
        if ($VM.PowerState -ne "PoweredOff") {
            throw "VM '$($VM.Name)' did not power off within ${HardTimeoutSeconds}s of hard power-off command"
        }
        Write-Log "  VM powered off (hard -- Tools unavailable)" "OK"
        return "ForcedOff"
    }

    # Poll until PoweredOff or graceful timeout
    $gracefulDeadline = (Get-Date).AddSeconds($GracefulTimeoutSeconds)
    do {
        Start-Sleep -Seconds $PollIntervalSeconds
        $VM = Get-VM -Name $VM.Name
        Write-Log "  Power state: $($VM.PowerState) -- waiting for PoweredOff..."
    } while ($VM.PowerState -ne "PoweredOff" -and (Get-Date) -lt $gracefulDeadline)

    if ($VM.PowerState -eq "PoweredOff") {
        Write-Log "  VM shut down gracefully" "OK"
        return "GracefulOff"
    }

    # Graceful shutdown timed out -- escalate to hard power-off
    Write-Log "  Graceful shutdown did not complete within ${GracefulTimeoutSeconds}s -- hard power-off" "WARN"
    Stop-VM -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null

    $hardDeadline = (Get-Date).AddSeconds($HardTimeoutSeconds)
    do { Start-Sleep -Seconds 5; $VM = Get-VM -Name $VM.Name }
    while ($VM.PowerState -ne "PoweredOff" -and (Get-Date) -lt $hardDeadline)

    if ($VM.PowerState -ne "PoweredOff") {
        throw "VM '$($VM.Name)' did not power off after both graceful (${GracefulTimeoutSeconds}s) and hard (${HardTimeoutSeconds}s) attempts"
    }

    Write-Log "  VM powered off (hard -- graceful timed out)" "OK"
    return "ForcedOff"
}

# ==============================================================================
# HELPERS: GRACEFUL REBOOT WITH HARD REBOOT FALLBACK
# ==============================================================================
# IMPORTANT: For a restart (not shutdown), VM PowerState stays PoweredOn throughout.
# Checking PowerState will NEVER detect a reboot. The correct signal is VMware Tools
# going offline (toolsNotRunning) while PoweredOn -- that means the OS is restarting.
function Invoke-GracefulRestart {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [int]$GracefulTimeoutSeconds = 150,
        [int]$PollIntervalSeconds    = 20
    )

    $VM = Get-VM -Name $VM.Name
    Write-Log "  Sending graceful restart request (OS-level via VMware Tools)..."

    $gracefulSent = $false
    try {
        Restart-VMGuest -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null
        $gracefulSent = $true
        Write-Log "  Graceful restart signal sent -- monitoring Tools status for reboot detection..."
    } catch {
        Write-Log "  Graceful restart request failed: $($_.Exception.Message)" "WARN"
        Write-Log "  Falling back to hard stop + start..." "WARN"
    }

    if ($gracefulSent) {
        # Detect reboot via Tools status, NOT PowerState.
        # PowerState stays PoweredOn for the entire reboot cycle.
        # Tools going toolsNotRunning = OS is in shutdown/restart phase.
        $deadline      = (Get-Date).AddSeconds($GracefulTimeoutSeconds)
        $toolsWentDown = $false
        do {
            Start-Sleep -Seconds $PollIntervalSeconds
            $refreshed   = Get-VM -Name $VM.Name
            $toolsStatus = $refreshed.Guest.ExtensionData.ToolsStatus
            Write-Log "  Tools status: $toolsStatus"
            if ($toolsStatus -eq "toolsNotRunning") {
                $toolsWentDown = $true
                Write-Log "  Reboot detected (Tools went offline) -- reboot is in progress" "OK"
                break
            }
        } while ((Get-Date) -lt $deadline)

        if ($toolsWentDown) {
            return  # Caller uses Wait-VMTools to wait for the VM to come back
        }

        # Tools never went offline in the window.
        # Two possible explanations:
        #   a) VM rebooted so fast that Tools came back before our first poll (short OS restart)
        #   b) Restart signal was not acted on (rare -- guest OS ignored it)
        # Since the restart signal was successfully sent, assume (a) and proceed.
        # Do NOT fall through to hard reboot -- if (a) is true, that would be a double-reboot
        # and could cause data loss if the OS is still mid-restart.
        Write-Log "  Tools did not go offline within ${GracefulTimeoutSeconds}s" "WARN"
        Write-Log "  Restart signal was sent -- assuming fast reboot or already completed. Proceeding to Wait-VMTools." "WARN"
        return
    }

    # Graceful restart was not sent -- fall back to hard reboot
    Write-Log "  Performing hard stop + start..."
    try { Stop-VM -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null } catch { }

    $offDeadline = (Get-Date).AddSeconds(90)
    do { Start-Sleep -Seconds 5; $VM = Get-VM -Name $VM.Name }
    while ($VM.PowerState -ne "PoweredOff" -and (Get-Date) -lt $offDeadline)

    Start-VM -VM $VM -Confirm:$false | Out-Null
    Write-Log "  VM hard-rebooted (graceful restart unavailable)" "OK"
}

# ==============================================================================
# HELPERS: CREDENTIAL VALIDATION WITH RE-PROMPT
# ==============================================================================
# Returns the validated (possibly updated) credential, or $null on failure.
# If auth fails, prompts the user to re-enter up to $MaxAttempts times before
# giving up and aborting the VM -- prevents burning through an account lockout
# threshold and avoids the script looping forever on wrong creds.
function Test-GuestCredential {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$MaxAttempts = 3
    )

    $currentCred = $Credential

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $probe = Invoke-VMScript -VM $VM -ScriptText 'Write-Output "cred_ok"' `
                        -GuestCredential $currentCred -ScriptType PowerShell -ErrorAction Stop
            if ($probe.ScriptOutput -match 'cred_ok') {
                if ($attempt -gt 1) {
                    Write-Log "  Credentials accepted on attempt $attempt" "OK"
                } else {
                    Write-Log "  Credentials validated" "OK"
                }
                return $currentCred
            }
        } catch {
            $errMsg = $_.Exception.Message

            if ($errMsg -match 'Failed to authenticate|authentication|credentials') {
                Write-Log "  Auth failed (attempt $attempt of $MaxAttempts): wrong username or password" "WARN"

                if ($attempt -lt $MaxAttempts) {
                    Write-Host ""
                    Write-Host "  [!] Authentication failed for VM '$($VM.Name)'" -ForegroundColor Yellow
                    Write-Host "      Attempt $attempt of $MaxAttempts. Please re-enter the guest OS credentials." -ForegroundColor Yellow
                    Write-Host "      Account: $($currentCred.UserName)" -ForegroundColor Yellow
                    Write-Host ""
                    $newCred = Get-Credential -Message "Guest credentials for $($VM.Name) (attempt $attempt of $($MaxAttempts - 1) remaining)"
                    if ($newCred) {
                        $currentCred = $newCred
                    } else {
                        Write-Log "  Credential prompt cancelled -- aborting VM" "ERROR"
                        return $null
                    }
                } else {
                    Write-Log "  Auth failed after $MaxAttempts attempts -- aborting VM '$($VM.Name)' to prevent account lockout" "ERROR"
                    Write-Host ""
                    Write-Host "  [X] Authentication failed $MaxAttempts times for '$($VM.Name)'." -ForegroundColor Red
                    Write-Host "      VM will be skipped. Re-run with correct credentials." -ForegroundColor Red
                    Write-Host ""
                    return $null
                }
            } else {
                # Non-auth error (timing, agent starting up, etc.) -- not a cred problem
                Write-Log "  Credential probe non-auth error (may be timing): $($errMsg -replace '\r?\n',' ')" "WARN"
                return $currentCred
            }
        }
    }
    return $null
}

# ==============================================================================
# HELPERS: REMEDIATION PLAN DISPLAY + CONFIRMATION
# ==============================================================================
function Show-RemediationPlan {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [bool]$SkipNvramRename,
        [bool]$SkipCertUpdate,
        [string]$CurrentPKStatus,
        [string]$PKPath
    )

    $g = 'Green'; $y = 'Yellow'; $c = 'Cyan'; $gr = 'Gray'

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor $c
    Write-Host "  REMEDIATION PLAN: $($VM.Name)" -ForegroundColor $c
    Write-Host "  ============================================================" -ForegroundColor $c

    if ($SkipNvramRename) {
        Write-Host "  [SKIP] Steps 2-3 : NVRAM already renamed (.nvram_old exists)" -ForegroundColor $g
    } else {
        Write-Host "  [RUN ] Step  2   : Power off VM" -ForegroundColor $y
        Write-Host "  [RUN ] Step  3   : Rename .nvram -> .nvram_old on datastore" -ForegroundColor $y
    }

    if ($SkipCertUpdate) {
        Write-Host "  [SKIP] Steps 4-6 : 2023 certs present + AvailableUpdates=0x0000" -ForegroundColor $g
    } else {
        Write-Host "  [RUN ] Step  4   : Power on -- ESXi regenerates NVRAM with 2023 certs (1 reboot)" -ForegroundColor $y
        Write-Host "  [RUN ] Step  5   : Registry fix + trigger Secure-Boot-Update task" -ForegroundColor $y
        Write-Host "  [RUN ] Step  6   : Reboot VM (1 reboot)" -ForegroundColor $y
    }

    Write-Host "  [RUN ] Step  7   : Verify KEK/DB 2023 + AvailableUpdates" -ForegroundColor $y

    $pkNeeds = $CurrentPKStatus -in @("Valid_Other","Invalid_NULL","NotChecked")
    if ($PKPath -and $pkNeeds) {
        Write-Host "  [RUN ] Step  9   : PK enrollment via UEFI SetupMode (1 reboot)" -ForegroundColor $y
    } elseif (-not $PKPath) {
        Write-Host "  [SKIP] Step  9   : PK enrollment (-PKDerPath not provided)" -ForegroundColor $gr
    } else {
        Write-Host "  [SKIP] Step  9   : PK already valid ($CurrentPKStatus)" -ForegroundColor $g
    }

    $reboots = 0
    if (-not $SkipCertUpdate) { $reboots += 2 }
    if ($PKPath -and $pkNeeds)  { $reboots += 1 }
    Write-Host ""
    Write-Host "  Total reboots planned: $reboots" -ForegroundColor $c
    Write-Host "  ============================================================" -ForegroundColor $c
    Write-Host ""
}


function Get-NvramPaths {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM)

    $vmxPath = $VM.ExtensionData.Config.Files.VmPathName
    # vmxPath format: "[datastoreName] folder/vmname.vmx"
    $nvramPath    = $vmxPath -replace '\.vmx$', '.nvram'
    $nvramOldPath = $vmxPath -replace '\.vmx$', '.nvram_old'
    $nvramNewPath = $vmxPath -replace '\.vmx$', '.nvram_new'

    return @{
        Vmx      = $vmxPath
        Nvram    = $nvramPath
        NvramOld = $nvramOldPath
        NvramNew = $nvramNewPath
    }
}

function Test-NvramOldExists {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [hashtable]$Paths
    )
    try {
        $dsName  = $Paths.Nvram -replace '^\[(.+?)\].*', '$1'
        $ds      = Get-Datastore -Name $dsName -ErrorAction Stop
        $browser = Get-View $ds.ExtensionData.Browser

        # SearchDatastore_Task expects full datastore path: "[datastoreName] folder"
        # NOT just the folder name -- strip only the filename, keep the [ds] prefix
        $folder  = $Paths.Nvram -replace '/[^/]+$', ''   # e.g. "[VMFS203] SUNNYHANDA2"
        $nvramOldFile = ($Paths.NvramOld -split '/')[-1]  # e.g. "SUNNYHANDA2.nvram_old"

        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.MatchPattern = @($nvramOldFile)             # exact filename match

        $taskRef  = $browser.SearchDatastore_Task($folder, $spec)
        $taskView = Get-View $taskRef
        $deadline = (Get-Date).AddSeconds(30)
        do { Start-Sleep -Seconds 2; $taskView.UpdateViewData() }
        while ($taskView.Info.State -in @('running','queued') -and (Get-Date) -lt $deadline)

        $result = $taskView.Info.Result
        if ($result -ne $null -and $result.PSObject.Properties['File'] -ne $null) {
            $matchedFiles = @($result.File | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue)
            if ($matchedFiles -contains $nvramOldFile) {
                return $true
            }
        }
        return $false
    } catch {
        Write-Log "  Test-NvramOldExists error: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Move-DatastoreFile {
    param([string]$SourcePath, [string]$DestPath, $Datacenter, [switch]$Force)

    Write-Log "  Datastore move: $SourcePath -> $DestPath"
    $si      = Get-View ServiceInstance
    $fileMgr = Get-View $si.Content.FileManager
    $dcRef   = $Datacenter.ExtensionData.MoRef

    $taskRef = $fileMgr.MoveDatastoreFile_Task($SourcePath, $dcRef, $DestPath, $dcRef, [bool]$Force)
    $taskView = Get-View $taskRef
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $taskView.UpdateViewData()
    } while ($taskView.Info.State -in @('running','queued') -and (Get-Date) -lt $deadline)

    if ($taskView.Info.State -ne 'success') {
        throw "Datastore file move failed: $($taskView.Info.Error.LocalizedMessage)"
    }
    Write-Log "  Datastore move complete" "OK"
}

function Remove-DatastoreFile {
    param([string]$DsPath, $Datacenter)

    Write-Log "  Datastore delete: $DsPath"
    $si      = Get-View ServiceInstance
    $fileMgr = Get-View $si.Content.FileManager
    $dcRef   = $Datacenter.ExtensionData.MoRef

    $taskRef = $fileMgr.DeleteDatastoreFile_Task($DsPath, $dcRef)
    $taskView = Get-View $taskRef
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $taskView.UpdateViewData()
    } while ($taskView.Info.State -in @('running','queued') -and (Get-Date) -lt $deadline)

    if ($taskView.Info.State -ne 'success') {
        throw "Datastore file delete failed: $($taskView.Info.Error.LocalizedMessage)"
    }
    Write-Log "  Datastore delete complete" "OK"
}

# ==============================================================================
# HELPERS: VMX EXTRA CONFIG
# ==============================================================================
function Set-VMExtraConfig {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [string]$Key,
        [string]$Value  # Pass empty string "" to remove the key
    )
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $opt  = New-Object VMware.Vim.OptionValue
    $opt.Key   = $Key
    $opt.Value = $Value
    $spec.ExtraConfig = @($opt)
    $VM.ExtensionData.ReconfigVM($spec)
    Write-Log "  VMX extra config set: $Key = '$Value'" "OK"
}

function Get-VMExtraConfig {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [string]$Key
    )
    $refreshed = Get-VM -Name $VM.Name
    $entry = $refreshed.ExtensionData.Config.ExtraConfig | Where-Object { $_.Key -eq $Key }
    if ($entry) { return $entry.Value }
    return $null
}

# ==============================================================================
# HELPERS: GUEST OPERATIONS VIA INVOKE-VMSCRIPT
# ==============================================================================
function Invoke-GuestPS {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [string]$Script,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$AsBat  # Use Bat staging for SYSTEM-level operations
    )

    if ($AsBat) {
        # Write PS script to temp file, execute via schtasks as SYSTEM
        # This bypasses UAC filtering for privileged registry/task operations
        $escaped = $Script -replace '"', '\"'
        $batScript = @"
schtasks /create /tn "TempSBFix_$$" /sc once /st 00:00 /ru SYSTEM /tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass -Command \"$escaped\"" /f
schtasks /run /tn "TempSBFix_$$"
timeout /t 15 /nobreak
schtasks /delete /tn "TempSBFix_$$" /f
"@
        $result = Invoke-VMScript -VM $VM -ScriptText $batScript -GuestCredential $Credential `
                    -ScriptType Bat -ErrorAction Stop
        return $result
    }

    $result = Invoke-VMScript -VM $VM -ScriptText $Script -GuestCredential $Credential `
                -ScriptType PowerShell -ErrorAction Stop
    return $result
}

# ==============================================================================
# HELPERS: GUEST SECURE BOOT STATUS CHECKS
# ==============================================================================
function Get-GuestSecureBootStatus {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )

    $checkScript = @'
$result = @{}
try {
    $dbBytes  = (Get-SecureBootUEFI -Name db  -ErrorAction Stop).Bytes
    $kekBytes = (Get-SecureBootUEFI -Name KEK -ErrorAction Stop).Bytes
    $dbStr    = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $kekStr   = [System.Text.Encoding]::ASCII.GetString($kekBytes)
    $result["DB_2023"]  = ($dbStr  -match "2023").ToString()
    $result["KEK_2023"] = ($kekStr -match "2023").ToString()
} catch {
    $result["DB_2023"]  = "Error"
    $result["KEK_2023"] = "Error"
}
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$reg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
if ($reg) {
    $result["Capable"]    = [string]$reg.WindowsUEFICA2023Capable
    $result["RawStatus"]  = [string]$reg.UEFICA2023Status
} else {
    $result["Capable"]   = "Missing"
    $result["RawStatus"] = "Missing"
}
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$avail = Get-ItemPropertyValue $regBase -Name AvailableUpdates -ErrorAction SilentlyContinue
$result["AvailableUpdates"] = if ($avail -ne $null) { "0x{0:X4}" -f $avail } else { "Missing" }
foreach ($k in $result.Keys) { "$k=$($result[$k])" }
'@

    $raw = Invoke-GuestPS -VM $VM -Script $checkScript -Credential $Credential
    $out = @{}
    foreach ($line in ($raw.ScriptOutput -split "`n" | Where-Object { $_ -match "=" })) {
        $parts = $line.Trim() -split "=", 2
        if ($parts.Count -eq 2) { $out[$parts[0]] = $parts[1] }
    }
    return $out
}

function Get-GuestPKStatus {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )

    $checkScript = @'
try {
    $pk = Get-SecureBootUEFI -Name PK -ErrorAction Stop
    if ($pk -eq $null -or $pk.Bytes.Count -eq 0) {
        "Invalid_NULL"
    } else {
        $pkStr = [System.Text.Encoding]::ASCII.GetString($pk.Bytes)
        if ($pkStr -match "Windows OEM Devices") { "Valid_WindowsOEM" }
        elseif ($pkStr -match "Microsoft") { "Valid_Microsoft" }
        else { "Valid_Other" }
    }
} catch { "CheckFailed: " + $_.Exception.Message }
'@

    $raw = Invoke-GuestPS -VM $VM -Script $checkScript -Credential $Credential
    return $raw.ScriptOutput.Trim()
}

function Test-GuestIsDomainController {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )
    try {
        $raw = Invoke-GuestPS -VM $VM -Script '(Get-WmiObject Win32_OperatingSystem).ProductType' `
                 -Credential $Credential
        return ([int]($raw.ScriptOutput.Trim()) -eq 2)
    } catch {
        return $false
    }
}

function Test-GuestBitLockerActive {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )
    try {
        $script = '(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus'
        $raw = Invoke-GuestPS -VM $VM -Script $script -Credential $Credential
        return ($raw.ScriptOutput.Trim() -eq "On")
    } catch {
        return $false
    }
}

# ==============================================================================
# STEP 0: PREFLIGHT CHECK PER VM
# ==============================================================================
function Invoke-PreflightCheck {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )

    $issues = @()

    # ESXi host version
    $vmHost = Get-VMHost -VM $VM
    $hostVer = $vmHost.Version
    $verParts = $hostVer -split '\.'
    $major = [int]$verParts[0]
    $minor = if ($verParts.Count -gt 1) { [int]$verParts[1] } else { 0 }
    $patch = if ($verParts.Count -gt 2) { [int]($verParts[2] -replace '[^0-9]', '') } else { 0 }
    $isEsxi8u2 = ($major -gt 8) -or ($major -eq 8 -and ($minor -gt 0 -or $patch -ge 2))
    if (-not $isEsxi8u2) {
        $issues += "ESXi host '$($vmHost.Name)' is v$hostVer -- requires 8.0.2+"
    } else {
        Write-Log "  ESXi host: $($vmHost.Name) v$hostVer -- OK" "OK"
    }

    # Hardware version -- HardwareVersion returns "vmx-13", "vmx-14" etc
    $hwVer = [int]($VM.HardwareVersion -replace '[^0-9]','')
    if ($hwVer -lt 13) {
        $issues += "Hardware version $hwVer -- requires 13+"
    } else {
        Write-Log "  Hardware version: $hwVer -- OK" "OK"
    }

    # EFI firmware
    $firmware = $VM.ExtensionData.Config.Firmware
    if ($firmware -ne "efi") {
        $issues += "Firmware is '$firmware' -- must be EFI"
    } else {
        Write-Log "  Firmware: EFI -- OK" "OK"
    }

    # Secure Boot enabled
    $sbEnabled = $VM.ExtensionData.Config.BootOptions.EfiSecureBootEnabled
    if (-not $sbEnabled) {
        $issues += "Secure Boot is not enabled at hypervisor level"
    } else {
        Write-Log "  Secure Boot enabled: True -- OK" "OK"
    }

    # VMware Tools status
    $toolsStatus = $VM.Guest.ExtensionData.ToolsStatus
    if ($toolsStatus -notin @("toolsOk","toolsOld")) {
        $issues += "VMware Tools status: $toolsStatus -- must be toolsOk"
    } else {
        Write-Log "  VMware Tools: $toolsStatus -- OK" "OK"
    }

    # Domain Controller check (only if we have credentials and VM is powered on)
    if ($Credential -and $VM.PowerState -eq "PoweredOn") {
        try {
            $isDC = Test-GuestIsDomainController -VM $VM -Credential $Credential
            if ($isDC) {
                $issues += "VM is a Domain Controller -- excluded from automated remediation (use DC_SecureBoot_Manual_Steps)"
            } else {
                Write-Log "  Domain Controller check: Not a DC -- OK" "OK"
            }
        } catch {
            Write-Log "  Could not determine if DC (Tools may not be ready): $($_.Exception.Message)" "WARN"
        }

        # BitLocker check
        try {
            $hasBL = Test-GuestBitLockerActive -VM $VM -Credential $Credential
            if ($hasBL) {
                $issues += "BitLocker is active on C: -- suspend BitLocker before running remediation or use a dedicated approach"
            } else {
                Write-Log "  BitLocker: Not active on C: -- OK" "OK"
            }
        } catch {
            Write-Log "  Could not check BitLocker: $($_.Exception.Message)" "WARN"
        }
    }

    return $issues
}

# ==============================================================================
# MAIN PER-VM REMEDIATION
# ==============================================================================
function Invoke-VMRemediation {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )

    $rec = [PSCustomObject]@{
        VMName           = $VM.Name
        SnapshotCreated  = $false
        NVRAMRenamed     = $false
        KEK_AfterNVRAM   = $false
        DB_AfterNVRAM    = $false
        UpdateTriggered  = $false
        KEK_2023         = $false
        DB_2023          = $false
        FinalStatus      = "NotStarted"
        PK_Status        = "NotChecked"
        PKEnrolled       = $false
        SnapshotRetained = $false
        Result           = "Pending"
        Notes            = ""
    }

    $snapName = "Pre-SecureBoot-Fix_" + (Get-Date -Format 'yyyyMMdd_HHmmss')
    $dc    = Get-Datacenter -VM $VM
    $paths = Get-NvramPaths -VM $VM

    try {
        Write-Section "VM: $($VM.Name)"
        Write-Log "VMX path : $($paths.Vmx)"
        Write-Log "NVRAM    : $($paths.Nvram)"

        # ------------------------------------------------------------------
        # Step 0: Preflight
        # ------------------------------------------------------------------
        Write-Log "[0/9] Preflight checks..."
        $issues = @(Invoke-PreflightCheck -VM $VM -Credential $Credential)
        if ($issues.Count -gt 0) {
            foreach ($i in $issues) { Write-Log "  FAIL: $i" "ERROR" }
            $rec.Result = "SkippedPreflight"
            $rec.Notes  = $issues -join "; "
            return $rec
        }
        Write-Log "[0/9] Preflight passed" "OK"

        # ------------------------------------------------------------------
        # SMART RESUME: detect what prior runs have already completed
        # ------------------------------------------------------------------
        $skipNvramRename  = $false   # True = .nvram_old exists, rename already done
        $skipCertUpdate   = $false   # True = certs present + AvailableUpdates=0x0000
        $forceNvramRename = $false   # True = .nvram_old exists but snapshot was reverted
                                     #        -- current .nvram is old, must re-rename with overwrite
        $currentPKStatus  = "NotChecked"

        Write-Log "Checking prior remediation state for smart resume..."

        # Check .nvram_old on datastore (independent of VM power state)
        $nvramOldExists = Test-NvramOldExists -VM $VM -Paths $paths
        if ($nvramOldExists) {
            $skipNvramRename = $true
            $rec.NVRAMRenamed = $true
            Write-Log "  [Resume] .nvram_old found -- NVRAM rename already done in a prior run" "WARN"
        } else {
            Write-Log "  [Resume] .nvram_old not found -- full run required"
        }

        # Check guest cert/task state (only possible if VM is powered on)
        if ($skipNvramRename -and $VM.PowerState -eq "PoweredOn") {
            try {
                Write-Log "  [Resume] Probing guest Secure Boot state..."
                $agentReady = Wait-GuestOpsAgent -VM $VM -Credential $Credential -TimeoutSeconds 150
                if ($agentReady) {
                    $priorStatus    = Get-GuestSecureBootStatus -VM $VM -Credential $Credential
                    $certsDone      = ($priorStatus["KEK_2023"] -eq "True" -and $priorStatus["DB_2023"] -eq "True")
                    $availDone      = ($priorStatus["AvailableUpdates"] -eq "0x0000")
                    $currentPKStatus = Get-GuestPKStatus -VM $VM -Credential $Credential

                    Write-Log "  [Resume] KEK_2023=$($priorStatus['KEK_2023'])  DB_2023=$($priorStatus['DB_2023'])  AvailableUpdates=$($priorStatus['AvailableUpdates'])  PK=$currentPKStatus"

                    if ($certsDone -and $availDone) {
                        $skipCertUpdate = $true
                        $rec.KEK_AfterNVRAM  = $true
                        $rec.DB_AfterNVRAM   = $true
                        $rec.UpdateTriggered = $true
                        Write-Log "  [Resume] Certs present + task complete -- cert update steps will be skipped" "WARN"
                    } elseif ($certsDone) {
                        Write-Log "  [Resume] Certs present but task not yet complete (AvailableUpdates=$($priorStatus['AvailableUpdates'])) -- will re-trigger" "WARN"
                    } else {
                        # Certs are absent even though .nvram_old exists.
                        # Root cause: snapshot was reverted, which RESTORED the original .nvram
                        # (snapshot tracks .nvram) but LEFT .nvram_old on the datastore
                        # (snapshots do not track renamed/extra files).
                        # The VM booted with the restored OLD .nvram -- not a regenerated one.
                        # Fix: we must re-rename .nvram -> .nvram_old (force-overwriting the
                        # stale .nvram_old) and let ESXi regenerate NVRAM with 2023 certs.
                        $skipNvramRename  = $false
                        $forceNvramRename = $true
                        $rec.NVRAMRenamed = $false
                        Write-Log "  [Resume] .nvram_old exists but certs are absent" "WARN"
                        Write-Log "  [Resume] Snapshot revert likely restored original .nvram -- must re-rename (force overwrite)" "WARN"
                        Write-Log "  [Resume] Will proceed with full NVRAM rename and regeneration" "WARN"
                    }
                } else {
                    Write-Log "  [Resume] Guest ops agent not ready for state probe -- will attempt full cert steps" "WARN"
                }
            } catch {
                Write-Log "  [Resume] Could not probe guest state: $($_.Exception.Message) -- proceeding with full run" "WARN"
            }
        } elseif ($skipNvramRename -and $VM.PowerState -ne "PoweredOn") {
            Write-Log "  [Resume] VM is powered off -- will power on and check certs from step 4"
        }

        # -- FULL VALIDATION EARLY EXIT -------------------------------------
        # Nothing left to do: NVRAM renamed + certs done + PK valid
        $pkAlreadyValid = $currentPKStatus -in @("Valid_WindowsOEM","Valid_Microsoft")
        $noPKNeeded     = (-not $PKDerPath) -or $pkAlreadyValid

        if ($skipNvramRename -and $skipCertUpdate -and $noPKNeeded) {
            Write-Log "[VALIDATION ONLY] VM appears fully remediated from prior run -- re-validating without changes" "OK"

            $finalStatus = Get-GuestSecureBootStatus -VM $VM -Credential $Credential
            $rec.KEK_2023    = ($finalStatus["KEK_2023"] -eq "True")
            $rec.DB_2023     = ($finalStatus["DB_2023"]  -eq "True")
            $rec.FinalStatus = "Updated"
            $rec.PK_Status   = $currentPKStatus
            $rec.PKEnrolled  = $pkAlreadyValid

            if ($rec.KEK_2023 -and $rec.DB_2023 -and $pkAlreadyValid) {
                $rec.Result = "Success"
                Write-Log "RESULT: SUCCESS (Validation only -- no changes made)" "OK"
            } elseif ($rec.KEK_2023 -and $rec.DB_2023 -and -not $PKDerPath) {
                $rec.Result = "Success"
                Write-Log "RESULT: SUCCESS (Certs OK -- PK not checked, -PKDerPath not provided)" "OK"
            } else {
                $rec.Result = "PartialSuccess"
                $rec.Notes  = "Validation: KEK=$($rec.KEK_2023) DB=$($rec.DB_2023) PK=$($rec.PK_Status). Re-run with -PKDerPath to fix PK."
                Write-Log "RESULT: PARTIAL (Validation) -- $($rec.Notes)" "WARN"
            }
            if ($rec.SnapshotCreated) { $rec.SnapshotRetained = $true }
            return $rec
        }

        # -- CREDENTIAL VALIDATION (before any changes) --------------------
        # If VM is powered on we can validate creds now -- before snapshot,
        # before NVRAM touch, before anything. Prompts up to 3 times on auth
        # failure rather than looping forever or triggering account lockout.
        # If VM is powered off (fresh run), skipped here -- validated at step 4.
        if ($VM.PowerState -eq "PoweredOn") {
            Write-Log "Validating guest credentials before making any changes..."
            $validatedCred = Test-GuestCredential -VM $VM -Credential $Credential
            if ($null -eq $validatedCred) {
                $rec.Result = "AuthFailed"
                $rec.Notes  = "Guest authentication failed after max attempts. Re-run with correct credentials."
                Write-Log "RESULT: AUTHFAILED -- VM skipped. Re-run with correct credentials." "ERROR"
                return $rec
            }
            $Credential = $validatedCred
        } else {
            Write-Log "VM is powered off -- credentials will be validated after first boot (step 4)" "WARN"
        }

        # -- CONFIRMATION PROMPT -------------------------------------------
        # Show exactly what steps will run and ask Y/N.
        # Skip with -Force for bulk/automated runs.
        if (-not $Force) {
            Show-RemediationPlan -VM $VM `
                -SkipNvramRename $skipNvramRename `
                -SkipCertUpdate  $skipCertUpdate  `
                -CurrentPKStatus $currentPKStatus `
                -PKPath          $PKDerPath

            $confirm = Read-Host "  Proceed with remediation for '$($VM.Name)'? (Y/N)"
            Write-Host ""
            if ($confirm -notmatch '^[Yy]') {
                Write-Log "User declined remediation for '$($VM.Name)' -- skipping" "WARN"
                $rec.Result = "Skipped_UserDeclined"
                return $rec
            }
            Write-Log "User confirmed -- proceeding" "OK"
        }

        # ------------------------------------------------------------------
        # Step 2 (FIRST): Graceful shutdown before any snapshot
        # ------------------------------------------------------------------
        # Shutdown BEFORE the snapshot so the snapshot captures a clean
        # powered-off state. Graceful OS shutdown is attempted first via
        # VMware Tools; hard power-off is only used if graceful times out.
        # ------------------------------------------------------------------
        if (-not $skipNvramRename) {
            Write-Log "[2/9] Initiating graceful shutdown (before snapshot)..."
            Invoke-GracefulShutdown -VM $VM -GracefulTimeoutSeconds 200 | Out-Null
            $VM = Get-VM -Name $VM.Name
            if ($VM.PowerState -ne "PoweredOff") {
                throw "VM '$($VM.Name)' is not in PoweredOff state after shutdown sequence"
            }
            Write-Log "[2/9] VM is powered off" "OK"
        } else {
            Write-Log "[2/9] SKIPPED -- VM power-off not needed (.nvram_old exists from prior run)" "WARN"
        }

        # ------------------------------------------------------------------
        # Step 1 (SECOND): Snapshot -- taken after VM is confirmed powered off
        # ------------------------------------------------------------------
        # Snapshot of a powered-off VM is a cleaner, consistent rollback point:
        # no memory state, no in-flight I/O, no quiescing concerns.
        # ------------------------------------------------------------------
        if (-not $NoSnapshot) {
            Write-Log "[1/9] Taking snapshot: $snapName ..."
            $existingSnap = @(Get-Snapshot -VM $VM -Name "Pre-SecureBoot-Fix*" -ErrorAction SilentlyContinue)
            if ($existingSnap.Count -gt 0) {
                Write-Log "  Snapshot already exists: $($existingSnap[0].Name) -- reusing" "WARN"
                $rec.SnapshotCreated = $true
            } else {
                New-Snapshot -VM $VM -Name $snapName -Description "Pre Secure Boot 2023 cert fix" `
                    -Quiesce:$false -Memory:$false -Confirm:$false | Out-Null
                $rec.SnapshotCreated = $true
                Write-Log "[1/9] Snapshot created: $snapName" "OK"
            }
        } else {
            Write-Log "[1/9] Skipping snapshot (-NoSnapshot)" "WARN"
        }

        # ------------------------------------------------------------------
        # Step 3: Rename NVRAM (VM is already powered off from step 2)
        # ------------------------------------------------------------------
        if (-not $skipNvramRename) {
            Write-Log "[3/9] Renaming NVRAM: $(($paths.Nvram -split '/')[-1]) -> $(($paths.NvramOld -split '/')[-1]) ..."
            try {
                if ($forceNvramRename) {
                    # Snapshot was reverted -- .nvram_old already exists from a prior run
                    # but .nvram was restored to its original state. Force-overwrite .nvram_old
                    # so ESXi generates a truly fresh NVRAM with 2023 certs on next boot.
                    Write-Log "  Force-overwriting existing .nvram_old (snapshot-revert scenario)..." "WARN"
                    Move-DatastoreFile -SourcePath $paths.Nvram -DestPath $paths.NvramOld -Datacenter $dc -Force
                } else {
                    Move-DatastoreFile -SourcePath $paths.Nvram -DestPath $paths.NvramOld -Datacenter $dc
                }
            } catch {
                if ($_.Exception.Message -match 'already exists') {
                    Write-Log "  .nvram_old already exists (detection missed) -- treating as prior run, continuing" "WARN"
                } else {
                    throw
                }
            }
            $rec.NVRAMRenamed = $true
            Write-Log "[3/9] NVRAM renamed" "OK"

        } else {
            Write-Log "[3/9] SKIPPED -- NVRAM already renamed in prior run" "WARN"
        }

        # ------------------------------------------------------------------
        # Steps 4-6: Boot + cert verify + registry fix + reboot  (skip if done)
        # ------------------------------------------------------------------
        if (-not $skipCertUpdate) {
            Write-Log "[4/9] Powering on VM -- ESXi will regenerate NVRAM with 2023 certs..."
            if ($VM.PowerState -ne "PoweredOn") {
                Start-VM -VM $VM -Confirm:$false | Out-Null
            }
            $VM = Get-VM -Name $VM.Name

            $toolsOk = Wait-VMTools -VM $VM -TimeoutSeconds ($WaitSeconds + 120)
            if (-not $toolsOk) { throw "VMware Tools did not come up after NVRAM regeneration boot" }
            $VM = Get-VM -Name $VM.Name

            $agentOk = Wait-GuestOpsAgent -VM $VM -Credential $Credential -TimeoutSeconds 150
            if (-not $agentOk) { Write-Log "  Guest ops agent slow -- proceeding anyway" "WARN" }

            Write-Log "  Checking KEK/DB 2023 presence in new NVRAM..."
            $statusAfter = Get-GuestSecureBootStatus -VM $VM -Credential $Credential
            $rec.KEK_AfterNVRAM = ($statusAfter["KEK_2023"] -eq "True")
            $rec.DB_AfterNVRAM  = ($statusAfter["DB_2023"]  -eq "True")
            Write-Log "  KEK 2023 present: $($rec.KEK_AfterNVRAM)"
            Write-Log "  DB  2023 present: $($rec.DB_AfterNVRAM)"

            if (-not $rec.KEK_AfterNVRAM -or -not $rec.DB_AfterNVRAM) {
                $rec.Notes += "2023 certs not found after NVRAM regen -- ESXi host may not be 8.0.2+. "
                Write-Log "  2023 certs missing after NVRAM regen -- check ESXi host version" "ERROR"
            }
            Write-Log "[4/9] NVRAM regeneration complete" "OK"

            Write-Log "[5/9] Applying registry fix and triggering Secure-Boot-Update task..."
            $regFixScript = @'
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" /v UEFICA2023Status /f 2>NUL
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" /v WindowsUEFICA2023Capable /f 2>NUL
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot" /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" /v WindowsUEFICA2023Capable /t REG_DWORD /d 2 /f
'@
            Invoke-GuestPS -VM $VM -Script $regFixScript -Credential $Credential -AsBat | Out-Null
            Write-Log "  Registry flags set" "OK"

            $triggerScript = 'Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction SilentlyContinue'
            try {
                Invoke-GuestPS -VM $VM -Script $triggerScript -Credential $Credential | Out-Null
                $rec.UpdateTriggered = $true
                Write-Log "  Secure-Boot-Update task triggered" "OK"
            } catch {
                Write-Log "  Could not trigger task (may not exist yet pre-reboot): $($_.Exception.Message)" "WARN"
            }
            Write-Log "[5/9] Registry fix applied" "OK"

            Write-Log "[6/9] Rebooting VM (graceful)..."
            Invoke-GracefulRestart -VM $VM -GracefulTimeoutSeconds 150
            $VM = Get-VM -Name $VM.Name

            $toolsOk = Wait-VMTools -VM $VM -TimeoutSeconds ($WaitSeconds + 120)
            if (-not $toolsOk) { throw "VMware Tools did not come up after reboot" }
            $VM = Get-VM -Name $VM.Name

            $agentOk = Wait-GuestOpsAgent -VM $VM -Credential $Credential -TimeoutSeconds 120
            if (-not $agentOk) { Write-Log "  Guest ops agent slow post-reboot -- proceeding" "WARN" }

            Start-Sleep -Seconds 15
            try {
                Invoke-GuestPS -VM $VM -Script $triggerScript -Credential $Credential | Out-Null
                Write-Log "  Secure-Boot-Update task triggered (post-reboot)" "OK"
            } catch {
                Write-Log "  Could not trigger task post-reboot: $($_.Exception.Message)" "WARN"
            }
            Start-Sleep -Seconds 30
            Write-Log "[6/9] Reboot complete" "OK"

        } else {
            Write-Log "[4/9] SKIPPED -- NVRAM boot not needed (certs already present from prior run)" "WARN"
            Write-Log "[5/9] SKIPPED -- Registry fix already complete (AvailableUpdates=0x0000)" "WARN"
            Write-Log "[6/9] SKIPPED -- Reboot not needed" "WARN"
            # Ensure VM is powered on for steps 7-9
            if ($VM.PowerState -ne "PoweredOn") {
                Write-Log "  VM is powered off -- powering on for verification..."
                Start-VM -VM $VM -Confirm:$false | Out-Null
                $VM = Get-VM -Name $VM.Name
                Wait-VMTools -VM $VM -TimeoutSeconds ($WaitSeconds + 120) | Out-Null
                $VM = Get-VM -Name $VM.Name
                Wait-GuestOpsAgent -VM $VM -Credential $Credential -TimeoutSeconds 120 | Out-Null
            }
        }

        # ------------------------------------------------------------------
        # Step 7: Verify final status (always runs)
        # ------------------------------------------------------------------
        Write-Log "[7/9] Verifying final Secure Boot status..."
        $finalStatus = Get-GuestSecureBootStatus -VM $VM -Credential $Credential

        $rec.KEK_2023 = ($finalStatus["KEK_2023"] -eq "True")
        $rec.DB_2023  = ($finalStatus["DB_2023"]  -eq "True")

        $rawStatus    = $finalStatus["RawStatus"]
        $availUpdates = $finalStatus["AvailableUpdates"]
        $availComplete = ($availUpdates -eq "0x0000")
        $statusComplete = ($rawStatus -eq "Updated" -or $rawStatus -eq "2" -or $availComplete)

        if ($availComplete -and $rawStatus -eq "Missing") {
            $rec.FinalStatus = "Updated"
        } elseif ($statusComplete) {
            $rec.FinalStatus = "Updated"
        } elseif ($rawStatus -eq "Missing") {
            $rec.FinalStatus = "Missing"
        } else {
            $rec.FinalStatus = "InProgress_$rawStatus"
        }

        Write-Log "  KEK 2023         : $($rec.KEK_2023)"
        Write-Log "  DB  2023         : $($rec.DB_2023)"
        Write-Log "  UEFICA2023Status : $rawStatus"
        Write-Log "  AvailableUpdates : $availUpdates  (0x0000 = complete)"
        Write-Log "  Status resolved  : $($rec.FinalStatus)"

        if (-not $statusComplete) {
            Write-Log "  Status not yet complete -- a second reboot may be required" "WARN"
            $rec.Notes += "UEFICA2023Status=$rawStatus AvailableUpdates=$availUpdates after fix. May need another reboot. "
        }
        Write-Log "[7/9] Verification complete" "OK"

        # ------------------------------------------------------------------
        # Step 8: PK status check (always runs)
        # ------------------------------------------------------------------
        Write-Log "[8/9] Checking Platform Key (PK) status..."
        $pkStatus = if ($currentPKStatus -ne "NotChecked") { $currentPKStatus } else {
            Get-GuestPKStatus -VM $VM -Credential $Credential
        }
        # Always re-read fresh PK status at this point for accuracy
        $pkStatus = Get-GuestPKStatus -VM $VM -Credential $Credential
        $rec.PK_Status = $pkStatus
        Write-Log "  PK Status: $pkStatus"

        $needsPKEnroll = $pkStatus -in @("Valid_Other","Invalid_NULL")
        if (-not $needsPKEnroll) {
            Write-Log "  PK is valid -- no enrollment needed" "OK"
        } else {
            Write-Log "  PK requires enrollment ($pkStatus)" "WARN"
        }
        Write-Log "[8/9] PK check complete" "OK"

        # ------------------------------------------------------------------
        # Step 9: PK enrollment (only if needed)
        # ------------------------------------------------------------------
        if ($needsPKEnroll) {
            if (-not $PKDerPath) {
                Write-Log "[9/9] Skipping PK enrollment -- -PKDerPath not provided" "WARN"
                $rec.Notes += "PK=$pkStatus but -PKDerPath not supplied. "
            } else {
                Write-Log "[9/9] Starting PK enrollment via UEFI SetupMode..."
                $esxiHost  = Get-VMHost -VM $VM
                $esxiMajor = [int](($esxiHost.Version -split '\.')[0])
                if ($esxiMajor -lt 8) {
                    Write-Log "  ESXi $($esxiHost.Version) -- SetupMode requires ESXi 8+. Manual PK enrollment required." "WARN"
                    $rec.Notes += "PK enrollment skipped -- ESXi $($esxiHost.Version) does not support SetupMode VMX. "
                } else {
                    $enrolled = Invoke-PKEnrollment -VM $VM -Credential $Credential
                    $rec.PKEnrolled = $enrolled
                    $VM = Get-VM -Name $VM.Name
                    if ($enrolled) {
                        $rec.PK_Status = "Valid_WindowsOEM"
                        Write-Log "[9/9] PK enrollment completed successfully" "OK"
                    } else {
                        Write-Log "[9/9] PK enrollment failed -- see notes" "WARN"
                    }
                }
            }
        } else {
            Write-Log "[9/9] PK enrollment not required" "OK"
        }

        # ------------------------------------------------------------------
        # Final outcome
        # ------------------------------------------------------------------
        $certOk   = $rec.KEK_2023 -and $rec.DB_2023
        $statusOk = $rec.FinalStatus -eq "Updated"
        $pkOk     = $rec.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft","NotChecked")

        if ($certOk -and $statusOk -and $pkOk) {
            $rec.Result = "Success"
            Write-Log "RESULT: SUCCESS -- VM '$($VM.Name)' fully remediated" "OK"
        } elseif ($certOk) {
            $rec.Result = "PartialSuccess"
            Write-Log "RESULT: PARTIAL -- Certs OK but status=$($rec.FinalStatus), PK=$($rec.PK_Status). Reboot and re-run." "WARN"
        } else {
            $rec.Result = "Failed"
            Write-Log "RESULT: FAILED -- Certs missing. Check ESXi version and NVRAM regen." "ERROR"
        }

        # Remove snapshot on clean success (unless -RetainSnapshots or -NoSnapshot)
        if ($rec.Result -eq "Success" -and -not $RetainSnapshots -and -not $NoSnapshot -and $rec.SnapshotCreated) {
            Write-Log "Removing snapshot (success + -RetainSnapshots not set)..."
            @(Get-Snapshot -VM $VM -Name "Pre-SecureBoot-Fix*" -ErrorAction SilentlyContinue) |
                Remove-Snapshot -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            $rec.SnapshotRetained = $false
            Write-Log "Snapshot removed" "OK"
        } elseif ($rec.SnapshotCreated) {
            $rec.SnapshotRetained = $true
            Write-Log "Snapshot retained: $snapName" "WARN"
        }

    } catch {
        $rec.Result = "Error"
        $rec.Notes += "EXCEPTION: $($_.Exception.Message)"
        Write-Log "ERROR on VM '$($VM.Name)': $($_.Exception.Message)" "ERROR"
        Write-Log "Stack: $($_.ScriptStackTrace)" "ERROR"
        if ($rec.SnapshotCreated) { $rec.SnapshotRetained = $true }
    }

    return $rec
}

# PK ENROLLMENT VIA SETUPMODE
# ==============================================================================
function Invoke-PKEnrollment {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        # PK 1/5: Set SetupMode on VMX
        Write-Log "  [PK 1/5] Setting uefi.secureBootMode.overrideOnce = SetupMode..."
        Set-VMExtraConfig -VM $VM -Key "uefi.secureBootMode.overrideOnce" -Value "SetupMode"

        # PK 2/5: Graceful shutdown then power on to enter SetupMode
        Write-Log "  [PK 2/5] Gracefully shutting down VM for SetupMode boot..."
        Invoke-GracefulShutdown -VM $VM -GracefulTimeoutSeconds 200 | Out-Null
        $VM = Get-VM -Name $VM.Name
        if ($VM.PowerState -ne "PoweredOff") {
            throw "VM '$($VM.Name)' did not reach PoweredOff state before SetupMode boot"
        }
        Start-VM -VM $VM -Confirm:$false | Out-Null
        $VM = Get-VM -Name $VM.Name

        $toolsOk = Wait-VMTools -VM $VM -TimeoutSeconds ($WaitSeconds + 150)
        if (-not $toolsOk) { throw "VMware Tools did not come up after SetupMode reboot" }
        $VM = Get-VM -Name $VM.Name

        # Verify we're actually in SetupMode
        $setupMode = Get-GuestPKStatus -VM $VM -Credential $Credential
        Write-Log "  PK status in SetupMode boot: $setupMode"

        # PK 3/5: Copy .der file to guest
        Write-Log "  [PK 3/5] Copying WindowsOEMDevicesPK.der to guest..."
        $derBytes   = [System.IO.File]::ReadAllBytes((Resolve-Path $PKDerPath).Path)
        $derB64     = [Convert]::ToBase64String($derBytes)
        $copyScript = "[System.IO.File]::WriteAllBytes('C:\Windows\Temp\WindowsOEMDevicesPK.der', [Convert]::FromBase64String('$derB64'))"
        Invoke-GuestPS -VM $VM -Script $copyScript -Credential $Credential | Out-Null
        Write-Log "  .der file copied to C:\Windows\Temp\" "OK"

        # PK 4/5: Enroll PK
        Write-Log "  [PK 4/5] Enrolling PK via Format-SecureBootUEFI | Set-SecureBootUEFI..."
        $enrollScript = @'
$cert = "C:\Windows\Temp\WindowsOEMDevicesPK.der"
$owner = "55555555-0000-0000-0000-000000000000"
$time  = "2025-10-23T11:00:00Z"
Format-SecureBootUEFI -Name PK -CertificateFilePath $cert -SignatureOwner $owner -FormatWithCert -Time $time |
    Set-SecureBootUEFI -Time $time
"EnrollDone"
'@
        $enrollResult = Invoke-GuestPS -VM $VM -Script $enrollScript -Credential $Credential
        Write-Log "  Enroll output: $($enrollResult.ScriptOutput.Trim())"

        # PK 5/5: Clear VMX option, reboot, verify
        Write-Log "  [PK 5/5] Clearing SetupMode VMX option and rebooting (graceful)..."
        Set-VMExtraConfig -VM $VM -Key "uefi.secureBootMode.overrideOnce" -Value ""

        Invoke-GracefulRestart -VM $VM -GracefulTimeoutSeconds 150
        $VM = Get-VM -Name $VM.Name

        $toolsOk = Wait-VMTools -VM $VM -TimeoutSeconds ($WaitSeconds + 120)
        if (-not $toolsOk) { throw "VMware Tools did not come up after PK enrollment reboot" }
        $VM = Get-VM -Name $VM.Name

        # Extra wait for guest ops agent -- Tools running != agent accepting connections
        # This is the most common cause of "guest operations agent could not be contacted"
        $agentOk = Wait-GuestOpsAgent -VM $VM -Credential $Credential -TimeoutSeconds 200
        if (-not $agentOk) {
            throw "Guest operations agent did not become contactable after PK enrollment reboot"
        }

        # Refresh VM object and add a small buffer after agent confirmed ready --
        # prevents a race where the agent accepted the probe but isn't fully stable yet
        $VM = Get-VM -Name $VM.Name
        Start-Sleep -Seconds 5

        $finalPK = Get-GuestPKStatus -VM $VM -Credential $Credential
        Write-Log "  Final PK status: $finalPK"

        if ($finalPK -eq "Valid_WindowsOEM") {
            return $true
        } else {
            Write-Log "  PK did not reach Valid_WindowsOEM (got: $finalPK)" "WARN"
            return $false
        }

    } catch {
        # Ensure SetupMode VMX flag is cleared even on failure
        try { Set-VMExtraConfig -VM $VM -Key "uefi.secureBootMode.overrideOnce" -Value "" } catch { }
        Write-Log "  PK enrollment failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ==============================================================================
# CLEANUP: SNAPSHOTS
# ==============================================================================
function Invoke-CleanupSnapshots {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$VMs)

    $results = @()
    foreach ($vm in $VMs) {
        Write-Log "Cleaning up snapshots on: $($vm.Name)"
        $rec = [PSCustomObject]@{ VMName = $vm.Name; Result = "Pending"; Notes = "" }
        try {
            $snaps = @(Get-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix*" -ErrorAction SilentlyContinue)
            if ($snaps.Count -gt 0) {
                $snaps | Remove-Snapshot -Confirm:$false -ErrorAction Stop | Out-Null
                $rec.Result = "Removed"
                Write-Log "  Removed $($snaps.Count) snapshot(s)" "OK"
            } else {
                $rec.Result = "NoneFound"
                Write-Log "  No Pre-SecureBoot-Fix snapshots found" "WARN"
            }
        } catch {
            $rec.Result = "Error"
            $rec.Notes  = $_.Exception.Message
            Write-Log "  Error: $($_.Exception.Message)" "ERROR"
        }
        $results += $rec
    }
    return $results
}

# ==============================================================================
# CLEANUP: NVRAM OLD FILES
# ==============================================================================
function Invoke-CleanupNvram {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$VMs)

    $results = @()
    foreach ($vm in $VMs) {
        Write-Log "Cleaning up .nvram_old on: $($vm.Name)"
        $rec = [PSCustomObject]@{ VMName = $vm.Name; Result = "Pending"; Notes = "" }
        try {
            $paths = Get-NvramPaths -VM $vm
            $dc    = Get-Datacenter -VM $vm
            Remove-DatastoreFile -DsPath $paths.NvramOld -Datacenter $dc
            $rec.Result = "Removed"
            Write-Log "  .nvram_old removed" "OK"
        } catch {
            if ($_.Exception.Message -match "File not found|does not exist|No such") {
                $rec.Result = "NoneFound"
                Write-Log "  .nvram_old not found (already cleaned up)" "WARN"
            } else {
                $rec.Result = "Error"
                $rec.Notes  = $_.Exception.Message
                Write-Log "  Error: $($_.Exception.Message)" "ERROR"
            }
        }
        $results += $rec
    }
    return $results
}

# ==============================================================================
# ROLLBACK
# ==============================================================================
function Invoke-RollbackVM {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM)

    Write-Section "ROLLBACK: $($VM.Name)"
    $rec = [PSCustomObject]@{ VMName = $vm.Name; Result = "Pending"; Notes = "" }
    try {
        $paths = Get-NvramPaths -VM $VM
        $dc    = Get-Datacenter -VM $VM

        # Power off
        if ($VM.PowerState -ne "PoweredOff") {
            Write-Log "  Powering off..."
            Stop-VM -VM $VM -Confirm:$false | Out-Null
            $deadline = (Get-Date).AddSeconds(120)
            do { Start-Sleep -Seconds 5; $VM = Get-VM -Name $VM.Name }
            while ($VM.PowerState -ne "PoweredOff" -and (Get-Date) -lt $deadline)
        }

        # Rename current .nvram -> .nvram_new (preserve it)
        Write-Log "  Preserving current NVRAM as .nvram_new..."
        try { Move-DatastoreFile -SourcePath $paths.Nvram -DestPath $paths.NvramNew -Datacenter $dc -Force } catch { }

        # Restore .nvram_old -> .nvram
        Write-Log "  Restoring original NVRAM..."
        Move-DatastoreFile -SourcePath $paths.NvramOld -DestPath $paths.Nvram -Datacenter $dc

        # Revert snapshot if it exists
        $snap = Get-Snapshot -VM $VM -Name "Pre-SecureBoot-Fix*" -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($snap) {
            Write-Log "  Reverting to snapshot: $($snap.Name)..."
            Set-VM -VM $VM -Snapshot $snap -Confirm:$false | Out-Null
            $rec.Result = "RolledBack_NVRAMAndSnapshot"
            Write-Log "  Snapshot reverted" "OK"
        } else {
            Write-Log "  No Pre-SecureBoot-Fix snapshot found -- NVRAM restored only" "WARN"
            $rec.Result = "RolledBack_NVRAMOnly"
        }

        # Power on
        Start-VM -VM $VM -Confirm:$false | Out-Null
        Write-Log "  VM powered on" "OK"

    } catch {
        $rec.Result = "Error"
        $rec.Notes  = $_.Exception.Message
        Write-Log "  Rollback error: $($_.Exception.Message)" "ERROR"
    }
    return $rec
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================
Write-Section "Secure Boot 2023 Certificate Remediation"
Write-Log "Mode      : $($PSCmdlet.ParameterSetName)"
Write-Log "vCenter   : $VCenter"
Write-Log "Log       : $LogFile"
Write-Log "Output CSV: $OutputCsv"
if ($PKDerPath) { Write-Log "PK DER    : $PKDerPath" }

Initialize-PowerCLI
Connect-ToVCenter

Write-Log "Building target VM list..."
$targetVMs = @(Get-TargetVMs)
if ($targetVMs.Count -eq 0) {
    Write-Log "No target VMs found. Exiting." "WARN"
    exit 0
}
Write-Log "Target VMs ($($targetVMs.Count)): $(($targetVMs | Select-Object -ExpandProperty Name) -join ', ')"

$allResults = @()

# ==============================================================================
# PREFLIGHT ONLY
# ==============================================================================
if ($PreflightOnly) {
    Write-Section "PREFLIGHT ONLY MODE"
    # Prompt for credential if checking DC/BitLocker
    $pfCred = $null
    $credAnswer = Read-Host "Enter guest credential for DC/BitLocker checks? (Y/N)"
    if ($credAnswer -eq "Y") { $pfCred = Get-Credential }

    foreach ($vm in $targetVMs) {
        Write-Log "Preflight: $($vm.Name)"
        $issues = @(Invoke-PreflightCheck -VM $vm -Credential $pfCred)
        $status = if ($issues.Count -eq 0) { "Pass" } else { "Fail" }
        $allResults += [PSCustomObject]@{
            VMName = $vm.Name
            Result = $status
            Notes  = $issues -join "; "
        }
    }
    $allResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Log "Preflight CSV: $OutputCsv" "OK"
    $pass = ($allResults | Where-Object { $_.Result -eq "Pass" }).Count
    $fail = ($allResults | Where-Object { $_.Result -eq "Fail" }).Count
    Write-Log "Preflight summary: Pass=$pass  Fail=$fail"
    exit 0
}

# ==============================================================================
# CLEANUP: SNAPSHOTS
# ==============================================================================
if ($CleanupSnapshots) {
    Write-Section "CLEANUP SNAPSHOTS"
    $allResults = Invoke-CleanupSnapshots -VMs $targetVMs
    $allResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Log "Snapshot cleanup CSV: $OutputCsv" "OK"
    exit 0
}

# ==============================================================================
# CLEANUP: NVRAM
# ==============================================================================
if ($CleanupNvram) {
    Write-Section "CLEANUP NVRAM OLD FILES"
    $allResults = Invoke-CleanupNvram -VMs $targetVMs
    $allResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Log "NVRAM cleanup CSV: $OutputCsv" "OK"
    exit 0
}

# ==============================================================================
# ROLLBACK
# ==============================================================================
if ($Rollback) {
    Write-Section "ROLLBACK MODE"
    foreach ($vm in $targetVMs) {
        $allResults += Invoke-RollbackVM -VM $vm
    }
    $allResults | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Log "Rollback CSV: $OutputCsv" "OK"
    exit 0
}

# ==============================================================================
# MAIN REMEDIATION
# ==============================================================================
Write-Section "MAIN REMEDIATION"

foreach ($vm in $targetVMs) {
    $result = Invoke-VMRemediation -VM $vm -Credential $GuestCredential
    $allResults += $result
    # Write CSV after each VM (progress save in case of abort)
    $allResults | Export-Csv -Path $OutputCsv -NoTypeInformation
}

# ==============================================================================
# SUMMARY
# ==============================================================================
Write-Section "SUMMARY"

# Force array -- single-VM runs return a plain object, not a collection
$allResults = @($allResults)

$success  = @($allResults | Where-Object { $_.Result -eq "Success" }).Count
$partial  = @($allResults | Where-Object { $_.Result -eq "PartialSuccess" }).Count
$failed   = @($allResults | Where-Object { $_.Result -eq "Failed" }).Count
$errors   = @($allResults | Where-Object { $_.Result -eq "Error" }).Count
$skipped  = @($allResults | Where-Object { $_.Result -match "Skipped" }).Count

Write-Log "Total VMs     : $($targetVMs.Count)"
Write-Log "Success       : $success"
Write-Log "Partial       : $partial  (reboot + re-run required)"
Write-Log "Failed        : $failed   (check ESXi version / NVRAM)"
Write-Log "Errors        : $errors"
Write-Log "Skipped       : $skipped  (preflight / DC / BitLocker)"

if (@($allResults | Where-Object { $_.PK_Status -ne $null }).Count -gt 0) {
    $pkValid    = @($allResults | Where-Object { $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft") }).Count
    $pkOther    = @($allResults | Where-Object { $_.PK_Status -eq "Valid_Other" }).Count
    $pkEnrolled = @($allResults | Where-Object { $_.PKEnrolled -eq $true }).Count
    $pkFailed   = @($allResults | Where-Object { $_.PKEnrolled -eq $false -and $_.PK_Status -notin @("Valid_WindowsOEM","Valid_Microsoft","NotChecked") }).Count
    Write-Log "PK already valid  : $pkValid"
    Write-Log "PK placeholder    : $pkOther"
    Write-Log "PK enrolled OK    : $pkEnrolled"
    Write-Log "PK enroll failed  : $pkFailed"
}

# Notes for any VM that has them
$withNotes = @($allResults | Where-Object { $_.Notes -ne "" })
if ($withNotes.Count -gt 0) {
    Write-Log "---"
    Write-Log "NOTES:"
    foreach ($r in $withNotes) {
        Write-Log "  $($r.VMName): $($r.Notes)" "WARN"
    }
}

Write-Log "Output CSV: $OutputCsv" "OK"
Write-Log "Log file  : $LogFile"
Write-Log "Done."
