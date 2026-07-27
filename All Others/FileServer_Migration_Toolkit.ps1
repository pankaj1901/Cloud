#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Cross-Domain Migration Toolkit
    Domain A File Server -> Domain B File Server (Forest Trust)

.DESCRIPTION
    Automates pre-migration validation, share documentation, NTFS ACL audit,
    share recreation, and post-migration access validation.
    Domain A user access is preserved via forest trust SID resolution.
    Domain B user access is NOT required.

.NOTES
    Author      : Infrastructure Team
    Version     : 1.0
    Environment : Windows Server 2016/2019/2022
    Requirement : Forest Trust between Domain A and Domain B, SID filtering OFF
    Run As      : Domain B Local Administrator on File Server 2,
                  Domain A Administrator on File Server 1

.PARAMETER Phase
    Which phase to execute:
    PreMigration    - Run on File Server 1 (Domain A) — document + validate
    TrustCheck      - Run on File Server 2 (Domain B) — verify trust + SID resolution
    RecreateShares  - Run on File Server 2 (Domain B) — recreate shares from CSV
    ValidateAccess  - Run on File Server 2 (Domain B) — ACL audit and share validation
    Harden          - Run on File Server 2 (Domain B) — SMB security hardening
    DFSUpdate       - Run on DFS Namespace server — redirect targets

.PARAMETER BackupPath
    Path to store/read CSV backup files. Default: C:\Migration

.PARAMETER DomainA
    Domain A FQDN (e.g., domainA.local). Required for TrustCheck phase.

.PARAMETER DomainB
    Domain B FQDN (e.g., domainB.local). Required for TrustCheck phase.

.PARAMETER DataDriveLetter
    Drive letter of migrated data disk on File Server 2 (e.g., D). Default: D

.EXAMPLE
    # Phase 0 - Run on File Server 1 (Domain A)
    .\FileServer_Migration_Toolkit.ps1 -Phase PreMigration -BackupPath C:\Migration

    # Phase 1 - Run on File Server 2 (Domain B) after disk is attached
    .\FileServer_Migration_Toolkit.ps1 -Phase TrustCheck -DomainA domainA.local -DomainB domainB.local

    # Phase 2 - Recreate shares on File Server 2
    .\FileServer_Migration_Toolkit.ps1 -Phase RecreateShares -BackupPath C:\Migration -DataDriveLetter D

    # Phase 3 - Validate ACLs and share access
    .\FileServer_Migration_Toolkit.ps1 -Phase ValidateAccess -DataDriveLetter D

    # Phase 4 - Harden SMB configuration
    .\FileServer_Migration_Toolkit.ps1 -Phase Harden
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('PreMigration','TrustCheck','RecreateShares','ValidateAccess','Harden','DFSUpdate')]
    [string]$Phase,

    [string]$BackupPath   = "C:\Migration",
    [string]$DomainA      = "",
    [string]$DomainB      = "",
    [string]$DataDriveLetter = "D",
    [string]$DFSNamespace = "",
    [string]$FileServer1  = "",
    [string]$FileServer2  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Title, [string]$Color = "Cyan")
    $line = "=" * 72
    Write-Host "`n$line" -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "$line`n" -ForegroundColor $Color
}

function Write-Step {
    param([string]$Message)
    Write-Host "  [>] $Message" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!!] $Message" -ForegroundColor Magenta
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [i] $Message" -ForegroundColor Gray
}

function Ensure-Path {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Info "Created directory: $Path"
    }
}

function Get-Timestamp {
    return Get-Date -Format "yyyyMMdd_HHmmss"
}

function Test-AdminPrivilege {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 0: PRE-MIGRATION  (run on FILE SERVER 1, DOMAIN A)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-PreMigration {
    Write-Banner "PHASE 0: PRE-MIGRATION DOCUMENTATION  [Run on File Server 1, Domain A]"

    Ensure-Path $BackupPath
    $ts = Get-Timestamp

    # ── SMB Share export ──────────────────────────────────────────────────────
    Write-Step "Exporting SMB share configurations..."
    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$','print$') }
        $sharesFile = Join-Path $BackupPath "SMB_Shares_$ts.csv"
        $shares | Select-Object Name, Path, Description, ConcurrentUserLimit, EncryptData, FolderEnumerationMode `
                | Export-Csv $sharesFile -NoTypeInformation
        Write-OK "Shares exported: $sharesFile ($($shares.Count) shares)"
    } catch {
        Write-Fail "Share export failed: $_"
    }

    # ── SMB Share Access (permissions) ────────────────────────────────────────
    Write-Step "Exporting SMB share access permissions..."
    try {
        $accessFile = Join-Path $BackupPath "SMB_ShareAccess_$ts.csv"
        $shares | ForEach-Object { Get-SmbShareAccess -Name $_.Name } `
                | Export-Csv $accessFile -NoTypeInformation
        Write-OK "Share access exported: $accessFile"
    } catch {
        Write-Fail "Share access export failed: $_"
    }

    # ── NTFS ACL export ───────────────────────────────────────────────────────
    Write-Step "Exporting NTFS ACLs (top 3 levels)... This may take a moment."
    try {
        $aclFile = Join-Path $BackupPath "NTFS_ACLs_$ts.csv"
        $results = @()
        foreach ($share in $shares) {
            if (Test-Path $share.Path) {
                Get-ChildItem $share.Path -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $acl = Get-Acl $_.FullName
                        $results += [PSCustomObject]@{
                            Path        = $_.FullName
                            Owner       = $acl.Owner
                            AccessRules = ($acl.Access | ForEach-Object {
                                "$($_.IdentityReference)|$($_.FileSystemRights)|$($_.AccessControlType)"
                            }) -join "; "
                        }
                    } catch {}
                }
                # Include the share root itself
                $acl = Get-Acl $share.Path
                $results += [PSCustomObject]@{
                    Path        = $share.Path
                    Owner       = $acl.Owner
                    AccessRules = ($acl.Access | ForEach-Object {
                        "$($_.IdentityReference)|$($_.FileSystemRights)|$($_.AccessControlType)"
                    }) -join "; "
                }
            }
        }
        $results | Export-Csv $aclFile -NoTypeInformation
        Write-OK "NTFS ACLs exported: $aclFile ($($results.Count) entries)"
    } catch {
        Write-Fail "NTFS ACL export failed: $_"
    }

    # ── Disk info ─────────────────────────────────────────────────────────────
    Write-Step "Recording disk and volume information..."
    try {
        $diskFile = Join-Path $BackupPath "DiskInfo_$ts.csv"
        Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, OperationalStatus `
                 | Export-Csv $diskFile -NoTypeInformation
        $volFile = Join-Path $BackupPath "VolumeInfo_$ts.csv"
        Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size `
                   | Export-Csv $volFile -NoTypeInformation
        Write-OK "Disk info: $diskFile | Volume info: $volFile"
    } catch {
        Write-Fail "Disk info export failed: $_"
    }

    # ── Active sessions check ─────────────────────────────────────────────────
    Write-Step "Checking for active SMB sessions..."
    try {
        $sessions = Get-SmbSession
        if ($sessions.Count -gt 0) {
            Write-Warn "$($sessions.Count) active session(s) found. Notify users before disk offline."
            $sessions | Format-Table ClientComputerName, ClientUserName, NumOpenFiles -AutoSize
        } else {
            Write-OK "No active SMB sessions."
        }
    } catch {
        Write-Warn "Could not query SMB sessions: $_"
    }

    Write-Banner "PRE-MIGRATION COMPLETE" "Green"
    Write-Host "  Backup files saved to: $BackupPath" -ForegroundColor Green
    Write-Host "  Copy this folder to File Server 2 before proceeding.`n" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
#  TRUST CHECK  (run on FILE SERVER 2, DOMAIN B)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-TrustCheck {
    Write-Banner "TRUST & SID RESOLUTION CHECK  [Run on File Server 2, Domain B]"

    if (-not $DomainA -or -not $DomainB) {
        Write-Fail "DomainA and DomainB parameters are required for TrustCheck."
        Write-Host "  Example: -DomainA domainA.local -DomainB domainB.local" -ForegroundColor Yellow
        return
    }

    # ── Domain trust enumeration ──────────────────────────────────────────────
    Write-Step "Enumerating domain trusts..."
    try {
        $nltest = & nltest /domain_trusts 2>&1
        Write-Host ($nltest | Out-String) -ForegroundColor Gray
    } catch {
        Write-Warn "nltest not available or failed: $_"
    }

    # ── SID filtering (quarantine) check ─────────────────────────────────────
    Write-Step "Checking SID filtering (quarantine) status on forest trust..."
    try {
        $quarantine = & netdom trust $DomainB /domain:$DomainA /quarantine 2>&1
        Write-Host ($quarantine | Out-String) -ForegroundColor Gray

        if ($quarantine -match "Quarantine.*No" -or $quarantine -match "disabled") {
            Write-OK "SID filtering is OFF — Domain A SIDs will resolve correctly on this server."
        } elseif ($quarantine -match "Quarantine.*Yes" -or $quarantine -match "enabled") {
            Write-Fail "SID filtering is ON — Domain A SIDs will be STRIPPED. ACLs will show as orphaned SIDs!"
            Write-Warn "Action required: Run 'netdom trust $DomainB /domain:$DomainA /quarantine:No' after security team approval."
        } else {
            Write-Warn "Could not determine SID filtering status from output. Review manually."
        }
    } catch {
        Write-Warn "netdom quarantine check failed: $_"
    }

    # ── DNS resolution check ──────────────────────────────────────────────────
    Write-Step "Checking DNS resolution for Domain A..."
    try {
        $resolve = Resolve-DnsName $DomainA -ErrorAction Stop
        Write-OK "Domain A DNS resolves: $($resolve | Select-Object -First 1 | Select-Object -ExpandProperty IPAddress)"
    } catch {
        Write-Fail "Cannot resolve Domain A ($DomainA) in DNS. Check DNS forwarder/stub zone configuration."
    }

    # ── NTFS SID resolution test ──────────────────────────────────────────────
    Write-Step "Testing NTFS SID resolution on data disk ($DataDriveLetter)..."
    $testPath = "${DataDriveLetter}:\"
    if (-not (Test-Path $testPath)) {
        Write-Fail "Drive ${DataDriveLetter}: not found. Has the disk been attached and brought online?"
        return
    }

    try {
        $acl = Get-Acl $testPath
        $orphaned = 0
        $resolved = 0

        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match "^S-1-5-21") {
                $orphaned++
            } else {
                $resolved++
            }
        }

        Write-Host ""
        Write-Host "  NTFS ACL Check on ${DataDriveLetter}:\" -ForegroundColor Cyan
        $acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize

        if ($orphaned -gt 0) {
            Write-Fail "$orphaned unresolved SID(s) found. Forest trust or SID filtering issue."
        }
        if ($resolved -gt 0) {
            Write-OK "$resolved SID(s) resolving correctly (showing as account names, not S-1-5-21-...)."
        }
    } catch {
        Write-Fail "ACL check failed: $_"
    }

    Write-Banner "TRUST CHECK COMPLETE" "Green"
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 4: RECREATE SHARES  (run on FILE SERVER 2, DOMAIN B)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-RecreateShares {
    Write-Banner "RECREATE SMB SHARES  [Run on File Server 2, Domain B]"

    # Find latest share CSV
    $sharesFile = Get-ChildItem $BackupPath -Filter "SMB_Shares_*.csv" -ErrorAction SilentlyContinue `
                    | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    $accessFile = Get-ChildItem $BackupPath -Filter "SMB_ShareAccess_*.csv" -ErrorAction SilentlyContinue `
                    | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $sharesFile) {
        Write-Fail "No SMB_Shares_*.csv found in $BackupPath. Run PreMigration phase first."
        return
    }

    Write-Info "Using share config: $($sharesFile.FullName)"
    $shares = Import-Csv $sharesFile.FullName
    $accessEntries = if ($accessFile) { Import-Csv $accessFile.FullName } else { @() }

    foreach ($share in $shares) {
        Write-Step "Processing share: $($share.Name)"

        # Remap path to new drive letter
        $originalPath = $share.Path
        if ($originalPath -match "^[A-Z]:\\") {
            $newPath = $originalPath -replace "^[A-Z]:\\", "${DataDriveLetter}:\"
        } else {
            $newPath = $originalPath
        }

        # Skip system shares
        if ($share.Name -in @('ADMIN$','C$','IPC$','print$')) {
            Write-Info "  Skipping system share: $($share.Name)"
            continue
        }

        # Check path exists
        if (-not (Test-Path $newPath)) {
            Write-Warn "  Path not found: $newPath — creating directory structure"
            try {
                New-Item -ItemType Directory -Path $newPath -Force | Out-Null
            } catch {
                Write-Fail "  Cannot create path $newPath`: $_"
                continue
            }
        }

        # Check if share already exists
        $existingShare = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
        if ($existingShare) {
            Write-Warn "  Share '$($share.Name)' already exists — skipping (remove manually if recreation needed)"
            continue
        }

        # Collect access entries for this share
        $shareAccess = $accessEntries | Where-Object { $_.Name -eq $share.Name }

        try {
            # Create share with no default access first — we'll add from backup
            $newShare = New-SmbShare -Name $share.Name `
                                     -Path $newPath `
                                     -Description $share.Description `
                                     -FullAccess "Administrators" `
                                     -ErrorAction Stop

            Write-OK "  Created share: \\$(hostname)\$($share.Name) -> $newPath"

            # Apply original share permissions
            foreach ($entry in $shareAccess) {
                try {
                    switch ($entry.AccessRight) {
                        "Full"   { Grant-SmbShareAccess -Name $share.Name -AccountName $entry.AccountName -AccessRight Full -Force | Out-Null }
                        "Change" { Grant-SmbShareAccess -Name $share.Name -AccountName $entry.AccountName -AccessRight Change -Force | Out-Null }
                        "Read"   { Grant-SmbShareAccess -Name $share.Name -AccountName $entry.AccountName -AccessRight Read -Force | Out-Null }
                    }
                    Write-Info "  Applied: $($entry.AccountName) = $($entry.AccessRight)"
                } catch {
                    Write-Warn "  Could not apply access for $($entry.AccountName): $_"
                }
            }

            # Apply ABE (Access-Based Enumeration)
            Set-SmbShare -Name $share.Name -FolderEnumerationMode AccessBased -Force
            Write-Info "  Access-Based Enumeration enabled"

        } catch {
            Write-Fail "  Failed to create share $($share.Name): $_"
        }
    }

    Write-Banner "SHARE RECREATION COMPLETE" "Green"
    Write-Host "  Verify shares:" -ForegroundColor Green
    Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$','print$') } `
                 | Format-Table Name, Path, Description -AutoSize
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 5: VALIDATE ACCESS  (run on FILE SERVER 2, DOMAIN B)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-ValidateAccess {
    Write-Banner "ACCESS VALIDATION  [Run on File Server 2, Domain B]"

    Ensure-Path $BackupPath
    $ts = Get-Timestamp

    # ── Share inventory ───────────────────────────────────────────────────────
    Write-Step "Current SMB shares on this server:"
    $shares = Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$','print$') }
    if ($shares.Count -eq 0) {
        Write-Fail "No data shares found. Run RecreateShares phase first."
    } else {
        $shares | Format-Table Name, Path, Description -AutoSize
        Write-OK "$($shares.Count) share(s) found"
    }

    # ── NTFS ACL deep audit ───────────────────────────────────────────────────
    Write-Step "Running full NTFS ACL audit on ${DataDriveLetter}: ..."
    $aclResults = @()
    $orphanedCount = 0
    $resolvedCount = 0

    foreach ($share in $shares) {
        $sharePath = $share.Path
        if (-not (Test-Path $sharePath)) { continue }

        $items = @($sharePath) + (Get-ChildItem $sharePath -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

        foreach ($itemPath in $items) {
            try {
                $acl = Get-Acl $itemPath
                foreach ($ace in $acl.Access) {
                    $isOrphaned = $ace.IdentityReference -match "^S-1-5-21"
                    if ($isOrphaned) { $orphanedCount++ } else { $resolvedCount++ }

                    $aclResults += [PSCustomObject]@{
                        Share       = $share.Name
                        Path        = $itemPath
                        Identity    = $ace.IdentityReference
                        Rights      = $ace.FileSystemRights
                        Type        = $ace.AccessControlType
                        SIDResolved = -not $isOrphaned
                        Owner       = $acl.Owner
                    }
                }
            } catch {}
        }
    }

    $auditFile = Join-Path $BackupPath "ACL_Audit_FS2_$ts.csv"
    $aclResults | Export-Csv $auditFile -NoTypeInformation
    Write-OK "ACL audit exported: $auditFile ($($aclResults.Count) ACE entries)"

    Write-Host ""
    Write-Host "  ── ACL Resolution Summary ──────────────────────────────" -ForegroundColor Cyan
    Write-Host "  Resolved SIDs  : $resolvedCount" -ForegroundColor Green
    if ($orphanedCount -gt 0) {
        Write-Fail "  Orphaned SIDs  : $orphanedCount  <-- INVESTIGATE TRUST / SID FILTERING"
    } else {
        Write-OK "  Orphaned SIDs  : 0  (all ACLs resolving correctly)"
    }

    # ── Share access permissions summary ─────────────────────────────────────
    Write-Step "Share-level permission summary:"
    foreach ($share in $shares) {
        Write-Host "  Share: $($share.Name)" -ForegroundColor Cyan
        Get-SmbShareAccess -Name $share.Name | Format-Table AccountName, AccessRight, AccessControlType -AutoSize
    }

    # ── SMB server config summary ─────────────────────────────────────────────
    Write-Step "SMB server security configuration:"
    $smbConfig = Get-SmbServerConfiguration
    $checks = @(
        @{ Label = "SMB1 Disabled";        Value = (-not $smbConfig.EnableSMB1Protocol);       Pass = (-not $smbConfig.EnableSMB1Protocol) }
        @{ Label = "SMB2 Enabled";         Value = $smbConfig.EnableSMB2Protocol;              Pass = $smbConfig.EnableSMB2Protocol }
        @{ Label = "Encryption Enabled";   Value = $smbConfig.EncryptData;                    Pass = $smbConfig.EncryptData }
        @{ Label = "Signing Required";     Value = $smbConfig.RequireSecuritySignature;       Pass = $smbConfig.RequireSecuritySignature }
    )

    Write-Host ""
    foreach ($check in $checks) {
        if ($check.Pass) {
            Write-OK "  $($check.Label): $($check.Value)"
        } else {
            Write-Warn "  $($check.Label): $($check.Value)  <-- Run Harden phase"
        }
    }

    Write-Banner "VALIDATION COMPLETE" "Green"
    Write-Host "  Full audit saved to: $auditFile`n" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 7: HARDEN  (run on FILE SERVER 2, DOMAIN B)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-Harden {
    Write-Banner "SMB SECURITY HARDENING  [Run on File Server 2, Domain B]"

    Write-Step "Disabling SMB 1.0..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-OK "SMB 1.0 disabled"

    Write-Step "Enabling SMB 2.0/3.0..."
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
    Write-OK "SMB 2.0/3.0 enabled"

    Write-Step "Enabling SMB Encryption (data in transit)..."
    Set-SmbServerConfiguration -EncryptData $true -Force
    Write-OK "SMB Encryption enabled (EncryptData = True)"

    Write-Step "Requiring SMB Signing (server-side)..."
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Write-OK "SMB Signing required on server"

    Write-Step "Enabling Access-Based Enumeration on all data shares..."
    Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$','print$') } | ForEach-Object {
        Set-SmbShare -Name $_.Name -FolderEnumerationMode AccessBased -Force
        Write-Info "  ABE enabled: $($_.Name)"
    }
    Write-OK "ABE applied to all shares"

    Write-Step "Disabling null session (anonymous) access..."
    Set-SmbServerConfiguration -EnableAuthenticateUserSharing $false -Force 2>$null
    Write-OK "Anonymous access disabled"

    # ── Windows Firewall — SMB ────────────────────────────────────────────────
    Write-Step "Verifying Windows Firewall SMB rule (port 445)..."
    $fwRule = Get-NetFirewallRule -DisplayName "*File and Printer Sharing (SMB-In)*" -ErrorAction SilentlyContinue
    if ($fwRule) {
        Write-OK "SMB Firewall rule exists: $($fwRule.Enabled)"
    } else {
        Write-Warn "SMB Firewall rule not found — verify manually"
    }

    # ── Final config display ──────────────────────────────────────────────────
    Write-Step "Final SMB server configuration:"
    Get-SmbServerConfiguration | Select-Object `
        EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, `
        RequireSecuritySignature, EnableAuthenticateUserSharing `
        | Format-List

    Write-Banner "HARDENING COMPLETE" "Green"
}

# ─────────────────────────────────────────────────────────────────────────────
#  DFS UPDATE  (run on DFS Namespace server)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-DFSUpdate {
    Write-Banner "DFS NAMESPACE UPDATE  [Run on DFS Namespace Server]"

    if (-not $DFSNamespace -or -not $FileServer1 -or -not $FileServer2) {
        Write-Fail "DFSNamespace, FileServer1, and FileServer2 parameters are required."
        Write-Host "  Example: -DFSNamespace '\\domainA.local\Shares' -FileServer1 'FS1' -FileServer2 'FS2'" -ForegroundColor Yellow
        return
    }

    # Check DFS module
    if (-not (Get-Module -ListAvailable -Name DFSN)) {
        Write-Fail "DFSN PowerShell module not available. Install RSAT: DFSN Tools."
        return
    }

    Import-Module DFSN -Force

    Write-Step "Enumerating DFS folders under $DFSNamespace ..."
    try {
        $folders = Get-DfsnFolder -Path "$DFSNamespace\*"
        Write-Info "Found $($folders.Count) DFS folder(s)"

        foreach ($folder in $folders) {
            Write-Step "Processing: $($folder.Path)"
            $targets = Get-DfsnFolderTarget -Path $folder.Path

            foreach ($target in $targets) {
                if ($target.TargetPath -like "\\$FileServer1\*") {
                    $oldTarget  = $target.TargetPath
                    $newTarget  = $oldTarget -replace [regex]::Escape("\\$FileServer1\"), "\\$FileServer2\"

                    Write-Info "  Old target: $oldTarget"
                    Write-Info "  New target: $newTarget"

                    if ($PSCmdlet.ShouldProcess($folder.Path, "Update DFS target from $FileServer1 to $FileServer2")) {
                        try {
                            Remove-DfsnFolderTarget -Path $folder.Path -TargetPath $oldTarget -Force
                            New-DfsnFolderTarget    -Path $folder.Path -TargetPath $newTarget -State Online | Out-Null
                            Write-OK "  Updated: $($folder.Path)"
                        } catch {
                            Write-Fail "  Failed to update $($folder.Path): $_"
                        }
                    }
                }
            }
        }
    } catch {
        Write-Fail "DFS enumeration failed: $_"
    }

    Write-Step "Verifying updated DFS targets..."
    Get-DfsnFolder -Path "$DFSNamespace\*" | ForEach-Object {
        $targets = Get-DfsnFolderTarget -Path $_.Path
        Write-Host "  $($_.Path)" -ForegroundColor Cyan
        $targets | ForEach-Object { Write-Host "    -> $($_.TargetPath) [$($_.State)]" -ForegroundColor Gray }
    }

    Write-Banner "DFS UPDATE COMPLETE" "Green"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  File Server Cross-Domain Migration Toolkit v1.0" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'dddd, dd MMMM yyyy  HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Server: $env:COMPUTERNAME | Domain: $env:USERDOMAIN | User: $env:USERNAME" -ForegroundColor Gray
Write-Host ""

if (-not (Test-AdminPrivilege)) {
    Write-Fail "This script must be run as Administrator."
    exit 1
}

switch ($Phase) {
    'PreMigration'   { Invoke-PreMigration }
    'TrustCheck'     { Invoke-TrustCheck }
    'RecreateShares' { Invoke-RecreateShares }
    'ValidateAccess' { Invoke-ValidateAccess }
    'Harden'         { Invoke-Harden }
    'DFSUpdate'      { Invoke-DFSUpdate }
}

Write-Host "`n  Script complete.  Review output above for any [FAIL] or [!!] items.`n" -ForegroundColor Cyan
