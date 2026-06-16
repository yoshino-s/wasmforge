# dc01-kerberoast-targets.ps1 — create kerberoastable + AS-REP-roastable users.
# Run on dc01-ssh as Domain Admin.
#
# Unblocks:
#   - Rubeus kerberoast (wf-svc-mssql)
#   - Rubeus asreproast (wf-noPreauth)
#   - SharpView Invoke-Kerberoast

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction Stop

# 1. Kerberoastable service account with SPN
if (-not (Get-ADUser -Filter "samAccountName -eq 'wf-svc-mssql'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name 'wf-svc-mssql' -SamAccountName 'wf-svc-mssql' `
        -AccountPassword (ConvertTo-SecureString 'WfSpnP@ss1!' -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true `
        -ServicePrincipalNames @('MSSQLSvc/wf-svc-mssql.sevenkingdoms.local:1433')
    Write-Host '[+] wf-svc-mssql created with MSSQLSvc SPN'
} else {
    # Ensure the SPN is set even if user pre-existed
    $u = Get-ADUser wf-svc-mssql -Properties servicePrincipalName
    if (-not $u.servicePrincipalName) {
        Set-ADUser wf-svc-mssql -ServicePrincipalNames @{Add='MSSQLSvc/wf-svc-mssql.sevenkingdoms.local:1433'}
        Write-Host '[+] wf-svc-mssql SPN added'
    } else {
        Write-Host '[.] wf-svc-mssql already configured'
    }
}

# 2. AS-REP-roastable user (DONT_REQUIRE_PREAUTH bit)
if (-not (Get-ADUser -Filter "samAccountName -eq 'wf-noPreauth'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name 'wf-noPreauth' -SamAccountName 'wf-noPreauth' `
        -AccountPassword (ConvertTo-SecureString 'WfAsrepP@ss1!' -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
    Set-ADAccountControl -Identity 'wf-noPreauth' -DoesNotRequirePreAuth $true
    Write-Host '[+] wf-noPreauth created with DONT_REQUIRE_PREAUTH'
} else {
    Set-ADAccountControl -Identity 'wf-noPreauth' -DoesNotRequirePreAuth $true
    Write-Host '[.] wf-noPreauth already exists; DONT_REQUIRE_PREAUTH reapplied'
}

# Verify
$svc = Get-ADUser wf-svc-mssql -Properties servicePrincipalName
$asr = Get-ADUser wf-noPreauth -Properties userAccountControl
Write-Host ("[VERIFY] wf-svc-mssql SPNs: {0}" -f ($svc.servicePrincipalName -join ', '))
Write-Host ("[VERIFY] wf-noPreauth UAC: {0} (0x{1:X})" -f $asr.userAccountControl, $asr.userAccountControl)
$preauthBit = [int]($asr.userAccountControl) -band 0x400000
Write-Host ("[VERIFY] DONT_REQUIRE_PREAUTH bit set: {0}" -f ($preauthBit -ne 0))
