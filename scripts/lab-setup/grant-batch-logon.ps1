# grant-batch-logon.ps1 — grant SeBatchLogonRight to sevenkingdoms\domainuser
# so the rubeus-precache scheduled task can launch as that user.
# Run on win11-ssh as Administrator.

$ErrorActionPreference = 'Continue'

# Export current local security policy
$cfg = "$env:TEMP\secpol.inf"
secedit /export /cfg $cfg /quiet
$content = Get-Content $cfg

# Find SeBatchLogonRight line and append the SID of domainuser if not present
$user = New-Object System.Security.Principal.NTAccount('sevenkingdoms', 'domainuser')
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "[*] sevenkingdoms\domainuser SID = $sid"

$updated = @()
$matched = $false
foreach ($line in $content) {
    if ($line -match '^SeBatchLogonRight\s*=\s*(.*)$') {
        $vals = $matches[1].Split(',') | ForEach-Object { $_.Trim() }
        if ($vals -notcontains "*$sid") {
            $vals += "*$sid"
            $updated += "SeBatchLogonRight = " + ($vals -join ',')
        } else {
            $updated += $line
        }
        $matched = $true
    } else {
        $updated += $line
    }
}
if (-not $matched) {
    # No existing entry — append in [Privilege Rights] section
    $newCfg = @()
    foreach ($line in $updated) {
        $newCfg += $line
        if ($line -match '^\[Privilege Rights\]') {
            $newCfg += "SeBatchLogonRight = *$sid"
        }
    }
    $updated = $newCfg
}

$updated | Set-Content -Path $cfg -Encoding Unicode

# Reapply
$db = "$env:TEMP\secedit.sdb"
secedit /configure /db $db /cfg $cfg /quiet
Remove-Item -Force $cfg, $db -ErrorAction SilentlyContinue
Write-Host '[+] SeBatchLogonRight granted to domainuser'
