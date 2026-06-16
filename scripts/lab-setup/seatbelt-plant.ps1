# seatbelt-plant.ps1 — idempotently plant artifacts Seatbelt enumerates.
# Run as Administrator on win11-ssh.

$ErrorActionPreference = 'Continue'
function Section($n) { Write-Host "==> $n" -ForegroundColor Cyan }
function Ok($m)      { Write-Host "    [+] $m" -ForegroundColor Green }
function Skip($m)    { Write-Host "    [.] $m" -ForegroundColor DarkGray }

# ---- WindowsVault: generic credential entries ----
Section 'WindowsVault (cmdkey generic credential)'
cmdkey /list 2>$null | Out-Null
# Add multiple representative entries
cmdkey /generic:WfLabVaultTarget /user:'WfVaultUser' /pass:'WfVaultP@ss1' | Out-Null
cmdkey /generic:LegacyGeneric:target=WfLegacyTarget /user:'WfLegacyUser' /pass:'WfLegacyP@ss2' | Out-Null
Ok 'WfLabVaultTarget + WfLegacyTarget generic credentials added'

# ---- NetworkShares: SMB share ----
Section 'NetworkShares (net share WfShare)'
$shareName = 'WfShare'
$sharePath = 'C:\Users\Public\WfSharedFolder'
New-Item -ItemType Directory -Path $sharePath -Force | Out-Null
net share $shareName=$sharePath /grant:Everyone,READ /remark:'WasmForge parity test share' 2>$null | Out-Null
Ok "Share $shareName -> $sharePath (Everyone:READ)"

# ---- RDP enable (for RDPSessions to be even more meaningful) ----
Section 'RDP'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Force | Out-Null
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Out-Null
Ok 'RDP enabled + firewall rule on'

Write-Host ''
Write-Host '[OK] Seatbelt plant complete.' -ForegroundColor Green
