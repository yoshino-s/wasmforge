# rubeus-precache.ps1 — populate domainuser's LSA TGT cache.
#
# The SSH-spawned PowerShell session as domainuser does not get a TGT cached
# automatically (Windows OpenSSH uses NTLM, not Kerberos, for the login).
# Rubeus klist / triage / dump / logonsession all expect cached tickets, so
# we use a scheduled task running as domainuser that invokes native Rubeus
# with /ptt to atomically request a TGT and import it into the LSA cache for
# the resulting interactive session.
#
# Run from win11-ssh (localuser, admin) — scheduled task elevates to domainuser.

$ErrorActionPreference = 'Continue'

$task = '\WfLab\PreCacheTGT'
schtasks /Delete /TN $task /F 2>$null | Out-Null

# /ptt loads the TGT into the current process' session. Run the task with
# /RL HIGHEST so the process can write to LSA cache.
schtasks /Create /SC ONCE /ST 23:59 /TN $task `
    /RU 'sevenkingdoms\domainuser' /RP 'password' /RL HIGHEST `
    /TR 'C:\WfNative\native-Rubeus.exe asktgt /user:domainuser /password:password /domain:sevenkingdoms.local /ptt' /F | Out-Null
schtasks /Run /TN $task | Out-Null
Start-Sleep -Seconds 8

# Surface the result (best-effort verification — actual cache lives in
# the scheduled task's session, not ours).
Write-Host '[+] PreCacheTGT scheduled task triggered. Verify with:'
Write-Host '    labctl exec win11-domainuser klist'
