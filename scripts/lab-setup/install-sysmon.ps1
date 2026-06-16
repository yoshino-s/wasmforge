# install-sysmon.ps1 — idempotent Sysmon install on win11-ssh as Administrator.
# Run via: labctl exec win11-ssh "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\localuser\\install-sysmon.ps1"

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Host '[.] Sysmon64 already installed'
} else {
    $dst = 'C:\Tools\Sysmon'
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Write-Host '[*] Downloading Sysmon'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
        -OutFile "$dst\Sysmon.zip" -UseBasicParsing
    Expand-Archive -Force "$dst\Sysmon.zip" -DestinationPath $dst
    Write-Host '[*] Downloading sysmon-modular config'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml' `
        -OutFile "$dst\sysmonconfig.xml" -UseBasicParsing
    & "$dst\Sysmon64.exe" -accepteula -i "$dst\sysmonconfig.xml"
    Write-Host '[+] Sysmon installed'
}

# Enable Process Creation auditing (EID 4688 in Security log)
# This unblocks Seatbelt ProcessCreationEvents.
auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable | Out-Null
Write-Host '[+] Process Creation auditing enabled (success+failure)'

# Enable PowerShell ScriptBlock logging (EID 4104) for Seatbelt PowerShellEvents
$psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $psKey -Force | Out-Null
New-ItemProperty -Path $psKey -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host '[+] PowerShell ScriptBlockLogging enabled'

# Generate representative events so the goldens won't be empty
Write-Host '[*] Generating sample events'
for ($i = 0; $i -lt 12; $i++) {
    Start-Process cmd.exe -ArgumentList '/c','exit','0' -Wait -WindowStyle Hidden
}
# Trigger a PowerShell script-block event
powershell -NoProfile -Command "Write-Output 'WfLab parity test event'; Get-Date" | Out-Null

Write-Host '[OK] Sysmon + audit + PS logging complete'
