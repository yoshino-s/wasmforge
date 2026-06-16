# sharpup-cleanup.ps1 — reverse the SharpUp plant. Run as Administrator.

$ErrorActionPreference = 'Continue'
function Section($n) { Write-Host "==> $n" -ForegroundColor Cyan }

Section 'AlwaysInstallElevated'
foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer',
                 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer')) {
    if (Test-Path $p) {
        Remove-ItemProperty -Path $p -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    }
}

Section 'CachedGPPPassword'
$gpp = Join-Path $env:ProgramData 'Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $gpp

Section 'HijackablePaths'
$hd = 'C:\WfHijackPath'
if (Test-Path $hd) { Remove-Item -Recurse -Force $hd }
$sysPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$cleaned = ($sysPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $hd }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $cleaned, 'Machine')

Section 'McAfeeSitelistFiles'
$m = Join-Path $env:ProgramData 'McAfee'
if (Test-Path $m) { Remove-Item -Recurse -Force $m }

Section 'ModifiableScheduledTaskFile'
schtasks /Delete /TN '\WfLab\WritableTaskExe' /F 2>$null | Out-Null
schtasks /Delete /TN '\WfLab' /F 2>$null | Out-Null
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Users\Public\WfWritableTask'

foreach ($svc in 'WfWeakBinarySvc','WfWeakRegSvc','WfWeakSvc','WfUnquotedSvc') {
    sc.exe delete $svc 2>$null | Out-Null
}
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Users\Public\WfWeakBinarySvc'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Program Files\Wf Unquoted Test'

Section 'RegistryAutoLogons'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($n in 'AutoAdminLogon','DefaultUserName','DefaultPassword','DefaultDomainName') {
    Remove-ItemProperty -Path $wl -Name $n -ErrorAction SilentlyContinue
}

Section 'RegistryAutoruns'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'WfAutorun' -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Users\Public\WfAutorun'

Section 'UnattendedInstallFiles'
Remove-Item -Force -ErrorAction SilentlyContinue 'C:\Windows\Panther\Unattend.xml'

Write-Host '[OK] SharpUp cleanup complete.' -ForegroundColor Green
