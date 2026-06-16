# sharpup-plant.ps1 — idempotently plant SharpUp findings on the Win11 worker.
# Run as Administrator (localuser is in Administrators). After this runs,
# `SharpUp.exe audit <check>` as a low-priv user (e.g. domainuser) will
# produce non-empty findings for every supported check.
#
# Use sharpup-cleanup.ps1 to reverse.

$ErrorActionPreference = 'Continue'
$WarningPreference     = 'SilentlyContinue'

function Section($name) { Write-Host "==> $name" -ForegroundColor Cyan }
function Ok($msg)       { Write-Host "    [+] $msg" -ForegroundColor Green }
function Skip($msg)     { Write-Host "    [.] $msg" -ForegroundColor DarkGray }
function Warn($msg)     { Write-Host "    [!] $msg" -ForegroundColor Yellow }

# 1) AlwaysInstallElevated --------------------------------------------------
Section 'AlwaysInstallElevated (HKLM + HKCU)'
$paths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
)
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name 'AlwaysInstallElevated' -PropertyType DWord -Value 1 -Force | Out-Null
    Ok "$p\AlwaysInstallElevated = 1"
}

# 2) CachedGPPPassword ------------------------------------------------------
# Drop a Groups.xml under the local GPP history with a real cpassword blob.
# The cpassword below decrypts to "Local*P4ssword!" using the known
# AES key Microsoft published in MS14-025.
Section 'CachedGPPPassword (Local GPP history)'
$gppHistoryGuid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
$gppHistoryDir  = Join-Path $env:ProgramData "Microsoft\Group Policy\History\$gppHistoryGuid\Machine\Preferences\Groups"
New-Item -ItemType Directory -Path $gppHistoryDir -Force | Out-Null
$gppXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="WfLabUser"
        image="2" changed="2026-05-30 04:00:00" uid="{E5C0D7F1-3B59-4D0A-87E0-26F0E2A4BDFE}">
    <Properties action="C" fullName="" description="WasmForge planted lab user"
        cpassword="2gOZNKgVPmIxJh6PA4t3MFFSrZ7gIp/yQfNvLrkBzJ4"
        changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0"
        userName="WfLabUser"/>
  </User>
</Groups>
'@
$gppPath = Join-Path $gppHistoryDir 'Groups.xml'
$gppXml | Set-Content -Path $gppPath -Encoding UTF8
Ok "$gppPath dropped (cpassword present)"

# 3) HijackablePaths --------------------------------------------------------
Section 'HijackablePaths (writable PATH entry)'
$hijackDir = 'C:\WfHijackPath'
if (-not (Test-Path $hijackDir)) { New-Item -ItemType Directory -Path $hijackDir | Out-Null }
icacls $hijackDir /grant 'Everyone:(OI)(CI)F' | Out-Null
$sysPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (-not $sysPath.ToLower().Contains($hijackDir.ToLower())) {
    [Environment]::SetEnvironmentVariable('Path', $sysPath + ';' + $hijackDir, 'Machine')
    Ok "$hijackDir added to system PATH (Everyone:F)"
} else {
    Skip "$hijackDir already in PATH"
}

# 4) McAfeeSitelistFiles ----------------------------------------------------
Section 'McAfeeSitelistFiles'
$mcafeeDir = Join-Path $env:ProgramData 'McAfee\Common Framework'
New-Item -ItemType Directory -Path $mcafeeDir -Force | Out-Null
$siteListXml = @'
<?xml version="1.0" encoding="UTF-8"?>
<ns:SiteLists xmlns:ns="naSiteList">
  <SiteList Default="1" Name="SomeGUID">
    <HttpSite Type="repository" Name="WfMirror" Order="1" Server="updates.example.com:80"
              Enabled="1" Local="0">
      <UserName>wfMcAfeeUser</UserName>
      <Password Encrypted="1">jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDA==</Password>
    </HttpSite>
  </SiteList>
</ns:SiteLists>
'@
$siteListPath = Join-Path $mcafeeDir 'SiteList.xml'
$siteListXml | Set-Content -Path $siteListPath -Encoding UTF8
Ok "$siteListPath dropped"

# 5) ModifiableScheduledTaskFile --------------------------------------------
Section 'ModifiableScheduledTaskFile'
$taskDir = 'C:\Users\Public\WfWritableTask'
New-Item -ItemType Directory -Path $taskDir -Force | Out-Null
icacls $taskDir /grant 'Everyone:(OI)(CI)F' | Out-Null
$taskExe = Join-Path $taskDir 'runme.exe'
if (-not (Test-Path $taskExe)) {
    Copy-Item C:\Windows\System32\notepad.exe $taskExe -Force
}
icacls $taskExe /grant 'Everyone:F' | Out-Null
# create scheduled task pointing at world-writable exe
schtasks /Query /TN '\WfLab\WritableTaskExe' >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    schtasks /Create /SC ONSTART /TN '\WfLab\WritableTaskExe' /TR $taskExe /RU SYSTEM /F | Out-Null
    Ok "task \WfLab\WritableTaskExe -> $taskExe (Everyone:F)"
} else {
    Skip "scheduled task already exists"
}

# 6) ModifiableServiceBinaries ----------------------------------------------
Section 'ModifiableServiceBinaries (WfWeakBinarySvc)'
$svcDir = 'C:\Users\Public\WfWeakBinarySvc'
New-Item -ItemType Directory -Path $svcDir -Force | Out-Null
icacls $svcDir /grant 'Everyone:(OI)(CI)F' | Out-Null
$svcExe = Join-Path $svcDir 'svc.exe'
if (-not (Test-Path $svcExe)) { Copy-Item C:\Windows\System32\notepad.exe $svcExe -Force }
icacls $svcExe /grant 'Everyone:F' | Out-Null
sc.exe query WfWeakBinarySvc >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    sc.exe create WfWeakBinarySvc binPath= "`"$svcExe`"" start= demand | Out-Null
    Ok "WfWeakBinarySvc created (binary world-writable)"
} else {
    Skip "WfWeakBinarySvc exists"
}

# 7) ModifiableServiceRegistryKeys ------------------------------------------
Section 'ModifiableServiceRegistryKeys (WfWeakRegSvc)'
sc.exe query WfWeakRegSvc >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    sc.exe create WfWeakRegSvc binPath= 'C:\Windows\System32\notepad.exe' start= demand | Out-Null
    Ok "WfWeakRegSvc created"
}
# Grant Everyone full control on the service's registry key.
$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\WfWeakRegSvc'
$acl = Get-Acl $regKey
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    'Everyone', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl -Path $regKey -AclObject $acl
Ok "WfWeakRegSvc reg key granted Everyone:FullControl"

# 8) ModifiableServices -----------------------------------------------------
Section 'ModifiableServices (WfWeakSvc SCM ACL)'
sc.exe query WfWeakSvc >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    sc.exe create WfWeakSvc binPath= 'C:\Windows\System32\notepad.exe' start= demand | Out-Null
    Ok "WfWeakSvc created"
}
# SDDL grants Everyone all access (RP=start, WP=stop, DC=config, LC=enum, SW=interrogate, etc.)
sc.exe sdset WfWeakSvc 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)' | Out-Null
Ok "WfWeakSvc SCM ACL grants Everyone (WD) full access"

# 9) RegistryAutoLogons -----------------------------------------------------
Section 'RegistryAutoLogons'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
New-ItemProperty -Path $wl -Name 'AutoAdminLogon' -PropertyType String -Value '1'              -Force | Out-Null
New-ItemProperty -Path $wl -Name 'DefaultUserName' -PropertyType String -Value 'WfAutoLogonUser' -Force | Out-Null
New-ItemProperty -Path $wl -Name 'DefaultPassword' -PropertyType String -Value 'WfAutoLogonP@ss!' -Force | Out-Null
New-ItemProperty -Path $wl -Name 'DefaultDomainName' -PropertyType String -Value $env:COMPUTERNAME -Force | Out-Null
Ok 'AutoAdminLogon credentials planted'

# 10) RegistryAutoruns ------------------------------------------------------
Section 'RegistryAutoruns'
$runKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$runDir  = 'C:\Users\Public\WfAutorun'
$runExe  = Join-Path $runDir 'autorun.exe'
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
icacls $runDir /grant 'Everyone:(OI)(CI)F' | Out-Null
if (-not (Test-Path $runExe)) { Copy-Item C:\Windows\System32\notepad.exe $runExe -Force }
icacls $runExe /grant 'Everyone:F' | Out-Null
New-ItemProperty -Path $runKey -Name 'WfAutorun' -PropertyType String -Value $runExe -Force | Out-Null
Ok "Run\WfAutorun -> $runExe (Everyone:F)"

# 11) UnattendedInstallFiles ------------------------------------------------
Section 'UnattendedInstallFiles'
$pantherDir = 'C:\Windows\Panther'
New-Item -ItemType Directory -Path $pantherDir -Force | Out-Null
$unattend = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        language="neutral"
        versionScope="nonSxS"
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <AutoLogon>
        <Password>
          <Value>WfUnattendP@ssw0rd!</Value>
          <PlainText>true</PlainText>
        </Password>
        <Username>WfUnattendUser</Username>
        <Enabled>true</Enabled>
      </AutoLogon>
    </component>
  </settings>
</unattend>
'@
$unattend | Set-Content -Path (Join-Path $pantherDir 'Unattend.xml') -Encoding UTF8
Ok 'C:\Windows\Panther\Unattend.xml planted'

# 12) UnquotedServicePath ---------------------------------------------------
Section 'UnquotedServicePath (WfUnquotedSvc)'
$uqDir = 'C:\Program Files\Wf Unquoted Test'
New-Item -ItemType Directory -Path $uqDir -Force | Out-Null
$uqExe = Join-Path $uqDir 'svc.exe'
if (-not (Test-Path $uqExe)) { Copy-Item C:\Windows\System32\notepad.exe $uqExe -Force }
sc.exe query WfUnquotedSvc >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    # NOTE: deliberately no surrounding quotes around binPath value:
    sc.exe create WfUnquotedSvc binPath= "$uqExe" start= demand | Out-Null
    Ok "WfUnquotedSvc created with unquoted path containing space"
} else {
    Skip "WfUnquotedSvc exists"
}

Write-Host ''
Write-Host '[OK] SharpUp plant complete.' -ForegroundColor Green
