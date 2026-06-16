# seatbelt-extras.ps1 — light artifacts so Seatbelt has data to find for
# checks that depend on optional system features the lab doesn't carry by
# default. Run on win11-ssh as Administrator.

$ErrorActionPreference = 'Continue'

# 1. McAfee SiteList — drop a representative XML even though McAfee
#    isn't installed. SharpUp + Seatbelt both look for this file.
$mcafeeDir = 'C:\ProgramData\McAfee\Common Framework'
New-Item -ItemType Directory -Force -Path $mcafeeDir | Out-Null
$siteList = @'
<?xml version="1.0" encoding="UTF-8"?>
<ns:SiteLists xmlns:ns="naSiteList">
  <SiteList Default="1" Name="WfLab">
    <HttpSite Type="repository" Name="WfMirror" Order="1" Server="updates.example.com:80" Enabled="1" Local="0">
      <UserName>wfMcAfeeUser</UserName>
      <Password Encrypted="1">jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDA==</Password>
    </HttpSite>
  </SiteList>
</ns:SiteLists>
'@
$siteList | Set-Content -Path "$mcafeeDir\SiteList.xml" -Encoding UTF8
Write-Host "[+] $mcafeeDir\SiteList.xml dropped"

# 2. Edge user data dir for localuser (ChromiumPresence). Edge is installed
#    by default but the user data dir may not exist until first launch.
$edgeData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
New-Item -ItemType Directory -Force -Path $edgeData | Out-Null
if (-not (Test-Path "$edgeData\History")) {
    # 16-byte SQLite-ish stub so File.Exists is true; ChromiumPresence
    # surfaces the install path either way.
    [byte[]]@(0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00) `
        | Set-Content -Path "$edgeData\History" -Encoding Byte
}
Write-Host "[+] Edge user data dir + History stub at $edgeData"

# 3. Light AMSI provider plant — register a fake provider key so
#    Seatbelt AMSIProviders has something to find. We only register the
#    key (not a real CLSID); native Seatbelt prints the path either way.
$amsi = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{wf-lab-amsi-9999-0000-000000000001}'
New-Item -Path $amsi -Force | Out-Null
New-ItemProperty -Path $amsi -Name '(default)' -Value 'WfLab AMSI Provider' -Force | Out-Null
Write-Host "[+] AMSI provider stub registered"

Write-Host '[OK] Seatbelt extras complete'
