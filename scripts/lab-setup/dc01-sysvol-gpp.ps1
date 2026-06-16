# dc01-sysvol-gpp.ps1 — plant a SYSVOL Groups.xml containing a real
# cpassword for the DomainGPPPassword check (and similar tools).
# Run as DA on DC01 (kingslanding).
#
# Drops to a non-policy folder under SYSVOL so AD GP doesn't actually
# apply the GPP, but the file is reachable via the SYSVOL share for
# enumeration tooling.

$ErrorActionPreference = 'Continue'

$dom = 'sevenkingdoms.local'
$root = "C:\Windows\SYSVOL\sysvol\$dom\Policies\{ABCDEF12-0000-0000-0000-WFLAB000001}\Machine\Preferences\Groups"
New-Item -ItemType Directory -Path $root -Force | Out-Null

$xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="WfDomainGppUser"
        image="2"
        changed="2026-05-30 04:30:00"
        uid="{55555555-5555-5555-5555-555555555555}">
    <Properties action="C" fullName="" description="WasmForge lab planted GPP user"
        cpassword="2gOZNKgVPmIxJh6PA4t3MFFSrZ7gIp/yQfNvLrkBzJ4"
        changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0"
        userName="WfDomainGppUser"/>
  </User>
</Groups>
'@
$path = Join-Path $root 'Groups.xml'
$xml | Set-Content -Path $path -Encoding UTF8
Write-Host "[+] Planted SYSVOL Groups.xml at $path"
