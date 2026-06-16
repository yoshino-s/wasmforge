# sharpdpapi-plant.ps1 — populate user-scope DPAPI artifacts for the
# domainuser profile so SharpDPAPI user-scope verbs (triage, masterkeys,
# credentials, vaults, rdg, certificates, blob, search) return real
# findings against the lab.
#
# Strategy: run a scheduled task as 'sevenkingdoms\domainuser' that
# performs ProtectedData.Protect (which forces master-key creation),
# adds cmdkey entries, drops an .rdg file, and imports a cert with a
# private key. The scheduled task runs in a session that triggers the
# normal DPAPI master-key initialization path.
#
# Run on win11-ssh as Administrator (the scheduled task elevates to
# domainuser via /RU /RP).

$ErrorActionPreference = 'Continue'

# Inner script that runs as domainuser
$inner = @'
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Security

# 1. Force user master key creation via DPAPI Protect.
try {
    $blob = [System.Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes('WfDpapiSecret-' + (Get-Date -Format "yyyy-MM-dd")),
        $null, 'CurrentUser')
    New-Item -ItemType Directory -Force -Path C:\WfLab\dpapi-user | Out-Null
    [IO.File]::WriteAllBytes('C:\WfLab\dpapi-user\blob.bin', $blob)
    "[+] dpapi-user blob written ($($blob.Length) bytes)" | Out-File C:\WfLab\dpapi-user\plant.log -Append
} catch {
    "[!] Protect failed: $_" | Out-File C:\WfLab\dpapi-user\plant.log -Append
}

# 2. Cached credentials (Credential Manager)
cmdkey /generic:WfDpapiTarget /user:WfDpapiUser /pass:WfCredP@ss1!  | Out-File C:\WfLab\dpapi-user\plant.log -Append
cmdkey /add:smb.example.com /user:WfSmbUser /pass:WfSmbP@ss2!         | Out-File C:\WfLab\dpapi-user\plant.log -Append

# 3. RDG file
$rdg = @"
<?xml version=`"1.0`" encoding=`"utf-8`"?>
<RDCMan programVersion=`"2.83`" schemaVersion=`"3`">
  <file>
    <properties>
      <name>WfLab</name>
    </properties>
    <server>
      <properties>
        <name>dc01.sevenkingdoms.local</name>
      </properties>
      <logonCredentials inherit=`"None`">
        <userName>domainadmin</userName>
        <password storeAsClearText=`"False`">WfLabRdgP@ssword</password>
      </logonCredentials>
    </server>
  </file>
</RDCMan>
"@
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Documents" | Out-Null
$rdg | Out-File -Encoding UTF8 "$env:USERPROFILE\Documents\WfLab.rdg"
"[+] WfLab.rdg dropped" | Out-File C:\WfLab\dpapi-user\plant.log -Append

# 4. Self-signed cert with exportable private key
try {
    $cert = New-SelfSignedCertificate -Subject 'CN=WfDpapiTestCert' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeyAlgorithm RSA -KeyLength 2048
    "[+] cert thumbprint $($cert.Thumbprint)" | Out-File C:\WfLab\dpapi-user\plant.log -Append
} catch {
    "[!] cert create failed: $_" | Out-File C:\WfLab\dpapi-user\plant.log -Append
}
'@

# Write inner script + ensure C:\WfLab exists
New-Item -ItemType Directory -Force -Path C:\WfLab\dpapi-user | Out-Null
icacls C:\WfLab /grant 'Everyone:(OI)(CI)F' | Out-Null
$inner | Out-File -Encoding UTF8 'C:\WfLab\dpapi-user\inner.ps1'
icacls 'C:\WfLab\dpapi-user\inner.ps1' /grant 'Everyone:R' | Out-Null

# Register the scheduled task
$task = '\WfLab\DpapiPlant'
schtasks /Delete /TN $task /F 2>$null | Out-Null
schtasks /Create /SC ONCE /ST 23:59 /TN $task `
    /RU 'sevenkingdoms\domainuser' /RP 'password' /RL HIGHEST `
    /TR 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\WfLab\dpapi-user\inner.ps1' /F | Out-Null
schtasks /Run /TN $task | Out-Null
Start-Sleep -Seconds 12

# Verify by reading the plant log
if (Test-Path C:\WfLab\dpapi-user\plant.log) {
    Write-Host '[+] Plant log:'
    Get-Content C:\WfLab\dpapi-user\plant.log
} else {
    Write-Host '[!] Plant log missing — task may not have run'
}

# Best-effort: surface task result
$result = schtasks /Query /TN $task /V /FO LIST 2>$null | Select-String 'Last Result'
Write-Host "[INFO] $result"
