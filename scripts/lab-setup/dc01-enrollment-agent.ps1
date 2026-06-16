# dc01-enrollment-agent.ps1 — create a WfEnrollmentAgent template by
# duplicating the User template and adding the Certificate Request Agent
# EKU. Publish the new template to SEVENKINGDOMS-CA so Certify
# request-agent can enroll against it.
#
# Run on dc01-ssh as Domain Admin.

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$dn = (Get-ADRootDSE).defaultNamingContext
$tmplContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$dn"
$newName = 'WfEnrollmentAgent'
$newPath = "CN=$newName,$tmplContainer"

if (Get-ADObject -Filter "cn -eq '$newName'" -SearchBase $tmplContainer -ErrorAction SilentlyContinue) {
    Write-Host "[.] $newName template already exists"
} else {
    $user = Get-ADObject -Identity "CN=User,$tmplContainer" -Properties *
    # Build attribute hash from User template, override the identity-specific ones
    $other = @{}
    $skipKeys = @('cn','name','distinguishedName','displayName',
                  'msPKI-Cert-Template-OID','msPKI-Template-Schema-Version',
                  'objectClass','objectCategory','whenCreated','whenChanged',
                  'uSNCreated','uSNChanged','objectGUID','dSCorePropagationData',
                  'CanonicalName','PropertyCount','PropertyNames','ModifiedProperties',
                  'AddedProperties','RemovedProperties','isDeleted','RecycleBin')
    foreach ($p in $user.PSObject.Properties) {
        if ($skipKeys -contains $p.Name) { continue }
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [array] -and $v.Count -eq 0) { continue }
        $other[$p.Name] = $v
    }
    # Override identity + EKU + OID
    $other['displayName'] = $newName
    $other['msPKI-Cert-Template-OID'] = '1.3.6.1.4.1.311.21.8.999.1.2.3.4.999.1'
    # Certificate Request Agent EKU
    $other['pKIExtendedKeyUsage'] = @('1.3.6.1.4.1.311.20.2.1')
    # Make sure Domain Admins can enroll
    try {
        New-ADObject -Type 'pKICertificateTemplate' -Path $tmplContainer `
            -Name $newName -OtherAttributes $other -ErrorAction Stop
        Write-Host "[+] $newName template created"
    } catch {
        Write-Host "[!] New-ADObject failed: $_"
    }
}

# Grant Domain Admins enrollment permission (idempotent via dsacls)
dsacls $newPath /G 'sevenkingdoms\domainadmin:CA;Enroll' 2>&1 | Out-Null

# Publish to the CA
Write-Host '[*] Publishing template to SEVENKINGDOMS-CA'
$caCfg = 'kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA'
certutil -config $caCfg -SetCATemplates "+$newName" 2>&1 | Out-Null

# Verify
$pub = certutil -config $caCfg -CATemplates 2>&1 | Out-String
if ($pub -match $newName) {
    Write-Host "[+] $newName visible in CA template list"
} else {
    Write-Host "[!] $newName not yet visible (CA may need restart): $pub"
}
