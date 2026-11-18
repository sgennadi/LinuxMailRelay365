#requires -Version 7.0
# Review-first Microsoft 365 OnPremises Connector creation. NO tenant changes
# in Preview; Apply requires exact tenant, state SHA and explicit confirmation.
[CmdletBinding()]
param(
    [ValidateSet('Preview','Apply')][string]$Action = 'Preview',
    [guid]$TenantId = [guid]::Empty,
    [string]$AcceptedDomain = '',
    [string]$ConnectorName = '',
    [string]$PublicIpv4 = '',
    [string]$CertificateName = '',
    [string]$ExpectedSha256 = '',
    [string]$TypedConfirmation = '',
    [string]$ResultPath = '',
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Dns([string]$value) {
    return $value.Length -ge 4 -and $value.Length -le 253 -and
        $value -cmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'
}
function Test-PublicIPv4([string]$value) {
    $ip = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($value,[ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $b = $ip.GetAddressBytes()
    if ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and ($b[1] -eq 168 -or
            ($b[1] -eq 0 -and $b[2] -in @(0,2)))) -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or
            ($b[1] -eq 51 -and $b[2] -eq 100))) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return $false }
    return $true
}
function Fingerprint([guid]$tenant,[string]$domain,[string]$name,
                     [string]$ident,[object[]]$connectors) {
    $lines = @($connectors | ForEach-Object {
        $ips = @($_.SenderIPAddresses | ForEach-Object { [string]$_ } | Sort-Object) -join ','
        "$([string]$_.Identity)|$([string]$_.ConnectorType)|$([string]$_.Enabled)|$ips|$([string]$_.TlsSenderCertificateName)"
    } | Sort-Object)
    $nl = [Environment]::NewLine
    $payload = [string]::Join($nl,@('lmr365-connector/v1',$tenant.ToString('D'),
        $domain.ToLowerInvariant(),$name.ToLowerInvariant(),
        $ident.ToLowerInvariant(), [string]::Join($nl,$lines)))
    $raw = [System.Text.Encoding]::UTF8.GetBytes($payload)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
}
if ($SelfTest) {
    if (-not (Test-Dns 'smtp.example.org') -or (Test-Dns 'invalid domain') -or
        (Test-Dns '127.0.0.1') -or -not (Test-PublicIPv4 '8.8.8.8') -or
        (Test-PublicIPv4 '192.168.1.1') -or (Test-PublicIPv4 '203.0.113.10')) {
        throw 'Local connector selftest failed'
    }
    Write-Output 'EXO_CONNECTOR_MANAGER_SELF_TEST=pass'
    Write-Output 'CHANGES_APPLIED=no'
    return
}
if ($TenantId -eq [guid]::Empty -or -not (Test-Dns $AcceptedDomain) -or
    $ConnectorName.Length -lt 3 -or $ConnectorName.Length -gt 70 -or
    $ConnectorName -notmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{2,69}$' -or
    (([bool]$PublicIpv4) -eq ([bool]$CertificateName)) -or
    ($PublicIpv4 -and -not (Test-PublicIPv4 $PublicIpv4)) -or
    ($CertificateName -and -not (Test-Dns $CertificateName))) {
    throw 'Enter exact tenant, accepted domain, connector name, and one public IPv4 or TLS certificate DNS name.'
}
if ($Action -eq 'Apply' -and
    ($ExpectedSha256 -notmatch '^[a-f0-9]{64}$' -or
     $TypedConfirmation -cne 'CREATE_REVIEWED_M365_CONNECTOR')) {
    throw 'Reviewed connector SHA-256 and typed consent are required.'
}
if ($Action -eq 'Preview' -and ($ExpectedSha256 -or $TypedConfirmation)) {
    throw 'Preview does not accept write options.'
}
if (-not [System.IO.Path]::IsPathFullyQualified($ResultPath)) {
    throw 'An absolute result path is required.'
}
$opened = $false
try {
    if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) {
        throw 'Install ExchangeOnlineManagement for PowerShell 7.'
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    $sessions = @(Get-ConnectionInformation -ErrorAction Stop)
    if ($sessions.Count -eq 0) {
        Write-Host 'Sign into Exchange Online using your administrator Device Code.'
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        $opened = $true
        $sessions = @(Get-ConnectionInformation -ErrorAction Stop)
    }
    if ($sessions.Count -ne 1 -or -not $sessions[0].TenantID -or
        [guid]$sessions[0].TenantID -ne $TenantId) {
        throw 'Exchange session belongs to a different tenant.'
    }
    foreach ($name in @('Get-AcceptedDomain','Get-InboundConnector')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw 'Read permission for Exchange Connector / accepted domains missing.'
        }
    }
    $domains = @(Get-AcceptedDomain -ErrorAction Stop)
    $valid = @($domains | Where-Object {
        [string]$_.DomainName -eq $AcceptedDomain -and
        [string]$_.DomainType -in @('Authoritative','InternalRelay')
    })
    if ($valid.Count -ne 1) {
        throw 'The accepted domain is not verified in this tenant.'
    }
    $connectors = @(Get-InboundConnector -ErrorAction Stop)
    if ($connectors.Count -gt 500) { throw 'Connector count requires manual inspection.' }
    foreach ($item in $connectors) {
        if ([string]$item.Name -eq $ConnectorName) {
            throw 'Connector name already exists.'
        }
        if ($PublicIpv4) {
            foreach ($ip in @($item.SenderIPAddresses)) {
                $value = [string]$ip
                if ($value -eq $PublicIpv4 -or $value -eq "$PublicIpv4/32") {
                    throw 'Existing Connector claims the egress IPv4.'
                }
                if ($value.Contains('/')) {
                    throw 'Existing Connector contains an IP range; review overlap manually.'
                }
            }
        }
        if ($CertificateName -and
            [string]$item.TlsSenderCertificateName -eq $CertificateName) {
            throw 'Existing Connector has matching certificate identity.'
        }
    }
    $identity = if ($PublicIpv4) { "ip:$PublicIpv4" } else {
        "cert:$($CertificateName.ToLowerInvariant())"
    }
    $sha = Fingerprint $TenantId $AcceptedDomain $ConnectorName $identity $connectors
    $safe = [System.Collections.Generic.List[string]]::new()
    $safe.Add('EXO_CONNECTOR_PLAN=ready')
    $safe.Add('EXO_CONNECTOR_TENANT=exact_match')
    $safe.Add('EXO_CONNECTOR_ACCEPTED_DOMAIN=verified')
    $safe.Add("EXO_CONNECTOR_REVIEW_SHA256=$sha")
    $safe.Add('EXO_CONNECTOR_DELIVERY_VERIFIED=no')
    if ($Action -eq 'Preview') {
        $safe.Add('CHANGES_APPLIED=no')
    } else {
        if ($sha -cne $ExpectedSha256) { throw 'Exchange Connector state changed since Preview.' }
        if (-not (Get-Command New-InboundConnector -ErrorAction SilentlyContinue)) {
            throw 'No permissions to create Exchange Online inbound connectors.'
        }
        $options = @{
            Name = $ConnectorName
            ConnectorType = 'OnPremises'
            SenderDomains = $AcceptedDomain
            Enabled = $true
            CloudServicesMailEnabled = $false
            ErrorAction = 'Stop'
        }
        if ($PublicIpv4) { $options['SenderIPAddresses'] = @($PublicIpv4) }
        else { $options['TlsSenderCertificateName'] = $CertificateName }
        New-InboundConnector @options | Out-Null
        $created = @(Get-InboundConnector -Identity $ConnectorName -ErrorAction Stop)
        if ($created.Count -ne 1 -or
            [string]$created[0].ConnectorType -ne 'OnPremises' -or
            $created[0].Enabled -ne $true) {
            throw 'New Connector requires manual identity/permission inspection.'
        }
        $safe.Add('EXO_CONNECTOR_CREATED=yes')
        $safe.Add('CHANGES_APPLIED=tenant_new_connector_only')
    }
    # No cloud object IDs, connector names, actual IPs, mailbox addresses or tokens.
    [System.IO.File]::WriteAllText($ResultPath,
        ($safe -join [Environment]::NewLine) + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false))
}
finally {
    if ($opened) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}
