#requires -Version 7.0
<#
LinuxMailRelay365 read-only Microsoft 365 accepted-domain and inbound Connector audit.

Run inside an administrator-authenticated Exchange Online PowerShell session:
  Connect-ExchangeOnline -Device
  .\Test-LinuxMailRelay365OutboundMode.ps1 -Mode Connector -AcceptedDomain example.org -PublicIpv4 203.0.113.20
This script NEVER creates/changes connectors or tenant permissions. It never
claims end-to-end delivery or reproduces real tenant/connector identifiers.
#>
[CmdletBinding()]
param(
    [ValidateSet('Connector', 'DirectSend')][string]$Mode = 'DirectSend',
    [string]$AcceptedDomain = '',
    [string]$PublicIpv4 = '',
    [string]$CertificateName = '',
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status([string]$key, [string]$value) {
    if ($key -notmatch '^[A-Z][A-Z0-9_]{1,63}$' -or
        $value -notmatch '^[a-z0-9_]{1,90}$') {
        throw 'Unexpected status output.'
    }
    Write-Output "$key=$value"
}

function Test-VerifiedDomain([string]$Name) {
    if ($Name.Length -lt 4 -or $Name.Length -gt 253 -or
        $Name -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$') {
        return $false
    }
    $ip = [System.Net.IPAddress]::None
    return -not [System.Net.IPAddress]::TryParse($Name, [ref]$ip)
}

function Test-PublicIpv4([string]$Value) {
    $ip = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $b = $ip.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or
        $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and $b[1] -eq 168) -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)) {
        return $false
    }
    return $true
}

function Test-ConnectorHint([object]$Item, [string]$Ip, [string]$Cert) {
    # Conservative heuristic only. IP exact match is not a range allow check.
    if ($null -eq $Item -or [string]$Item.ConnectorType -ne 'OnPremises' -or
        $Item.Enabled -ne $true) {
        return $false
    }
    $hasIp = $false
    if ($Ip) {
        foreach ($address in @($Item.SenderIPAddresses)) {
            $raw = [string]$address
            if ($raw -eq $Ip -or $raw -eq "$Ip/32") {
                $hasIp = $true
            }
        }
    }
    $hasCert = $false
    if ($Cert -and $Item.PSObject.Properties.Name -contains 'TlsSenderCertificateName') {
        $hasCert = ([string]$Item.TlsSenderCertificateName).Equals(
            $Cert, [System.StringComparison]::OrdinalIgnoreCase)
    }
    return $hasIp -or $hasCert
}

if ($SelfTest) {
    if (-not (Test-VerifiedDomain 'smtp.example.org') -or
        (Test-VerifiedDomain '127.0.0.1') -or
        (Test-VerifiedDomain 'bad domain') -or
        (Test-PublicIpv4 '192.168.1.5') -or
        (Test-PublicIpv4 '10.0.0.7') -or
        (Test-PublicIpv4 '100.64.0.1')) {
        throw 'Outbound mode validation self-test failed.'
    }
    Write-Status 'EXO_OUTBOUND_AUDIT_SELF_TEST' 'pass'
    Write-Status 'CHANGES_APPLIED' 'no'
    return
}

if (-not (Test-VerifiedDomain $AcceptedDomain)) {
    throw 'Specify one valid accepted domain DNS name.'
}
if ($Mode -eq 'Connector' -and
    -not ((Test-PublicIpv4 $PublicIpv4) -or
          ($CertificateName -and (Test-VerifiedDomain $CertificateName)))) {
    throw 'Connector mode requires a declared public egress IPv4 or exact certificate DNS name.'
}
Write-Status 'EXO_OUTBOUND_MODE' $Mode.ToLowerInvariant()
Write-Status 'EXO_ACCEPTED_DOMAIN' 'not_verified'
Write-Status 'EXO_ONPREMISES_CONNECTOR' 'not_verified'
Write-Status 'EXO_CONNECTED_TENANT_IDENTITY' 'not_verified'
Write-Status 'EXO_DELIVERY' 'not_verified'
Write-Status 'CHANGES_APPLIED' 'no'

foreach ($cmd in @('Get-ConnectionInformation', 'Get-AcceptedDomain')) {
    if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) {
        Write-Status 'EXO_AUDIT_RESULT' 'exchange_online_session_required'
        return
    }
}
$connections = @(Get-ConnectionInformation -ErrorAction Stop)
if ($connections.Count -eq 0) {
    Write-Status 'EXO_AUDIT_RESULT' 'exchange_online_session_required'
    return
}
$domains = @(Get-AcceptedDomain -ErrorAction Stop)
$matchedDomain = $false
foreach ($item in $domains) {
    if ([string]$item.DomainName -eq $AcceptedDomain -and
        [string]$item.DomainType -in @('Authoritative', 'InternalRelay')) {
        $matchedDomain = $true
    }
}
Write-Status 'EXO_ACCEPTED_DOMAIN_OBSERVED' $(if ($matchedDomain) {'yes'} else {'no'})

if ($Mode -eq 'DirectSend') {
    Write-Status 'EXO_RECIPIENT_SCOPE' 'internal_only'
    Write-Status 'EXO_AUDIT_RESULT' 'read_only_tenant_domain_checked'
    return
}
if (-not (Get-Command -Name 'Get-InboundConnector' -ErrorAction SilentlyContinue)) {
    Write-Status 'EXO_AUDIT_RESULT' 'inbound_connector_permission_missing'
    return
}
$matchingCount = 0
$connectors = @(Get-InboundConnector -ErrorAction Stop)
foreach ($item in $connectors) {
    if (Test-ConnectorHint -Item $item -Ip $PublicIpv4 -Cert $CertificateName) {
        $matchingCount++
    }
}
Write-Status 'EXO_ONPREMISES_CONNECTOR_CANDIDATE' $(if ($matchingCount -gt 0) {'yes'} else {'no'})
Write-Status 'EXO_AUDIT_RESULT' 'manual_connector_policy_and_delivery_test_required'
