#requires -Version 7.0
# Review-first Microsoft 365 OnPremises Connector creation. NO tenant changes
# in Preview; Apply requires exact tenant, state SHA and explicit confirmation.
[CmdletBinding()]
param(
    [ValidateSet('Inspect','Preview','Apply')][string]$Action = 'Preview',
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
    $ip = [System.Net.IPAddress]::None
    return ($value.Length -ge 4 -and $value.Length -le 253 -and
        $value -cmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' -and
        -not [System.Net.IPAddress]::TryParse($value,[ref]$ip))
}
function Test-PublicIPv4([string]$value) {
    $ip = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($value,[ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $ip.ToString() -cne $value) {
        return $false
    }
    $b = $ip.GetAddressBytes()
    if ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and ($b[1] -eq 168 -or
            ($b[1] -eq 0 -and $b[2] -in @(0,2)) -or
            ($b[1] -eq 88 -and $b[2] -eq 99))) -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or
            ($b[1] -eq 51 -and $b[2] -eq 100))) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return $false }
    return $true
}
function Get-CertificateOverlap([string]$existing, [string]$requested) {
    if (-not $existing) { return 'none' }
    if ($existing -ieq $requested) { return 'exact' }
    if ($existing.StartsWith('*.')) {
        $suffix = $existing.Substring(2)
        if (-not (Test-Dns $suffix)) { return 'unknown' }
        if ($requested -ieq $suffix -or $requested.EndsWith('.' + $suffix, [StringComparison]::OrdinalIgnoreCase)) {
            return 'wildcard'
        }
        return 'none'
    }
    if (Test-Dns $existing) { return 'none' }
    return 'unknown'
}
function Get-IPv4Overlap([string]$existing,[string]$requested) {
    # Exact addresses and /32 only; never assume a range is disjoint.
    if (-not $existing) { return 'unknown' }
    if ($existing.EndsWith('/32')) { $existing=$existing.Substring(0,$existing.Length-3) }
    $parsed=[System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($existing,[ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -cne $existing) { return 'unknown' }
    if ($existing -ceq $requested) { return 'exact' }
    return 'none'
}
function Fingerprint([guid]$tenant,[string]$domain,[string]$name,
                     [string]$ident,[object[]]$connectors) {
    $lines = @($connectors | ForEach-Object {
        $ips = @($_.SenderIPAddresses | ForEach-Object { [string]$_ } | Sort-Object) -join ','
        $senderDomains = @($_.SenderDomains | ForEach-Object { [string]$_ } | Sort-Object) -join ','
        "$([string]$_.Identity)|$([string]$_.Name)|$([string]$_.ConnectorType)|$([string]$_.Enabled)|$ips|$([string]$_.TlsSenderCertificateName)|$([string]$_.RequireTls)|$senderDomains|$([string]$_.CloudServicesMailEnabled)"
    } | Sort-Object)
    $nl = [Environment]::NewLine
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('lmr365-connector/v2')
    $parts.Add($tenant.ToString('D'))
    $parts.Add($domain.ToLowerInvariant())
    $parts.Add($name.ToLowerInvariant())
    $parts.Add($ident.ToLowerInvariant())
    $parts.Add([string]::Join($nl, [string[]]$lines))
    $payload = [string]::Join($nl, $parts.ToArray())
    $raw = [System.Text.Encoding]::UTF8.GetBytes($payload)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
}
if ($SelfTest) {
    if (-not (Test-Dns 'smtp.example.org') -or (Test-Dns 'invalid domain') -or
        (Test-Dns '127.0.0.1') -or -not (Test-PublicIPv4 '8.8.8.8') -or
        (Test-PublicIPv4 '192.168.1.1') -or (Test-PublicIPv4 '203.0.113.10')) {
        throw 'Local connector selftest failed'
    }
    if ((Get-CertificateOverlap '*.example.org' 'relay.example.org') -ne 'wildcard' -or
        (Get-CertificateOverlap 'relay.example.org' 'relay.example.org') -ne 'exact' -or
        (Get-CertificateOverlap '*.example.org' 'evil-example.org') -ne 'none' -or
        (Get-CertificateOverlap '<I>CN=Issuer<S>CN=example.org' 'relay.example.org') -ne 'unknown') {
        throw 'Certificate overlap selftest failed'
    }
    if ((Get-IPv4Overlap '8.8.8.8/32' '8.8.8.8') -ne 'exact' -or
        (Get-IPv4Overlap '8.8.4.4' '8.8.8.8') -ne 'none' -or
        (Get-IPv4Overlap '8.8.8.0/24' '8.8.8.8') -ne 'unknown' -or
        (Test-PublicIPv4 '127.1')) { throw 'IPv4 identity selftest failed' }
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
if ($Action -ne 'Apply' -and ($ExpectedSha256 -or $TypedConfirmation)) {
    throw 'Read-only actions do not accept write options.'
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
    if ($CertificateName) {
        $certificateDomains = @($domains | Where-Object {
            [string]$_.DomainName -eq $CertificateName -and
            [string]$_.DomainType -in @('Authoritative','InternalRelay')
        })
        if ($certificateDomains.Count -ne 1) {
            throw 'Certificate DNS identity must itself be an exact accepted domain. Review wildcard or subdomain policy manually.'
        }
    }
    $connectors = @(Get-InboundConnector -ErrorAction Stop)
    if ($connectors.Count -gt 500) { throw 'Connector count requires manual inspection.' }
    if ($Action -eq 'Inspect' -and $PublicIpv4) {
        $exact=0
        $compatible=0
        $conflicts=0
        $nameTaken=0
        foreach ($item in $connectors) {
            if ([string]$item.Name -ieq $ConnectorName) { $nameTaken++ }
            $ips=@($item.SenderIPAddresses | Where-Object { [string]$_ })
            $matches=@($ips | ForEach-Object { Get-IPv4Overlap ([string]$_) $PublicIpv4 })
            if ('unknown' -in $matches) { $conflicts++ }
            if ('exact' -in $matches) {
                $exact++
                $senderDomains=@($item.SenderDomains | ForEach-Object { [string]$_ })
                if ($ips.Count -eq 1 -and [string]$item.ConnectorType -eq 'OnPremises' -and
                    $item.Enabled -eq $true -and $item.CloudServicesMailEnabled -eq $false -and
                    $item.TreatMessagesAsInternal -eq $false -and
                    -not [string]$item.TlsSenderCertificateName -and $AcceptedDomain -in $senderDomains) {
                    $compatible++
                }
            }
        }
        $binding=if ($exact -eq 1 -and $compatible -eq 1 -and $conflicts -eq 0) {
            'exact_enabled_connector_observed'
        } elseif ($exact -eq 0 -and $conflicts -eq 0) {
            'no_matching_connector'
        } else { 'manual_review_required' }
        $lines=@('EXO_CONNECTOR_TENANT=exact_match','EXO_CONNECTOR_ACCEPTED_DOMAIN=verified',
            "EXO_CONNECTOR_PUBLIC_IPV4=$PublicIpv4","EXO_CONNECTOR_BINDING=$binding",
            "EXO_CONNECTOR_EXACT_COUNT=$exact","EXO_CONNECTOR_CONFLICT_COUNT=$conflicts",
            "EXO_CONNECTOR_NAME_TAKEN=$nameTaken",'EXO_CONNECTOR_DELIVERY_VERIFIED=no','CHANGES_APPLIED=no')
        [IO.File]::WriteAllText($ResultPath,($lines -join [Environment]::NewLine)+[Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        return
    }
    if ($Action -eq 'Inspect') {
        if (-not $CertificateName) { throw 'Inspect requires a certificate DNS identity.' }
        $exact = 0
        $compatible = 0
        $conflicts = 0
        $nameTaken = 0
        foreach ($item in $connectors) {
            if ([string]$item.Name -ieq $ConnectorName) { $nameTaken++ }
            $overlap = Get-CertificateOverlap ([string]$item.TlsSenderCertificateName) $CertificateName
            if ($overlap -eq 'exact') {
                $exact++
                $senderDomains = @($item.SenderDomains | ForEach-Object { [string]$_ })
                $ips = @($item.SenderIPAddresses | Where-Object { [string]$_ })
                if ([string]$item.ConnectorType -eq 'OnPremises' -and $item.Enabled -eq $true -and
                    $item.RequireTls -eq $true -and $item.CloudServicesMailEnabled -eq $false -and
                    $ips.Count -eq 0 -and $AcceptedDomain -in $senderDomains) {
                    $compatible++
                }
            } elseif ($overlap -in @('wildcard','unknown')) { $conflicts++ }
        }
        $binding = if ($exact -eq 1 -and $compatible -eq 1 -and $conflicts -eq 0) {
            'exact_enabled_connector_observed'
        } elseif ($exact -eq 0 -and $conflicts -eq 0) {
            'no_matching_connector'
        } else { 'manual_review_required' }
        $lines = @('EXO_CONNECTOR_TENANT=exact_match',
                   'EXO_CONNECTOR_ACCEPTED_DOMAIN=verified',
                   'EXO_CONNECTOR_CERTIFICATE_DOMAIN=verified',
                   "EXO_CONNECTOR_BINDING=$binding",
                   "EXO_CONNECTOR_EXACT_COUNT=$exact",
                   "EXO_CONNECTOR_CONFLICT_COUNT=$conflicts",
                   "EXO_CONNECTOR_NAME_TAKEN=$nameTaken",
                   'EXO_CONNECTOR_DELIVERY_VERIFIED=no','CHANGES_APPLIED=no')
        [System.IO.File]::WriteAllText($ResultPath,
            ($lines -join [Environment]::NewLine) + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false))
        return
    }
    foreach ($item in $connectors) {
        if ([string]$item.Name -eq $ConnectorName) {
            throw 'Connector name already exists.'
        }
        if ($PublicIpv4) {
            foreach ($ip in @($item.SenderIPAddresses)) {
                $value = [string]$ip
                $overlap=Get-IPv4Overlap $value $PublicIpv4
                if ($overlap -eq 'exact') {
                    throw 'Existing Connector claims the egress IPv4.'
                }
                if ($overlap -eq 'unknown') {
                    throw 'Existing Connector contains an IP range or unknown syntax; review overlap manually.'
                }
            }
        }
        if ($CertificateName -and
            (Get-CertificateOverlap ([string]$item.TlsSenderCertificateName) $CertificateName) -ne 'none') {
            throw 'Existing Connector has matching, wildcard or unrecognized certificate identity; review manually.'
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
        # New objects carry an exact tenant-bound provenance marker. Names
        # alone are never sufficient authority to edit/delete a Connector.
        $marker = 'LinuxMailRelay365/v1;tenant=' + $TenantId.ToString('D')
        $options = @{
            Name = $ConnectorName
            Comment = $marker
            ConnectorType = 'OnPremises'
            SenderDomains = $AcceptedDomain
            Enabled = $true
            CloudServicesMailEnabled = $false
            ErrorAction = 'Stop'
        }
        if ($PublicIpv4) { $options['SenderIPAddresses'] = @($PublicIpv4) }
        else {
            $options['TlsSenderCertificateName'] = $CertificateName
            $options['RequireTls'] = $true
        }
        New-InboundConnector @options | Out-Null
        $created = @(Get-InboundConnector -Identity $ConnectorName -ErrorAction Stop)
        if ($created.Count -ne 1 -or
            [string]$created[0].ConnectorType -ne 'OnPremises' -or
            $created[0].Enabled -ne $true -or
            [string]$created[0].Name -ne $ConnectorName -or
            [string]$created[0].Comment -cne $marker) {
            throw 'New Connector requires manual identity/permission inspection.'
        }
        $actualDomains = @($created[0].SenderDomains | ForEach-Object { [string]$_ })
        if ($AcceptedDomain -notin $actualDomains) {
            throw 'New Connector sender-domain scope differs from reviewed domain.'
        }
        if ($PublicIpv4) {
            $actualIps = @($created[0].SenderIPAddresses | ForEach-Object { [string]$_ })
            if ($actualIps.Count -ne 1 -or
                (Get-IPv4Overlap $actualIps[0] $PublicIpv4) -ne 'exact' -or
                [string]$created[0].TlsSenderCertificateName -or
                $created[0].CloudServicesMailEnabled -ne $false -or
                $created[0].TreatMessagesAsInternal -ne $false) {
                throw 'New Connector source IP differs from reviewed public egress identity.'
            }
        }
        elseif (-not [string]::Equals([string]$created[0].TlsSenderCertificateName,
                $CertificateName, [StringComparison]::OrdinalIgnoreCase) -or
                $created[0].RequireTls -ne $true -or
                @($created[0].SenderIPAddresses | Where-Object { [string]$_ }).Count -ne 0) {
            throw 'New Connector TLS identity or security settings differ from reviewed values.'
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
