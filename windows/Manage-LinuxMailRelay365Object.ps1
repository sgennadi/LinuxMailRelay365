#requires -Version 7.0
# EXACT tenant + ownership marker + reviewed live inventory required to modify.
# Never touch Entra applications, SPs, certs, Exchange RBAC, mailboxes or Linux.
[CmdletBinding()]
param(
  [ValidateSet('Review','Apply')][string]$Phase='Review',
  [ValidateSet('Enable','Disable','Rename','Delete','EditSettings')][string]$Operation='Disable',
  [guid]$TenantId=[guid]::Empty,
  [string]$ConnectorName='',
  [string]$ConnectorIdentity='',
  [string]$NewName='',
  [string]$NewSenderDomains='',
  [string]$NewPublicIps='',
  [string]$NewCertificateName='',
  [string]$BackupPath='',
  [string]$ExpectedSenderDomains='',
  [string]$ExpectedPublicIps='',
  [string]$ExpectedCertificateName='',
  [string]$ExpectedSha256='',
  [string]$TypedConfirmation='',
  [string]$ResultPath='',
  [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Require([bool]$ok,[string]$reason) { if (-not $ok) { throw $reason } }
function Identifier([string]$s,[int]$limit=256) {
  Require ($s.Length -ge 3 -and $s.Length -le $limit -and
           $s -notmatch '[\x00-\x1F\x7F]' -and
           $s -cmatch '^[A-Za-z0-9][A-Za-z0-9._ -]+$') 'invalid_cloud_connector_id'
  return $s
}
function State-Line($item) {
  $ip=@($item.SenderIPAddresses | ForEach-Object { [string]$_ } | Sort-Object)
  $domains=@($item.SenderDomains | ForEach-Object { [string]$_ } | Sort-Object)
  Require ($ip.Count -le 24 -and $domains.Count -le 40) 'unbounded_cloud_connector_state'
  $values=@(
    [string]$item.Identity,[string]$item.Name,[string]$item.ConnectorType,
    [string]$item.ConnectorSource,[string]$item.Enabled,[string]$item.Comment,
    [string]$item.TlsSenderCertificateName,[string]$item.RequireTls,
    [string]$item.RestrictDomainsToIPAddresses,
    [string]$item.RestrictDomainsToCertificate,
    [string]$item.CloudServicesMailEnabled,
    [string]$item.TreatMessagesAsInternal,
    ($ip -join ','),($domains -join ',')
  )
  Require (-not (@($values | Where-Object { $_.Length -gt 4096 -or
                  $_ -match '[\x00-\x1F\x7F]' }).Count -gt 0)) 'untrusted_connector_inventory'
  return ($values -join [char]31)
}
function Plan-Hash([guid]$tenant,[string]$operation,[string]$name,
  [string]$identity,[string]$newName,[object[]]$all,[string]$edit='') {
  $lines=@($all | ForEach-Object { State-Line $_ } | Sort-Object)
  $payload=@(
    'linuxmailrelay365-connector-manage/v1',
    $tenant.ToString('D'),$operation,$name,$identity,$newName
  ) + $lines
  if ($edit) { $payload += @('reviewed-settings/v1',$edit) }
  $bytes=[Text.Encoding]::UTF8.GetBytes(($payload -join [char]10))
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}
function Select-Target([object[]]$all,[string]$name,[string]$identity,[guid]$tenant) {
  $items=@($all | Where-Object { [string]$_.Name -ceq $name -and
                                [string]$_.Identity -ceq $identity })
  Require ($items.Count -eq 1) 'connector_identity_changed_or_missing'
  $item=$items[0]
  $stamp='LinuxMailRelay365/v1;tenant=' + $tenant.ToString('D')
  Require ([string]$item.Comment -ceq $stamp -and
           [string]$item.ConnectorType -eq 'OnPremises') 'connector_ownership_not_verified'
  return $item
}
function Action-Allowed($item,[string]$action,[string]$newName,[object[]]$all) {
  if ($action -eq 'Enable') {
    Require (-not [bool]$item.Enabled -and -not $newName) 'enable_requires_disabled_connector'
  } elseif ($action -eq 'Disable') {
    Require ([bool]$item.Enabled -and -not $newName) 'disable_requires_enabled_connector'
  } elseif ($action -eq 'Delete') {
    Require (-not [bool]$item.Enabled -and -not $newName) 'delete_requires_disabled_connector'
  } elseif ($action -eq 'Rename') {
    Require (-not [bool]$item.Enabled) 'rename_requires_disabled_connector'
    Require ($newName -cmatch '^LinuxMailRelay365[A-Za-z0-9._ -]{3,58}$' -and
             $newName -cne [string]$item.Name) 'rename_must_use_managed_name'
    Require (@($all | Where-Object { [string]$_.Name -eq $newName }).Count -eq 0) 'rename_name_already_in_use'
  } elseif ($action -eq 'EditSettings') {
    Require (-not [bool]$item.Enabled -and -not $newName) 'edit_requires_disabled_connector'
    Require (-not [bool]$item.CloudServicesMailEnabled -and -not [bool]$item.TreatMessagesAsInternal) 'hybrid_or_internal_trust_requires_manual_review'
  } else {
    throw 'unknown_cloud_connector_action'
  }
}
function Exact-Dns([string]$name) {
  return ($name.Length -ge 4 -and $name.Length -le 253 -and
    $name -cmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$' -and
    $name -notmatch '^\d+(?:\.\d+)+$')
}
function Public-IP([string]$value) {
  if ($value.EndsWith('/32')) { $value=$value.Substring(0,$value.Length-3) }
  Require ($value -cmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$') 'exact_public_ipv4_required'
  $ip=[Net.IPAddress]::None
  Require ([Net.IPAddress]::TryParse($value,[ref]$ip) -and
    $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
    $ip.ToString() -ceq $value) 'exact_public_ipv4_required'
  $b=$ip.GetAddressBytes()
  Require (-not ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or
    ($b[0] -eq 169 -and $b[1] -eq 254) -or
    ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
    ($b[0] -eq 192 -and ($b[1] -eq 168 -or ($b[1] -eq 0 -and $b[2] -in @(0,2)) -or ($b[1] -eq 88 -and $b[2] -eq 99))) -or
    ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
    ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or
    ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113))) 'nonpublic_ipv4_refused'
  return $value
}
function Exact-Domain-List([string]$csv) {
  Require ($csv.Length -gt 0 -and $csv.Length -le 10240) 'invalid_sender_domains'
  $rows=@($csv.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() })
  Require ($rows.Count -le 40) 'too_many_sender_domains'
  foreach ($row in $rows) { Require (Exact-Dns $row) 'exact_sender_domain_required' }
  Require (@($rows | Sort-Object -Unique).Count -eq $rows.Count) 'duplicate_sender_domain'
  return @($rows | Sort-Object)
}
function Exact-IP-List([string]$csv) {
  Require ($csv.Length -gt 0 -and $csv.Length -le 512) 'invalid_sender_ips'
  $rows=@($csv.Split(',') | ForEach-Object { Public-IP $_.Trim() })
  Require ($rows.Count -le 24 -and @($rows | Sort-Object -Unique).Count -eq $rows.Count) 'invalid_or_duplicate_sender_ips'
  return @($rows | Sort-Object)
}
function Certificate-Overlap([string]$existing,[string]$requested) {
  $existing=$existing.ToLowerInvariant()
  if (-not $existing) { return $false }
  if ($existing.StartsWith('*.')) {
    $suffix=$existing.Substring(2)
    if (-not (Exact-Dns $suffix)) { return $true }
    return ($requested -ceq $suffix -or $requested.EndsWith('.'+$suffix,[StringComparison]::Ordinal))
  }
  if (-not (Exact-Dns $existing)) { return $true }
  return ($existing -ceq $requested)
}
function Reviewed-Settings($current,[object[]]$all,[object[]]$accepted,[string]$domainCsv,[string]$ipCsv,[string]$certificate) {
  $domains=@(Exact-Domain-List $domainCsv)
  $oldDomains=@(Exact-Domain-List (@($current.SenderDomains | ForEach-Object { [string]$_ }) -join ','))
  $oldIps=@($current.SenderIPAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ })
  $oldCert=([string]$current.TlsSenderCertificateName).ToLowerInvariant()
  $certificate=$certificate.Trim().ToLowerInvariant()
  $ips=@()
  Require (($oldIps.Count -gt 0) -ne [bool]$oldCert) 'ambiguous_current_connector_identity'
  if ($oldCert) {
    Require ((Exact-Dns $oldCert) -and (Exact-Dns $certificate) -and -not $ipCsv -and [bool]$current.RequireTls) 'certificate_mode_must_be_preserved'
  } else {
    [void]@(Exact-IP-List ($oldIps -join ','))
    Require (-not $certificate -and [bool]$ipCsv) 'public_ip_mode_must_be_preserved'
    $ips=@(Exact-IP-List $ipCsv)
  }
  foreach ($domain in @($domains)+@($certificate | Where-Object { $_ })) {
    Require (@($accepted | Where-Object { [string]$_.DomainName -eq $domain -and
      [string]$_.DomainType -in @('Authoritative','InternalRelay') }).Count -eq 1) 'exact_accepted_domain_required'
  }
  foreach ($other in $all) {
    if ([string]$other.Identity -ceq [string]$current.Identity) { continue }
    if ($certificate) {
      Require (-not (Certificate-Overlap ([string]$other.TlsSenderCertificateName) $certificate)) 'certificate_identity_overlap'
    } else {
      foreach ($otherIp in @($other.SenderIPAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ })) {
        # Refuse ranges and unknown address syntax rather than guess overlap.
        $otherIp=$otherIp.Trim()
        if ($otherIp.EndsWith('/32')) { $otherIp=$otherIp.Substring(0,$otherIp.Length-3) }
        Require ($otherIp -cmatch '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') 'other_connector_ip_range_requires_manual_review'
        Require ($otherIp -notin $ips) 'public_ip_identity_overlap'
      }
    }
  }
  $oldCanonical=@()
  if ($oldIps.Count -gt 0) { $oldCanonical=@(Exact-IP-List ($oldIps -join ',')) }
  Require (($oldDomains -join ',') -cne ($domains -join ',') -or
    ($oldCanonical -join ',') -cne ($ips -join ',') -or $oldCert -cne $certificate) 'no_settings_change'
  return [ordered]@{senderDomains=$domains; senderIps=$ips; certificateName=$certificate}
}
function Write-Settings-Backup([string]$path,[guid]$tenant,[string]$sha,$current,$edit) {
  Require ([IO.Path]::IsPathFullyQualified($path)) 'private_backup_path_required'
  $file=Get-Item -LiteralPath $path -ErrorAction Stop
  Require (-not $file.PSIsContainer -and $file.Length -eq 0 -and
    -not ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'empty_private_backup_file_required'
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl=Get-Acl -LiteralPath $path
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  Require ($acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and
    $rules[0].IdentityReference -eq $sid -and
    $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
    ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData)) 'backup_acl_not_private'
  $snapshot=[ordered]@{schema='linuxmailrelay365-connector-settings-backup/v1'
    tenantId=$tenant.ToString('D'); reviewedSha256=$sha; utc=[DateTimeOffset]::UtcNow.ToString('o')
    identity=[string]$current.Identity; name=[string]$current.Name
    before=[ordered]@{enabled=[bool]$current.Enabled; senderDomains=@($current.SenderDomains | ForEach-Object { [string]$_ })
      senderIps=@($current.SenderIPAddresses | ForEach-Object { [string]$_ }); certificateName=[string]$current.TlsSenderCertificateName
      requireTls=[bool]$current.RequireTls; restrictDomainsToIPAddresses=[bool]$current.RestrictDomainsToIPAddresses
      restrictDomainsToCertificate=[bool]$current.RestrictDomainsToCertificate
      cloudServicesMailEnabled=[bool]$current.CloudServicesMailEnabled; treatMessagesAsInternal=[bool]$current.TreatMessagesAsInternal}
    proposed=$edit
  }
  $bytes=[Text.Encoding]::UTF8.GetBytes(($snapshot | ConvertTo-Json -Depth 6 -Compress))
  Require ($bytes.Length -gt 0 -and $bytes.Length -le 65536) 'invalid_backup_size'
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {
    Require ($stream.Length -eq 0) 'backup_already_used'
    $stream.Write($bytes,0,$bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
}
if ($SelfTest) {
  $tenant=[guid]'22222222-2222-4222-8222-222222222222'
  $sample=[pscustomobject]@{
    Identity='LinuxMailRelay365 Test'; Name='LinuxMailRelay365 Test'
    Comment=('LinuxMailRelay365/v1;tenant=' + $tenant.ToString('D'))
    ConnectorType='OnPremises'; ConnectorSource='Default'; Enabled=$false
    SenderIPAddresses=@('8.8.8.8'); SenderDomains=@('example.org')
    TlsSenderCertificateName=''; RequireTls=$false
    RestrictDomainsToIPAddresses=$true; RestrictDomainsToCertificate=$false
    CloudServicesMailEnabled=$false; TreatMessagesAsInternal=$false
  }
  $ok=Select-Target @($sample) $sample.Name $sample.Identity $tenant
  Action-Allowed $ok 'Delete' '' @($sample)
  Action-Allowed $ok 'Rename' 'LinuxMailRelay365 Renamed' @($sample)
  $sha=Plan-Hash $tenant 'Delete' $sample.Name $sample.Identity '' @($sample)
  Require ($sha -match '^[a-f0-9]{64}$') 'plan_hash_failed'
  try { [void](Select-Target @($sample) $sample.Name $sample.Identity ([guid]::NewGuid())); throw 'bad_selftest' }
  catch { Require ($_.Exception.Message -eq 'connector_ownership_not_verified') 'wrong_tenant_allowed' }
  $accepted=@([pscustomobject]@{DomainName='example.org';DomainType='Authoritative'},
    [pscustomobject]@{DomainName='relay.example.org';DomainType='InternalRelay'})
  Action-Allowed $ok 'EditSettings' '' @($sample)
  $edit=Reviewed-Settings $ok @($sample) $accepted 'example.org,relay.example.org' '8.8.4.4' ''
  Require ($edit.senderDomains.Count -eq 2 -and $edit.senderIps[0] -ceq '8.8.4.4') 'edit_settings_selftest_failed'
  $editSha=Plan-Hash $tenant 'EditSettings' $sample.Name $sample.Identity '' @($sample) ($edit | ConvertTo-Json -Compress)
  Require ($editSha -cne (Plan-Hash $tenant 'EditSettings' $sample.Name $sample.Identity '' @($sample) 'different')) 'edit_hash_not_bound'
  try { [void](Reviewed-Settings $ok @($sample) $accepted 'other.example.org' '8.8.4.4' ''); throw 'bad_selftest' }
  catch { Require ($_.Exception.Message -eq 'exact_accepted_domain_required') 'unaccepted_domain_allowed' }
  try { [void](Reviewed-Settings $ok @($sample) $accepted 'example.org' '10.0.0.1' ''); throw 'bad_selftest' }
  catch { Require ($_.Exception.Message -eq 'nonpublic_ipv4_refused') 'private_ip_allowed' }
  try { [void](Reviewed-Settings $ok @($sample) $accepted 'example.org' '' 'relay.example.org'); throw 'bad_selftest' }
  catch { Require ($_.Exception.Message -eq 'public_ip_mode_must_be_preserved') 'identity_mode_change_allowed' }
  Write-Output 'M365_CONNECTOR_OBJECT_MANAGER_SELF_TEST=pass'
  Write-Output 'CHANGES_APPLIED=no'
  return
}
Require ($TenantId -ne [guid]::Empty) 'tenant_required'
$ConnectorName=Identifier $ConnectorName 90
$ConnectorIdentity=Identifier $ConnectorIdentity 256
Require ([IO.Path]::IsPathFullyQualified($ResultPath)) 'absolute_result_required'
if ($Phase -eq 'Review') {
  Require (-not $ExpectedSha256 -and -not $TypedConfirmation) 'review_cannot_mutate'
} else {
  $required=if ($Operation -eq 'Delete') { 'DELETE_REVIEWED_LMR365_CONNECTOR' }
    else { 'MODIFY_REVIEWED_LMR365_CONNECTOR' }
  Require ($ExpectedSha256 -cmatch '^[a-f0-9]{64}$' -and
           $TypedConfirmation -ceq $required) 'reviewed_sha_and_typed_confirmation_required'
}
if ($Operation -ne 'Rename') { Require (-not $NewName) 'new_name_is_only_for_rename' }
if ($Operation -ne 'EditSettings') {
  Require (-not $NewSenderDomains -and -not $NewPublicIps -and -not $NewCertificateName -and -not $BackupPath -and
    -not $ExpectedSenderDomains -and -not $ExpectedPublicIps -and -not $ExpectedCertificateName) 'unexpected_edit_arguments'
} elseif ($Phase -eq 'Review') {
  Require (-not $BackupPath) 'review_cannot_create_backup'
} else {
  Require ([IO.Path]::IsPathFullyQualified($BackupPath)) 'backup_required_before_edit'
}
$opened=$false
try {
  Require ($null -ne (Get-Module -ListAvailable ExchangeOnlineManagement)) 'exchange_module_missing'
  Import-Module ExchangeOnlineManagement -ErrorAction Stop
  $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  if ($sessions.Count -eq 0) {
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    $opened=$true
    $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  }
  Require ($sessions.Count -eq 1 -and $sessions[0].TenantID -and
           ([guid]$sessions[0].TenantID) -eq $TenantId) 'wrong_exchange_tenant'
  $all=@(Get-InboundConnector -ResultSize 501 -ErrorAction Stop)
  Require ($all.Count -le 500) 'connector_inventory_unbounded'
  $current=Select-Target $all $ConnectorName $ConnectorIdentity $TenantId
  Action-Allowed $current $Operation $NewName $all
  $edit=$null
  $editJson=''
  if ($Operation -eq 'EditSettings') {
    # Reject stale UI inventory before review as well as before Apply.
    $oldDomains=@(Exact-Domain-List (@($current.SenderDomains | ForEach-Object { [string]$_ }) -join ','))
    $oldIps=@($current.SenderIPAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ })
    if ($oldIps.Count -gt 0) { $oldIps=@(Exact-IP-List ($oldIps -join ',')) }
    $expectedIps=@()
    if ($ExpectedPublicIps) { $expectedIps=@(Exact-IP-List $ExpectedPublicIps) }
    Require (($oldDomains -join ',') -ceq (@(Exact-Domain-List $ExpectedSenderDomains) -join ',') -and
      ($oldIps -join ',') -ceq ($expectedIps -join ',') -and
      ([string]$current.TlsSenderCertificateName).ToLowerInvariant() -ceq $ExpectedCertificateName.Trim().ToLowerInvariant()) 'selected_settings_changed_refresh_inventory'
    $accepted=@(Get-AcceptedDomain -ErrorAction Stop)
    $edit=Reviewed-Settings $current $all $accepted $NewSenderDomains $NewPublicIps $NewCertificateName
    $editJson=$edit | ConvertTo-Json -Depth 4 -Compress
  }
  $sha=Plan-Hash $TenantId $Operation $ConnectorName $ConnectorIdentity $NewName $all $editJson
  $out=[Collections.Generic.List[string]]::new()
  $out.Add('M365_CONNECTOR_MANAGE_TENANT=exact_match')
  $out.Add('M365_CONNECTOR_MANAGE_OWNERSHIP=tenant_marker_verified')
  $out.Add('M365_CONNECTOR_MANAGE_OPERATION=' + $Operation)
  $out.Add('M365_CONNECTOR_MANAGE_PLAN_SHA256=' + $sha)
  if ($Phase -eq 'Review') {
    $out.Add('M365_CONNECTOR_MANAGE_APPLIED=no')
    $out.Add('M365_CONNECTOR_MANAGE_POSTCHECK=not_run')
    $out.Add('CHANGES_APPLIED=no')
  } else {
    Require ($ExpectedSha256 -ceq $sha) 'connector_inventory_changed_review_again'
    if ($Operation -eq 'Enable') {
      Set-InboundConnector -Identity $ConnectorIdentity -Enabled $true -ErrorAction Stop
    } elseif ($Operation -eq 'Disable') {
      Set-InboundConnector -Identity $ConnectorIdentity -Enabled $false -ErrorAction Stop
    } elseif ($Operation -eq 'Rename') {
      Set-InboundConnector -Identity $ConnectorIdentity -Name $NewName -ErrorAction Stop
    } elseif ($Operation -eq 'EditSettings') {
      Write-Settings-Backup $BackupPath $TenantId $sha $current $edit
      $settings=@{Identity=$ConnectorIdentity; SenderDomains=[string[]]$edit.senderDomains; ErrorAction='Stop'}
      if ($edit.certificateName) { $settings['TlsSenderCertificateName']=$edit.certificateName }
      else { $settings['SenderIPAddresses']=[string[]]$edit.senderIps }
      Set-InboundConnector @settings
    } else {
      Remove-InboundConnector -Identity $ConnectorIdentity -Confirm:$false -ErrorAction Stop
    }
    $after=@(Get-InboundConnector -ResultSize 501 -ErrorAction Stop)
    Require ($after.Count -le 500) 'postcheck_connector_inventory_unbounded'
    if ($Operation -eq 'Delete') {
      Require (@($after | Where-Object { [string]$_.Name -ceq $ConnectorName -or
         [string]$_.Identity -ceq $ConnectorIdentity }).Count -eq 0) 'connector_deletion_not_verified'
    } else {
      $actualName=if ($Operation -eq 'Rename') { $NewName } else { $ConnectorName }
      $target=@($after | Where-Object { [string]$_.Name -ceq $actualName })
      Require ($target.Count -eq 1) 'connector_postcheck_not_unique'
      $stamp='LinuxMailRelay365/v1;tenant=' + $TenantId.ToString('D')
      Require ([string]$target[0].Comment -ceq $stamp -and
               [string]$target[0].ConnectorType -eq 'OnPremises') 'postcheck_ownership_changed'
      if ($Operation -eq 'EditSettings') {
        $updated=$target[0]
        Require ([string]$updated.Identity -ceq $ConnectorIdentity -and -not [bool]$updated.Enabled) 'edited_connector_identity_or_state_changed'
        $actualDomains=@(Exact-Domain-List (@($updated.SenderDomains | ForEach-Object { [string]$_ }) -join ','))
        $actualIps=@($updated.SenderIPAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ })
        if ($actualIps.Count -gt 0) { $actualIps=@(Exact-IP-List ($actualIps -join ',')) }
        Require (($actualDomains -join ',') -ceq ($edit.senderDomains -join ',') -and
          ($actualIps -join ',') -ceq ($edit.senderIps -join ',') -and
          ([string]$updated.TlsSenderCertificateName).ToLowerInvariant() -ceq $edit.certificateName) 'edited_values_not_verified'
        foreach ($field in @('RequireTls','RestrictDomainsToIPAddresses','RestrictDomainsToCertificate','CloudServicesMailEnabled','TreatMessagesAsInternal','ConnectorSource')) {
          Require ([string]$updated.$field -ceq [string]$current.$field) 'unreviewed_connector_setting_changed'
        }
        $beforeOthers=@($all | Where-Object { [string]$_.Identity -cne $ConnectorIdentity } | ForEach-Object { State-Line $_ } | Sort-Object)
        $afterOthers=@($after | Where-Object { [string]$_.Identity -cne $ConnectorIdentity } | ForEach-Object { State-Line $_ } | Sort-Object)
        Require (($beforeOthers -join [char]10) -ceq ($afterOthers -join [char]10)) 'other_connector_inventory_changed'
      }
      if ($Operation -eq 'Enable') { Require ([bool]$target[0].Enabled) 'connector_not_enabled' }
      if ($Operation -eq 'Disable' -or $Operation -eq 'Rename') {
        Require (-not [bool]$target[0].Enabled) 'connector_not_disabled'
      }
    }
    $out.Add('M365_CONNECTOR_MANAGE_APPLIED=yes')
    $out.Add('M365_CONNECTOR_MANAGE_POSTCHECK=passed')
    $out.Add('CHANGES_APPLIED=tenant_connector_only')
  }
  [IO.File]::WriteAllText($ResultPath,($out -join [Environment]::NewLine) +
    [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  Write-Output 'M365_CONNECTOR_MANAGE=completed'
}
finally {
  if ($opened) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
