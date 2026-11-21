#requires -Version 7.0
# EXACT tenant + ownership marker + reviewed live inventory required to modify.
# Never touch Entra applications, SPs, certs, Exchange RBAC, mailboxes or Linux.
[CmdletBinding()]
param(
  [ValidateSet('Review','Apply')][string]$Phase='Review',
  [ValidateSet('Enable','Disable','Rename','Delete')][string]$Operation='Disable',
  [guid]$TenantId=[guid]::Empty,
  [string]$ConnectorName='',
  [string]$ConnectorIdentity='',
  [string]$NewName='',
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
  [string]$identity,[string]$newName,[object[]]$all) {
  $lines=@($all | ForEach-Object { State-Line $_ } | Sort-Object)
  $payload=@(
    'linuxmailrelay365-connector-manage/v1',
    $tenant.ToString('D'),$operation,$name,$identity,$newName
  ) + $lines
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
  } else {
    throw 'unknown_cloud_connector_action'
  }
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
  $sha=Plan-Hash $TenantId $Operation $ConnectorName $ConnectorIdentity $NewName $all
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
