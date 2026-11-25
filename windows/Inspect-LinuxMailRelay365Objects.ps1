#requires -Version 7.0
# Exchange-only read-only inventory. Graph App/SP/certificate inspection now runs in native C#; prefixes are NOT ownership proof.
[CmdletBinding()]
param(
  [guid]$TenantId = [guid]::Empty,
  [guid]$ClientId = [guid]::Empty,
  [string]$ConnectorName = '',
  [string]$Mailbox = '',
  [guid]$EnterpriseObjectId = [guid]::Empty,
  [string]$ResultPath = '',
  [switch]$MailboxOnly,
  [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Require([bool]$value,[string]$message) { if (-not $value) { throw $message } }
function SafeText([object]$value,[int]$limit=128) {
  $text = [string]$value
  Require ($text.Length -le $limit -and $text -notmatch '[\x00-\x1F\x7F]') 'unsafe_cloud_text'
  return $text
}
function ConnectorRecord($item,[guid]$exactTenant = [guid]::Empty) {
  $ips = @($item.SenderIPAddresses | ForEach-Object { SafeText $_ 64 } | Sort-Object -Unique)
  $domains = @($item.SenderDomains | ForEach-Object { SafeText $_ 253 } | Sort-Object -Unique)
  Require ($ips.Count -le 24 -and $domains.Count -le 40) 'connector_inventory_unbounded'
  $marker = 'LinuxMailRelay365/v1;tenant=' + $exactTenant.ToString('D')
  $provenance = if ($exactTenant -ne [guid]::Empty -and
    [string]$item.Comment -ceq $marker -and
    [string]$item.ConnectorType -eq 'OnPremises') { 'verified' } else { 'unverified' }
  return [ordered]@{
    identity=SafeText $item.Identity 256
    name=SafeText $item.Name 90
    type=SafeText $item.ConnectorType 40
    enabled=[bool]$item.Enabled
    senderIps=$ips
    senderDomains=$domains
    tlsCertificateName=SafeText $item.TlsSenderCertificateName 253
    ownership=$provenance
  }
}
function SmtpPolicy($item,[bool]$allowInherit) {
  if ($null -eq $item) { return 'unverified' }
  $property = $item.PSObject.Properties['SmtpClientAuthenticationDisabled']
  if ($null -eq $property) { return 'unverified' }
  $v = $property.Value
  if ($null -eq $v) {
    if ($allowInherit) { return 'inherit' }
    return 'unverified'
  }
  if ($v -isnot [bool]) { return 'unverified' }
  if ($v) { return 'disabled' }
  return 'enabled'
}
function EffectiveSmtpPolicy([string]$organization,[string]$mailbox) {
  if ($mailbox -cin @('enabled','disabled')) { return $mailbox }
  if ($mailbox -ceq 'inherit' -and $organization -cin @('enabled','disabled')) { return $organization }
  return 'unverified'
}
function SmtpRbac($rows) {
  $items = @($rows)
  if ($items.Count -gt 256) { return 'unverified' }
  $matched = $false
  $inScope = $false
  foreach ($item in $items) {
    if ($null -eq $item -or $null -eq $item.PSObject.Properties['RoleName']) { return 'unverified' }
    if ([string]$item.RoleName -cne 'Application SMTP.SendAsApp') { continue }
    $matched = $true
    if ($null -eq $item.PSObject.Properties['InScope'] -or $item.InScope -isnot [bool]) { return 'unverified' }
    if ($item.InScope) { $inScope = $true }
  }
  if ($inScope) { return 'in_scope' }
  if ($matched) { return 'out_of_scope' }
  return 'no_smtp_role'
}
function AssertExactExchangeTenant([guid]$expected) {
  $current=@(Get-ConnectionInformation -ErrorAction Stop)
  Require ($current.Count -eq 1 -and $current[0].TenantID -and
    ([guid]$current[0].TenantID) -eq $expected) 'wrong_exchange_tenant'
}
function ReadSmtpMailboxAudit([guid]$exactTenant,[guid]$exactClient,[guid]$exactEnterprise,[string]$exactMailbox) {
  AssertExactExchangeTenant $exactTenant
  $audit=[ordered]@{
    mailbox=$exactMailbox; enterpriseObjectId=$exactEnterprise.ToString('D')
    mailboxIdentity='unverified'; organizationPolicy='unverified'
    mailboxPolicy='unverified'; effectivePolicy='unverified'
    exchangePrincipal='unverified'; smtpRbac='unverified'
  }
  try {
    $config=@(Get-TransportConfig -ErrorAction Stop)
    if ($config.Count -eq 1) { $audit.organizationPolicy=SmtpPolicy $config[0] $false }
  } catch { } # No raw error or permission-success inference.
  try {
    $target=@(Get-Mailbox -Identity $exactMailbox -ErrorAction Stop)
    if ($target.Count -eq 1 -and ([string]$target[0].PrimarySmtpAddress).ToLowerInvariant() -ceq $exactMailbox) {
      $audit.mailboxIdentity='verified'
    }
  } catch { }
  if ($audit.mailboxIdentity -ceq 'verified') {
    try {
      $cas=@(Get-CASMailbox -Identity $exactMailbox -ErrorAction Stop)
      if ($cas.Count -eq 1) { $audit.mailboxPolicy=SmtpPolicy $cas[0] $true }
    } catch { }
  }
  $audit.effectivePolicy=EffectiveSmtpPolicy $audit.organizationPolicy $audit.mailboxPolicy
  try {
    # The exact Graph Enterprise Application ID, not the app registration ID.
    $principal=@(Get-ServicePrincipal -Identity $exactEnterprise.ToString('D') -ErrorAction Stop)
    if ($principal.Count -eq 1 -and ([guid]$principal[0].AppId) -eq $exactClient -and
        ([guid]$principal[0].ObjectId) -eq $exactEnterprise) {
      $audit.exchangePrincipal='verified'
    }
  } catch { }
  if ($audit.exchangePrincipal -ceq 'verified' -and $audit.mailboxIdentity -ceq 'verified') {
    try {
      $authorization=@(Test-ServicePrincipalAuthorization -Identity $exactEnterprise.ToString('D') -Resource $exactMailbox -ErrorAction Stop)
      $audit.smtpRbac=SmtpRbac $authorization
    } catch { }
  }
  AssertExactExchangeTenant $exactTenant
  return $audit
}
if ($SelfTest) {
  Require ((SmtpPolicy ([pscustomobject]@{SmtpClientAuthenticationDisabled=$false}) $true) -ceq 'enabled') 'smtp_policy_enabled'
  Require ((SmtpPolicy ([pscustomobject]@{SmtpClientAuthenticationDisabled=$true}) $true) -ceq 'disabled') 'smtp_policy_disabled'
  Require ((SmtpPolicy ([pscustomobject]@{SmtpClientAuthenticationDisabled=$null}) $true) -ceq 'inherit') 'smtp_policy_inherit'
  Require ((SmtpPolicy ([pscustomobject]@{}) $true) -ceq 'unverified') 'smtp_missing_property'
  Require ((SmtpPolicy ([pscustomobject]@{SmtpClientAuthenticationDisabled='False'}) $true) -ceq 'unverified') 'smtp_string_not_bool'
  Require ((EffectiveSmtpPolicy 'disabled' 'enabled') -ceq 'enabled') 'smtp_mailbox_override'
  Require ((EffectiveSmtpPolicy 'enabled' 'disabled') -ceq 'disabled') 'smtp_mailbox_disable'
  Require ((EffectiveSmtpPolicy 'disabled' 'inherit') -ceq 'disabled') 'smtp_inherit_disabled'
  Require ((EffectiveSmtpPolicy 'enabled' 'unverified') -ceq 'unverified') 'smtp_unknown_not_inherited'
  Require ((SmtpRbac @()) -ceq 'no_smtp_role') 'smtp_no_role'
  $allowed=[pscustomobject]@{RoleName='Application SMTP.SendAsApp';InScope=$true}
  $outside=[pscustomobject]@{RoleName='Application SMTP.SendAsApp';InScope=$false}
  $unknown=[pscustomobject]@{RoleName='Application SMTP.SendAsApp';InScope='True'}
  Require ((SmtpRbac @($outside,$allowed)) -ceq 'in_scope') 'smtp_scope_union'
  Require ((SmtpRbac @($outside)) -ceq 'out_of_scope') 'smtp_outside_scope'
  Require ((SmtpRbac @($unknown)) -ceq 'unverified') 'smtp_bad_scope'
  Write-Output 'M365_SMTP_MAILBOX_POLICY_SELF_TEST=pass'
  $test = ConnectorRecord ([pscustomobject]@{
    Identity='test-connector'; Name='LinuxMailRelay365 Test'
    Comment=''; ConnectorType='OnPremises'; Enabled=$true
    SenderIPAddresses=@('8.8.8.8'); SenderDomains=@('example.org')
    TlsSenderCertificateName=''
  })
  Require ($test.enabled -and $test.senderIps.Count -eq 1 -and
           $test.ownership -eq 'unverified') 'connector_self_test_failed'
  $stampTenant = [guid]'22222222-2222-4222-8222-222222222222'
  $stamped = ConnectorRecord ([pscustomobject]@{
    Identity='test'; Name='LinuxMailRelay365 Managed'; Comment=('LinuxMailRelay365/v1;tenant=' + $stampTenant.ToString('D'))
    ConnectorType='OnPremises'; Enabled=$false
    SenderIPAddresses=@('8.8.8.8'); SenderDomains=@('example.org')
    TlsSenderCertificateName=''
  }) $stampTenant
  Require ($stamped.ownership -eq 'verified') 'connector_marker_self_test_failed'
  Write-Output 'M365_OBJECT_INSPECT_SELF_TEST=pass'
  Write-Output 'CHANGES_APPLIED=no'
  return
}
Require ($TenantId -ne [guid]::Empty) 'tenant_required'
Require ([IO.Path]::IsPathFullyQualified($ResultPath)) 'absolute_result_required'
Require ($ConnectorName.Length -le 70 -and (-not $ConnectorName -or
  $ConnectorName -cmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{2,69}$')) 'invalid_connector_name'
Require ($null -ne (Get-Module -ListAvailable ExchangeOnlineManagement)) 'exchange_module_missing'
$graphRequested = $ClientId -ne [guid]::Empty
$mailboxRequested = $Mailbox.Length -gt 0
Require ($mailboxRequested -eq ($EnterpriseObjectId -ne [guid]::Empty)) 'smtp_audit_selection_incomplete'
Require (-not $MailboxOnly -or ($mailboxRequested -and $graphRequested -and -not $ConnectorName)) 'mailbox_only_requires_exact_identity'
if ($mailboxRequested) {
  Require ($graphRequested -and $Mailbox.Length -le 254 -and $Mailbox -ceq $Mailbox.ToLowerInvariant() -and
    $Mailbox -cmatch '^[a-z0-9.!#$%&''*+/=?^_\x60{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -and
    -not $Mailbox.Contains('..')) 'smtp_audit_mailbox_invalid'
}
$inventory = [ordered]@{
  schema='linuxmailrelay365-cloud-objects/v1'
  tenantId=$TenantId.ToString('D')
  clientId=$(if ($graphRequested) { $ClientId.ToString('D') } else { '' })
  application=[ordered]@{ status='not_selected'; objectId=''; name='' }
  enterpriseApplication=[ordered]@{ status='not_selected'; objectId='' }
  certificates=@()
  connectors=@()
  scopes=@()
  roleAssignments=@()
  mailboxAudit=$null
  changesApplied=$false
}
$exoOpened=$false
try {
  Import-Module ExchangeOnlineManagement -ErrorAction Stop
  $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  if ($sessions.Count -eq 0) {
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    $exoOpened=$true
    $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  }
  Require ($sessions.Count -eq 1 -and $sessions[0].TenantID -and
    ([guid]$sessions[0].TenantID) -eq $TenantId) 'wrong_exchange_tenant'
  # A selected mailbox audit does not enumerate organization-wide connectors,
  # scopes or assignments. Their absence in this mode is not a deletion.
  if (-not $MailboxOnly) {
    $connectors=@(Get-InboundConnector -ResultSize 501 -ErrorAction Stop)
    Require ($connectors.Count -le 500) 'too_many_connectors'
    $selected=@($connectors | Where-Object {
      ([string]$_.Name).StartsWith('LinuxMailRelay365',[StringComparison]::OrdinalIgnoreCase) -or
      ($ConnectorName -and [string]$_.Name -ceq $ConnectorName)
    })
    Require ($selected.Count -le 100) 'too_many_matching_connectors'
    $inventory.connectors=@($selected | ForEach-Object { ConnectorRecord $_ $TenantId })
    if ($graphRequested) {
      $prefix='LMR365-' + $ClientId.ToString('N').Substring(0,16)
      $scopes=@(Get-ManagementScope -ErrorAction Stop)
      Require ($scopes.Count -le 3000) 'too_many_scopes'
      $matchingScopes=@($scopes | Where-Object {
        ([string]$_.Name).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)
      })
      Require ($matchingScopes.Count -le 100) 'too_many_matching_scopes'
      $inventory.scopes=@($matchingScopes | ForEach-Object {
        [ordered]@{name=SafeText $_.Name;filter=SafeText $_.RecipientRestrictionFilter 300}
      })
      $assignments=@(Get-ManagementRoleAssignment -ErrorAction Stop)
      Require ($assignments.Count -le 10000) 'too_many_assignments'
      $mine=@($assignments | Where-Object {
        ([string]$_.Name).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)
      })
      Require ($mine.Count -le 100) 'too_many_matching_assignments'
      $inventory.roleAssignments=@($mine | ForEach-Object {
        [ordered]@{name=SafeText $_.Name;role=SafeText $_.Role;scope=SafeText $_.CustomResourceScope}
      })
    }
  }
  if ($mailboxRequested) {
    $inventory.mailboxAudit=ReadSmtpMailboxAudit $TenantId $ClientId $EnterpriseObjectId $Mailbox
  }
  AssertExactExchangeTenant $TenantId
  $path=Split-Path -Parent $ResultPath
  if ($path -and -not (Test-Path -LiteralPath $path)) {
    [void](New-Item -ItemType Directory -Path $path -Force)
  }
  $json=$inventory | ConvertTo-Json -Depth 12 -Compress
  Require ($json.Length -le 300000) 'cloud_inventory_too_large'
  [IO.File]::WriteAllText($ResultPath,$json,[Text.UTF8Encoding]::new($false))
  Write-Output 'M365_OBJECT_INSPECT=read_only'
  Write-Output 'CHANGES_APPLIED=no'
}
finally {
  if ($exoOpened) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
