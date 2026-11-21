#requires -Version 7.0
# Read-only tenant object inventory. Prefixes are search hints, NOT ownership proof.
[CmdletBinding()]
param(
  [guid]$TenantId = [guid]::Empty,
  [guid]$ClientId = [guid]::Empty,
  [string]$ConnectorName = '',
  [string]$ResultPath = '',
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
function SafeGuid([object]$value) {
  $guid = [guid]::Empty
  Require ([guid]::TryParse([string]$value,[ref]$guid) -and $guid -ne [guid]::Empty) 'unsafe_cloud_guid'
  return $guid.ToString('D')
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
function CredentialRecord($key) {
  return [ordered]@{
    keyId=SafeGuid $key.keyId
    label=SafeText $key.displayName 128
    type=SafeText $key.type 32
    usage=SafeText $key.usage 32
    validFrom=([datetimeoffset]::Parse([string]$key.startDateTime)).ToUniversalTime().ToString('o')
    validUntil=([datetimeoffset]::Parse([string]$key.endDateTime)).ToUniversalTime().ToString('o')
  }
}
if ($SelfTest) {
  $test = ConnectorRecord ([pscustomobject]@{
    Identity='test-connector'; Name='LinuxMailRelay365 Test'
    ConnectorType='OnPremises'; Enabled=$true
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
  $cert = CredentialRecord ([pscustomobject]@{
    keyId='11111111-1111-4111-8111-111111111111'
    displayName='LinuxMailRelay365'; type='AsymmetricX509Cert'; usage='Verify'
    startDateTime='2026-01-01T00:00:00Z'; endDateTime='2027-01-01T00:00:00Z'
  })
  Require ($cert.keyId -eq '11111111-1111-4111-8111-111111111111') 'certificate_self_test_failed'
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
if ($graphRequested) {
  Require ($null -ne (Get-Module -ListAvailable Microsoft.Graph.Authentication)) 'graph_module_missing'
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
  changesApplied=$false
}
$graphOpened=$false
$exoOpened=$false
try {
  if ($graphRequested) {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Connect-MgGraph -TenantId $TenantId.ToString('D') -Scopes @('Application.Read.All') -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
    $graphOpened=$true
    $context=Get-MgContext -ErrorAction Stop
    Require ($null -ne $context -and ([guid]$context.TenantId) -eq $TenantId -and
      [string]$context.AuthType -eq 'Delegated') 'wrong_graph_tenant'
    $url="/v1.0/applications(appId='$($ClientId.ToString('D'))')?" + '$select=id,appId,displayName,keyCredentials'
    $app=Invoke-MgGraphRequest -Uri $url -Method GET -ErrorAction Stop
    Require (([guid]$app.appId) -eq $ClientId) 'wrong_graph_app'
    $inventory.application=[ordered]@{status='found';objectId=SafeGuid $app.id;name=SafeText $app.displayName}
    $certs=@($app.keyCredentials | Where-Object { $null -ne $_ })
    Require ($certs.Count -le 64) 'too_many_certificates'
    $inventory.certificates=@($certs | ForEach-Object { CredentialRecord $_ })
    try {
      $spUrl="/v1.0/servicePrincipals(appId='$($ClientId.ToString('D'))')?" + '$select=id,appId'
      $sp=Invoke-MgGraphRequest -Uri $spUrl -Method GET -ErrorAction Stop
      Require (([guid]$sp.appId) -eq $ClientId) 'wrong_enterprise_app'
      $inventory.enterpriseApplication=[ordered]@{status='found';objectId=SafeGuid $sp.id}
    } catch {
      # A missing object and a denied request are NOT equivalent: do not infer absence.
      $inventory.enterpriseApplication.status='unverified'
    }
  }
  Import-Module ExchangeOnlineManagement -ErrorAction Stop
  $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  if ($sessions.Count -eq 0) {
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    $exoOpened=$true
    $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
  }
  Require ($sessions.Count -eq 1 -and $sessions[0].TenantID -and
    ([guid]$sessions[0].TenantID) -eq $TenantId) 'wrong_exchange_tenant'
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
  if ($graphOpened) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}
