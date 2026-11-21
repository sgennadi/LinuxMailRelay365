#requires -Version 7.0
# Microsoft Graph v1.0 addKey ONLY: never PATCH keyCredentials/removeKey.
# Payload comes via protected local file; Linux private PEM/TPM key never leaves host.
[CmdletBinding()]
param(
  [ValidateSet('Preview','Apply')][string]$Action = 'Preview',
  [string]$InputPath = '',
  [string]$ResultPath = '',
  [string]$ExpectedSha256 = '',
  [string]$TypedConfirmation = '',
  [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Require([bool]$ok,[string]$code) { if (-not $ok) { throw $code } }
function Sha([byte[]]$raw) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
}
function Cert([string]$encoded) {
  Require ($encoded.Length -ge 350 -and $encoded.Length -le 32768 -and
    $encoded -cmatch '^[A-Za-z0-9+/]+={0,2}$') 'invalid_public_certificate_encoding'
  try {
    $raw = [Convert]::FromBase64String($encoded)
    Require ($raw.Length -ge 250 -and $raw.Length -le 24576) 'invalid_public_certificate_length'
    return [Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
  } catch { throw 'invalid_public_x509_certificate' }
}
function FromUrl64([string]$part) {
  Require ($part -cmatch '^[A-Za-z0-9_-]+$') 'invalid_jwt_encoding'
  $s = $part.Replace('-','+').Replace('_','/')
  return [Convert]::FromBase64String($s + ('=' * ((4 - ($s.Length % 4)) % 4)))
}
function Thumb($key) {
  $value = $key.customKeyIdentifier
  if ($value -is [byte[]]) { $raw = $value }
  elseif ($value -is [string]) {
    try { $raw = [Convert]::FromBase64String($value) }
    catch { throw 'graph_key_thumbprint_invalid' }
  } else { throw 'graph_key_thumbprint_absent' }
  Require ($raw.Length -eq 20) 'graph_key_thumbprint_invalid'
  return [Convert]::ToHexString([byte[]]$raw).ToLowerInvariant()
}
function Inventory($app) {
  $raw = @($app.keyCredentials | Where-Object { $null -ne $_ })
  Require ($raw.Count -le 40) 'graph_app_key_count_requires_manual_review'
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $items = [Collections.Generic.List[object]]::new()
  foreach ($key in $raw) {
    $id = ([guid]$key.keyId).ToString('D')
    Require ($seen.Add($id)) 'duplicate_graph_key_identifier'
    $items.Add([pscustomobject]@{
      id = $id
      type = [string]$key.type
      usage = [string]$key.usage
      thumb = Thumb $key
      start = [datetimeoffset]::Parse([string]$key.startDateTime).ToUniversalTime()
      end = [datetimeoffset]::Parse([string]$key.endDateTime).ToUniversalTime()
    })
  }
  return @($items.ToArray() | Sort-Object id)
}
function Plan($data,[string]$objectId,[object[]]$items,[datetimeoffset]$now,
              [string]$oldThumb,[string]$newThumb) {
  Require ($items.Count -ge 1) 'no_valid_existing_key_for_graph_addkey'
  $active = @($items | Where-Object {
    $_.thumb -ceq $oldThumb -and $_.type -eq 'AsymmetricX509Cert' -and
    $_.usage -eq 'Verify' -and $_.start -le $now -and $_.end -gt $now.AddMinutes(10)
  })
  Require ($active.Count -ge 1) 'current_certificate_not_valid_in_entra'
  Require (@($items | Where-Object { $_.thumb -ceq $newThumb }).Count -eq 0) 'new_certificate_already_registered'
  $lines = @($items | ForEach-Object {
    $start = $_.start.ToUniversalTime().ToString('o')
    $end = $_.end.ToUniversalTime().ToString('o')
    "$($_.id)|$($_.type)|$($_.usage)|$($_.thumb)|$start|$end"
  } | Sort-Object)
  $basis = @('lmr365-entra-cert/v1',$data.tenantId,$data.clientId,$objectId,
    $data.activeSha,$data.stageSha,$data.activeCertSha,$data.candidateCertSha,
    $oldThumb,$newThumb) + $lines
  return Sha ([Text.Encoding]::UTF8.GetBytes(($basis -join [char]10)))
}
function Verify-Pop([string]$jwt,[string]$objectId,$currentCertificate) {
  Require ($jwt.Length -ge 300 -and $jwt.Length -le 12000 -and
    $jwt -cmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') 'invalid_graph_proof'
  $chunks = $jwt.Split('.')
  try {
    $header = [Text.Encoding]::UTF8.GetString((FromUrl64 $chunks[0])) | ConvertFrom-Json -AsHashtable
    $claims = [Text.Encoding]::UTF8.GetString((FromUrl64 $chunks[1])) | ConvertFrom-Json -AsHashtable
    $signature = FromUrl64 $chunks[2]
  } catch { throw 'invalid_graph_proof' }
  Require ($header.alg -ceq 'RS256' -and $header.typ -ceq 'JWT') 'graph_proof_alg_invalid'
  $proofThumb = [Convert]::ToHexString([byte[]](FromUrl64 ([string]$header.x5t))).ToLowerInvariant()
  Require ($proofThumb -ceq $currentCertificate.Thumbprint.ToLowerInvariant()) 'graph_proof_not_current_cert'
  Require ($claims.aud -ceq '00000002-0000-0000-c000-000000000000' -and
    $claims.iss -ceq $objectId) 'graph_proof_wrong_app_or_audience'
  $nbf = [long]$claims.nbf
  $exp = [long]$claims.exp
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  Require ($exp -eq $nbf + 600 -and $nbf -le $now -and $now -lt $exp) 'graph_proof_expired'
  $bytes = [Text.Encoding]::ASCII.GetBytes(($chunks[0] + '.' + $chunks[1]))
  $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($currentCertificate)
  try {
    Require ($null -ne $rsa -and $rsa.VerifyData($bytes,$signature,
      [Security.Cryptography.HashAlgorithmName]::SHA256,
      [Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'graph_proof_signature_invalid'
  } finally { if ($null -ne $rsa) { $rsa.Dispose() } }
}
if ($SelfTest) {
  Require ((Sha ([Text.Encoding]::ASCII.GetBytes('abc'))).Length -eq 64) 'sha_selftest'
  Require ((FromUrl64 'YWJj').Length -eq 3) 'base64_selftest'
  Write-Output 'ENTRA_CERT_SELFTEST=pass'
  Write-Output 'CHANGES_APPLIED=no'
  return
}
Require ([IO.Path]::IsPathFullyQualified($InputPath) -and
  [IO.Path]::IsPathFullyQualified($ResultPath)) 'absolute_input_output_paths_required'
if ($Action -eq 'Preview') {
  Require (-not $ExpectedSha256 -and -not $TypedConfirmation) 'preview_cannot_have_write_options'
} else {
  Require ($ExpectedSha256 -cmatch '^[a-f0-9]{64}$' -and
    $TypedConfirmation -ceq 'ADD_REVIEWED_ENTRA_OAUTH_CERT') 'approved_sha_and_consent_required'
}
try {
  $raw = [IO.File]::ReadAllText($InputPath,[Text.Encoding]::UTF8)
  Require ($raw.Length -ge 500 -and $raw.Length -le 90000) 'certificate_input_size_invalid'
  $data = $raw | ConvertFrom-Json -AsHashtable
  $raw = $null
  if ($Action -eq 'Apply') { Remove-Item -LiteralPath $InputPath -Force -ErrorAction Stop }
  Require ($data.schema -ceq 'lmr365-entra-oauth-cert/v1') 'unrecognized_certificate_input'
  foreach ($name in @('tenantId','clientId','activeSha','stageSha',
                      'activeCertSha','candidateCertSha','activeDer','candidateDer')) {
    Require ($data.ContainsKey($name) -and [bool]$data[$name]) 'missing_certificate_input'
  }
  foreach ($name in @('tenantId','clientId')) {
    Require ([string]$data[$name] -cmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') 'invalid_tenant_or_client_id'
  }
  foreach ($name in @('activeSha','stageSha','activeCertSha','candidateCertSha')) {
    Require ([string]$data[$name] -cmatch '^[a-f0-9]{64}$') 'invalid_certificate_sha'
  }
  $oldCert = Cert ([string]$data.activeDer)
  $newCert = Cert ([string]$data.candidateDer)
  Require ((Sha $oldCert.RawData) -ceq $data.activeCertSha -and
    (Sha $newCert.RawData) -ceq $data.candidateCertSha) 'certificate_der_integrity_mismatch'
  $oldThumb = $oldCert.Thumbprint.ToLowerInvariant()
  $newThumb = $newCert.Thumbprint.ToLowerInvariant()
  Require ($oldThumb -cne $newThumb) 'old_and_new_certificate_same'
  $now = [datetimeoffset]::UtcNow
  Require ($oldCert.NotBefore.ToUniversalTime() -le $now -and
    $oldCert.NotAfter.ToUniversalTime() -gt $now.AddMinutes(10)) 'active_certificate_expired'
  Require ($newCert.NotBefore.ToUniversalTime() -le $now.AddMinutes(5) -and
    $newCert.NotAfter.ToUniversalTime() -gt $now.AddDays(1) -and
    ($newCert.NotAfter - $newCert.NotBefore).TotalDays -le 366) 'new_certificate_dates_invalid'
  $newRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($newCert)
  try {
    Require ($null -ne $newRsa -and $newRsa.KeySize -ge 2048) 'new_certificate_rsa2048_required'
  } finally { if ($null -ne $newRsa) { $newRsa.Dispose() } }
  if ($Action -eq 'Preview') { Require (-not $data.ContainsKey('proof')) 'proof_disallowed_in_preview' }
  else { Require ([bool]$data.proof) 'fresh_proof_required' }

  if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is required for PowerShell 7'
  }
  Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
  $scope = if ($Action -eq 'Preview') { 'Application.Read.All' } else { 'Application.ReadWrite.All' }
  Connect-MgGraph -TenantId ([string]$data.tenantId) -Scopes @($scope) -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
  $ctx = Get-MgContext -ErrorAction Stop
  Require ($null -ne $ctx -and $ctx.TenantId -eq $data.tenantId -and
    $ctx.AuthType -eq 'Delegated') 'graph_session_wrong_tenant_or_auth'
  # Exact appId lookup. This script never searches by display name.
  $uri = "/v1.0/applications(appId='$($data.clientId)')?" + '$select=id,appId,keyCredentials'
  $app = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
  Require ([string]$app.appId -ceq [string]$data.clientId) 'graph_wrong_app'
  $objectId = ([guid]$app.id).ToString('D')
  $before = @(Inventory $app)
  $planHash = Plan $data $objectId $before ([datetimeoffset]::UtcNow) $oldThumb $newThumb
  $report = [Collections.Generic.List[string]]::new()
  $report.Add('ENTRA_CERT_VERSION=1')
  $report.Add('ENTRA_CERT_TENANT=exact_match')
  $report.Add('ENTRA_CERT_APP=exact_client_id')
  $report.Add("ENTRA_CERT_OBJECT_ID=$objectId")
  $report.Add("ENTRA_CERT_PLAN_SHA256=$planHash")
  $report.Add('ENTRA_CERT_ACTIVE_KEY=valid')
  $report.Add('ENTRA_CERT_CANDIDATE=not_registered')
  $report.Add('ENTRA_CERT_EXISTING_KEYS_PRESERVED=yes')
  $report.Add('ENTRA_CERT_PRIVATE_KEY_EXPORTED=no')
  $report.Add('ENTRA_CERT_DELETE_EXISTING_KEYS=no')
  if ($Action -eq 'Preview') {
    $report.Add('ENTRA_CERT_ADDED=no')
    $report.Add('CHANGES_APPLIED=no')
  } else {
    Require ($planHash -ceq $ExpectedSha256) 'graph_inventory_changed_since_preview'
    $proof = [string]$data.proof
    Verify-Pop $proof $objectId $oldCert
    $data['proof'] = $null
    $body = @{
      keyCredential = @{
        type = 'AsymmetricX509Cert'
        usage = 'Verify'
        key = [Convert]::ToBase64String($newCert.RawData)
        displayName = 'LinuxMailRelay365 Hardware OAuth'
        startDateTime = $newCert.NotBefore.ToUniversalTime().ToString('o')
        endDateTime = $newCert.NotAfter.ToUniversalTime().ToString('o')
      }
      passwordCredential = $null
      proof = $proof
    } | ConvertTo-Json -Compress -Depth 7
    $proof = $null
    try {
      [void](Invoke-MgGraphRequest -Uri ("/v1.0/applications/$objectId/addKey") -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop)
    } catch { throw 'graph_addkey_failed_inspect_app_before_retry' }
    $body = $null
    $app2 = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
    $after = @(Inventory $app2)
    Require ($after.Count -eq ($before.Count + 1)) 'graph_addkey_may_have_succeeded_verify_manually'
    foreach ($entry in $before) {
      $same = @($after | Where-Object {
        $_.id -ceq $entry.id -and $_.thumb -ceq $entry.thumb -and
        $_.type -ceq $entry.type -and $_.usage -ceq $entry.usage -and
        $_.start -eq $entry.start -and $_.end -eq $entry.end
      })
      Require ($same.Count -eq 1) 'graph_existing_key_changed_manual_review_required'
    }
    Require (@($after | Where-Object {
      $_.thumb -ceq $newThumb -and $_.type -ceq 'AsymmetricX509Cert' -and $_.usage -ceq 'Verify'
    }).Count -eq 1) 'graph_new_certificate_not_verified_inspect_manually'
    $report.Add('ENTRA_CERT_ADDED=yes')
    $report.Add('ENTRA_CERT_EXISTING_KEYS_PRESERVED=yes')
    $report.Add('CHANGES_APPLIED=entra_addkey_only')
  }
  [IO.File]::WriteAllText($ResultPath,($report -join [Environment]::NewLine) +
    [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
} finally {
  if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
  }
}
