#requires -Version 7.0
# Exchange Online ONLY. Graph App Registration and certificate changes use
# native C# MSAL / Graph and must be separately verified first.
# No Graph PowerShell module, client secrets, OAuth tokens or Linux private keys.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][guid]$ClientId,
    [Parameter(Mandatory)][guid]$ApplicationObjectId,
    [Parameter(Mandatory)][guid]$EnterpriseAppObjectId,
    [Parameter(Mandatory)][string]$ApplicationName,
    [Parameter(Mandatory)][string]$CertificateSha256,
    [Parameter(Mandatory)][datetime]$CertificateExpiresUtc,
    [Parameter(Mandatory)][string]$ResultPath,
    [switch]$AppCreated,
    [switch]$EnterpriseAppCreated,
    [switch]$AddedCertificate,
    [switch]$PlanOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Mailbox = $Mailbox.Trim().ToLowerInvariant()
if ($TenantId -eq [guid]::Empty -or $ClientId -eq [guid]::Empty -or
    $ApplicationObjectId -eq [guid]::Empty -or $EnterpriseAppObjectId -eq [guid]::Empty) {
    throw 'exact_entra_object_identity_required'
}
if ($Mailbox -notmatch '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw 'invalid_mailbox'
}
if ($ApplicationName.Length -lt 3 -or $ApplicationName.Length -gt 90 -or
    $ApplicationName -match '[\x00-\x1F]') { throw 'invalid_application_name' }
if ($CertificateSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'invalid_certificate_sha256' }
if ($CertificateExpiresUtc.ToUniversalTime() -lt [datetime]::UtcNow.AddDays(3) -or
    $CertificateExpiresUtc.ToUniversalTime() -gt [datetime]::UtcNow.AddDays(366)) {
    throw 'invalid_certificate_expiry'
}
if (-not [IO.Path]::IsPathFullyQualified($ResultPath)) { throw 'absolute_result_required' }
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    throw 'exchange_online_management_module_required'
}
if ($PlanOnly) {
    Write-Output 'EXO_BOOTSTRAP_PREFLIGHT=exchange_module_available_no_changes'
    Write-Output 'CHANGES_APPLIED=no'
    return
}
if (-not $PSCmdlet.ShouldProcess("Tenant $TenantId / mailbox $Mailbox",
    'Configure exact Exchange Online scoped SMTP.SendAsApp role')) { return }
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$clientId = $ClientId
$serviceObjectId = $EnterpriseAppObjectId
$sha = $CertificateSha256
$app = [pscustomobject]@{ id = $ApplicationObjectId.ToString('D'); displayName = $ApplicationName }
$createdThisRun = [ordered]@{
    appRegistration = [bool]$AppCreated
    enterpriseApplication = [bool]$EnterpriseAppCreated
    exchangeServicePrincipal = $false
    managementScope = $false
    smtpRoleAssignment = $false
    mailboxTag = $false
    addedCertificate = [bool]$AddedCertificate
}
$folder = Split-Path -Parent $ResultPath
if ($folder -and -not (Test-Path -LiteralPath $folder)) {
    [void](New-Item -ItemType Directory -Path $folder -Force)
}
function Save-State([object]$state) {
    $tmp = $ResultPath + '.new'
    $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tmp -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $ResultPath -Force
}
try {
    Write-Host 'Connecting to Exchange Online with device authentication.'
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    # Even when Graph authentication used the selected tenant, EXO opens a separate
    # login session. Verify its actual TenantID BEFORE any Exchange mutations.
    $connections = @(Get-ConnectionInformation -ErrorAction Stop)
    if ($connections.Count -ne 1 -or -not $connections[0].TenantID -or
        [guid]$connections[0].TenantID -ne $TenantId) {
        throw 'Exchange Online tenant mismatch or ambiguous session. No Exchange settings were changed.'
    }
    $target = Get-Mailbox -Identity $Mailbox -ErrorAction Stop
    if ($target.PrimarySmtpAddress.ToString().ToLowerInvariant() -ne $Mailbox) {
        throw 'Use the mailbox PRIMARY SMTP address.'
    }
    # Multiple Linux hosts can share one Entra application but use DIFFERENT
    # mailboxes. RBAC scope names and tags must be unique for each mailbox.
    # These scopes are an APP-level union, not separate per-certificate grants.
    $appPrefix = 'LMR365-' + $clientId.ToString('N').Substring(0,16)
    $mailboxKey = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.Encoding]::UTF8.GetBytes($Mailbox))).Substring(0,16)
    $prefix = $appPrefix + '-' + $mailboxKey
    $tag = $prefix
    $existingTag = $target.CustomAttribute15
    if ($existingTag -eq $appPrefix) {
        # Preview 4 used an app-wide tag. Keep it for this already-configured
        # mailbox; never retag or remove its existing management scope.
        $prefix = $appPrefix
        $tag = $appPrefix
        Write-Host 'Preserving compatible legacy mailbox scope.'
    }
    if ($existingTag -and $existingTag -ne $tag) {
        throw 'CustomAttribute15 is already used on this mailbox; refusing to overwrite it.'
    }
    $others = @(Get-Recipient -Filter "CustomAttribute15 -eq '$tag'" -ResultSize Unlimited |
        Where-Object { $_.PrimarySmtpAddress.ToString().ToLowerInvariant() -ne $Mailbox })
    if ($others.Count -gt 0) { throw 'RBAC tag found on another recipient; refusing to broaden access.' }
    $sp = Get-ServicePrincipal -Identity $serviceObjectId.ToString() -ErrorAction SilentlyContinue
    if ($null -eq $sp) {
        New-ServicePrincipal -AppId $clientId.ToString() -ObjectId $serviceObjectId.ToString() `
            -DisplayName $ApplicationName | Out-Null
        $createdThisRun.exchangeServicePrincipal = $true
    } elseif ([guid]$sp.AppId -ne $clientId) { throw 'Exchange service principal mismatch.' }
    $scope = Get-ManagementScope -Identity $prefix -ErrorAction SilentlyContinue
    $filter = "CustomAttribute15 -eq '$tag'"
    if ($null -eq $scope) {
        New-ManagementScope -Name $prefix -RecipientRestrictionFilter $filter | Out-Null
        $createdThisRun.managementScope = $true
    } elseif ($scope.RecipientRestrictionFilter.ToString() -ne $filter) {
        throw 'Scope filter changed; refusing to continue.'
    }
    $assignmentName = $prefix + '-SMTP'
    $assignment = Get-ManagementRoleAssignment -Identity $assignmentName -ErrorAction SilentlyContinue
    if ($null -eq $assignment) {
        New-ManagementRoleAssignment -Name $assignmentName -App $serviceObjectId.ToString() `
            -Role 'Application SMTP.SendAsApp' -CustomResourceScope $prefix | Out-Null
        $createdThisRun.smtpRoleAssignment = $true
    } elseif ($assignment.Role.ToString() -ne 'Application SMTP.SendAsApp' -or
              $assignment.CustomResourceScope.ToString() -ne $prefix) {
        throw 'Unexpected existing role assignment.'
    }
    if (-not $existingTag) {
        Set-Mailbox -Identity $Mailbox -CustomAttribute15 $tag -ErrorAction Stop
        $createdThisRun.mailboxTag = $true
    }
    Set-CASMailbox -Identity $Mailbox -SmtpClientAuthenticationDisabled $false -ErrorAction Stop
    $auth = @(Test-ServicePrincipalAuthorization -Identity $serviceObjectId.ToString() -Resource $Mailbox)
    if (@($auth | Where-Object { $_.RoleName -eq 'Application SMTP.SendAsApp' -and $_.InScope -eq $true }).Count -lt 1) {
        throw 'Scoped Exchange SMTP authorization has not yet been verified as InScope.'
    }
    $state = [ordered]@{
        tenantId = $TenantId.ToString(); mailbox = $Mailbox
        displayName = $app.displayName
        applicationObjectId = [string]$app.id
        clientId = $clientId.ToString()
        enterpriseAppObjectId = $serviceObjectId.ToString()
        certificateSha256 = $sha; certificateExpiresUtc = $CertificateExpiresUtc.ToUniversalTime().ToString('o')
        rbacReady = $true
        createdObjectEvidence = [ordered]@{
            schema = 'linuxmailrelay365-created-object-hints/v1'
            # Local audit hint only, NEVER sufficient authorization to delete.
            exchangeServicePrincipalObjectId = $serviceObjectId.ToString('D')
            managementScopeName = $prefix
            roleAssignmentName = $assignmentName
            mailboxScopeTag = $tag
            createdThisRun = $createdThisRun
        }
    }
    Save-State $state
    Write-Host 'READY: Scoped Application SMTP.SendAsApp authorized for sender mailbox.'
    Write-Host 'CAUTION: Tenant Security Defaults or Conditional Access can still block SMTP AUTH.'
    Write-Host 'No Entra app permissions, Graph Mail.Send, refresh tokens or passwords were created.'
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
