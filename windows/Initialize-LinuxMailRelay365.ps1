# LinuxMailRelay365 | One-time app provisioning and safe multi-server certificate addition.
# Linux private keys NEVER leave their server. Script handles PUBLIC X.509 certificates only.
# Administrator signs in interactively via Microsoft Graph and Exchange Online PowerShell.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$CertificatePath,
    [Parameter(Mandatory)][string]$ResultPath,
    [ValidateLength(3, 90)][string]$ApplicationName = 'Linux Mail Relay 365',
    [ValidateLength(3, 90)][string]$CertificateLabel = 'LinuxMailRelay365 server',
    [guid]$ExistingAppId = [guid]::Empty,
    [switch]$PlanOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Mailbox = $Mailbox.Trim().ToLowerInvariant()
if ($Mailbox -notmatch '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw 'Mailbox is invalid.'
}
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) { throw 'Public certificate not found.' }
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
if ($cert.HasPrivateKey) { throw 'Only public X.509 certificate is allowed on the management workstation.' }
$now = [datetime]::UtcNow
if ($cert.NotAfter.ToUniversalTime() -le $now.AddDays(3) -or
    $cert.NotAfter.ToUniversalTime() -gt $cert.NotBefore.ToUniversalTime().AddDays(366)) {
    throw 'Certificate must be valid for 1..365 days (with tolerance for time representation).'
}
$sha = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($cert.RawData))
$clientId = $ExistingAppId
Write-Host "PLAN: Tenant $TenantId; mailbox $Mailbox; certificate SHA256 $sha"
Write-Host "PLAN: $($(if ($clientId -eq [guid]::Empty) {'Create new app'} else {'Reuse existing app'})) and add one public certificate."
Write-Host 'PLAN: scoped Exchange Application SMTP.SendAsApp ONLY. No mailbox password or Graph Mail.Send.'
Write-Host 'PLAN: Existing public certificates remain registered; the app can be shared by multiple Linux servers.'
if ($PlanOnly -or -not $PSCmdlet.ShouldProcess("Tenant $TenantId / $ApplicationName", 'Configure Entra + scoped Exchange SMTP role')) { return }
foreach ($module in @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Missing PowerShell module '$module'. Run Install-Module $module -Scope CurrentUser"
    }
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$folder = Split-Path -Parent $ResultPath
if ($folder -and -not (Test-Path -LiteralPath $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}
function Save-State([object]$state) {
    $tmp = $ResultPath + '.new'
    $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tmp -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $ResultPath -Force
}
function Graph([string]$method, [string]$uri, [object]$body = $null) {
    if ($null -eq $body) { return Invoke-MgGraphRequest -Method $method -Uri $uri -ErrorAction Stop }
    return Invoke-MgGraphRequest -Method $method -Uri $uri -ContentType 'application/json' `
        -Body ($body | ConvertTo-Json -Depth 12 -Compress) -ErrorAction Stop
}
function CertEntry([System.Security.Cryptography.X509Certificates.X509Certificate2]$value, [string]$label) {
    return @{
        type = 'AsymmetricX509Cert'; usage = 'Verify'; displayName = $label
        key = [Convert]::ToBase64String($value.RawData)
        startDateTime = $value.NotBefore.ToUniversalTime().ToString('o')
        endDateTime = $value.NotAfter.ToUniversalTime().ToString('o')
    }
}
function Fetch-App([guid]$id) {
    # IMPORTANT: $select=keyCredentials on a SINGLE app is required for public key bytes.
    # Without it, Graph returns null keys and PATCH would destroy valid existing credentials.
    $url = "https://graph.microsoft.com/v1.0/applications(appId='$id')?`$select=id,appId,displayName,keyCredentials"
    return Graph GET $url
}
try {
    Write-Host 'Connecting to Microsoft Graph by device code. Requires an authorized Entra application administrator.'
    Connect-MgGraph -TenantId $TenantId.ToString() -Scopes 'Application.ReadWrite.All' `
        -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
    if ([guid](Get-MgContext).TenantId -ne $TenantId) { throw 'Wrong Entra tenant.' }
    if ($clientId -eq [guid]::Empty) {
        $app = Graph POST 'https://graph.microsoft.com/v1.0/applications' @{
            displayName = $ApplicationName
            signInAudience = 'AzureADMyOrg'
            keyCredentials = @((CertEntry $cert $CertificateLabel))
        }
        $clientId = [guid]$app.appId
        Write-Host "New Entra application created. Client ID: $clientId"
    } else {
        $app = Fetch-App $clientId
        if ($null -eq $app -or [guid]$app.appId -ne $clientId) { throw 'Existing app not found.' }
        $old = @($app.keyCredentials)
        if ($old.Count -gt 0 -and @($old | Where-Object { -not $_.key }).Count -gt 0) {
            throw 'Graph omitted existing public certificate bytes. Refusing to replace existing credentials.'
        }
        $digestSet = @($old | ForEach-Object {
            [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($_.key)))
        })
        if ($digestSet -contains $sha) {
            Write-Host 'Certificate already registered; no Graph key replacement needed.'
        } else {
            # Preserve all existing X.509 public keys. Do NOT send a PATCH with only the new certificate.
            $entries = @($old | ForEach-Object {
                @{
                    keyId = $_.keyId; type = $_.type; usage = $_.usage
                    displayName = $_.displayName; key = $_.key
                    startDateTime = $_.startDateTime; endDateTime = $_.endDateTime
                }
            })
            $entries += CertEntry $cert $CertificateLabel
            [void](Graph PATCH "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
                @{ keyCredentials = $entries })
            $verify = Fetch-App $clientId
            $valid = @($verify.keyCredentials | Where-Object {
                $_.key -and [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($_.key))) -eq $sha
            }).Count -gt 0
            if (-not $valid -or @($verify.keyCredentials).Count -ne $entries.Count) {
                throw 'Certificate add verification failed. STOP and verify all certificate credentials in Entra.'
            }
            Write-Host "Added public certificate; preserved $($old.Count) existing credential(s)."
        }
    }
    $app = Fetch-App $clientId
    try {
        $service = Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$clientId')"
    } catch {
        # New registration often has no Enterprise Application until created.
        $service = Graph POST 'https://graph.microsoft.com/v1.0/servicePrincipals' @{ appId = $clientId.ToString() }
    }
    if (-not $service.id) { throw 'Enterprise Application object ID missing.' }
    $serviceObjectId = [guid]$service.id
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

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
    } elseif ([guid]$sp.AppId -ne $clientId) { throw 'Exchange service principal mismatch.' }
    $scope = Get-ManagementScope -Identity $prefix -ErrorAction SilentlyContinue
    $filter = "CustomAttribute15 -eq '$tag'"
    if ($null -eq $scope) {
        New-ManagementScope -Name $prefix -RecipientRestrictionFilter $filter | Out-Null
    } elseif ($scope.RecipientRestrictionFilter.ToString() -ne $filter) {
        throw 'Scope filter changed; refusing to continue.'
    }
    $assignmentName = $prefix + '-SMTP'
    $assignment = Get-ManagementRoleAssignment -Identity $assignmentName -ErrorAction SilentlyContinue
    if ($null -eq $assignment) {
        New-ManagementRoleAssignment -Name $assignmentName -App $serviceObjectId.ToString() `
            -Role 'Application SMTP.SendAsApp' -CustomResourceScope $prefix | Out-Null
    } elseif ($assignment.Role.ToString() -ne 'Application SMTP.SendAsApp' -or
              $assignment.CustomResourceScope.ToString() -ne $prefix) {
        throw 'Unexpected existing role assignment.'
    }
    if (-not $existingTag) { Set-Mailbox -Identity $Mailbox -CustomAttribute15 $tag -ErrorAction Stop }
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
        certificateSha256 = $sha; certificateExpiresUtc = $cert.NotAfter.ToUniversalTime().ToString('o')
        rbacReady = $true
    }
    Save-State $state
    Write-Host 'READY: Scoped Application SMTP.SendAsApp authorized for sender mailbox.'
    Write-Host 'CAUTION: Tenant Security Defaults or Conditional Access can still block SMTP AUTH.'
    Write-Host 'No Entra app permissions, Graph Mail.Send, refresh tokens or passwords were created.'
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
