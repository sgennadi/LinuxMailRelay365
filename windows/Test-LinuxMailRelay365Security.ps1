# Read-only, opt-in Microsoft 365 security readiness check.
# No application, policy, licensing or sign-in configuration is changed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$ResultPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'PowerShell 7 module Microsoft.Graph.Authentication is required.'
}
Import-Module Microsoft.Graph.Authentication
$info = [ordered]@{
    tenantId = $TenantId.ToString()
    checkedUtc = [datetime]::UtcNow.ToString('o')
    conditionalAccessPolicyRead = 'not_verified'
    signInLogRead = 'not_verified'
    workloadIdPremium = 'not_verified'
    ipPolicyConfigured = 'not_checked'
    changesApplied = $false
}
try {
    # Scopes are requested ONLY on this explicit diagnostic action.
    Connect-MgGraph -TenantId $TenantId.ToString() -UseDeviceCode -NoWelcome -Scopes @(
        'Policy.Read.All', 'AuditLog.Read.All', 'Organization.Read.All'
    ) -ContextScope Process -ErrorAction Stop | Out-Null
    if ([guid](Get-MgContext).TenantId -ne $TenantId) { throw 'Wrong Microsoft 365 tenant.' }
    try {
        $null = Invoke-MgGraphRequest -Method GET -Uri `
            'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=1' -ErrorAction Stop
        $info.conditionalAccessPolicyRead = 'accessible'
    } catch { $info.conditionalAccessPolicyRead = 'not_accessible_or_insufficient_rights' }
    try {
        $null = Invoke-MgGraphRequest -Method GET -Uri `
            'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1' -ErrorAction Stop
        $info.signInLogRead = 'accessible'
    } catch { $info.signInLogRead = 'not_accessible_or_insufficient_rights' }
    try {
        $sku = Invoke-MgGraphRequest -Method GET -Uri `
            'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' -ErrorAction Stop
        if ($null -ne $sku.value) {
            # Generic Graph SKU listing does not prove assignment of Entra Workload ID Premium.
            $info.workloadIdPremium = 'manual_license_verification_required'
        }
    } catch { $info.workloadIdPremium = 'not_verified' }
    Write-Host 'READ-ONLY: Entra security capability check completed. No policy was created or enabled.'
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
$dir = Split-Path -Parent $ResultPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$tmp = $ResultPath + '.new'
$info | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding utf8
Move-Item -LiteralPath $tmp -Destination $ResultPath -Force
