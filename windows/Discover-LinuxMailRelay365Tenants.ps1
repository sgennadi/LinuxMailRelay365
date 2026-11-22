# One-time Microsoft Entra tenant discovery; NO tenant or Linux changes.
# Az.Accounts is installed for CurrentUser only when missing.
# Never persist passwords, OAuth tokens or raw exception text in result JSON.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResultPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$info = [ordered]@{
    schema = 'linux-mail-relay-tenant-discovery/v1'
    capturedUtc = [datetime]::UtcNow.ToString('o')
    method = 'Az.Accounts/Get-AzTenant'
    status = 'error'
    errorCode = ''
    tenants = @()
}
$phase = 'initialize'

function Write-DiscoveryResult {
    param([System.Collections.IDictionary]$Data, [string]$Path)
    # Keep this allowlisted result separate from the local Az token cache.
    $folder = Split-Path -Parent $Path
    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    $tmp = $Path + '.new'
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

try {
    $phase = 'module_install'
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host 'Installing official Az.Accounts for CurrentUser (no machine-wide changes).'
        Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }

    $phase = 'module_import'
    Import-Module Az.Accounts -ErrorAction Stop

    $phase = 'authentication'
    # Avoid modifying the user's saved Az account contexts.
    Disable-AzContextAutosave -Scope Process -ErrorAction Stop | Out-Null
    Write-Host 'Sign in to Microsoft Entra using the device code shown in this window.'
    Connect-AzAccount -UseDeviceAuthentication -Scope Process -SkipContextPopulation -ErrorAction Stop | Out-Null

    $phase = 'tenant_query'
    $items = @(Get-AzTenant -ErrorAction Stop)
    $rows = foreach ($item in $items) {
        $idText = [string]$item.Id
        $guid = [guid]::Empty
        if (-not [guid]::TryParse($idText, [ref]$guid) -or $guid -eq [guid]::Empty) { continue }
        $domains = @($item.Domains | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $name = [string]$item.Name
        if (-not $name) { $name = 'Microsoft Entra tenant' }
        [pscustomobject]@{
            tenantId = $guid.ToString()
            displayName = $name
            primaryDomain = $(if ($domains.Count) { $domains[0] } else { '' })
            category = [string]$item.Category
        }
    }
    $info.tenants = @($rows | Where-Object { $null -ne $_ } | Sort-Object tenantId -Unique)

    $phase = 'write_result'
    $info.status = 'ok'
    Write-DiscoveryResult -Data $info -Path $ResultPath
    if (@($info.tenants).Count -eq 0) {
        Write-Host 'Authentication completed but no tenants were enumerated. Manual Tenant ID remains available.'
    } else {
        Write-Host ('Discovered {0} tenant(s). Review the chosen tenant before provisioning.' -f @($info.tenants).Count)
    }
}
catch {
    # Deliberately never serialize $_.Exception.Message: authentication failures
    # can contain account identifiers, claims challenges or device-code details.
    $info.status = 'error'
    $info.tenants = @()
    $info.errorCode = switch ($phase) {
        'module_install' { 'az_module_install_failed' }
        'module_import' { 'az_module_import_failed' }
        'authentication' { 'device_sign_in_failed' }
        'tenant_query' { 'tenant_enumeration_failed' }
        'write_result' { 'result_write_failed' }
        default { 'discovery_failed' }
    }
    try {
        Write-DiscoveryResult -Data $info -Path $ResultPath
    }
    catch {
        # Only a fixed, secret-free diagnostic is printed.
        Write-Host 'Tenant discovery result could not be written. Check local folder access.'
    }
    Write-Host ('Tenant discovery failed at stage {0}. No tenant settings were changed.' -f $phase)
    exit 1
}
finally {
    if (Get-Module -Name Az.Accounts) {
        Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
