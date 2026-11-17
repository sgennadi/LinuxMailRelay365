# One-time Microsoft Entra tenant discovery; NO configuration mutations.
# Installs the official Az.Accounts module for CurrentUser only when missing.
# Identity tokens and credentials are never written to the result JSON.
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
    tenants = @()
}
try {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host 'Installing Az.Accounts for CurrentUser (no machine-wide changes).'
        Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module Az.Accounts -ErrorAction Stop
    # Do not save any new account context in the user's persistent Az profile.
    Disable-AzContextAutosave -Scope Process -ErrorAction Stop | Out-Null
    Write-Host 'Sign in once to discover the Microsoft Entra tenants available to this account.'
    Connect-AzAccount -UseDeviceAuthentication -Scope Process -SkipContextPopulation -ErrorAction Stop | Out-Null
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
    $folder = Split-Path -Parent $ResultPath
    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    $tmp = $ResultPath + '.new'
    $info | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $ResultPath -Force
    Write-Host ('Discovered {0} tenant(s). Review the selected tenant in the wizard before provisioning.' -f @($info.tenants).Count)
} finally {
    if (Get-Module -Name Az.Accounts) {
        Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
