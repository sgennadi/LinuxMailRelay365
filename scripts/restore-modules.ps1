[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target = Join-Path $root 'modules/UniversalUpdater'
$pinned = '01b7613ba7aa46debd489b206f6e44416bc37334'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required.' }
if (-not (Test-Path (Join-Path $target '.git'))) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    git clone --no-checkout https://github.com/sgennadi/UniversalUpdater.git $target
    if ($LASTEXITCODE -ne 0) { throw 'Unable to clone private UniversalUpdater. Check GitHub authentication.' }
}
$have = (git -C $target rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or $have -ne $pinned) {
    git -C $target fetch --no-tags origin main
    if ($LASTEXITCODE -ne 0) { throw 'Failed to fetch UniversalUpdater.' }
    git -C $target checkout --detach $pinned
    if ($LASTEXITCODE -ne 0) { throw 'Cannot check out pinned UniversalUpdater commit.' }
}
Write-Host "UniversalUpdater restored at $pinned"
