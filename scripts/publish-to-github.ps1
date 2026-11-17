# Explicit publication helper for the user's existing or new repository.
[CmdletBinding()]
param([switch]$Public)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repository = 'sgennadi/LinuxMailRelay365'
$expectedHttps = 'https://github.com/sgennadi/LinuxMailRelay365.git'
$expectedSsh = 'git@github.com:sgennadi/LinuxMailRelay365.git'
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) is required.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required.' }
Push-Location $root
try {
    gh auth status
    if ($LASTEXITCODE -ne 0) { throw 'Sign in with: gh auth login' }
    if (-not (Test-Path '.git')) {
        git init -b main
        if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed.' }
    }
    git add -A
    if ($LASTEXITCODE -ne 0) { throw 'Git staging failed.' }
    $staged = @(git diff --cached --name-only)
    $unsafe = @($staged | Where-Object { $_ -match '(?i)(^|/)(\.env|id_rsa|id_ed25519|.*\.(pem|pfx|p12|key|token|secret)|.*credentials.*\.json)$' })
    if ($unsafe.Count -gt 0) { throw ('Refusing to publish sensitive filenames: ' + ($unsafe -join ', ')) }
    git diff --cached --quiet
    if ($LASTEXITCODE -ne 0) {
        git commit -m 'LinuxMailRelay365 preview - tenant discovery and guarded multi-tenant provisioning'
        if ($LASTEXITCODE -ne 0) { throw 'Git commit failed (configure user.name and user.email).' }
    }
    gh repo view $repository 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $visibility = if ($Public) { '--public' } else { '--private' }
        gh repo create $repository $visibility --source . --remote origin
        if ($LASTEXITCODE -ne 0) { throw 'GitHub repository creation failed.' }
    }
    $remote = (git remote get-url origin 2>$null)
    if ($LASTEXITCODE -ne 0) {
        git remote add origin $expectedHttps
        if ($LASTEXITCODE -ne 0) { throw 'Could not add origin.' }
    } elseif ($remote -ne $expectedHttps -and $remote -ne $expectedSsh) {
        throw 'Existing origin points to another repository. Refusing to change it.'
    }
    # Fast-forward only. Never force push or overwrite another person's changes.
    git push -u origin HEAD:refs/heads/main
    if ($LASTEXITCODE -ne 0) { throw 'Push rejected. Review the remote branch; no force push was attempted.' }
    Write-Host ('Published: https://github.com/' + $repository)
} finally { Pop-Location }
