#requires -Version 7.0
<#
CI-only disposable migration smoke for published Preview 24 -> reviewed candidate.
Exercises real release binaries and a replace/backup/rollback transaction.
This does NOT prove the interactive GUI or non-elevated updater helper.
No production files, registry, tenant, SMTP or Linux service is modified.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CandidateExe,
    [ValidatePattern('^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:preview|rc)\.(?:0|[1-9][0-9]*))?$')]
    [string]$ExpectedCandidateVersion = '0.1.1-rc.2'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP -or -not [IO.Path]::IsPathFullyQualified($env:RUNNER_TEMP)) {
    throw 'Preview migration smoke is restricted to GitHub Actions.'
}
if (-not [IO.Path]::IsPathFullyQualified($CandidateExe) -or -not (Test-Path -LiteralPath $CandidateExe -PathType Leaf)) {
    throw 'Candidate EXE must be an existing absolute path.'
}
if ([IO.Path]::GetFileName($CandidateExe) -cne 'LinuxMailRelay365.exe') { throw 'Unexpected candidate name.' }
function Assert([bool]$yes, [string]$message) {
    if (-not $yes) { throw $message }
}
function Sha([string]$file) {
    return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
}
function PeMachine([string]$file) {
    $stream = [IO.File]::OpenRead($file)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        try {
            Assert ($reader.ReadUInt16() -eq 0x5a4d) 'Invalid MZ signature.'
            $stream.Position = 0x3c
            $offset = $reader.ReadInt32()
            Assert ($offset -ge 64 -and $offset -lt $stream.Length - 6) 'Invalid PE offset.'
            $stream.Position = $offset
            Assert ($reader.ReadUInt32() -eq 0x4550) 'Invalid PE signature.'
            return $reader.ReadUInt16()
        }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}
function Version([string]$file) {
    return [string](Get-Item -LiteralPath $file).VersionInfo.ProductVersion
}
function Invoke-SelfTest([string]$file) {
    $p = Start-Process -FilePath $file -ArgumentList '--self-test' -Wait -PassThru
    Assert ($null -ne $p -and $p.ExitCode -eq 0) 'EXE built-in self-test failed.'
}
function Invoke-VerifiedFileReplace(
    [string]$source, [string]$destination, [string]$backup,
    [string]$sourceDigest, [string]$destinationDigest) {
    # Windows AV/indexers may briefly hold an EXE after its process exits.
    # Only retry ERROR_SHARING_VIOLATION=32 / ERROR_LOCK_VIOLATION=33.
    # Reject changed bytes, missing files and all other errors immediately.
    for ($attempt = 0; $attempt -lt 8; $attempt++) {
        Assert ((Test-Path -LiteralPath $source -PathType Leaf) -and
                (Test-Path -LiteralPath $destination -PathType Leaf)) 'Replace source/destination vanished.'
        Assert ((Sha $source) -ceq $sourceDigest -and
                (Sha $destination) -ceq $destinationDigest) 'Replace input hash drift.'
        try {
            [IO.File]::Replace($source, $destination, $backup, $false)
            return
        }
        catch {
            $cause = $_.Exception
            while ($cause.InnerException) { $cause = $cause.InnerException }
            $code = $cause.HResult -band 0xffff
            if ($cause -isnot [IO.IOException] -or
                $code -notin @(32, 33) -or $attempt -ge 7) {
                throw
            }
            # A failed atomic replace must not consume the source file.
            Assert ((Test-Path -LiteralPath $source -PathType Leaf) -and
                    (Test-Path -LiteralPath $destination -PathType Leaf)) 'Ambiguous replace outcome.'
            Start-Sleep -Milliseconds (200 * ($attempt + 1))
        }
    }
    throw 'File replacement did not complete.'
}
$root = Join-Path $env:RUNNER_TEMP ("LMRPreviewUpgrade-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $releaseJson = gh api 'repos/sgennadi/LinuxMailRelay365/releases/tags/v0.1.0-preview.24'
    if ($LASTEXITCODE -ne 0) { throw 'Could not query the published Preview 24.' }
    $release = ($releaseJson -join [Environment]::NewLine) | ConvertFrom-Json
    Assert ($release.prerelease -eq $true -and $release.draft -eq $false) 'Previous release is not a published Preview.'
    $assetName = 'LinuxMailRelay365-win-x64.zip'
    $assets = @($release.assets | Where-Object { $_.name -ceq $assetName })
    Assert ($assets.Count -eq 1) 'Previous x64 release asset missing or duplicated.'
    $asset = $assets[0]
    Assert ($asset.digest -cmatch '^sha256:[a-f0-9]{64}$') 'Missing source-reported SHA256.'
    Assert ($asset.browser_download_url -ceq "https://github.com/sgennadi/LinuxMailRelay365/releases/download/v0.1.0-preview.24/$assetName") 'Untrusted asset URL.'
    $zipPath = Join-Path $root $assetName
    gh release download 'v0.1.0-preview.24' --repo sgennadi/LinuxMailRelay365 --pattern $assetName --dir $root
    if ($LASTEXITCODE -ne 0) { throw 'Previous release download failed.' }
    Assert ((Get-Item -LiteralPath $zipPath).Length -eq $asset.size) 'Previous ZIP size mismatch.'
    Assert ((Sha $zipPath) -ceq $asset.digest.Substring(7)) 'Previous ZIP SHA256 mismatch.'
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        Assert ($archive.Entries.Count -eq 1 -and $archive.Entries[0].FullName -ceq 'LinuxMailRelay365.exe') 'Untrusted ZIP layout.'
        $oldFolder = Join-Path $root 'previous'
        [IO.Directory]::CreateDirectory($oldFolder) | Out-Null
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $oldFolder)
    }
    finally { $archive.Dispose() }
    $oldExe = Join-Path $oldFolder 'LinuxMailRelay365.exe'
    Assert ((Version $oldExe) -match '^0\.1\.0-preview\.24(?:\+.*)?$') 'Incorrect old version.'
    Assert ((Version $CandidateExe) -match ('^' + [regex]::Escape($ExpectedCandidateVersion) + '(?:\+.*)?$')) 'Incorrect new version.'
    Assert ((PeMachine $oldExe) -eq 0x8664) 'Previous EXE is not x64.'
    Assert ((PeMachine $CandidateExe) -eq 0x8664) 'Candidate EXE is not x64.'
    Invoke-SelfTest $oldExe
    Invoke-SelfTest $CandidateExe
    $live = Join-Path $root 'live'
    $stage = Join-Path $root 'stage'
    [IO.Directory]::CreateDirectory($live) | Out-Null
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $target = Join-Path $live 'LinuxMailRelay365.exe'
    $candidate = Join-Path $stage 'LinuxMailRelay365.exe'
    $backup = "$target.bak"
    [IO.File]::Copy($oldExe, $target)
    [IO.File]::Copy($CandidateExe, $candidate)
    $oldHash = Sha $target
    $newHash = Sha $candidate
    Invoke-VerifiedFileReplace $candidate $target $backup $newHash $oldHash
    Assert ((Sha $target) -ceq $newHash -and (Sha $backup) -ceq $oldHash) 'Upgrade/backup digest mismatch.'
    Invoke-SelfTest $target
    Write-Output 'PUBLISHED_PREVIEW_TO_CANDIDATE_DISPOSABLE_REPLACEMENT=PASS'
    # Match the actual updater: Windows File.Replace needs a real third path.
    # The consumed .update-new pathname is available for the failed version.
    $failedVersion = "$target.update-new"
    Invoke-VerifiedFileReplace $backup $target $failedVersion $oldHash $newHash
    Assert ((Sha $failedVersion) -ceq $newHash) 'Preserved failed-version digest mismatch.'
    Assert ((Sha $target) -ceq $oldHash) 'Rollback digest mismatch.'
    Invoke-SelfTest $target
    Write-Output 'CANDIDATE_TO_PUBLISHED_PREVIEW_DISPOSABLE_ROLLBACK=PASS'
    Write-Output 'REAL_GUI_AND_HELPER_ACCEPTANCE=NOT_TESTED'
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
