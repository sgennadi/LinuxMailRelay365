#requires -Version 7.0
<#
Production release gate for separately published LinuxMailRelay365 Windows EXEs.
Never signs an executable, downloads software or modifies a release. It checks
PE machine type, version agreement, Authenticode trust and EXACT publisher
certificate thumbprint before creating a checksum manifest. Preview unsigned
builds are intentionally rejected. Use a real trusted code-signing certificate.
#>
[CmdletBinding()]
param(
    [string]$X64Exe = '',
    [string]$Arm64Exe = '',
    [string]$PublisherThumbprint = '',
    [string]$ManifestPath = '',
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Thumbprint([string]$value) {
    return $value -cmatch '^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$'
}
function Get-PeMachine([string]$path) {
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 512 -or $stream.Length -gt 500MB) {
            throw 'Unexpected executable size.'
        }
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Not a PE executable.' }
            $stream.Position = 0x3C
            $offset = $reader.ReadInt32()
            if ($offset -lt 64 -or $offset -gt 8MB -or
                $offset -gt $stream.Length - 24) {
                throw 'Untrusted PE header offset.'
            }
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw 'Invalid PE signature.'
            }
            return $reader.ReadUInt16()
        }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}
function Verify-Publisher([string]$path, [string]$thumb) {
    $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $sig.SignerCertificate -or
        $sig.SignatureType -eq [System.Management.Automation.SignatureType]::None) {
        throw 'Authenticode signature is missing or not trusted.'
    }
    if (-not ([string]$sig.SignerCertificate.Thumbprint).Equals(
            $thumb, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Executable signer is not the pinned publisher.'
    }
}
if ($SelfTest) {
    if (-not (Test-Thumbprint ('A'*40)) -or
        -not (Test-Thumbprint ('b'*64)) -or
        (Test-Thumbprint 'test') -or
        (Test-Thumbprint ('G'*40))) {
        throw 'Publisher thumbprint parser selftest failed.'
    }
    Write-Output 'RELEASE_SIGNATURE_GATE_SELF_TEST=pass'
    Write-Output 'RELEASE_PUBLISHED=no'
    return
}
if (-not (Test-Thumbprint $PublisherThumbprint)) {
    throw 'A real exact publisher Authenticode certificate thumbprint is required.'
}
$paths = @($X64Exe, $Arm64Exe, $ManifestPath)
if ($paths | Where-Object { -not $_ -or
        -not [System.IO.Path]::IsPathFullyQualified($_) }) {
    throw 'Specify absolute executable and manifest paths.'
}
if ($X64Exe -eq $Arm64Exe) { throw 'x64 and ARM64 must be separate binaries.' }
$items = @(
    @{ Name = 'win-x64'; Path = $X64Exe; Machine = 0x8664 },
    @{ Name = 'win-arm64'; Path = $Arm64Exe; Machine = 0xAA64 }
)
$versions = @()
$manifest = @()
foreach ($item in $items) {
    $path = [System.IO.Path]::GetFullPath($item.Path)
    $f = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($f.LinkType -or -not $f.Exists -or $f.PSIsContainer -or
        $f.Length -lt 512 -or $f.Length -gt 500MB) {
        throw 'Unsigned/reparse/untrusted EXE source.'
    }
    if ((Get-PeMachine $path) -ne $item.Machine) {
        throw 'Windows EXE architecture does not match release artifact name.'
    }
    Verify-Publisher $path $PublisherThumbprint
    $version = [string]$f.VersionInfo.ProductVersion
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'Stable release requires numeric stable product version, not preview.'
    }
    $versions += $version
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest += [ordered]@{
        artifact = $item.Name
        filename = 'LinuxMailRelay365.exe'
        sha256 = $hash
        version = $version
        authenticode = 'trusted_exact_publisher'
    }
}
if ($versions[0] -ne $versions[1]) {
    throw 'x64 and ARM64 product versions differ.'
}
$target = [System.IO.Path]::GetFullPath($ManifestPath)
if (Test-Path -LiteralPath $target) {
    throw 'Release manifest already exists, refuse overwrite.'
}
$manifestDirectory = [System.IO.Path]::GetDirectoryName($target)
if (-not (Test-Path -LiteralPath $manifestDirectory -PathType Container)) {
    throw 'Release manifest parent directory must already exist.'
}
$payload = [ordered]@{
    schema = 'linuxmailrelay365-signed-release/v1'
    product = 'LinuxMailRelay365'
    version = $versions[0]
    published = $false
    requires_test_tenant_acceptance = $true
    artifacts = $manifest
}
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    (ConvertTo-Json $payload -Depth 8) + [Environment]::NewLine)
$handle = [System.IO.File]::Open($target, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try {
    $handle.Write($bytes, 0, $bytes.Length)
    $handle.Flush($true)
}
finally { $handle.Dispose() }
Write-Output 'RELEASE_SIGNED_ARTIFACTS=two_verified'
Write-Output 'RELEASE_PUBLISHED=no'
Write-Output 'RELEASE_PRODUCTION_ACCEPTED=no'
