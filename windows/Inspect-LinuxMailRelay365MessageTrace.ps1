#requires -Version 7.0
# Read-only Exchange Online V2 trace for a recorded local Postfix probe.
[CmdletBinding()]
param(
    [guid]$TenantId = [guid]::Empty,
    [string]$RequestPath = '',
    [string]$ResultPath = '',
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Mailbox([string]$value) {
    return ($value.Length -le 254 -and $value -notmatch '\.\.' -and
        $value -cmatch '\A[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z')
}
function Assert-Tenant([guid]$expected) {
    $sessions = @(Get-ConnectionInformation -ErrorAction Stop)
    if ($sessions.Count -ne 1 -or -not $sessions[0].TenantID -or
        [guid]$sessions[0].TenantID -ne $expected) {
        throw 'Exact Exchange Online tenant is not verified.'
    }
}
function Get-TraceState([object[]]$rows, [string]$messageId, [string]$sender,
                        [string]$recipient, [datetime]$start, [datetime]$end) {
    if ($rows.Count -eq 0) { return @{state='not_observed'; count=0} }
    if ($rows.Count -ge 100) { return @{state='ambiguous'; count=$rows.Count} }
    $matched = @($rows | Where-Object {
        [string]$_.MessageId -ceq $messageId -and
        [string]$_.SenderAddress -ieq $sender -and
        [string]$_.RecipientAddress -ieq $recipient
    })
    if ($matched.Count -ne 1 -or $rows.Count -ne 1) {
        return @{state='ambiguous'; count=$rows.Count}
    }
    $received = [datetime]$matched[0].Received
    if ($received.Kind -eq [DateTimeKind]::Unspecified) {
        $received = [datetime]::SpecifyKind($received,[DateTimeKind]::Utc)
    } else { $received = $received.ToUniversalTime() }
    if ($received -lt $start -or $received -gt $end) {
        return @{state='ambiguous'; count=1}
    }
    $state = switch -Regex (([string]$matched[0].Status).ToLowerInvariant()) {
        '^delivered$' { 'delivered'; break }
        '^pending$' { 'pending'; break }
        '^failed$' { 'failed'; break }
        '^quarantined$' { 'quarantined'; break }
        '^expanded$' { 'expanded'; break }
        '^filtered[ ]?as[ ]?spam$' { 'filtered_as_spam'; break }
        '^getting[ ]?status$' { 'getting_status'; break }
        '^recalled$' { 'recalled'; break }
        default { 'unknown_status' }
    }
    return @{state=$state; count=1}
}
if ($SelfTest) {
    $start = [datetime]::UtcNow.AddHours(-1)
    $end = [datetime]::UtcNow
    $id = '<lmr365-test-internal@example.org>'
    $row = [pscustomobject]@{MessageId=$id; SenderAddress='sender@example.org';
        RecipientAddress='test@example.org'; Received=$end.AddMinutes(-1); Status='Delivered'}
    if ((Get-TraceState @($row) $id 'sender@example.org' 'test@example.org' $start $end).state -ne 'delivered' -or
        (Get-TraceState @() $id 'sender@example.org' 'test@example.org' $start $end).state -ne 'not_observed' -or
        (Get-TraceState @($row,$row) $id 'sender@example.org' 'test@example.org' $start $end).state -ne 'ambiguous' -or
        (Get-TraceState @($row) $id 'sender@example.org' 'wrong@example.org' $start $end).state -ne 'ambiguous') {
        throw 'Message trace match self-test failed.'
    }
    $row.Status = 'FilteredAsSpam'
    if ((Get-TraceState @($row) $id 'sender@example.org' 'test@example.org' $start $end).state -ne 'filtered_as_spam' -or
        -not (Test-Mailbox 'sender@example.org') -or (Test-Mailbox ('x@example.org'+[char]10))) {
        throw 'Message trace status self-test failed.'
    }
    $row.Received = $start.AddMinutes(-1)
    if ((Get-TraceState @($row) $id 'sender@example.org' 'test@example.org' $start $end).state -ne 'ambiguous') {
        throw 'Message trace time self-test failed.'
    }
    Write-Output 'EXO_MESSAGE_TRACE_SELF_TEST=pass'
    return
}
if ($TenantId -eq [guid]::Empty -or
    -not [IO.Path]::IsPathFullyQualified($RequestPath) -or
    -not [IO.Path]::IsPathFullyQualified($ResultPath) -or $RequestPath -eq $ResultPath) {
    throw 'Exact tenant and separate absolute request/result paths required.'
}
if ((Get-Item -LiteralPath $RequestPath).Length -gt 8192) { throw 'Request too large.' }
$request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json -AsHashtable
$keys = @('run_id','accepted_domain','sender','internal','external','started_unix','attempted')
if ($request.Count -ne $keys.Count -or
    @($keys | Where-Object { -not $request.ContainsKey($_) }).Count -ne 0) {
    throw 'Invalid request fields.'
}
if ([string]$request.run_id -cnotmatch '\A[a-f0-9]{32}\z' -or
    [string]$request.accepted_domain -cnotmatch '\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z' -or
    $request.accepted_domain.Length -gt 253 -or
    -not (Test-Mailbox $request.sender) -or -not (Test-Mailbox $request.internal) -or
    -not (Test-Mailbox $request.external) -or
    -not $request.sender.EndsWith('@'+$request.accepted_domain,[StringComparison]::OrdinalIgnoreCase) -or
    -not $request.internal.EndsWith('@'+$request.accepted_domain,[StringComparison]::OrdinalIgnoreCase) -or
    $request.external.EndsWith('@'+$request.accepted_domain,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Invalid probe identity or recipient roles.'
}
$attempted = @($request.attempted)
if ($attempted.Count -lt 1 -or $attempted.Count -gt 2 -or
    @($attempted | Where-Object { $_ -cnotin @('internal','external') }).Count -ne 0 -or
    @($attempted | Select-Object -Unique).Count -ne $attempted.Count) {
    throw 'Recorded attempted recipient role required.'
}
$now = [datetime]::UtcNow
$started = [DateTimeOffset]::FromUnixTimeSeconds([long]$request.started_unix).UtcDateTime
if ($started -lt $now.AddDays(-7) -or $started -gt $now.AddMinutes(5)) {
    throw 'Probe must have been recorded within the last seven days; check server time.'
}
$start = $started.AddMinutes(-5)
$opened = $false
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    $sessions = @(Get-ConnectionInformation -ErrorAction Stop)
    if ($sessions.Count -eq 0) {
        Write-Host 'Sign in to the selected Exchange Online tenant for read-only message tracing.'
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        $opened = $true
    }
    Assert-Tenant $TenantId
    if (-not (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
        throw 'Get-MessageTraceV2 unavailable. Update ExchangeOnlineManagement or review trace permissions.'
    }
    $domains = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object {
        [string]$_.DomainName -ieq [string]$request.accepted_domain -and
        [string]$_.DomainType -in @('Authoritative','InternalRelay')
    })
    if ($domains.Count -ne 1) { throw 'Selected sender domain not verified in Exchange tenant.' }
    $outcomes = [ordered]@{}
    foreach ($role in @('internal','external')) {
        if ($role -cnotin $attempted) {
            $outcomes[$role] = @{state='not_attempted'; count=0}
            continue
        }
        Assert-Tenant $TenantId
        $id = '<lmr365-' + $request.run_id + '-' + $role + '@' + $request.accepted_domain + '>'
        $end = [datetime]::UtcNow
        $query = @{MessageId=$id; SenderAddress=$request.sender; RecipientAddress=$request[$role];
            StartDate=$start; EndDate=$end; ResultSize=100; ErrorAction='Stop'}
        $rows = @(Get-MessageTraceV2 @query)
        Assert-Tenant $TenantId
        $outcomes[$role] = Get-TraceState $rows $id $request.sender $request[$role] $start $end
    }
    Assert-Tenant $TenantId
    $result = [ordered]@{version=1; status='exchange_trace_observed'; tenant_id=$TenantId.ToString('D');
        run_id=$request.run_id; outcomes=$outcomes; inbox_verified=$false; changes_applied=$false}
    [IO.File]::WriteAllText($ResultPath, ($result | ConvertTo-Json -Depth 5 -Compress),
        [Text.UTF8Encoding]::new($false))
}
finally {
    if ($opened) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
