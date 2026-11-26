#requires -Version 7.0
# Exchange-only create-scoped SMTP RBAC; never changes Entra API grants.
[CmdletBinding()]
param(
    [ValidateSet('Preview','Apply')][string]$Phase='Preview',
    [guid]$TenantId=[guid]::Empty,
    [guid]$ClientId=[guid]::Empty,
    [guid]$EnterpriseObjectId=[guid]::Empty,
    [string]$Mailbox='',
    [string]$Nonce='',
    [string]$ExpectedSha256='',
    [string]$TypedConfirmation='',
    [string]$ResultPath='',
    [switch]$EnableMailboxSmtp,
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$role='Application SMTP.SendAsApp'
$phrase='CREATE_REVIEWED_MAILBOX_SMTP_SCOPE'
function Require([bool]$ok,[string]$code) { if (-not $ok) { throw $code } }
function HashText([string]$value) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($value))).ToLowerInvariant()
}
function ExactGuid($value) {
    $id=[guid]::Empty
    Require ([guid]::TryParse([string]$value,[ref]$id) -and $id -ne [guid]::Empty) 'invalid_cloud_object_guid'
    return $id.ToString('D')
}
function ScopeName([guid]$tenant,[guid]$app,[string]$id) {
    return 'LMR365-MBX-' + (HashText ($tenant.ToString('D')+'|'+$app.ToString('D')+'|'+$id)).Substring(0,32)
}
function ExactFilter([string]$id) { return "Guid -eq '$(ExactGuid $id)'" }
function IsExactFilter([string]$actual,[string]$id) {
    $normalized=$actual.Trim()
    if ($normalized.StartsWith('(') -and $normalized.EndsWith(')')) {
        $normalized=$normalized.Substring(1,$normalized.Length-2).Trim()
    }
    return ($normalized -replace '\s+',' ') -ieq (ExactFilter $id)
}
function Policy($item,[bool]$inherit) {
    $p=$item.PSObject.Properties['SmtpClientAuthenticationDisabled']
    Require ($null -ne $p) 'smtp_policy_missing'
    if ($null -eq $p.Value) {
        Require $inherit 'organization_policy_unknown'
        return 'inherit'
    }
    Require ($p.Value -is [bool]) 'smtp_policy_type_unknown'
    if ($p.Value) { return 'disabled' }
    return 'enabled'
}
function Effective([string]$o,[string]$m) {
    Require ($o -cin @('disabled','enabled') -and $m -cin @('disabled','enabled','inherit')) 'invalid_smtp_policy'
    if ($m -ceq 'inherit') { return $o }
    return $m
}
function AssertTenant {
    $sessions=@(Get-ConnectionInformation -ErrorAction Stop)
    Require ($sessions.Count -eq 1 -and (ExactGuid $sessions[0].TenantID) -ceq $TenantId.ToString('D')) 'wrong_exchange_tenant'
}
function ReadMailbox {
    $items=@(Get-Mailbox -Identity $Mailbox -ErrorAction Stop)
    Require ($items.Count -eq 1 -and ([string]$items[0].PrimarySmtpAddress).ToLowerInvariant() -ceq $Mailbox) 'primary_mailbox_required'
    Require ([string]$items[0].RecipientTypeDetails -cin @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox')) 'unsupported_mailbox_type'
    return ExactGuid $items[0].Guid
}
function AssertOneRecipient([string]$filter,[string]$id) {
    Require (IsExactFilter $filter $id) 'unexpected_scope_filter'
    $items=@(Get-Recipient -Filter $filter -ResultSize 2 -ErrorAction Stop)
    Require ($items.Count -eq 1 -and (ExactGuid $items[0].Guid) -ceq $id -and
        ([string]$items[0].PrimarySmtpAddress).ToLowerInvariant() -ceq $Mailbox) 'scope_not_exact_single_mailbox'
}
function PrincipalState {
    # Never interpret a permission or transport error as absence.
    $items=@(Get-ServicePrincipal -ErrorAction Stop)
    Require ($items.Count -le 8192) 'principal_inventory_limit'
    $matches=@($items | Where-Object {
        (ExactGuid $_.AppId) -ceq $ClientId.ToString('D') -or
        (ExactGuid $_.ObjectId) -ceq $EnterpriseObjectId.ToString('D')
    })
    Require ($matches.Count -le 1) 'ambiguous_exchange_principal'
    if ($matches.Count -eq 0) { return 'create' }
    Require ((ExactGuid $matches[0].AppId) -ceq $ClientId.ToString('D') -and
        (ExactGuid $matches[0].ObjectId) -ceq $EnterpriseObjectId.ToString('D')) 'exchange_principal_mismatch'
    return 'reuse'
}
function Authorization {
    $items=@(Test-ServicePrincipalAuthorization -Identity $EnterpriseObjectId.ToString('D') -Resource $Mailbox -ErrorAction Stop)
    Require ($items.Count -le 256) 'authorization_inventory_limit'
    $matches=@($items | Where-Object { [string]$_.RoleName -ceq $role })
    foreach ($item in $matches) { Require ($item.InScope -is [bool]) 'smtp_scope_unverified' }
    return [ordered]@{matching=$matches.Count;inScope=@($matches | Where-Object { $_.InScope }).Count}
}
function ReadPolicy {
    $org=@(Get-TransportConfig -ErrorAction Stop)
    $cas=@(Get-CASMailbox -Identity $Mailbox -ErrorAction Stop)
    Require ($org.Count -eq 1 -and $cas.Count -eq 1) 'smtp_policy_ambiguous'
    $o=Policy $org[0] $false
    $m=Policy $cas[0] $true
    return [ordered]@{organization=$o;mailbox=$m;effective=(Effective $o $m)}
}
function AssertNamesUnused([string]$scopeName,[string]$assignmentName) {
    $scopes=@(Get-ManagementScope -ErrorAction Stop)
    $assignments=@(Get-ManagementRoleAssignment -ErrorAction Stop)
    Require ($scopes.Count -le 8192 -and $assignments.Count -le 32768) 'exchange_inventory_limit'
    Require (@($scopes | Where-Object { [string]$_.Name -ieq $scopeName }).Count -eq 0) 'scope_name_exists_manual_review'
    Require (@($assignments | Where-Object { [string]$_.Name -ieq $assignmentName }).Count -eq 0) 'assignment_name_exists_manual_review'
}
function ReadPlan {
    AssertTenant
    $id=ReadMailbox
    $filter=ExactFilter $id
    AssertOneRecipient $filter $id
    $name=ScopeName $TenantId $ClientId $id
    $principal=PrincipalState
    $auth=if ($principal -ceq 'reuse') { Authorization } else { [ordered]@{matching=0;inScope=0} }
    $policy=ReadPolicy
    $create=$auth.inScope -eq 0
    if ($create) { AssertNamesUnused $name ($name+'-SMTP') }
    AssertTenant
    return [ordered]@{
        schema='linuxmailrelay365-mailbox-smtp-plan/v1'
        tenantId=$TenantId.ToString('D');clientId=$ClientId.ToString('D')
        enterpriseObjectId=$EnterpriseObjectId.ToString('D');mailbox=$Mailbox;mailboxGuid=$id;nonce=$Nonce
        scopeName=$name;assignmentName=($name+'-SMTP');filter=$filter
        principal=$principal;existingSmtpRoles=$auth.matching;existingInScope=$auth.inScope
        organizationPolicy=$policy.organization;mailboxPolicy=$policy.mailbox;effectivePolicy=$policy.effective
        createRole=[bool]$create;enableMailboxSmtp=([bool]$EnableMailboxSmtp -and $policy.effective -ceq 'disabled')
        requestedEnableMailboxSmtp=[bool]$EnableMailboxSmtp
    }
}
function PlanHash($plan) { return HashText ($plan | ConvertTo-Json -Compress -Depth 8) }
function VerifyScope([string]$name,[string]$id) {
    $items=@(Get-ManagementScope -Identity $name -ErrorAction Stop)
    Require ($items.Count -eq 1 -and [string]$items[0].Name -ceq $name) 'scope_readback_mismatch'
    $s=$items[0]
    Require ($s.Exclusive -is [bool] -and -not $s.Exclusive -and
        [string]$s.ScopeRestrictionType -ceq 'RecipientScope' -and
        [string]::IsNullOrEmpty([string]$s.RecipientRoot)) 'unexpected_scope_type_or_root'
    AssertOneRecipient ([string]$s.RecipientFilter) $id
    return ExactGuid $s.Guid
}
function VerifyAssignment($plan,[string]$scopeGuid) {
    $items=@(Get-ManagementRoleAssignment -Identity $plan.assignmentName -ErrorAction Stop)
    Require ($items.Count -eq 1 -and [string]$items[0].Name -ceq $plan.assignmentName) 'assignment_readback_mismatch'
    $item=$items[0]
    Require ([string]$item.Role -ceq $role -and [string]$item.RoleAssigneeType -ceq 'ServicePrincipal' -and
        $item.Enabled -is [bool] -and $item.Enabled -and $item.Delegating -is [bool] -and -not $item.Delegating) 'assignment_role_mismatch'
    $linked=@(Get-ManagementRoleAssignment -RoleAssignee $EnterpriseObjectId.ToString('D') -ErrorAction Stop |
        Where-Object { [string]$_.Name -ceq $plan.assignmentName })
    Require ($linked.Count -eq 1 -and (ExactGuid $linked[0].Guid) -ceq (ExactGuid $item.Guid)) 'assignment_assignee_unverified'
    Require (-not [string]::IsNullOrWhiteSpace([string]$item.CustomResourceScope)) 'assignment_scope_missing'
    $linkedScope=@(Get-ManagementScope -Identity ([string]$item.CustomResourceScope) -ErrorAction Stop)
    Require ($linkedScope.Count -eq 1 -and (ExactGuid $linkedScope[0].Guid) -ceq $scopeGuid) 'assignment_scope_unverified'
}
function ApplyPlan($plan,[string]$sha) {
    Require ((PlanHash (ReadPlan)) -ceq $sha) 'plan_changed_before_apply'
    if ($plan.createRole) {
        if ($plan.principal -ceq 'create') {
            AssertTenant
            New-ServicePrincipal -AppId $ClientId.ToString('D') -ObjectId $EnterpriseObjectId.ToString('D') -DisplayName ('LinuxMailRelay365 '+$ClientId.ToString('N').Substring(0,12)) -ErrorAction Stop | Out-Null
        }
        Require ((PrincipalState) -ceq 'reuse') 'principal_creation_unverified'
        AssertTenant
        Require ((ReadMailbox) -ceq $plan.mailboxGuid) 'mailbox_changed_before_scope'
        AssertOneRecipient $plan.filter $plan.mailboxGuid
        AssertNamesUnused $plan.scopeName $plan.assignmentName
        New-ManagementScope -Name $plan.scopeName -RecipientRestrictionFilter $plan.filter -ErrorAction Stop | Out-Null
        $scopeGuid=VerifyScope $plan.scopeName $plan.mailboxGuid
        AssertTenant
        Require ((ReadMailbox) -ceq $plan.mailboxGuid) 'mailbox_changed_before_assignment'
        Require ((PrincipalState) -ceq 'reuse') 'principal_changed_before_assignment'
        Require ((Authorization).inScope -eq 0) 'authorization_changed_before_assignment'
        Require ((VerifyScope $plan.scopeName $plan.mailboxGuid) -ceq $scopeGuid) 'scope_changed_before_assignment'
        New-ManagementRoleAssignment -Name $plan.assignmentName -App $EnterpriseObjectId.ToString('D') -Role $role -CustomResourceScope $scopeGuid -ErrorAction Stop | Out-Null
        VerifyAssignment $plan $scopeGuid
        Require ((VerifyScope $plan.scopeName $plan.mailboxGuid) -ceq $scopeGuid) 'scope_changed_after_assignment'
    }
    if ($plan.enableMailboxSmtp) {
        AssertTenant
        Require ((ReadMailbox) -ceq $plan.mailboxGuid) 'mailbox_changed_before_cas'
        $before=ReadPolicy
        Require ($before.organization -ceq $plan.organizationPolicy -and
            $before.mailbox -ceq $plan.mailboxPolicy -and $before.effective -ceq 'disabled') 'smtp_policy_changed_before_cas'
        Set-CASMailbox -Identity $plan.mailboxGuid -SmtpClientAuthenticationDisabled $false -ErrorAction Stop | Out-Null
    }
    AssertTenant
    Require ((ReadMailbox) -ceq $plan.mailboxGuid) 'mailbox_changed_after_apply'
    Require ((PrincipalState) -ceq 'reuse') 'principal_changed_after_apply'
    Require ((Authorization).inScope -gt 0) 'smtp_rbac_postcheck_unverified'
    $after=ReadPolicy
    Require ($after.organization -ceq $plan.organizationPolicy) 'organization_policy_changed'
    if ($plan.enableMailboxSmtp) {
        Require ($after.mailbox -ceq 'enabled' -and $after.effective -ceq 'enabled') 'smtp_enable_postcheck_failed'
    } else { Require ($after.mailbox -ceq $plan.mailboxPolicy) 'mailbox_policy_changed' }
    return $after.effective
}
function SaveResult($plan,[string]$sha,[bool]$applied,[string]$effective) {
    $result=[ordered]@{
        plan=$plan;planSha256=$sha;applied=$applied
        changes=($applied -and ($plan.createRole -or $plan.enableMailboxSmtp))
        effectivePolicy=$effective;authorization=$(if ($applied) {'in_scope'} else {'not_run'})
        graphChanged=$false;organizationChanged=$false;mailSent=$false;postFixChanged=$false
    }
    $bytes=[Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress -Depth 10))
    $file=[IO.File]::Open($ResultPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
if ($SelfTest) {
    $id='11111111-1111-4111-8111-111111111111'
    Require ((ExactFilter $id) -ceq "Guid -eq '$id'") 'filter_selftest'
    Require (IsExactFilter "(Guid -eq '$id')" $id) 'normalized_filter_selftest'
    Require (-not (IsExactFilter "(Guid -eq '$id') -or (Name -like '*')" $id)) 'broad_filter_selftest'
    Require (-not (IsExactFilter "Guid -eq '22222222-2222-4222-8222-222222222222'" $id)) 'wrong_guid_selftest'
    Require ((Effective 'disabled' 'inherit') -ceq 'disabled') 'policy_inherit_selftest'
    Require ((Effective 'disabled' 'enabled') -ceq 'enabled') 'policy_override_selftest'
    Require ((ScopeName ([guid]$id) ([guid]$id) $id) -cmatch '^LMR365-MBX-[a-f0-9]{32}$') 'name_selftest'
    Require ((ScopeName ([guid]$id) ([guid]$id) $id) -cne
        (ScopeName ([guid]$id) ([guid]$id) '22222222-2222-4222-8222-222222222222')) 'name_separation_selftest'
    Require ((PlanHash ([ordered]@{mailbox=$id;enable=$false})) -cne
        (PlanHash ([ordered]@{mailbox=$id;enable=$true}))) 'plan_policy_binding_selftest'
    Write-Output 'MAILBOX_SMTP_SCOPE_SELF_TEST=pass'
    return
}
Require ($TenantId -ne [guid]::Empty -and $ClientId -ne [guid]::Empty -and
    $EnterpriseObjectId -ne [guid]::Empty -and $ClientId -ne $EnterpriseObjectId) 'exact_cloud_identity_required'
Require ($Mailbox.Length -le 254 -and $Mailbox -ceq $Mailbox.ToLowerInvariant() -and
    $Mailbox -cmatch '^[a-z0-9][a-z0-9._+-]{0,62}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -and
    -not $Mailbox.Contains('..')) 'invalid_primary_mailbox'
Require ($Nonce -cmatch '^[a-f0-9]{64}$' -and [IO.Path]::IsPathFullyQualified($ResultPath) -and
    -not (Test-Path -LiteralPath $ResultPath)) 'invalid_report_context'
Require (($Phase -ceq 'Preview' -and -not $ExpectedSha256 -and -not $TypedConfirmation) -or
    ($Phase -ceq 'Apply' -and $ExpectedSha256 -cmatch '^[a-f0-9]{64}$' -and $TypedConfirmation -ceq $phrase)) 'approval_required'
Require ($null -ne (Get-Module -ListAvailable ExchangeOnlineManagement)) 'exchange_module_required'
$attempted=$false
$opened=$false
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Require (@(Get-ConnectionInformation -ErrorAction Stop).Count -eq 0) 'unexpected_existing_exchange_session'
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    $opened=$true
    AssertTenant
    $plan=ReadPlan
    $sha=PlanHash $plan
    Require ((PlanHash (ReadPlan)) -ceq $sha) 'plan_changed_during_preview'
    if ($Phase -ceq 'Preview') { SaveResult $plan $sha $false $plan.effectivePolicy; return }
    Require ($sha -ceq $ExpectedSha256 -and ($plan.createRole -or $plan.enableMailboxSmtp)) 'stale_or_empty_approved_plan'
    $attempted=$true
    $effective=ApplyPlan $plan $sha
    SaveResult $plan $sha $true $effective
} catch {
    if ($attempted) { Write-Warning 'Apply outcome requires manual review; never retry blindly. No automatic removal.' }
    throw
} finally {
    if ($opened) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
}
