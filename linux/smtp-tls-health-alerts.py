"""Convert certificate health observations into actionable alerts."""
def alerts(report):
    checks=report.get("checks",{})
    result=[]
    def add(code,severity):
        result.append(dict(code=code,severity=severity))
    def status(key):
        return checks.get(key,{}).get("status")
    if status("generation")!="passed":
        add("active_generation_unverified","critical")
    elif status("valid_for_0_days")=="failed":
        add("certificate_expired_or_invalid","critical")
    elif status("valid_for_7_days")=="failed":
        add("certificate_expires_within_7_days","critical")
    elif status("valid_for_30_days")=="failed":
        add("certificate_expires_within_30_days","warning")
    elif status("valid_for_30_days")!="passed":
        add("expiration_unverified","warning")
    if status("postfix_binding")!="passed":
        add("postfix_binding_unverified","critical")
    timer=checks.get("timer",{}).get("properties",{})
    if timer.get("ActiveState")!="active":
        add("renewal_timer_not_active_or_unknown","warning")
    service=checks.get("service",{}).get("properties",{})
    if service.get("Result") not in (None,"","success"):
        add("last_renewal_failed","critical")
    return result
