"""Conservative DNS-01 provider recommendations from discovery evidence."""
PROVIDERS=("dns-cloudflare","dns-azure","dns-google","dns-route53","dns-rfc2136")

def recommend(dns, delegation, plugins):
    zone=delegation.get("zone_hint") or dns
    hint=zone.get("provider_hint","unknown") if isinstance(zone,dict) else "unknown"
    delegated=delegation.get("delegated",False)
    registered=plugins.get("providers",{}) if plugins.get("status")=="completed" else {}
    options=[]
    for provider in PROVIDERS:
        available=registered.get(provider,{}).get("registered") is True
        matches=provider==hint
        options.append(dict(provider=provider,registered=available,
            dns_hint_matches=matches,credentials_verified=False,
            recommended=available and matches and not delegated,
            issuance_verified=False))
    selected=[x["provider"] for x in options if x["recommended"]]
    return dict(recommended_provider=selected[0] if len(selected)==1 else None,
        options=options,manual_available=True,
        delegated=delegated,delegation_support_verified=False,
        automatic_issuance_allowed=False,
        reason="delegated_challenge_requires_review" if delegated else
        "provider_hint_only" if selected else "manual_provider_review_required")
