#!/usr/bin/env python3
"""Read-only ACME DNS-01 issuance plan. Never invokes Certbot."""
import json
import re
import sys
import hashlib

def dns(value):
    if not isinstance(value,str) or len(value)>253:
        raise ValueError("invalid DNS name")
    value=value.lower()
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
               for x in value.split(".")) or "." not in value:
        raise ValueError("invalid DNS name")
    return value

def plan(request):
    domain=dns(request["accepted_domain"])
    name=dns(request["certificate_name"])
    if name!=domain and not name.endswith("."+domain):
        raise ValueError("name outside selected domain")
    provider=request["provider"]
    if provider not in ("manual","dns-azure","dns-cloudflare","dns-route53",
                        "dns-google","dns-rfc2136"):
        raise ValueError("unsupported provider")
    result=dict(version=1,certificate_name=name,accepted_domain=domain,
                challenge="_acme-challenge."+name,provider=provider,
                renewal_method="manual" if provider=="manual" else "plugin_candidate",
                accepted_domain_verified=False,ca_client_tls_verified=False,
                issuance_supported=False)
    result["plan_sha256"]=hashlib.sha256(json.dumps(result,sort_keys=True,
        separators=(",",":")).encode("ascii")).hexdigest()
    return result

if __name__=="__main__":
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384:
            raise ValueError("request too large")
        print(json.dumps(plan(json.loads(raw.decode("utf-8")))))
    except (ValueError,KeyError,TypeError):
        print(json.dumps({"status":"refused","issuance_supported":False}))
        sys.exit(1)
