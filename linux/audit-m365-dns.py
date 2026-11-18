#!/usr/bin/env python3
"""Read-only public DNS evidence for a Microsoft 365 accepted mail domain.

No DNS changes, no mail submission, no tenant permissions, no sensitive
identifiers or raw DNS record values are returned to the Wizard. Python 3.6+.
A correct public DNS record is never proof the tenant accepts that domain.
"""
import argparse
import re
import shlex
import shutil
import subprocess
import sys

DOMAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
ENDPOINT = ".mail.protection.outlook.com"


def value(name, item):
    print("{}={}".format(name, item))


def lookup(domain, kind, timeout=9):
    if not shutil.which("dig"):
        return None
    try:
        response = subprocess.run(
            ["dig", "+time=3", "+tries=1", "+short", kind, domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, universal_newlines=True, check=False)
        if response.returncode or len(response.stdout) > 8192:
            return None
        return response.stdout.strip().splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return None


def txt_records(lines):
    if lines is None:
        return None
    records = []
    for line in lines:
        try:
            parts = shlex.split(line)
        except ValueError:
            return None
        if not parts or len(parts) > 32:
            continue
        # DNS TXT can be split into 255-byte character-strings.
        records.append("".join(parts))
    return records


def evaluate(domain, mxhost="", resolver=lookup):
    statuses = {
        "DOMAIN_DNS_REPORT_VERSION": "1",
        "DOMAIN_DNS_CHECK": "read_only",
        "M365_ACCEPTED_DOMAIN_VERIFIED": "no",
        "EXCHANGE_CONNECTOR_VERIFIED": "no",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no"
    }
    mx = resolver(domain, "MX")
    if mx is None:
        statuses["DNS_MX"] = "unknown"
    else:
        targets = []
        for line in mx:
            match = re.fullmatch(r"\s*[0-9]{1,5}\s+([A-Za-z0-9.-]+)[.]?\s*", line)
            if match:
                targets.append(match.group(1).lower().rstrip("."))
        matching = [m for m in targets if m.endswith(ENDPOINT)]
        statuses["DNS_MX"] = "microsoft365_candidate" if matching else (
            "other_provider" if targets else "not_found")
        if mxhost:
            statuses["DNS_SELECTED_EOP_MX"] = (
                "public_mx_matches_selection" if mxhost.lower().rstrip(".") in matching
                else "not_confirmed_by_public_mx")
    txt = txt_records(resolver(domain, "TXT"))
    if txt is None:
        statuses["DNS_SPF"] = "unknown"
    else:
        spf = [v for v in txt if re.match(r"^v=spf1(?:\s|$)", v, re.I)]
        if len(spf) > 1:
            statuses["DNS_SPF"] = "multiple_spf_records_invalid"
        elif not spf:
            statuses["DNS_SPF"] = "not_found"
        elif re.search(r"(?:^|\s)include:spf[.]protection[.]outlook[.]com(?:\s|$)", spf[0], re.I):
            statuses["DNS_SPF"] = "m365_include_present"
        else:
            statuses["DNS_SPF"] = "other_spf_review_required"
    dmarc = txt_records(resolver("_dmarc." + domain, "TXT"))
    if dmarc is None:
        statuses["DNS_DMARC"] = "unknown"
    else:
        policies = [v for v in dmarc if re.match(r"^v=DMARC1\s*;", v, re.I)]
        if not policies:
            statuses["DNS_DMARC"] = "not_found"
        elif len(policies) > 1:
            statuses["DNS_DMARC"] = "multiple_records_invalid"
        else:
            match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)",
                              policies[0], re.I)
            statuses["DNS_DMARC"] = match.group(1).lower() if match else "policy_invalid"
    for number in ("1", "2"):
        result = resolver("selector{}._domainkey.{}".format(number, domain), "CNAME")
        if result is None:
            state = "unknown"
        else:
            targets = [r.strip().rstrip(".") for r in result]
            state = "cname_present_unverified" if any(DOMAIN.fullmatch(x) for x in targets) else "not_found"
        statuses["DNS_DKIM_SELECTOR" + number] = state
    if any(statuses.get(x) == "unknown" for x in
           ("DNS_MX", "DNS_SPF", "DNS_DMARC", "DNS_DKIM_SELECTOR1", "DNS_DKIM_SELECTOR2")):
        statuses["DNS_EVIDENCE"] = "partial_no_dns_records_changed"
    else:
        statuses["DNS_EVIDENCE"] = "public_records_only_no_tenant_authorization"
    return statuses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="")
    parser.add_argument("--mx-host", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        value("DNS_AUDIT_PARSER", "ready")
        return 0
    if not DOMAIN.fullmatch(args.domain) or len(args.domain) > 253:
        parser.error("An exact accepted-domain DNS name is required")
    if args.mx_host and (not DOMAIN.fullmatch(args.mx_host) or
                         not args.mx_host.lower().endswith(ENDPOINT)):
        parser.error("Selected MX must be an exact EOP hostname")
    for key, item in evaluate(args.domain.lower(), args.mx_host.lower()).items():
        value(key, item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
