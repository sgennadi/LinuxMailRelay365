#!/usr/bin/env python3
"""Read-only SMTP client certificate eligibility check; no issuance or installation."""
import argparse
import json
import subprocess
import re

def openssl(*args):
    return subprocess.check_output(["/usr/bin/openssl"]+list(args),
        stderr=subprocess.DEVNULL, timeout=15)

def inspect(cert, chain, domain, ca_file):
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", domain):
        raise ValueError("invalid DNS name")
    openssl("x509","-in",cert,"-noout","-checkend","0")
    openssl("verify","-purpose","sslclient","-CAfile",ca_file,
            "-untrusted",chain,cert)
    details=openssl("x509","-in",cert,"-noout","-subject","-issuer",
                    "-dates","-fingerprint","-sha256").decode("utf-8")
    # Local trust and purpose checks are not proof of Exchange Online acceptance.
    return {"status":"local_checks_passed","requested_domain":domain,
            "details":details,"exchange_acceptance":"unverified",
            "name_match":"unverified","private_key_match":"unverified",
            "apply_supported":False}

def main():
    parser=argparse.ArgumentParser()
    for name in ("cert","chain","domain","ca-file"):
        parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(inspect(args.cert,args.chain,args.domain,args.ca_file)))
    except (ValueError,OSError,subprocess.SubprocessError):
        print(json.dumps({"status":"refused","apply_supported":False}))
        return 1
    return 0

if __name__=="__main__":
    raise SystemExit(main())
