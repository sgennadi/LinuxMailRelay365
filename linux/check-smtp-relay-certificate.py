#!/usr/bin/env python3
"""Read-only SMTP client certificate eligibility check; no issuance or installation."""
import argparse
import json
import subprocess
import re
import hmac

def openssl(*args):
    return subprocess.check_output(["/usr/bin/openssl"]+list(args),
        stderr=subprocess.DEVNULL, timeout=15)

def inspect(cert, chain, domain, ca_file, key):
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", domain):
        raise ValueError("invalid DNS name")
    openssl("x509","-in",cert,"-noout","-checkend","0")
    # Verify hostname using OpenSSL's certificate matching rules, not substring matching.
    openssl("verify","-verify_hostname",domain,"-CAfile",ca_file,
            "-untrusted",chain,cert)
    cert_pub=openssl("x509","-in",cert,"-pubkey","-noout")
    key_pub=openssl("pkey","-in",key,"-passin","pass:","-pubout")
    if not hmac.compare_digest(cert_pub.strip(),key_pub.strip()):
        raise ValueError("certificate key mismatch")
    openssl("verify","-purpose","sslclient","-CAfile",ca_file,
            "-untrusted",chain,cert)
    details=openssl("x509","-in",cert,"-noout","-subject","-issuer",
                    "-dates","-fingerprint","-sha256").decode("utf-8")
    extensions=openssl("x509","-in",cert,"-noout","-ext",
                       "subjectAltName,extendedKeyUsage").decode("utf-8")
    eku=re.search(r"X509v3 Extended Key Usage:[^\n]*\n([^\n]+)",extensions)
    client_auth="not_explicit"
    if eku:
        client_auth=("explicit" if any(x.strip() in
            ("TLS Web Client Authentication","1.3.6.1.5.5.7.3.2")
            for x in eku.group(1).split(",")) else "not_explicit")
    # Local trust and purpose checks are not proof of Exchange Online acceptance.
    return {"status":"local_checks_passed","requested_domain":domain,
            "details":details,"extensions":extensions,"client_auth_eku":client_auth,
            "exchange_acceptance":"unverified",
            "name_match":"verified","private_key_match":"verified",
            "apply_supported":False}

def main():
    parser=argparse.ArgumentParser()
    for name in ("cert","chain","domain","ca-file","key"):
        parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(inspect(args.cert,args.chain,args.domain,args.ca_file,args.key)))
    except (ValueError,OSError,subprocess.SubprocessError):
        print(json.dumps({"status":"refused","apply_supported":False}))
        return 1
    return 0

if __name__=="__main__":
    raise SystemExit(main())
