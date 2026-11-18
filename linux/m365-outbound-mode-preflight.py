#!/usr/bin/env python3
"""Microsoft 365 Direct Send / inbound Connector readiness plan (READ-ONLY).

No Connector is provisioned and no Postfix settings are modified. Direct Send
can deliver only to internal tenant recipients. SMTP Relay requires an inbound
Microsoft 365 connector and a static unshared public IP or validated TLS cert.
The selected local custom SMTP port is NOT the outbound Microsoft port 25.
Python 3.6+ on RHEL 8/Oracle Linux 8.
"""
import argparse
import ipaddress
import re
import shutil
import smtplib
import ssl
import subprocess
from pathlib import Path

DOMAIN=re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\Z")
PATH=re.compile(r"/[A-Za-z0-9_./-]{1,255}\Z")


def validate_domain(name):
    if not isinstance(name,str) or not 3<=len(name)<=253 or not DOMAIN.fullmatch(name):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def eop_mx_name(host):
    return validate_domain(host) and host.lower().endswith(".mail.protection.outlook.com") and len(host.split("."))>=5


def external_ipv4(value):
    if not value:
        return False
    try:
        addr=ipaddress.ip_address(value)
        return isinstance(addr,ipaddress.IPv4Address) and addr.is_global
    except ValueError:
        return False


def cert_matches(path,domains):
    """Conservative identity preview. Never reads or logs TLS private keys."""
    if not path or not PATH.fullmatch(path) or ".." in path.split("/"):
        return "not_configured"
    if not Path(path).is_file() or not shutil.which("openssl"):
        return "not_available"
    try:
        name=subprocess.run(["openssl","x509","-in",path,"-noout","-ext","subjectAltName"],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            universal_newlines=True,timeout=8,check=False)
        exp=subprocess.run(["openssl","x509","-in",path,"-noout","-checkend","604800"],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           universal_newlines=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return "unavailable"
    if name.returncode or exp.returncode:
        return "invalid_or_expiring"
    sans=[x.lower() for x in re.findall(r'DNS:([A-Za-z0-9*.-]+)',name.stdout)]
    if any(s in sans for s in [d.lower() for d in domains]):
        return "san_matches_declared_domain_not_tenant_verified"
    return "no_accepted_domain_san_match"


def connectivity(mx_host):
    """An opt-in STARTTLS probe only; no AUTH or MAIL/RCPT/DATA submitted."""
    result="not_checked"
    try:
        # Reject split-horizon/poisoned DNS resolutions to private or local IPs.
        import socket
        addrs=socket.getaddrinfo(mx_host,25,socket.AF_INET,socket.SOCK_STREAM)
        if not addrs or any(not ipaddress.ip_address(row[4][0]).is_global for row in addrs):
            return "unsafe_dns_ip"
        with smtplib.SMTP(mx_host,25,timeout=9) as client:
            code,_=client.ehlo("lmr365-read-only-check.invalid")
            if code!=250:
                return "ehlo_failed"
            if not client.has_extn("starttls"):
                return "starttls_missing"
            client.starttls(context=ssl.create_default_context())
            client.ehlo("lmr365-read-only-check.invalid")
        result="tls_12_plus_hostname_verified" # TLS version verified below in local option?
    except (OSError,smtplib.SMTPException,ssl.SSLError):
        result="unreachable_or_tls_unverified"
    return result


def plan(mode,port,mx,domains,public_ip="",cert_path="",probe=False):
    values={
        "OUTBOUND_MODE_PREFLIGHT_VERSION":"1",
        "SELECTED_LINUX_SMTP_PORT":str(port),
        "MICROSOFT365_OUTBOUND_PORT":"25",
        "MODE":mode,
        "RECIPIENT_SCOPE":"internal_only" if mode=="direct-send" else "internal_and_external_if_connector_authorized",
        "DOMAIN_SYNTAX":"valid" if domains and all(validate_domain(x) for x in domains) else "invalid",
        "MX_HOST_SYNTAX":"eop_format" if eop_mx_name(mx) else "invalid",
        "DECLARED_STATIC_PUBLIC_IPV4":"yes" if external_ipv4(public_ip) else "no",
        "TLS_CLIENT_CERTIFICATE":"not_configured",
        "TENANT_ACCEPTED_DOMAINS_VERIFIED":"no",
        "EXCHANGE_CONNECTOR_EXISTS_AND_MATCHES":"not_verified",
        "EOP_TLS_CONNECTIVITY":"not_checked",
        "DNS_MX_OWNERSHIP_VERIFIED":"no",
        "OUTBOUND_DEPLOYED":"no",
        "SMTP_DELIVERY_VERIFIED":"no",
        "CHANGES_APPLIED":"no"
    }
    if cert_path:
        values["TLS_CLIENT_CERTIFICATE"]=cert_matches(cert_path,domains)
    if values["DOMAIN_SYNTAX"]!="valid" or values["MX_HOST_SYNTAX"]!="eop_format":
        state="invalid_inputs"
    elif mode=="connector" and not (external_ipv4(public_ip) or
        values["TLS_CLIENT_CERTIFICATE"]=="san_matches_declared_domain_not_tenant_verified"):
        state="connector_identity_missing"
    elif mode=="direct-send":
        state="tenant_domain_and_internal_only_policy_unverified"
    else:
        state="tenant_connector_and_smtp_policy_unverified"
    if probe and state!="invalid_inputs":
        values["EOP_TLS_CONNECTIVITY"]=connectivity(mx)
    values["PLAN_READINESS"]=state
    return values


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("direct-send","connector"),required=True)
    ap.add_argument("--smtp-port",type=int,required=True)
    ap.add_argument("--mx-host",required=True)
    ap.add_argument("--accepted-domain",action="append",default=[])
    ap.add_argument("--public-ip",default="")
    ap.add_argument("--cert-file",default="")
    ap.add_argument("--check-network",action="store_true")
    args=ap.parse_args()
    if not 1024<=args.smtp_port<=65535:
        ap.error("Local custom SMTP port must be 1024-65535")
    if not 1<=len(args.accepted_domain)<=8:
        ap.error("One to eight accepted domains are required")
    if args.cert_file and (not PATH.fullmatch(args.cert_file) or
                           ".." in args.cert_file.split("/")):
        ap.error("Certificate path must be a safe absolute path on Linux")
    for k,v in plan(args.mode,args.smtp_port,args.mx_host,args.accepted_domain,
                    args.public_ip,args.cert_file,args.check_network).items():
        print("{}={}".format(k,v))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
