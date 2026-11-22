#!/usr/bin/env python3
"""Read-only local health report for isolated LinuxMailRelay365 Postfix.

Does not expose sender/recipient addresses, message IDs, tokens, credentials or
private keys. No mail is submitted and no external connections are made.
Compatible with Python 3.6 on RHEL/Oracle Linux 8. Local readiness is NOT
evidence of delivery to Exchange Online.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

QUEUE=Path("/var/spool/linuxmailrelay365-sidecar")
CONFIG=Path("/etc/linuxmailrelay365/sidecar-postfix")
IDENTITY=Path("/etc/linuxmailrelay365/sidecar-identity/app.json")
MAX_QUEUE_OUTPUT=8*1024*1024


def run(args,timeout=7):
    if not args or not shutil.which(args[0]):
        return None
    try:
        res=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           timeout=timeout,universal_newlines=True,check=False)
        if res.returncode:
            return None
        return res.stdout if len(res.stdout)<=MAX_QUEUE_OUTPUT else None
    except (OSError,subprocess.TimeoutExpired):
        return None


def queue_metrics(output,now=None):
    """Postfix -j gives JSON lines. Never retains or prints message metadata."""
    if output is None or len(output)>MAX_QUEUE_OUTPUT:
        return None
    now=time.time() if now is None else now
    total=0;deferred=0; oldest=0
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            item=json.loads(line)
            if not isinstance(item,dict):
                return None
            ts=item.get("arrival_time")
            if not isinstance(ts,(int,float)) or ts<0 or ts>now+300:
                return None
            recipients=item.get("recipients",[])
            if not isinstance(recipients,list) or len(recipients)>1000:
                return None
            if item.get("queue_name")=="deferred":
                deferred+=1
            total+=1
            oldest=max(oldest,int((now-ts)/60))
            if total>50000:
                return None
        except (ValueError,TypeError,OverflowError):
            return None
    return total,deferred,oldest


def certificate_days(cert_path,now=None):
    if not cert_path or not Path(cert_path).is_file():
        return None
    data=run(["openssl","x509","-in",str(cert_path),"-noout","-enddate"])
    if data is None:
        return None
    m=re.search(r'(?m)^notAfter=(.+)\s*$',data)
    if not m:
        return None
    try:
        from email.utils import parsedate_to_datetime
        moment=parsedate_to_datetime(m.group(1).strip())
        if moment.tzinfo is None:
            moment=moment.replace(tzinfo=datetime.timezone.utc)
        clock=datetime.datetime.now(datetime.timezone.utc) if now is None else now
        return int((moment-clock).total_seconds()//86400)
    except (ValueError,TypeError,OverflowError):
        return None


def sender_certificate():
    try:
        obj=json.loads(IDENTITY.read_text(encoding="utf-8"))
        value=obj.get("certificate","")
        if not isinstance(value,str) or not value.startswith("/") or len(value)>260:
            return None
        return certificate_days(value)
    except (OSError,ValueError,TypeError):
        return None


def service(name):
    raw=run(["systemctl","is-active",name])
    return "active" if raw and raw.strip()=="active" else "unavailable_or_inactive"


def health(port,max_deferred=20,max_age=60,min_free=1024,warn_cert=21):
    values={
        "RELAY_HEALTH_REPORT_VERSION":"1",
        "CUSTOM_SMTP_PORT":str(port),
        "HEALTH_SIDECAR":"not_installed",
        "HEALTH_SIDECAR_SERVICE":"unknown",
        "HEALTH_AUTH_SERVICE":"not_applicable",
        "HEALTH_AUTH_POLICY":"not_verified",
        "QUEUE_STATUS":"not_checked",
        "QUEUE_MESSAGES":"unknown",
        "QUEUE_DEFERRED":"unknown",
        "QUEUE_OLDEST_AGE_MIN":"unknown",
        "QUEUE_FREE_MIB":"unknown",
        "M365_CERT_REMAINING_DAYS":"unknown",
        "TLS_SERVER_CERT_REMAINING_DAYS":"not_applicable",
        "HEALTH_ALERTS":"not_installed",
        "HEALTH_STATUS":"not_installed",
        "MICROSOFT365_DELIVERY_VERIFIED":"no",
        "CHANGES_APPLIED":"no"
    }
    if not (CONFIG/"main.cf").is_file() or not (CONFIG/"smtp-port").is_file():
        return values
    values["HEALTH_SIDECAR"]="installed"
    alerts=[]
    try:
        actual=(CONFIG/"smtp-port").read_text(encoding="ascii").strip()
        if actual!=str(port):
            alerts.append("custom_port_mismatch")
    except (OSError,UnicodeError):
        alerts.append("custom_port_unreadable")
    values["HEALTH_SIDECAR_SERVICE"]=service("linuxmailrelay365-sidecar.service")
    if values["HEALTH_SIDECAR_SERVICE"]!="active":
        alerts.append("smtp_service_inactive")
    sasl=run(["postconf","-c",str(CONFIG),"-h","smtpd_sasl_auth_enable"])
    tls=run(["postconf","-c",str(CONFIG),"-h","smtpd_tls_security_level"])
    if sasl is not None and sasl.strip()=="yes":
        values["HEALTH_AUTH_POLICY"]="auth_tls" if tls and tls.strip()=="encrypt" else "auth_without_mandatory_tls"
        values["HEALTH_AUTH_SERVICE"]=service("linuxmailrelay365-smtp-auth.service")
        if values["HEALTH_AUTH_SERVICE"]!="active":
            alerts.append("dovecot_auth_service_inactive")
        if values["HEALTH_AUTH_POLICY"]!="auth_tls":
            alerts.append("auth_tls_policy_mismatch")
        tls_days=certificate_days("/etc/linuxmailrelay365/smtp-auth/fullchain.pem")
        values["TLS_SERVER_CERT_REMAINING_DAYS"]=str(tls_days) if tls_days is not None else "unknown"
        if tls_days is None or tls_days<warn_cert:
            alerts.append("smtp_tls_certificate_expiring_or_unknown")
    elif sasl is not None and sasl.strip()=="no":
        values["HEALTH_AUTH_POLICY"]="trusted_private_without_auth"
    else:
        values["HEALTH_AUTH_POLICY"]="unknown"
        alerts.append("smtp_auth_policy_unknown")

    raw=run(["postqueue","-c",str(CONFIG),"-j"],timeout=10)
    metrics=queue_metrics(raw)
    if metrics is None:
        values["QUEUE_STATUS"]="unknown"
        alerts.append("queue_inventory_unavailable")
    else:
        total,deferred,oldest=metrics
        values.update(QUEUE_STATUS="read_only",
                      QUEUE_MESSAGES=str(total),
                      QUEUE_DEFERRED=str(deferred),
                      QUEUE_OLDEST_AGE_MIN=str(oldest))
        if deferred>=max_deferred:
            alerts.append("deferred_queue_threshold")
        if oldest>=max_age:
            alerts.append("old_queue_message")
    try:
        disk=shutil.disk_usage(str(QUEUE))
        free=int(disk.free//(1024*1024))
        values["QUEUE_FREE_MIB"]=str(free)
        if free<min_free:
            alerts.append("low_queue_disk_space")
    except OSError:
        alerts.append("queue_disk_unknown")
    days=sender_certificate()
    values["M365_CERT_REMAINING_DAYS"]=str(days) if days is not None else "unknown"
    if days is None or days<warn_cert:
        alerts.append("m365_certificate_expiring_or_unknown")
    values["HEALTH_ALERTS"]=",".join(sorted(set(alerts))) if alerts else "none"
    values["HEALTH_STATUS"]="attention" if alerts else "local_preflight_only"
    return values


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--smtp-port",required=True,type=int)
    p.add_argument("--max-deferred",type=int,default=20)
    p.add_argument("--max-age-min",type=int,default=60)
    p.add_argument("--min-free-mib",type=int,default=1024)
    p.add_argument("--warn-cert-days",type=int,default=21)
    args=p.parse_args()
    if not (args.smtp_port == 25 or 1024<=args.smtp_port<=65535):
        p.error("custom SMTP port 1024-65535")
    if not 1<=args.max_deferred<=100000 or not 1<=args.max_age_min<=100000 or \
            not 64<=args.min_free_mib<=1000000 or not 1<=args.warn_cert_days<=365:
        p.error("monitoring thresholds outside supported range")
    for name,val in health(args.smtp_port,args.max_deferred,args.max_age_min,
                           args.min_free_mib,args.warn_cert_days).items():
        print("{}={}".format(name,val))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
