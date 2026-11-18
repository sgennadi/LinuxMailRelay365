#!/usr/bin/env python3
"""Verify SMTP STARTTLS certificate chain and DNS identity from Linux loopback.

Read-only, Python 3.6+, including RHEL/Oracle Linux 8. The local socket is
ALWAYS 127.0.0.1, while SNI and hostname verification use --server-name.
Never sends AUTH, MAIL FROM, RCPT TO or DATA, and never reads SMTP passwords.

This verifies trust in Linux's selected CA store, NOT the trust stores of
Windows/mobile/application clients. Never claims Exchange Online delivery.
"""
import argparse
import ipaddress
import os
import re
import smtplib
import socket
import ssl


def validate_hostname(name):
    if not isinstance(name, str) or len(name) > 253:
        return False
    if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", name):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def validate_ca_file(cafile):
    if not cafile:
        return True
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}", cafile)
            or ".." in cafile.split("/")):
        return False
    try:
        return os.path.isfile(cafile) and 0 < os.path.getsize(cafile) < 16 * 1024 * 1024
    except OSError:
        return False


class LoopbackOnlySmtp(smtplib.SMTP):
    """Keep SNI and hostname verification tied to DNS, not loopback IP."""

    def _get_socket(self, host, port, timeout):
        # __init__ stores 'host' as self._host for verified STARTTLS/SNI.
        # This overridden socket factory NEVER queries DNS or calls a remote IP.
        if host != self._host:
            raise OSError("Unexpected SMTP destination")
        return socket.create_connection(("127.0.0.1", port), timeout,
                                        self.source_address)


def probe_tls(port, server_name, ca_file=None, timeout=8):
    d = {
        "SMTP_TLS_PROBE_VERSION": "1",
        "SMTP_TLS_PORT": str(port),
        "SMTP_TLS_NETWORK": "loopback_only",
        "SMTP_TLS_CA_SOURCE": "explicit_linux_ca" if ca_file else "linux_system_trust",
        "SMTP_TLS_EHLO": "not_checked",
        "SMTP_TLS_STARTTLS": "not_checked",
        "SMTP_TLS_AUTH_BEFORE_TLS": "not_checked",
        "SMTP_TLS_CERT_CHAIN_AND_DNS": "not_verified",
        "SMTP_TLS_VERSION": "unknown",
        "SMTP_TLS_AUTH_AFTER_TLS": "not_checked",
        "SMTP_TLS_PROBE_RESULT": "failed",
        "SMTP_TLS_EXTERNAL_CLIENT_TRUST": "not_verified",
        "MICROSOFT365_DELIVERY_VERIFIED": "no",
        "CHANGES_APPLIED": "no",
    }
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        d["SMTP_TLS_PROBE_RESULT"] = "invalid_port"
        return d
    if not validate_hostname(server_name):
        d["SMTP_TLS_PROBE_RESULT"] = "invalid_dns_name"
        return d
    if not validate_ca_file(ca_file):
        d["SMTP_TLS_PROBE_RESULT"] = "invalid_ca_file"
        return d
    try:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        with LoopbackOnlySmtp(server_name, port, timeout=timeout) as smtp:
            status, _ = smtp.ehlo("lmr365-tls-identity-check.invalid")
            if status != 250:
                d["SMTP_TLS_PROBE_RESULT"] = "ehlo_failed"
                return d
            d["SMTP_TLS_EHLO"] = "ok"
            if not smtp.has_extn("starttls"):
                d["SMTP_TLS_STARTTLS"] = "not_advertised"
                d["SMTP_TLS_PROBE_RESULT"] = "starttls_not_advertised"
                return d
            d["SMTP_TLS_STARTTLS"] = "advertised"
            if smtp.has_extn("auth"):
                d["SMTP_TLS_AUTH_BEFORE_TLS"] = "yes"
                d["SMTP_TLS_PROBE_RESULT"] = "auth_advertised_before_tls"
                return d
            d["SMTP_TLS_AUTH_BEFORE_TLS"] = "no"
            # Context verifies certificate chain AND DNS SAN using SNI
            # server_name, despite the network socket going to 127.0.0.1.
            smtp.starttls(context=context)
            d["SMTP_TLS_CERT_CHAIN_AND_DNS"] = "verified"
            d["SMTP_TLS_VERSION"] = smtp.sock.version() or "unknown"
            status, _ = smtp.ehlo("lmr365-tls-identity-check.invalid")
            if status != 250:
                d["SMTP_TLS_PROBE_RESULT"] = "post_tls_ehlo_failed"
                return d
            d["SMTP_TLS_AUTH_AFTER_TLS"] = "yes" if smtp.has_extn("auth") else "no"
            if d["SMTP_TLS_VERSION"] not in ("TLSv1.2", "TLSv1.3"):
                d["SMTP_TLS_PROBE_RESULT"] = "tls_version_too_old_or_unknown"
                return d
            if d["SMTP_TLS_AUTH_AFTER_TLS"] != "yes":
                d["SMTP_TLS_PROBE_RESULT"] = "auth_not_advertised_after_tls"
                return d
            d["SMTP_TLS_PROBE_RESULT"] = "verified_local_chain_dns_and_starttls"
            return d
    except ssl.SSLCertVerificationError:
        d["SMTP_TLS_PROBE_RESULT"] = "certificate_untrusted_or_dns_mismatch"
    except ssl.SSLError:
        d["SMTP_TLS_PROBE_RESULT"] = "tls_handshake_failed"
    except (OSError, smtplib.SMTPException, ValueError):
        d["SMTP_TLS_PROBE_RESULT"] = "smtp_connection_or_protocol_failed"
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--smtp-port", type=int, required=True)
    ap.add_argument("--server-name", required=True)
    ap.add_argument("--ca-file", default=None,
                    help="Optional trusted CA bundle path on Linux; default system CA")
    ap.add_argument("--validate-only", action="store_true",
                    help="Validate arguments without opening any SMTP socket")
    args = ap.parse_args()
    if not 1024 <= args.smtp_port <= 65535:
        ap.error("Custom SMTP port must be 1024-65535")
    if not validate_hostname(args.server_name):
        ap.error("Server name must be a DNS hostname, not an IP or wildcard")
    if not validate_ca_file(args.ca_file):
        ap.error("CA file must exist, be readable, and be an absolute safe path")
    if args.validate_only:
        print("SMTP_TLS_PROBE_VERSION=1")
        print("SMTP_TLS_ARGUMENTS=valid_no_network")
        print("SMTP_TLS_PORT={}".format(args.smtp_port))
        print("CHANGES_APPLIED=no")
        return 0
    findings = probe_tls(args.smtp_port, args.server_name, args.ca_file)
    for name, value in findings.items():
        print("{}={}".format(name, value))
    return 0 if findings["SMTP_TLS_PROBE_RESULT"] == \
        "verified_local_chain_dns_and_starttls" else 2


if __name__ == "__main__":
    raise SystemExit(main())
