#!/usr/bin/env python3
"""Read-only SMTP STARTTLS diagnosis for a Microsoft 365 MX, no mail or AUTH."""
import hashlib
import ipaddress
import json
import os
import re
import signal
import smtplib
import socket
import ssl
import subprocess
import sys

MX = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
PORT = 25
TIMEOUT = 8
CERT_ERROR = getattr(ssl, "SSLCertVerificationError", ssl.CertificateError)


class DeadlineExceeded(Exception):
    pass


def validate(host):
    if (not isinstance(host, str) or len(host) > 253 or not MX.fullmatch(host)
            or not host.endswith(".mail.protection.outlook.com")):
        raise ValueError("invalid Microsoft 365 MX")
    return host


def resolve(host):
    addresses = []
    for family, kind, proto, _, address in socket.getaddrinfo(
            host, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
        ip = ipaddress.ip_address(address[0])
        if family not in (socket.AF_INET, socket.AF_INET6) or not ip.is_global or ip.is_multicast:
            raise ValueError("non-public or unsupported DNS answer")
        row = (family, kind, proto, address)
        if row not in addresses:
            addresses.append(row)
        if len(addresses) > 32:
            raise ValueError("too many DNS answers")
    if not addresses:
        raise ValueError("no usable DNS answers")
    return addresses


class PinnedSMTP(smtplib.SMTP):
    def __init__(self, host, address):
        self.address = address
        self._host = host
        super().__init__(host='', local_hostname="localhost", timeout=TIMEOUT)
        self._host = host

    def _get_socket(self, host, port, timeout):
        family, kind, proto, address = self.address
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            return sock
        except BaseException:
            sock.close()
            raise


def context():
    # Do not read SSLKEYLOGFILE or weaken hostname/chain validation.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Limit trust to the standard OpenSSL trust locations, not SSH environment overrides.
    defaults = ssl.get_default_verify_paths()
    for variable in (defaults.openssl_cafile_env, defaults.openssl_capath_env):
        if variable:
            os.environ.pop(variable, None)
    ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        for name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            ctx.options |= getattr(ssl, name)
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise ValueError("verification required")
    return ctx


def code_only(value):
    return value if type(value) is int and 100 <= value <= 599 else None


def safe_name(value):
    if isinstance(value, str) and 0 < len(value) <= 200 and all(32 <= ord(c) <= 126 for c in value):
        return value
    return None


def certificate(sock):
    der = sock.getpeercert(binary_form=True)
    details = sock.getpeercert()
    if not der or not isinstance(details, dict) or not details:
        raise ValueError("peer certificate unavailable")
    names = [safe_name(value) for kind, value in details.get("subjectAltName", ())
             if kind == "DNS"]
    issuer = next((safe_name(value) for row in details.get("issuer", ())
                   for key, value in row if key == "commonName"), None)
    cipher = sock.cipher()
    return {"protocol": safe_name(sock.version()), "cipher": safe_name(cipher[0]) if cipher else None,
            "certificate_sha256": hashlib.sha256(der).hexdigest(),
            "issuer_cn": issuer, "not_before": safe_name(details.get("notBefore")),
            "not_after": safe_name(details.get("notAfter")),
            "dns_sans": [name for name in names if name is not None][:32],
            "certificate_chain_and_hostname_verified": True}


def probe_one(host, address, ctx, factory=PinnedSMTP):
    row = {"family": "ipv4" if address[0] == socket.AF_INET else "ipv6",
           "address": address[3][0], "stage": "tcp_banner", "status": "unverified"}
    client = None
    try:
        client = factory(host, address)
        code, _ = client.connect(host, PORT)
        row["banner_code"] = code_only(code)
        if code != 220:
            row["status"] = "banner_refused"
            return row
        row["stage"] = "ehlo"
        code, _ = client.ehlo()
        row["ehlo_code"] = code_only(code)
        if code != 250:
            row["status"] = "ehlo_refused"
            return row
        if not client.has_extn("starttls"):
            row["status"] = "starttls_missing"
            return row
        row["stage"] = "starttls"
        code, _ = client.starttls(context=ctx)
        row["starttls_code"] = code_only(code)
        if code != 220:
            row["status"] = "starttls_refused"
            return row
        row.update(certificate(client.sock))
        if row["protocol"] not in ("TLSv1.2", "TLSv1.3"):
            row["status"] = "unsupported_protocol"
            return row
        row["stage"] = "post_tls_ehlo"
        code, _ = client.ehlo()
        row["post_tls_ehlo_code"] = code_only(code)
        row["status"] = "tls_verified" if code == 250 else "post_tls_ehlo_refused"
    except CERT_ERROR as error:
        row["status"] = "certificate_verification_failed"
        row["verify_code"] = getattr(error, "verify_code", None)
    except ssl.SSLError:
        row["status"] = "tls_handshake_failed"
    except smtplib.SMTPResponseException as error:
        row["status"] = "smtp_refused"
        row["smtp_code"] = code_only(error.smtp_code)
    except (socket.timeout, TimeoutError):
        row["status"] = "timeout"
    except ConnectionRefusedError:
        row["status"] = "connection_refused"
    except smtplib.SMTPException:
        row["status"] = "smtp_protocol_or_disconnect"
    except OSError:
        row["status"] = "network_error"
    except ValueError:
        row["status"] = "peer_details_unverified"
    finally:
        if client is not None:
            client.close()
    return row


def inspect(host, resolver=resolve, context_fn=context, probe=probe_one):
    validate(host)
    report = {"version": 1, "host": host, "port": PORT, "status": "diagnosis",
              "dns": "unverified", "observations": [], "client_certificate_loaded": False,
              "postfix_process_tested": False, "mail_sent": False, "auth_attempted": False,
              "exchange_connector_verified": False}
    try:
        addresses = resolver(host)
    except (OSError, ValueError):
        report["dns"] = "failed_or_nonpublic"
        return report
    report["dns"] = "resolved"
    report["resolved_count"] = len(addresses)
    # One address of each family at most. Do not claim all MX addresses work.
    chosen = []
    for family in (socket.AF_INET, socket.AF_INET6):
        match = next((row for row in addresses if row[0] == family), None)
        if match is not None:
            chosen.append(match)
    try:
        ctx = context_fn()
    except (OSError, ValueError, ssl.SSLError):
        report["status"] = "local_trust_unavailable"
        return report
    for address in chosen:
        report["observations"].append(probe(host, address, ctx))
    return report


def alarm_handler(*_):
    raise DeadlineExceeded("diagnostic deadline")


def public_mx(domain, runner=subprocess.run):
    """Observe public MX records, without assuming domain-to-EOP name conversion."""
    if not isinstance(domain, str) or len(domain) > 253 or not MX.fullmatch(domain):
        raise ValueError("invalid accepted domain")
    report = dict(version=1, status="dns_unverified", domain=domain, resolver="1.1.1.1",
                  records=[], recommended_mx=None, tenant_verified=False,
                  postfix_modified=False, mail_sent=False)
    try:
        reply = runner(["/usr/bin/dig", "-r", "@1.1.1.1", domain+".", "MX",
                        "+time=3", "+tries=1", "+noall", "+comments", "+answer"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
                       env={"PATH":"/usr/bin:/bin", "LC_ALL":"C"})
        if reply.returncode or len(reply.stdout) > 65536:
            return report
        text = reply.stdout.decode("ascii", "strict")
        statuses = re.findall(r"\bstatus:\s*([A-Z]+),", text)
        if len(statuses) != 1 or statuses[0] not in ("NOERROR","NXDOMAIN"):
            return report
        if any("tc" in line.split(";",1)[0].split() for line in
               (x[len(";; flags:"):].strip() for x in text.splitlines()
                if x.startswith(";; flags:"))):
            return report
        records = set()
        for line in text.splitlines():
            if not line.strip() or line.startswith(";"):
                continue
            fields = line.split()
            if (len(fields) != 6 or fields[0].lower() != domain+"." or not fields[1].isdigit()
                    or fields[2:4] != ["IN","MX"] or not re.fullmatch(r"[0-9]{1,5}", fields[4])):
                return report
            preference = int(fields[4])
            host = fields[5].lower()
            if preference > 65535 or (host != "." and
                    (not host.endswith(".") or len(host) > 254 or not MX.fullmatch(host[:-1]))):
                return report
            records.add((preference, host.rstrip(".") or "."))
            if len(records) > 32:
                return report
        if statuses[0] == "NXDOMAIN":
            if not records:
                report["status"] = "nxdomain"
            return report
        if not records:
            report["status"] = "no_mx"
            return report
        if any(host == "." for _, host in records):
            if records == {(0, ".")}:
                report["status"] = "null_mx"
            return report
        rows = [dict(preference=p, host=h, microsoft365=h.endswith(".mail.protection.outlook.com"))
                for p,h in sorted(records)]
        report["records"] = rows
        best = [r for r in rows if r["preference"] == rows[0]["preference"]]
        if not all(r["microsoft365"] for r in rows):
            report["status"] = "mixed_or_gateway"
        elif len(best) != 1:
            report["status"] = "multiple_preferred"
        else:
            report.update(status="direct_m365", recommended_mx=best[0]["host"])
    except FileNotFoundError:
        report["status"] = "dig_missing"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return report


def main():
    try:
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(55)
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024:
            raise ValueError("request too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("invalid request")
        if set(request) == {"mx"}:
            report = inspect(request["mx"])
        elif set(request) == {"accepted_domain"}:
            report = public_mx(request["accepted_domain"])
        else:
            raise ValueError("invalid request")
        print(json.dumps(report))
        return 0
    except (ValueError, OSError, DeadlineExceeded):
        print(json.dumps({"status": "refused_or_timeout", "mail_sent": False}))
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
