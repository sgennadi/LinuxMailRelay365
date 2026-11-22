#!/usr/bin/env python3
"""Read-only Gmail/Workspace SMTP transport diagnostics.

The script receives a one-off JSON config inside its SSH STDIN source, never
from argv, env, files or an interactive command line. It NEVER sends mail.
AUTH is performed only at the user's explicit request, after validated TLS,
and makes at most one SMTP AUTH attempt. Never output a server exception or
a credential; only fixed, non-sensitive status enums.
"""
import base64
import json
import re
import smtplib
import socket
import ssl
import sys

# LMR365_CONFIG_MARKER
GMAIL_HOST = "smtp.gmail.com"
WORKSPACE_HOST = "smtp-relay.gmail.com"
PROFILES = {
    "gmail": (GMAIL_HOST, ((587, "starttls"), (465, "ssl"))),
    "workspace": (WORKSPACE_HOST, ((587, "starttls"), (465, "ssl"), (25, "starttls"))),
}
TIMEOUT = 8


def config_from_encoded(value):
    # Only the Windows GUI embeds this encoded JSON over the encrypted SSH
    # standard input. It is not written into the Linux filesystem.
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Invalid input")
    data = json.loads(base64.b64decode(value, validate=True).decode("utf-8"))
    if type(data) is not dict:
        raise ValueError("Input must be a dictionary")
    profile = data.get("profile")
    if profile not in PROFILES:
        raise ValueError("Unsupported Google SMTP profile")
    auth = data.get("authenticate") is True
    if data.get("authenticate") not in (False, True):
        raise ValueError("Invalid auth mode")
    port = data.get("auth_port", 587)
    if type(port) is not int or port not in (465, 587):
        raise ValueError("Invalid credential test port")
    if auth:
        user, password = data.get("user"), data.get("secret")
        if not isinstance(user, str) or not re.fullmatch(
                r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,190}", user):
            raise ValueError("Invalid sender mailbox")
        if not isinstance(password, str) or not 1 <= len(password) <= 256 or any(
                ord(c) < 32 or ord(c) == 127 for c in password):
            raise ValueError("Invalid ephemeral authentication secret")
    else:
        if data.get("secret") or data.get("user"):
            raise ValueError("Unexpected credentials in a connectivity-only probe")
    return data


def connect_checked(host, port, tls_mode):
    """Return a live, certificate-verified SMTP session or sanitized status."""
    try:
        # Do not trust environment proxies, non-TLS downgrades, or SSL cert bypasses.
        context = ssl.create_default_context()
        if tls_mode == "ssl":
            client = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
        else:
            client = smtplib.SMTP(host, port, timeout=TIMEOUT)
        try:
            code, _ = client.ehlo()
            if code != 250:
                client.close()
                return None, "smtp_error", "unverified"
            if tls_mode == "starttls":
                if not client.has_extn("starttls"):
                    client.close()
                    return None, "reachable", "not_offered"
                client.starttls(context=context)
                code, _ = client.ehlo()
                if code != 250:
                    client.close()
                    return None, "reachable", "smtp_error"
            return client, "reachable", "verified"
        except Exception:
            client.close()
            raise
    except ssl.SSLCertVerificationError:
        return None, "reachable", "certificate_invalid"
    except (ssl.SSLError, smtplib.SMTPNotSupportedError):
        return None, "reachable", "tls_failed"
    except (TimeoutError, socket.timeout):
        return None, "timeout", "unverified"
    except ConnectionRefusedError:
        return None, "refused", "unverified"
    except (OSError, smtplib.SMTPException):
        return None, "failed", "unverified"


def advertised_auth(client):
    available = set(client.esmtp_features.get("auth", "").upper().split())
    if "PLAIN" in available:
        return "plain"
    if "LOGIN" in available:
        return "login"
    if "XOAUTH2" in available or "OAUTHBEARER" in available:
        return "oauth_only"
    return "none"


def try_one_auth(client, mechanism, user, password):
    # Exactly one SMTP AUTH, with no MAIL FROM/RCPT/DATA and no retry.
    if mechanism not in ("plain", "login"):
        return "method_not_advertised"
    try:
        if mechanism == "plain":
            code, _ = client.auth(
                "PLAIN", lambda challenge=None: "\0" + user + "\0" + password,
                initial_response_ok=True)
        else:
            client.user = user
            client.password = password
            code, _ = client.auth("LOGIN", client.auth_login, initial_response_ok=False)
        return "accepted" if code in (235, 503) else "rejected"
    except smtplib.SMTPAuthenticationError as error:
        # Classify SMTP reply CODE only; response body can contain sensitive
        # provider diagnostics or echoed identifiers.
        if error.smtp_code in (534, 535):
            return "rejected_or_policy"
        if 400 <= error.smtp_code < 500:
            return "temporary_error"
        return "rejected"
    except (smtplib.SMTPException, OSError, TimeoutError):
        return "unverified"
    finally:
        if hasattr(client, "user"):
            client.user = ""
        if hasattr(client, "password"):
            client.password = ""


def run(config):
    profile = config["profile"]
    host, targets = PROFILES[profile]
    print("GOOGLE_SMTP_AUDIT_VERSION=1")
    print("GOOGLE_SMTP_AUDIT_PROFILE=" + profile)
    print("GOOGLE_SMTP_AUDIT_HOST=" + host)
    try:
        socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        dns = "resolved"
    except OSError:
        dns = "failed"
    print("GOOGLE_SMTP_AUDIT_DNS=" + dns)
    evidence = {}
    for port, tls_mode in targets:
        client, tcp, tls = connect_checked(host, port, tls_mode) if dns == "resolved" else (
            None, "dns_failed", "unverified")
        mechanism = advertised_auth(client) if client is not None else "unverified"
        print(f"GOOGLE_SMTP_AUDIT_PORT_{port}_TCP={tcp}")
        print(f"GOOGLE_SMTP_AUDIT_PORT_{port}_TLS={tls}")
        print(f"GOOGLE_SMTP_AUDIT_PORT_{port}_AUTH={mechanism}")
        evidence[port] = (client, mechanism, tls)
        # One port is retained only if this is the user-selected auth test.
        if client is not None and (not config["authenticate"] or
                                   port != config["auth_port"]):
            client.quit()
            evidence[port] = (None, mechanism, tls)
    auth_result = "not_requested"
    if config["authenticate"]:
        client, mechanism, tls = evidence[config["auth_port"]]
        if client is None or tls != "verified":
            auth_result = "tls_or_connect_unverified"
        else:
            try:
                auth_result = try_one_auth(
                    client, mechanism, config["user"], config["secret"])
            finally:
                client.close()
    print("GOOGLE_SMTP_AUDIT_AUTH_RESULT=" + auth_result)
    print("GOOGLE_SMTP_AUDIT_MAIL_SENT=no")
    print("GOOGLE_SMTP_AUDIT_CONFIG_CHANGED=no")
    print("GOOGLE_SMTP_AUDIT_SECRETS_ECHOED=no")


def self_test():
    assert len(PROFILES["gmail"][1]) == 2
    assert len(PROFILES["workspace"][1]) == 3
    test = {
        "profile": "gmail", "authenticate": True,
        "auth_port": 587, "user": "relay@example.org", "secret": "only-for-test"
    }
    encoded = base64.b64encode(json.dumps(test).encode()).decode()
    assert config_from_encoded(encoded) == test
    for mutation in (
            dict(test, profile="bad"),
            dict(test, auth_port=2525),
            dict(test, user="bad\ninjected"),
            dict(test, secret="secret\rleaked"),
            dict(test, authenticate=False)):
        data = base64.b64encode(json.dumps(mutation).encode()).decode()
        try:
            config_from_encoded(data)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid test input was accepted")
    class AuthMock:
        esmtp_features = {"auth": "PLAIN LOGIN"}
        def auth(self, mechanism, responder, initial_response_ok=False):
            assert mechanism == "PLAIN"
            assert initial_response_ok is True
            assert responder() == "\0user@example.org\0test-secret"
            return 235, b"Authenticated"
    assert try_one_auth(AuthMock(), "plain", "user@example.org", "test-secret") == "accepted"
    assert try_one_auth(AuthMock(), "none", "user@example.org", "test-secret") == "method_not_advertised"
    print("Google SMTP probe self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        try:
            run(config_from_encoded(CONFIG_B64))
        except Exception:
            # Do not report exception text. SMTP errors often contain account
            # names, server replies, or provider URLs.
            print("GOOGLE_SMTP_AUDIT_VERSION=1")
            print("GOOGLE_SMTP_AUDIT_FATAL=unverified")
            print("GOOGLE_SMTP_AUDIT_MAIL_SENT=no")
            print("GOOGLE_SMTP_AUDIT_CONFIG_CHANGED=no")
            print("GOOGLE_SMTP_AUDIT_SECRETS_ECHOED=no")
            sys.exit(2)
