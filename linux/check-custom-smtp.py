#!/usr/bin/env python3
"""Read-only probe for an operator-selected SMTP smarthost.

This is not an SMTP relay installer. Only DNS, connect, EHLO, explicitly
selected TLS, and optionally ONE SMTP AUTH command are permitted. There is
no MAIL FROM, RCPT TO, DATA, STARTTLS downgrade, certificate bypass, or
transmission of a password over plaintext. The one-use request is supplied
inside encrypted SSH stdin (not argv/environment/file) by the Windows GUI.
"""
import base64
import ipaddress
import json
import re
import smtplib
import socket
import ssl
import sys

# LMR365_CONFIG_MARKER
TIMEOUT = 8
REQUIRED = frozenset(("host", "port", "tls", "authenticate", "username", "secret"))
HOST = re.compile(
    r"\A(?=.{1,253}\Z)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\Z")


def validate(request):
    if type(request) is not dict or set(request) != REQUIRED:
        raise ValueError("Invalid request fields")
    host = request["host"]
    if type(host) is not str or not HOST.fullmatch(host):
        raise ValueError("Invalid SMTP destination")
    if re.fullmatch(r"[0-9.]+", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise ValueError("Invalid SMTP IPv4 destination")
    if type(request["port"]) is not int or not 1 <= request["port"] <= 65535:
        raise ValueError("Invalid outgoing TCP port")
    if request["tls"] not in ("starttls", "implicit", "plain"):
        raise ValueError("Unsupported TLS mode")
    if type(request["authenticate"]) is not bool:
        raise ValueError("Authentication mode not boolean")
    user, secret = request["username"], request["secret"]
    if type(user) is not str or type(secret) is not str:
        raise ValueError("Credentials must be strings")
    if request["authenticate"]:
        if request["tls"] == "plain":
            raise ValueError("Cannot transmit credentials without TLS")
        if (not 1 <= len(user) <= 254 or not 1 <= len(secret) <= 256 or
                any(ord(ch) < 33 or ord(ch) > 126 for ch in user) or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in secret)):
            raise ValueError("Invalid ephemeral credential")
    elif user or secret:
        raise ValueError("Credentials provided without consent")
    return request


def from_encoded(encoded):
    if type(encoded) is not str or not 1 <= len(encoded) <= 4096:
        raise ValueError("Invalid request size")
    decoded = base64.b64decode(encoded, validate=True)
    if len(decoded) > 2048:
        raise ValueError("Oversized request")
    return validate(json.loads(decoded.decode("utf-8")))


def advertised(client):
    features = set(client.esmtp_features.get("auth", "").upper().split())
    if "PLAIN" in features:
        return "plain"
    if "LOGIN" in features:
        return "login"
    if "XOAUTH2" in features or "OAUTHBEARER" in features:
        return "oauth_only"
    return "none"


def one_auth(client, mechanism, username, password):
    if mechanism not in ("plain", "login"):
        return "method_not_advertised"
    try:
        if mechanism == "plain":
            code, _ = client.auth(
                "PLAIN", lambda challenge=None: "\0" + username + "\0" + password,
                initial_response_ok=True)
        else:
            client.user, client.password = username, password
            code, _ = client.auth("LOGIN", client.auth_login, initial_response_ok=False)
        return "accepted" if code == 235 else "unverified"
    except smtplib.SMTPAuthenticationError as error:
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


def probe(request):
    state = {
        "DNS": "failed", "TCP": "dns_failed", "TLS": "unverified",
        "AUTH": "unverified", "AUTH_RESULT": "not_requested",
    }
    host, port, mode = request["host"], request["port"], request["tls"]
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return state
    state["DNS"] = "resolved"
    state["TCP"] = "failed"
    client = None
    try:
        ctx = ssl.create_default_context()
        if mode == "implicit":
            client = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=ctx)
        else:
            client = smtplib.SMTP(host, port, timeout=TIMEOUT)
        state["TCP"] = "reachable"
        code, _ = client.ehlo()
        if code != 250:
            state["TCP"] = "smtp_error"
            return state
        if mode == "starttls":
            if not client.has_extn("starttls"):
                state["TLS"] = "not_offered"
                return state
            client.starttls(context=ctx)
            code, _ = client.ehlo()
            if code != 250:
                state["TLS"] = "smtp_error"
                return state
            state["TLS"] = "verified"
        elif mode == "implicit":
            state["TLS"] = "verified"
        else:
            state["TLS"] = "not_used"
            # Plaintext EHLO may reveal capabilities but is NOT permission to
            # send a password. No one-shot AUTH button exists for this mode.
            state["AUTH"] = "unverified"
            return state
        state["AUTH"] = advertised(client)
        if request["authenticate"]:
            state["AUTH_RESULT"] = one_auth(
                client, state["AUTH"], request["username"], request["secret"])
        return state
    except ssl.SSLCertVerificationError:
        state["TCP"], state["TLS"] = "reachable", "certificate_invalid"
    except (ssl.SSLError, smtplib.SMTPNotSupportedError):
        state["TCP"], state["TLS"] = "reachable", "tls_failed"
    except (TimeoutError, socket.timeout):
        state["TCP"] = "timeout"
    except ConnectionRefusedError:
        state["TCP"] = "refused"
    except (OSError, smtplib.SMTPException):
        state["TCP"] = "failed"
    finally:
        if client is not None:
            try:
                client.close()   # No QUIT/Mail/RCPT/DATA round trip
            except OSError:
                pass
    return state


def main(request):
    state = probe(request)
    print("CUSTOM_SMTP_AUDIT_VERSION=1")
    print("CUSTOM_SMTP_AUDIT_HOST=" + request["host"])
    print("CUSTOM_SMTP_AUDIT_PORT=" + str(request["port"]))
    print("CUSTOM_SMTP_AUDIT_MODE=" + request["tls"])
    for key in ("DNS", "TCP", "TLS", "AUTH", "AUTH_RESULT"):
        print("CUSTOM_SMTP_AUDIT_" + key + "=" + state[key])
    print("CUSTOM_SMTP_AUDIT_MAIL_SENT=no")
    print("CUSTOM_SMTP_AUDIT_CONFIG_CHANGED=no")
    print("CUSTOM_SMTP_AUDIT_SECRETS_ECHOED=no")


def self_test():
    request = {"host": "mail.example.org", "port": 587, "tls": "starttls",
               "authenticate": False, "username": "", "secret": ""}
    assert from_encoded(base64.b64encode(json.dumps(request).encode()).decode()) == request
    for mutation in (
            dict(request, host="mail;cat /etc/shadow"),
            dict(request, host="255.888.0.1"),
            dict(request, port=0),
            dict(request, port=65536),
            dict(request, tls="off"),
            dict(request, authenticate=True, username="user", secret="test",
                 tls="plain"),
            dict(request, authenticate=True, username="user", secret="bad\nsecret"),
            dict(request, authenticate=False, secret="secret")):
        try:
            validate(mutation)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid custom SMTP request accepted")
    print("Custom SMTP read-only self-test OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        try:
            main(from_encoded(CONFIG_B64))
        except Exception:
            # Never output exception text: server SMTP replies can echo
            # addresses, usernames or credentials.
            print("CUSTOM_SMTP_AUDIT_VERSION=1")
            print("CUSTOM_SMTP_AUDIT_FATAL=unverified")
            print("CUSTOM_SMTP_AUDIT_MAIL_SENT=no")
            print("CUSTOM_SMTP_AUDIT_CONFIG_CHANGED=no")
            print("CUSTOM_SMTP_AUDIT_SECRETS_ECHOED=no")
            sys.exit(2)
