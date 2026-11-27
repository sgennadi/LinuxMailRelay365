#!/usr/bin/env python3
"""No-mail STARTTLS with an explicitly selected active managed Postfix identity.

A loaded client certificate is not evidence that the remote server requested,
received, or accepted it. Never export private keys or fall back to unverified TLS.
"""
import hashlib
import importlib.util
import json
import os
import re
import signal
import ssl
import sys
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(mx, review, pf):
    pf.verify_managed()
    read = lambda name: pf.run(pf.postconf, "-h", "-x", name)
    if read("relayhost").lower() not in ("[" + mx + "]", "[" + mx + "]:25"):
        raise ValueError("selected MX differs from configured relayhost")
    if read("smtp_sasl_auth_enable") != "no" or read("smtp_tls_security_level") not in ("encrypt", "verify", "secure"):
        raise ValueError("managed connector TLS route required")
    for name in ("transport_maps", "sender_dependent_relayhost_maps",
                 "sender_dependent_default_transport_maps", "smtp_tls_policy_maps", "smtp_fallback_relay"):
        if read(name):
            raise ValueError("custom route or TLS policy requires review")
    overrides = pf.run(pf.postconf, "-P")
    if any(re.search(r"/(?:smtp_|relayhost|default_transport|relay_transport|transport_maps|sender_dependent_|content_filter)", line)
           for line in overrides.splitlines()):
        raise ValueError("service-specific route or TLS override")
    pf.run(pf.postfix, "status")
    review.directory(review.ROOT, True)
    generation = review.active_generation()
    if generation is None:
        raise ValueError("no active managed generation")
    state = review.config_state(pf)
    journals = review.terminal_journals(generation, state["main_sha256"])
    return generation, state, journals


def password_refused():
    raise ValueError("encrypted client key requires separate review")


def inspect(mx, tls=None, review=None, pf=None):
    if os.geteuid() != 0:
        raise ValueError("root required")
    tls = tls or load("inspect-m365-starttls")
    tls.validate(mx)
    review = review or load("review-smtp-tls-rotation")
    pf = pf or load("smtp-tls-postfix").Postfix()
    before = snapshot(mx, review, pf)
    generation = before[0]
    path = review.ROOT / generation
    full = review.read_file(path / "fullchain.pem", 3 * 1024 * 1024, True)
    leaf = re.search(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", full)
    if leaf is None:
        raise ValueError("certificate unavailable")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.group().decode("ascii"))).hexdigest()
    ctx = tls.context()
    # The protected generation is immutable under the managed transaction model.
    # Load the existing local files directly; no temporary key copy or key output.
    ctx.load_cert_chain(str(path / "fullchain.pem"), str(path / "key.pem"), password=password_refused)
    if snapshot(mx, review, pf) != before:
        raise ValueError("active configuration changed while loading certificate")
    report = tls.inspect(mx, context_fn=lambda: ctx)
    if snapshot(mx, review, pf) != before:
        raise ValueError("active configuration changed during test")
    report.update(client_certificate_loaded=True, client_certificate_sha256=fingerprint,
                  client_generation=generation, client_certificate_presentation_verified=False,
                  active_configuration_unchanged=True)
    return report


def inspect_candidate(mx, candidate, domain, tls=None, review=None, validator=None, lock=None):
    """Test an inactive, validated candidate; never alter the active pointer or Postfix."""
    if os.geteuid() != 0:
        raise ValueError("root required")
    tls = tls or load("inspect-m365-starttls")
    tls.validate(mx)
    if (not isinstance(candidate, str) or not re.fullmatch(r"candidate-[a-f0-9]{64}", candidate)
            or not isinstance(domain, str) or len(domain) > 253 or "." not in domain
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                       for part in domain.split("."))):
        raise ValueError("invalid candidate or certificate identity")
    review = review or load("review-smtp-tls-rotation")
    lock = lock or load("smtp-tls-transaction").deployment_lock
    review.directory(review.ROOT, True)
    with lock(review.ROOT):
        active = review.active_generation()
        if active == candidate:
            raise ValueError("use active managed certificate diagnosis")
        review.verify_files(candidate)
        if validator is None:
            checker = load("check-smtp-relay-certificate")
            validator = lambda: load("smtp-tls-validate-generation").validate(
                review.ROOT, candidate, domain, "auto", load("smtp-tls-generation"), checker)
        if validator().get("status") != "local_checks_passed":
            raise ValueError("candidate TLS validation refused")
        path = review.ROOT / candidate
        full = review.read_file(path / "fullchain.pem", 3 * 1024 * 1024, True)
        leaf = re.search(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", full)
        if leaf is None:
            raise ValueError("certificate unavailable")
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.group().decode("ascii"))).hexdigest()
        ctx = tls.context()
        ctx.load_cert_chain(str(path / "fullchain.pem"), str(path / "key.pem"), password=password_refused)
        def guard():
            review.verify_files(candidate)
            if review.active_generation() != active:
                raise ValueError("active generation changed during candidate probe")
        guard()
        report = tls.inspect(mx, context_fn=lambda: ctx)
        guard()
        report.update(client_certificate_loaded=True, client_certificate_sha256=fingerprint,
                      client_generation=candidate, certificate_domain=domain,
                      client_identity_mode="inactive_candidate", active_generation_unchanged=True,
                      client_certificate_presentation_verified=False, postfix_modified=False,
                      activation_attempted=False)
        return report


def main():
    tls = load("inspect-m365-starttls")
    try:
        signal.signal(signal.SIGALRM, tls.alarm_handler)
        signal.alarm(180)
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024:
            raise ValueError("request too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("invalid request")
        if set(request) == {"mx"}:
            report = inspect(request["mx"], tls=tls)
        elif set(request) == {"mx", "candidate", "domain", "confirm"} and request["confirm"] == "TEST_STAGED_CLIENT_CERTIFICATE":
            report = inspect_candidate(request["mx"], request["candidate"], request["domain"], tls=tls)
        else:
            raise ValueError("invalid request")
        print(json.dumps(report))
        return 0
    except Exception:
        print(json.dumps({"status": "refused_or_uncertain", "mail_sent": False,
                          "client_certificate_presentation_verified": False}))
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
