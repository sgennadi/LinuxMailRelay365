#!/usr/bin/env python3
"""Reviewed staged SMTP client TLS rotation for an already managed Postfix.

Initial setup is preview-only. No inbound SMTP, listener, relayhost, queue,
Exchange or main.cf changes. Use the existing durable activation transaction.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path("/etc/postfix/lmr365-smtp-tls")
CONFIG = Path("/etc/postfix")
GEN = re.compile(r"candidate-[a-f0-9]{64}")
SHA = re.compile(r"[a-f0-9]{64}")
EXPECTED = "/etc/postfix/lmr365-smtp-tls/active/client-chain.pem"


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def directory(path, private=False):
    for item in [path, *path.parents]:
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe directory")
    if private and path.stat().st_mode & 0o077:
        raise ValueError("private directory required")


def read_file(path, limit, private=False):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or st.st_mode & (0o077 if private else 0o022) or st.st_size > limit):
            raise ValueError("unsafe file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file too large")
        return data


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def terminal_journals(active, config_sha):
    result = {}
    for name in ("initial-deployment.json", "deployment.json"):
        path = ROOT / name
        if not os.path.lexists(path):
            result[name] = "absent"
            continue
        raw = read_file(path, 16384, True)
        state = json.loads(raw, object_pairs_hook=strict_object)
        phase = state.get("phase")
        if state.get("version") != 1 or phase not in ("verified", "rolled_back"):
            raise ValueError("unfinished or invalid deployment journal")
        if name == "deployment.json":
            previous, candidate = state.get("previous"), state.get("candidate")
            if not all(isinstance(x, str) and GEN.fullmatch(x) for x in (previous, candidate)):
                raise ValueError("invalid generation journal")
            if active != (candidate if phase == "verified" else previous):
                raise ValueError("active generation drift")
        else:
            previous, candidate = state.get("original_sha256"), state.get("candidate_sha256")
            if not all(isinstance(x, str) and SHA.fullmatch(x) for x in (previous, candidate)):
                raise ValueError("invalid initial journal")
            if config_sha != (candidate if phase == "verified" else previous):
                raise ValueError("initial configuration drift")
        result[name] = digest(raw)
    return result


def verify_files(name):
    if not isinstance(name, str) or not GEN.fullmatch(name):
        raise ValueError("invalid generation")
    directory(ROOT / name, True)
    full = read_file(ROOT / name / "fullchain.pem", 3 * 1024 * 1024, True)
    key = read_file(ROOT / name / "key.pem", 1024 * 1024, True)
    combined = read_file(ROOT / name / "client-chain.pem", 4 * 1024 * 1024, True)
    if not full or not key or combined != key.rstrip() + b"\n" + full or digest(combined) != name[10:]:
        raise ValueError("invalid generation material")


def active_generation():
    if not os.path.lexists(ROOT / "active"):
        return None
    name = os.readlink(ROOT / "active")
    verify_files(name)
    return name


def selinux_mode():
    path = Path("/sys/fs/selinux/enforce")
    if path.exists() or path.parent.is_mount():
        return "active_or_unknown"
    try:
        binary = load("smtp-tls-postfix").trusted_binary("/usr/sbin/getenforce")
        report = subprocess.run([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return "disabled" if report.returncode == 0 and report.stdout.strip() == b"Disabled" else "active_or_unknown"
    except FileNotFoundError:
        return "not_detected"
    except (OSError, ValueError, subprocess.SubprocessError):
        return "active_or_unknown"


def inventory():
    if not os.path.lexists(ROOT):
        return {"status": "inventory", "candidates": [], "active": None, "truncated": False}
    directory(ROOT, True)
    names = []
    truncated = False
    with os.scandir(ROOT) as entries:
        for index, entry in enumerate(entries):
            if index >= 4096 or len(names) >= 128:
                truncated = True
                break
            if GEN.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
    return {"status": "inventory", "candidates": sorted(names), "active": active_generation(),
            "truncated": truncated}


def config_state(pf):
    return {"main_sha256": digest(read_file(CONFIG / "main.cf", 8 * 1024 * 1024)),
            "master_sha256": digest(read_file(CONFIG / "master.cf", 8 * 1024 * 1024)),
            "postfix_version": pf.run(pf.postconf, "-h", "mail_version"),
            "overrides_sha256": digest(pf.run(pf.postconf, "-P").encode("utf-8"))}


def prepare(candidate, domain, pf=None):
    if (not GEN.fullmatch(candidate) or not isinstance(domain, str)
            or len(domain) > 253 or "." not in domain
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                       for part in domain.split("."))):
        raise ValueError("invalid candidate or domain")
    directory(ROOT, True)
    verify_files(candidate)
    previous = active_generation()
    pf = pf or load("smtp-tls-postfix").Postfix()
    state = config_state(pf)
    journals = terminal_journals(previous, state["main_sha256"])
    planner = load("plan-smtp-tls-initial")
    local = planner.plan(lambda key: pf.run(pf.postconf, "-h", key), pf.run(pf.postconf, "-P"))
    pf.run(pf.postfix, "status")
    gen, checker = load("smtp-tls-generation"), load("check-smtp-relay-certificate")
    validator = load("smtp-tls-validate-generation")
    ca = checker.resolve_ca_bundle("auto")
    ca_sha = digest(read_file(Path(ca), 8 * 1024 * 1024))
    checked = validator.validate(ROOT, candidate, domain, ca, gen, checker)
    if checked.get("status") != "local_checks_passed":
        raise ValueError("candidate TLS validation refused")
    mode = "rotation" if previous is not None and not local["changes"] else "initial_preview"
    if mode == "rotation":
        pf.verify_managed()
        # Ensure the rollback certificate still validates for this identity.
        if validator.validate(ROOT, previous, domain, ca, gen, checker).get("status") != "local_checks_passed":
            raise ValueError("rollback TLS validation refused")
    elif previous is not None or not local["changes"]:
        raise ValueError("inconsistent initial deployment state")
    selinux = selinux_mode()
    material = {"candidate": candidate, "previous": previous, "domain": domain,
                "mode": mode, "state": state, "journals": journals,
                "ca_sha256": ca_sha, "selinux": selinux, "changes": local["changes"]}
    sha = digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())
    if config_state(pf) != state or active_generation() != previous or terminal_journals(previous, state["main_sha256"]) != journals:
        raise ValueError("configuration changed during review")
    return dict(material, status="review_ready", plan_sha256=sha,
                apply_supported=mode == "rotation" and candidate != previous
                and selinux in ("disabled", "not_detected"),
                certificate_details=checked.get("details", ""),
                exchange_acceptance="unverified", mail_sent=False)


def execute(candidate, domain, expected, prepare_fn=prepare, activate_fn=None):
    pf = load("smtp-tls-postfix").Postfix()
    preview = prepare_fn(candidate, domain, pf)
    if preview["plan_sha256"] != expected or not preview["apply_supported"]:
        raise ValueError("review changed or activation unsupported")
    generation = load("smtp-tls-generation")
    transaction = load("smtp-tls-transaction")
    activation = load("smtp-tls-activate")
    # Existing transaction holds deployment.lock before this callback, so
    # concurrent managed rotation cannot change the approved active pointer.
    def validate(name):
        actual = prepare_fn(name, domain, pf)
        if actual["plan_sha256"] != expected or not actual["apply_supported"]:
            raise ValueError("review changed under deployment lock")

    def check():
        if config_state(pf) != preview["state"]:
            raise ValueError("Postfix configuration changed")
        pf.check()

    def reload():
        if config_state(pf) != preview["state"]:
            raise ValueError("Postfix configuration changed")
        pf.reload()

    result = (activate_fn or activation.activate)(ROOT, candidate, generation,
                transaction, check, reload, validate)
    return {"status": result, "plan_sha256": expected, "exchange_acceptance": "unverified",
            "mail_sent": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inventory", "preview", "activate"))
    parser.add_argument("--candidate")
    parser.add_argument("--domain")
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        os.umask(0o077)
        if args.action == "inventory":
            if any((args.candidate, args.domain, args.expected_sha)):
                raise ValueError("unexpected arguments")
            report = inventory()
        elif args.action == "preview":
            if args.expected_sha or not args.candidate or not args.domain:
                raise ValueError("invalid preview arguments")
            report = prepare(args.candidate, args.domain)
        else:
            if not SHA.fullmatch(args.expected_sha or "") or not args.candidate or not args.domain:
                raise ValueError("review required")
            report = execute(args.candidate, args.domain, args.expected_sha)
        print(json.dumps(report))
        return 0
    except Exception:
        # Never include configuration, key material or subprocess output.
        print(json.dumps({"status": "refused_or_failed", "exchange_acceptance": "unverified",
                          "mail_sent": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
