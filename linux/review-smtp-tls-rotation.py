#!/usr/bin/env python3
"""Reviewed staged SMTP client TLS deployment and rotation.
Initial deployment changes only smtp_tls_chain_files after approval.
No inbound SMTP, listener, relayhost, queue or Exchange changes.
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
    mode = "initial" if local["changes"] else "rotation"
    initial_config = None
    if mode == "rotation":
        if previous is None:
            raise ValueError("managed configuration without generation")
        pf.verify_managed()
        # Ensure the rollback certificate still validates for this identity.
        if validator.validate(ROOT, previous, domain, ca, gen, checker).get("status") != "local_checks_passed":
            raise ValueError("rollback TLS validation refused")
    else:
        if journals["deployment.json"] != "absent":
            raise ValueError("existing rotation journal requires manual review")
        if journals["initial-deployment.json"] != "absent":
            initial = json.loads(read_file(ROOT / "initial-deployment.json", 16384, True),
                                 object_pairs_hook=strict_object)
            if initial.get("phase") != "rolled_back":
                raise ValueError("existing initial deployment requires manual review")
            if previous is not None and (initial.get("bootstrap_generation") != previous or previous != candidate):
                raise ValueError("unreviewed retained pointer")
        elif previous is not None:
            raise ValueError("unreviewed existing pointer")
        original = read_file(CONFIG / "main.cf", 8 * 1024 * 1024)
        initial_config = load("smtp-tls-initial-candidate").preview(original)
        if not initial_config["changed"] or initial_config["original_sha256"] != state["main_sha256"]:
            raise ValueError("invalid initial candidate")
    version = re.match(r"^(\d+)\.(\d+)", local["postfix_version"])
    version_supported = bool(version and tuple(map(int, version.groups())) >= (3, 4))
    selinux = selinux_mode()
    material = {"candidate": candidate, "previous": previous, "domain": domain,
                "mode": mode, "state": state, "journals": journals,
                "ca_sha256": ca_sha, "selinux": selinux, "changes": local["changes"],
                "initial_config": initial_config, "tls_security_level": local["tls_security_level"],
                "postfix_version_supported": version_supported}
    sha = digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())
    if config_state(pf) != state or active_generation() != previous or terminal_journals(previous, state["main_sha256"]) != journals:
        raise ValueError("configuration changed during review")
    return dict(material, status="review_ready", plan_sha256=sha,
                apply_supported=version_supported and (mode == "initial" or candidate != previous)
                and selinux in ("disabled", "not_detected"),
                certificate_details=checked.get("details", ""),
                exchange_acceptance="unverified", mail_sent=False)


def initial_deploy(candidate, domain, expected, preview, pf, prepare_fn=prepare):
    tx = load("smtp-tls-transaction")
    generation = load("smtp-tls-generation")
    backup = load("smtp-tls-initial-backup")
    builder = load("smtp-tls-initial-candidate")
    journal = load("smtp-tls-initial-journal")
    deploy = load("smtp-tls-initial-deploy")
    initial = preview["initial_config"]
    old_sha, new_sha = initial["original_sha256"], initial["candidate_sha256"]
    previous = preview["previous"]
    target = CONFIG / "main.cf"

    def read():
        return read_file(target, 8 * 1024 * 1024)

    def guard(main_sha):
        state = dict(preview["state"], main_sha256=main_sha)
        if config_state(pf) != state:
            raise ValueError("Postfix configuration changed")

    def preflight():
        actual = prepare_fn(candidate, domain, pf)
        if actual["plan_sha256"] != expected or actual["mode"] != "initial" or not actual["apply_supported"]:
            raise ValueError("initial review changed under deployment lock")
        pf.run(pf.postfix, "check")
        guard(old_sha)

    def validate():
        verify_files(candidate)
        if active_generation() != previous:
            raise ValueError("active pointer changed")

    def save():
        saved = backup.backup(ROOT, target)
        data, meta = backup.verify(saved)
        if digest(data) != old_sha or meta["sha256"] != old_sha:
            raise ValueError("backup does not match reviewed original")
        return saved

    def prepare_pointer():
        guard(old_sha)
        verify_files(candidate)
        if previous is None:
            generation.switch(ROOT, candidate, None)
        elif active_generation() != candidate:
            raise ValueError("retained pointer changed")

    def replace(data, sha):
        guard(sha)
        backup.replace_config(data, sha, target)

    def check():
        guard(new_sha)
        pf.check()

    def reload():
        current = digest(read())
        if current not in (old_sha, new_sha):
            raise ValueError("unexpected configuration; manual recovery required")
        guard(current)
        if current == new_sha:
            pf.verify_managed()
        pf.run(pf.postfix, "check")
        pf.run(pf.postfix, "status")
        pf.run(pf.postfix, "reload")
        pf.run(pf.postfix, "status")
        guard(current)

    with tx.deployment_lock(ROOT):
        return deploy.deploy(old_sha, new_sha, read, builder.build, save, replace,
            lambda saved, sha: backup.restore(saved, sha, target),
            preflight, validate, check, reload,
            lambda *args: journal.record(ROOT, *args, bootstrap_generation=candidate),
            prepare_pointer=prepare_pointer)


def execute(candidate, domain, expected, prepare_fn=prepare, activate_fn=None, initial_fn=initial_deploy):
    pf = load("smtp-tls-postfix").Postfix()
    preview = prepare_fn(candidate, domain, pf)
    if preview["plan_sha256"] != expected or not preview["apply_supported"]:
        raise ValueError("review changed or activation unsupported")
    if preview.get("mode") == "initial":
        result = initial_fn(candidate, domain, expected, preview, pf, prepare_fn)
        return {"status": result, "mode": "initial", "plan_sha256": expected,
                "exchange_acceptance": "unverified", "mail_sent": False}
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


PENDING_PHASES = ("prepared", "switched", "rollback_required")
TERMINAL_PHASES = ("verified", "rolled_back")


def recovery_journal(name):
    path = ROOT / name
    if not os.path.lexists(path):
        return None, "absent"
    raw = read_file(path, 16384, True)
    state = json.loads(raw, object_pairs_hook=strict_object)
    if state.get("version") != 1 or state.get("phase") not in PENDING_PHASES + TERMINAL_PHASES:
        raise ValueError("unknown journal version or phase")
    return state, digest(raw)


def verified_backup(state):
    name = state.get("backup")
    if not isinstance(name, str) or not re.fullmatch(r"initial-backup-[A-Za-z0-9_]+", name):
        raise ValueError("invalid backup reference")
    original, candidate = state.get("original_sha256"), state.get("candidate_sha256")
    if not all(isinstance(v, str) and SHA.fullmatch(v) for v in (original, candidate)) or original == candidate:
        raise ValueError("invalid configuration hashes")
    backup = ROOT / name
    directory(backup, True)
    data = read_file(backup / "main.cf", 8 * 1024 * 1024, True)
    raw_meta = read_file(backup / "manifest.json", 16384, True)
    meta = json.loads(raw_meta, object_pairs_hook=strict_object)
    if (set(meta) != {"sha256", "uid", "gid", "mode"} or meta["sha256"] != original
            or meta["uid"] != 0 or type(meta["gid"]) is not int or meta["gid"] < 0
            or type(meta["mode"]) is not int or not 0 <= meta["mode"] <= 0o777
            or meta["mode"] & 0o022 or digest(data) != original):
        raise ValueError("invalid backup metadata or contents")
    if digest(load("smtp-tls-initial-candidate").build(data)) != candidate:
        raise ValueError("backup does not reproduce reviewed TLS change")
    return backup, digest(raw_meta)


def recovery_plan(pf=None):
    if not os.path.lexists(ROOT):
        return {"status": "no_transaction", "apply_supported": False,
                "exchange_acceptance": "unverified", "mail_sent": False}
    directory(ROOT, True)
    pf = pf or load("smtp-tls-postfix").Postfix()
    state = config_state(pf)
    active = active_generation()
    initial, initial_sha = recovery_journal("initial-deployment.json")
    rotation, rotation_sha = recovery_journal("deployment.json")
    pending_initial = initial is not None and initial["phase"] in PENDING_PHASES
    pending_rotation = rotation is not None and rotation["phase"] in PENDING_PHASES
    phases = {"initial": initial["phase"] if initial else "absent",
              "rotation": rotation["phase"] if rotation else "absent"}
    if not pending_initial and not pending_rotation:
        terminal_journals(active, state["main_sha256"])
        return {"status": "no_pending_transaction", "phases": phases,
                "apply_supported": False, "exchange_acceptance": "unverified", "mail_sent": False}
    if pending_initial and rotation is not None:
        raise ValueError("overlapping transaction history")
    if pf.run(pf.postconf, "-h", "config_directory") != str(CONFIG) or pf.run(pf.postconf, "-h", "multi_instance_directories"):
        raise ValueError("unsupported Postfix configuration")
    backup_meta_sha = None
    if pending_initial:
        mode = "initial"
        original, candidate = initial["original_sha256"], initial["candidate_sha256"]
        _, backup_meta_sha = verified_backup(initial)
        if state["main_sha256"] not in (original, candidate):
            raise ValueError("configuration drift; manual recovery required")
        bootstrap = initial.get("bootstrap_generation")
        if bootstrap is not None and (not isinstance(bootstrap, str) or not GEN.fullmatch(bootstrap) or active not in (None, bootstrap)):
            raise ValueError("unexpected bootstrap pointer")
        # Preserve the staged pointer; the previous main.cf is restored instead.
        current_tls = pf.run(pf.postconf, "-h", "smtp_tls_chain_files")
        if (state["main_sha256"] == candidate and current_tls != EXPECTED) or (state["main_sha256"] == original and current_tls):
            raise ValueError("unexpected effective client TLS setting")
        target = original
    else:
        mode = "rotation"
        previous, candidate = rotation.get("previous"), rotation.get("candidate")
        if previous == candidate or active not in (previous, candidate):
            raise ValueError("unexpected active generation")
        verify_files(previous)
        verify_files(candidate)
        if initial is not None:
            if initial["phase"] != "verified" or state["main_sha256"] != initial.get("candidate_sha256"):
                raise ValueError("initial configuration drift")
        pf.verify_managed()
        target = previous
    pf.run(pf.postfix, "status")
    selinux = selinux_mode()
    material = {"mode": mode, "phases": phases, "active": active, "restore_target": target,
                "state": state, "initial_journal_sha256": initial_sha,
                "rotation_journal_sha256": rotation_sha, "backup_metadata_sha256": backup_meta_sha,
                "selinux": selinux}
    sha = digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())
    if (config_state(pf) != state or active_generation() != active
            or recovery_journal("initial-deployment.json")[1] != initial_sha
            or recovery_journal("deployment.json")[1] != rotation_sha):
        raise ValueError("recovery state changed during review")
    return dict(material, status="recovery_review_ready", plan_sha256=sha,
                apply_supported=selinux in ("disabled", "not_detected"),
                exchange_acceptance="unverified", mail_sent=False)


def execute_recovery(expected, plan_fn=recovery_plan):
    pf = load("smtp-tls-postfix").Postfix()
    preview = plan_fn(pf)
    if preview.get("plan_sha256") != expected or not preview["apply_supported"]:
        raise ValueError("review changed or recovery unsupported")
    tx = load("smtp-tls-transaction")

    def guard_review():
        current = plan_fn(pf)
        if current.get("plan_sha256") != expected or not current["apply_supported"]:
            raise ValueError("recovery plan changed under lock")

    def guard_config(main_sha):
        if config_state(pf) != dict(preview["state"], main_sha256=main_sha):
            raise ValueError("configuration changed during recovery")

    def check():
        main_sha = preview["restore_target"] if preview["mode"] == "initial" else preview["state"]["main_sha256"]
        guard_config(main_sha)
        pf.run(pf.postfix, "check")
        guard_config(main_sha)

    def reload():
        check()
        pf.run(pf.postfix, "status")
        pf.run(pf.postfix, "reload")
        pf.run(pf.postfix, "status")
        check()

    if preview["mode"] == "initial":
        with tx.deployment_lock(ROOT):
            guard_review()
            state, _ = recovery_journal("initial-deployment.json")
            backup, _ = verified_backup(state)
            target = CONFIG / "main.cf"
            journal = load("smtp-tls-initial-journal")
            restore_module = load("smtp-tls-initial-backup")

            def restore(path, sha):
                guard_config(sha)
                if path != backup:
                    raise ValueError("backup reference changed")
                verified_backup(state)
                restore_module.restore(path, sha, target)

            result = journal.recover(ROOT, state, lambda: read_file(target, 8 * 1024 * 1024),
                restore, check, reload,
                lambda *args: journal.record(ROOT, *args, bootstrap_generation=state.get("bootstrap_generation")))
    else:
        result = load("smtp-tls-activate").recover(ROOT, load("smtp-tls-generation"), tx,
            check, reload, before_recover=guard_review)
    if result != "restored":
        raise ValueError("unexpected recovery result")
    return {"status": "restored", "mode": preview["mode"], "plan_sha256": expected,
            "exchange_acceptance": "unverified", "mail_sent": False}


def exact_dns_san(extensions, domain):
    in_san = False
    for line in extensions.splitlines():
        value = line.strip()
        if value.startswith("X509v3 "):
            in_san = value.startswith("X509v3 Subject Alternative Name:")
            continue
        if in_san:
            for item in value.split(","):
                if item.strip().lower() == "dns:" + domain.lower():
                    return True
    return False


def connector_binding(domain, pf=None):
    if not isinstance(domain, str) or len(domain) > 253 or "." not in domain or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in domain.split(".")):
        raise ValueError("invalid connector DNS identity")
    directory(ROOT, True)
    pf = pf or load("smtp-tls-postfix").Postfix()
    active = active_generation()
    if active is None:
        raise ValueError("no active managed certificate")
    state = config_state(pf)
    journals = terminal_journals(active, state["main_sha256"])
    pf.verify_managed()
    pf.run(pf.postfix, "status")
    checker = load("check-smtp-relay-certificate")
    ca = checker.resolve_ca_bundle("auto")
    ca_sha = digest(read_file(Path(ca), 8 * 1024 * 1024))
    checked = load("smtp-tls-validate-generation").validate(ROOT, active, domain, ca,
                load("smtp-tls-generation"), checker)
    if checked.get("status") != "local_checks_passed" or not exact_dns_san(checked.get("extensions", ""), domain):
        raise ValueError("exact certificate DNS SAN required")
    security = pf.run(pf.postconf, "-h", "smtp_tls_security_level")
    material = {"domain": domain, "generation": active, "state": state, "journals": journals,
                "ca_sha256": ca_sha, "smtp_tls_security_level": security}
    if config_state(pf) != state or active_generation() != active or terminal_journals(active, state["main_sha256"]) != journals:
        raise ValueError("local binding changed")
    return {"status": "local_binding_reviewed", "domain": domain, "generation": active,
            "binding_sha256": digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()),
            "smtp_tls_security_level": security, "certificate_details": checked.get("details", ""),
            "exchange_acceptance": "unverified", "mail_sent": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inventory", "preview", "activate", "recovery-preview", "recover", "binding-preview"))
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
        elif args.action == "binding-preview":
            if args.candidate or args.expected_sha or not args.domain:
                raise ValueError("invalid binding preview arguments")
            report = connector_binding(args.domain)
        elif args.action == "recovery-preview":
            if any((args.candidate, args.domain, args.expected_sha)):
                raise ValueError("unexpected recovery preview arguments")
            report = recovery_plan()
        elif args.action == "recover":
            if args.candidate or args.domain or not SHA.fullmatch(args.expected_sha or ""):
                raise ValueError("reviewed recovery SHA required")
            report = execute_recovery(args.expected_sha)
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
