#!/usr/bin/env python3
"""Read-only preview of a NEW primary TPM broker install on Rocky 10.3.

Run only from a trusted, root-owned candidate package. No apply command,
no service changes, no key creation, no policy loads, no udev changes, no
SMTP or token exchange. A successful plan is not approval for exclusive
TPM access: other consumers and concurrent host changes require review.
"""
import argparse
import errno
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

import m365_tpm_broker_bootstrap as bootstrap
import m365_tpm_broker_identity as identity
import m365_tpm_broker_service as service

HERE = Path(__file__).absolute().parent
UNIT = "linuxmailrelay365-primary-tpm-broker.service"
POLICY = "lmr365_tpm_signer"
RULE = "99-lmr365-primary-tpm-broker.rules"
DEVICE = Path("/dev/tpmrm0")
DESTINATIONS = (
    bootstrap.RUNTIME,
    Path("/etc/systemd/system") / UNIT,
    Path("/run/systemd/system") / UNIT,
    Path("/usr/lib/systemd/system") / UNIT,
    Path("/etc/systemd/system") / (UNIT + ".d"),
    Path("/run/systemd/system") / (UNIT + ".d"),
    Path("/usr/lib/systemd/system") / (UNIT + ".d"),
    Path("/etc/systemd/system/multi-user.target.wants") / UNIT,
    Path("/etc/udev/rules.d") / RULE,
    Path("/run/udev/rules.d") / RULE,
    Path("/usr/lib/udev/rules.d") / RULE,
)
ARTIFACTS = (
    ("m365_tpm_broker_bootstrap.py", "runtime/bootstrap.py"),
    ("m365_hardware_signer.py", "runtime/m365_hardware_signer.py"),
    ("m365_xoauth2_transport.py", "runtime/m365_xoauth2_transport.py"),
    ("m365_tpm_broker_protocol.py", "runtime/m365_tpm_broker_protocol.py"),
    ("m365_tpm_broker_identity.py", "runtime/m365_tpm_broker_identity.py"),
    ("m365_tpm_broker_service.py", "runtime/m365_tpm_broker_service.py"),
    ("systemd/" + UNIT, "systemd/" + UNIT),
    ("selinux/" + POLICY + ".te", "policy/" + POLICY + ".te"),
    ("selinux/" + POLICY + ".fc", "policy/" + POLICY + ".fc"),
    ("udev/" + RULE, "udev/" + RULE),
)
TOOLS = {
    "systemctl": "/usr/bin/systemctl",
    "semodule": "/usr/sbin/semodule",
    "postconf": "/usr/sbin/postconf",
    "openssl": "/usr/bin/openssl",
    "udevadm": "/usr/bin/udevadm",
    "make": "/usr/bin/make",
}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
       "HOME": "/nonexistent"}
STATUS_KEYS = ("LoadState", "ActiveState", "SubState", "MainPID")
POSTFIX_KEYS = STATUS_KEYS + ("PrivateDevices", "DevicePolicy", "DeviceAllow",
                              "BindPaths", "BindReadOnlyPaths", "RootDirectory",
                              "RootImage", "TemporaryFileSystem")


class Refused(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def trusted_dirs(path):
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             not info.st_mode & 0o6022, "broker_untrusted_directory")


def tool(name):
    need(name in TOOLS, "broker_unknown_tool")
    alias = Path(TOOLS[name])
    trusted_dirs(alias.parent)
    path = alias.resolve(strict=True)
    trusted_dirs(path.parent)
    info = path.lstat()
    need(path.parent in (Path("/usr/bin"), Path("/usr/sbin")) and
         stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         not info.st_mode & 0o6022 and info.st_mode & 0o111,
         "broker_untrusted_system_tool")
    return str(alias)


def command(name, args):
    result = subprocess.run([tool(name)] + list(args), input=b"",
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False, env=ENV)
    need(result.returncode == 0 and len(result.stdout) <= 262144,
         "broker_native_inspection_failed")
    return result.stdout.decode("ascii", "strict")


def platform():
    need(os.geteuid() == 0, "broker_preview_root_required")
    raw = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    need("ID=\"rocky\"" in raw or "ID=rocky" in raw,
         "broker_preview_rocky10_3_only")
    need("VERSION_ID=\"10.3\"" in raw or "VERSION_ID=10.3" in raw,
         "broker_preview_rocky10_3_only")
    need(Path("/proc/1/comm").read_text().strip() == "systemd" and
         Path("/sys/fs/selinux/enforce").read_bytes().strip() == b"1",
         "broker_preview_native_enforcing_required")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    need(re.fullmatch(r"[0-9a-f-]{36}", boot), "broker_boot_id_unverified")
    return boot


def parse_properties(raw, keys):
    values = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        need(sep and key in keys and key not in values and
             len(value) <= 8192 and not any(ord(c) < 32 for c in value),
             "broker_systemd_properties_unverified")
        values[key] = value
    need(set(values) == set(keys), "broker_systemd_properties_incomplete")
    return values


def unit_status(unit, keys, run=command):
    raw = run("systemctl", ["show", "--all", unit] + ["-p" + k for k in keys])
    return parse_properties(raw, keys)


def require_postfix_baseline(values):
    need(set(values) == set(POSTFIX_KEYS) and
         all(values[k] == v for k, v in {
             "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
             "MainPID": "0", "PrivateDevices": "yes", "DevicePolicy": "closed"
         }.items()) and not any(values[k] for k in
         ("DeviceAllow", "BindPaths", "BindReadOnlyPaths", "RootDirectory",
          "RootImage", "TemporaryFileSystem")), "broker_postfix_baseline_unverified")


def policy_inventory(raw):
    rows = [tuple(line.split()) for line in raw.splitlines() if line.strip()]
    need(bool(rows) and len(rows) == len(set(rows)) and
         all(len(row) in (3, 4) and row[0].isdigit() and
             re.fullmatch(r"[A-Za-z0-9_.-]+", row[1]) for row in rows),
         "broker_policy_inventory_unverified")
    need(not any(row[1] == POLICY for row in rows), "broker_existing_policy")
    return sorted(rows)


def absent_install():
    for path in DESTINATIONS:
        need(not os.path.lexists(str(path)), "broker_existing_destination")
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(service.SIGNER_ACCOUNT)
        except KeyError:
            continue
        raise Refused("broker_existing_signer_account")
    status = unit_status(UNIT, STATUS_KEYS)
    need(status == {"LoadState": "not-found", "ActiveState": "inactive",
                    "SubState": "dead", "MainPID": "0"}, "broker_existing_unit")
    return policy_inventory(command("semodule", ["-lfull"]))


def mail_account():
    try:
        mail = pwd.getpwnam(service.MAIL_ACCOUNT)
        gid = grp.getgrnam(service.MAIL_ACCOUNT).gr_gid
    except KeyError:
        raise Refused("broker_mail_account_missing") from None
    need(mail.pw_uid > 0 and gid > 0 and mail.pw_gid == gid and
         set(os.getgrouplist(service.MAIL_ACCOUNT, gid)) == {gid},
         "broker_mail_account_scope")
    return [mail.pw_uid, gid]


def device_evidence():
    meta = DEVICE.lstat()
    need(stat.S_ISCHR(meta.st_mode) and meta.st_uid == 0 and
         stat.S_IMODE(meta.st_mode) in (0o600, 0o660),
         "broker_device_metadata_unverified")
    number = "{}:{}".format(os.major(meta.st_rdev), os.minor(meta.st_rdev))
    sysdev = (Path("/sys/dev/char") / number).resolve(strict=True)
    need(sysdev.name == "tpmrm0" and
         (sysdev / "subsystem").resolve(strict=True).name == "tpmrm" and
         (sysdev / "dev").read_text().strip() == number and
         Path("/sys/class/tpm/tpm0/tpm_version_major").read_text().strip() == "2",
         "broker_native_tpm2_resource_manager_required")
    label = os.getxattr(str(DEVICE), "security.selinux", follow_symlinks=False)
    fields = label.rstrip(b"\0").split(b":", 3)
    need(len(fields) == 4 and fields[2] == b"tpm_device_t",
         "broker_device_selinux_label_unverified")
    try:
        os.getxattr(str(DEVICE), "system.posix_acl_access", follow_symlinks=False)
    except OSError as exc:
        need(exc.errno in (errno.ENODATA, errno.EOPNOTSUPP),
             "broker_device_acl_unverified")
    else:
        raise Refused("broker_device_existing_acl")
    need(identity.fingerprint(DEVICE.lstat()) == identity.fingerprint(meta),
         "broker_device_changed")
    return {"device": number, "metadata": identity.fingerprint(meta),
            "label": label.hex(), "sysfs": str(sysdev)}


def source_hashes():
    trusted_dirs(HERE)
    result = {}
    for relative, target in ARTIFACTS:
        path = HERE / relative
        trusted_dirs(path.parent)
        result[target] = bootstrap.file_digest(path, 0o644, bootstrap.MAX_MODULE).hex()
    native = bootstrap.NATIVE_PYTHON.resolve(strict=True)
    trusted_dirs(native.parent)
    result["runtime/python3"] = bootstrap.file_digest(
        native, 0o755, bootstrap.MAX_EXECUTABLE).hex()
    return result


def postfix_evidence():
    # Existing native guards: no mail process, no queued files. Never stop,
    # start, flush or purge Postfix as part of this read-only preview.
    spec = importlib.util.spec_from_file_location(
        "broker_native_postfix_guard", str(HERE / "inspect-conditional-postfix-activation.py"))
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    values = unit_status("postfix.service", POSTFIX_KEYS)
    require_postfix_baseline(values)
    for key, expected in (("config_directory", "/etc/postfix"),
                          ("queue_directory", "/var/spool/postfix"),
                          ("multi_instance_enable", "no"),
                          ("multi_instance_directories", "")):
        need(command("postconf", ["-h", key]).strip() == expected,
             "broker_postfix_native_layout_unverified")
    guard.stopped_units()
    guard.no_postfix_processes()
    fd = guard.open_directory("/var/spool/postfix", strict=False)
    try:
        guard.empty_queue(fd)
    finally:
        os.close(fd)
    return values


def dependencies():
    for name in TOOLS:
        tool(name)
    trusted_dirs(Path("/usr/share/selinux/devel"))
    need(Path("/usr/share/selinux/devel/Makefile").is_file(),
         "broker_selinux_devel_missing")
    version = command("openssl", ["version"]).splitlines()
    need(len(version) == 1 and re.match(r"^OpenSSL\s+3\.", version[0]),
         "broker_native_openssl3_required")
    return version[0]


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def prepare():
    boot = platform()
    hashes = source_hashes()
    version = dependencies()
    absent = absent_install()
    account = mail_account()
    before = identity.read_primary_snapshot()
    device = device_evidence()
    native = postfix_evidence()
    # Observe the same baseline twice. This cannot exclude an administrator
    # starting a service after preview, hence no Apply entrypoint exists yet.
    need(platform() == boot and source_hashes() == hashes and
         dependencies() == version and absent_install() == absent and
         mail_account() == account and before.matches(identity.read_primary_snapshot()) and
         device_evidence() == device and postfix_evidence() == native,
         "broker_preview_baseline_changed")
    evidence = {"schema": 1, "boot": boot, "sources": hashes,
                "openssl": version, "policy": absent, "account": account,
                "identity": before.approval_digest(), "device": device,
                "postfix": native, "destinations": [str(p) for p in DESTINATIONS],
                "exclusive_tpm_review": "required", "production_apply": False}
    return digest(evidence)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--preview", action="store_true")
    args = parser.parse_args(argv)
    if not args.preview:
        return 2
    try:
        approval = prepare()
        print("PRIMARY_TPM_BROKER_PLAN_SHA256=" + approval)
        print("PRIMARY_TPM_BROKER_PREVIEW=baseline_verified")
        print("PRIMARY_TPM_BROKER_EXCLUSIVE_TPM_REVIEW=required")
        print("PRIMARY_TPM_BROKER_APPLY_SUPPORTED=no")
        print("CHANGES_APPLIED=no")
        return 0
    except Exception as exc:
        # Only fixed local refusal codes; never dump native command output,
        # paths, identities, signatures, queue contents or exception details.
        code = str(exc) if isinstance(exc, Refused) else "broker_preview_unverified"
        print("PRIMARY_TPM_BROKER_PREVIEW=refused")
        print("PRIMARY_TPM_BROKER_REASON=" + code)
        print("CHANGES_APPLIED=no")
        return 2


if __name__ == "__main__":
    sys.exit(main())
