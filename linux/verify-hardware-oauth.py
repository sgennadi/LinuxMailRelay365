#!/usr/bin/env python3
"""Offline, secretless hardware XOAUTH2 signing acceptance.

Only predefined root-managed identities are inspected. No mailbox, Entra
token, SMTP DATA, primary MTA, TPM key creation or provider installation.
A signing check *uses* an existing TPM/HSM key; temporary TPM objects may
be used, but this script creates no persistent key. Python 3.6+.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

VERSION = "1"
TRANSPORT_ROOT = Path("/usr/local/libexec")
HELPER = TRANSPORT_ROOT / "m365_hardware_signer.py"
TARGETS = (
    ("SIDECAR_ACTIVE", Path("/etc/linuxmailrelay365/sidecar-identity/app.json"),
     TRANSPORT_ROOT / "linuxmailrelay365-sidecar-transport.py", "--config"),
    ("SIDECAR_STAGED", Path("/etc/linuxmailrelay365/sidecar-identity/hardware-staged.json"),
     TRANSPORT_ROOT / "linuxmailrelay365-sidecar-transport.py", "--candidate-config"),
    ("PRIMARY_ACTIVE", Path("/etc/postfix/m365-oauth/app.json"),
     TRANSPORT_ROOT / "m365_xoauth2_transport.py", "--config"),
    ("PRIMARY_STAGED", Path("/etc/postfix/m365-oauth/hardware-staged.json"),
     TRANSPORT_ROOT / "m365_xoauth2_transport.py", "--candidate-config"),
)
MAX_CONFIG = 32768


def secure_path(path, is_directory=False, group=None, mode=None):
    """Reject substituted paths, unsafe ownership and writable config."""
    try:
        st = Path(path).lstat()
    except OSError:
        return False
    if st.st_uid != 0 or (st.st_mode & 0o022):
        return False
    if is_directory:
        return stat.S_ISDIR(st.st_mode)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return False
    if group is not None and st.st_gid != group:
        return False
    if mode is not None and stat.S_IMODE(st.st_mode) != mode:
        return False
    return True


def read_configuration(path, expected_group):
    path = Path(path)
    if not secure_path(path.parent, is_directory=True):
        return "unsafe_identity_directory", None
    if not secure_path(path, group=expected_group, mode=0o640):
        return "unsafe_identity_file", None
    try:
        if not 1 <= path.stat().st_size <= MAX_CONFIG:
            return "invalid_identity_size", None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return "invalid_identity_json", None
    if not isinstance(data, dict):
        return "invalid_identity_json", None
    if "signer" not in data:
        return "software_signer_or_unconfigured", None
    signer = data.get("signer")
    if (not isinstance(signer, dict) or data.get("private_key") or
            signer.get("type") != "openssl-provider" or
            signer.get("provider") not in ("tpm2", "pkcs11")):
        return "invalid_hardware_identity", None
    return "hardware_configured_unverified", signer["provider"]


def check_target(label, config_path, transport_path, option, expected_group,
                 runner=subprocess.run, find_executable=shutil.which, verify=True):
    config_path = Path(config_path)
    if not config_path.exists() and not config_path.is_symlink():
        return "not_configured"
    stage, _provider = read_configuration(config_path, expected_group)
    if stage != "hardware_configured_unverified":
        return stage
    if not verify:
        return "hardware_configured_unverified"
    if not (secure_path(TRANSPORT_ROOT, is_directory=True) and
            secure_path(transport_path) and secure_path(HELPER)):
        return "transport_not_trusted_or_missing"
    runuser = find_executable("runuser")
    python = Path("/usr/bin/python3")
    if not runuser or not python.is_file():
        return "signing_runtime_missing"
    # Whitelisted paths only: never shell-evaluate identity content or
    # print private material, assertions, PINs, mailbox or subprocess output.
    argv = [runuser, "-u", "m365mailer", "--", str(python),
            str(transport_path), "--signing-check", option, str(config_path)]
    try:
        done = runner(argv, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "hardware_signature_unavailable"
    if done.returncode:
        return "hardware_signature_unavailable"
    return "provider_ps256_certificate_match_verified"


def inspect(targets=TARGETS, verify=True, output=print):
    if os.geteuid() != 0:
        output("HARDWARE_OAUTH_ERROR=root_required")
        return 2
    try:
        group = grp.getgrnam("m365mailer").gr_gid
    except KeyError:
        group = None
    output("HARDWARE_OAUTH_INSPECTION_VERSION=" + VERSION)
    output("HARDWARE_OAUTH_MODE=" + ("offline_signing" if verify else "inventory_only"))
    outcomes = {}
    for label, config, transport, option in targets:
        if group is None:
            state = "runtime_group_missing" if config.exists() else "not_configured"
        else:
            state = check_target(label, config, transport, option, group,
                                 verify=verify)
        outcomes[label] = state
        output("HARDWARE_OAUTH_" + label + "=" + state)
    good = "provider_ps256_certificate_match_verified"
    output("HARDWARE_OAUTH_INSTALLED_VERIFIED=" +
           ("yes" if any(outcomes.get(x) == good for x in
                         ("SIDECAR_ACTIVE", "PRIMARY_ACTIVE")) else "no"))
    output("HARDWARE_OAUTH_STAGED_VERIFIED=" +
           ("yes" if any(outcomes.get(x) == good for x in
                         ("SIDECAR_STAGED", "PRIMARY_STAGED")) else "no"))
    output("HARDWARE_OAUTH_HARDWARE_PROVENANCE_VERIFIED=no")
    output("HARDWARE_OAUTH_TENANT_DELIVERY_VERIFIED=no")
    output("HARDWARE_OAUTH_ENTRA_CONTACTED=no")
    output("HARDWARE_OAUTH_MAIL_CONFIG_CHANGED=no")
    output("HARDWARE_OAUTH_PERSISTENT_TPM_KEYS_CREATED=no")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-only", action="store_true",
                        help="Inspect configuration, do not sign or access TPM")
    args = parser.parse_args(argv)
    return inspect(verify=not args.inventory_only)


if __name__ == "__main__":
    sys.exit(main())
