#!/usr/bin/env python3
"""Guarded TPM2 dependency planning for RHEL-family Linux (Python 3.6+).

Read-only by default. Installation is separately approved and limited to
known RPM names. No third-party repositories, source builds, TPM clearing,
key provisioning, tpm2-abrmd enablement, SELinux or MTA mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

VERSION = "1"
CONFIRM = "INSTALL_TPM2_DEPENDENCIES"
RHEL_IDS = {"rhel", "ol", "rocky", "almalinux"}
# Runtime packages are distinct from optional development headers.
BASE = ("tpm2-tss", "tpm2-abrmd", "tpm2-tools")
BUILD = ("gcc", "make", "autoconf", "automake", "libtool",
         "autoconf-archive", "pkgconf-pkg-config", "openssl-devel",
         "tpm2-tss-devel")
PROFILES = ("runtime", "build-prereqs", "pkcs11", "native-provider")
PKG_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,79}$")


def read_os_release(file):
    result = {}
    for line in Path(file).read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line.strip())
        if not match:
            continue
        value = match.group(2)
        if len(value) > 256:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[match.group(1)] = value
    return result


def distro(os_data):
    name = os_data.get("ID", "").lower()
    major = re.match(r"^(\d+)(?:\.|$)", os_data.get("VERSION_ID", ""))
    version = int(major.group(1)) if major else 0
    if name not in RHEL_IDS or version not in (8, 9, 10):
        raise ValueError("unsupported_os_requires_manual_review")
    return name, version


def packages(major, profile):
    if profile == "runtime":
        return BASE
    if profile == "build-prereqs":
        return BASE + BUILD
    if profile == "pkcs11":
        if major == 8:
            raise ValueError("rhel8_openssl3_provider_not_supported_by_default")
        # Availability of pkcs11-provider varies by RHEL 9 minor/repo.
        # An OpenSSL 1.1 engine alone cannot satisfy our provider-based signer.
        return BASE + ("tpm2-pkcs11", "tpm2-pkcs11-tools",
                       "p11-kit", "opensc", "pkcs11-provider")
    if profile == "native-provider":
        if major != 10:
            raise ValueError("native_tpm2_openssl_rpm_requires_rhel10")
        return BASE + ("tpm2-openssl",)
    raise ValueError("unsupported_profile")


def tpm_state():
    node = "none"
    for name in ("/dev/tpmrm0", "/dev/tpm0"):
        try:
            if stat.S_ISCHR(os.lstat(name).st_mode):
                node = name
                break
        except OSError:
            pass
    try:
        version = Path("/sys/class/tpm/tpm0/tpm_version_major").read_text().strip()
    except OSError:
        version = "unknown"
    return node, version if version in ("1", "2") else "unknown"


def rpm_installed(package):
    if not PKG_PATTERN.fullmatch(package):
        raise ValueError("unsafe_package_name")
    rpm = shutil.which("rpm")
    if not rpm:
        raise RuntimeError("rpm_not_available")
    try:
        result = subprocess.run([rpm, "-q", "--", package],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("rpm_inventory_failed")
    return result.returncode == 0


def make_plan(os_data, profile, check_installed=rpm_installed, tpm_probe=tpm_state):
    name, major = distro(os_data)
    names = packages(major, profile)
    missing = tuple(p for p in names if not check_installed(p))
    node, version = tpm_probe()
    source = {"os_id": name, "os_major": major, "profile": profile,
              "packages": list(names), "missing": list(missing),
              "tpm_node": node, "tpm_major": version}
    raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
    return source, hashlib.sha256(raw).hexdigest()


def emit(plan, sha):
    print("TPM_DEPS_VERSION=" + VERSION)
    print("TPM_DEPS_OS=" + plan["os_id"])
    print("TPM_DEPS_MAJOR=" + str(plan["os_major"]))
    print("TPM_DEPS_PROFILE=" + plan["profile"])
    print("TPM_DEPS_NODE=" + plan["tpm_node"])
    print("TPM_DEPS_TPM_VERSION=" + plan["tpm_major"])
    print("TPM_DEPS_PACKAGES=" + ",".join(plan["packages"]))
    print("TPM_DEPS_MISSING=" + ",".join(plan["missing"]))
    print("TPM_DEPS_PLAN_SHA256=" + sha)
    print("TPM_DEPS_READY_FOR_INSTALL=" +
          ("yes" if plan["tpm_node"] != "none" and
           plan["tpm_major"] == "2" else "no"))
    if plan["os_major"] == 9:
        print("TPM_DEPS_RHEL9_NOTE=no_native_tpm2_openssl_rpm;use_reviewed_pkcs11_or_source_build")
    if plan["os_major"] == 8:
        print("TPM_DEPS_RHEL8_NOTE=openssl3_provider_not_in_base_openssl")
    print("TPM_DEPS_HARDWARE_SIGNING_ACTIVE=not_verified")
    print("TPM_DEPS_REPOSITORIES_CHANGED=no")
    print("TPM_DEPS_TPM_KEYS_CHANGED=no")


def install(plan, sha, confirm, approved_sha):
    if confirm != CONFIRM or approved_sha != sha:
        raise ValueError("typed_approval_or_reviewed_sha_mismatch")
    if os.geteuid() != 0:
        raise ValueError("root_required_for_explicit_install")
    if plan["tpm_node"] == "none" or plan["tpm_major"] != "2":
        raise ValueError("tpm2_hardware_not_verified")
    missing = plan["missing"]
    if not missing:
        print("TPM_DEPS_INSTALL_RESULT=already_installed")
        return
    dnf = shutil.which("dnf")
    if not dnf:
        raise RuntimeError("dnf_not_available")
    if any(p not in packages(plan["os_major"], plan["profile"]) or
           not PKG_PATTERN.fullmatch(p) for p in missing):
        raise ValueError("unsafe_package_plan")
    # No --enablerepo, --nogpgcheck, third-party RPM or unattended build.
    # The administrator must separately configure signed repositories.
    try:
        result = subprocess.run([dnf, "-y", "install"] + list(missing),
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=900)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("dnf_install_failed_or_timed_out")
    if result.returncode:
        raise RuntimeError("dnf_install_failed_check_repositories")
    if any(not rpm_installed(p) for p in missing):
        raise RuntimeError("post_install_rpm_verification_failed")
    print("TPM_DEPS_INSTALL_RESULT=verified_rpms")
    print("TPM_DEPS_PROVIDER_SIGNING=not_verified")
    print("TPM_DEPS_TPM_KEYS_CHANGED=no")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", choices=PROFILES, default="runtime")
    p.add_argument("--os-release-file", default="/etc/os-release")
    p.add_argument("--apply", action="store_true", help="Explicit guarded RPM installation")
    p.add_argument("--approve-sha256", default="")
    p.add_argument("--confirm", default="")
    args = p.parse_args(argv)
    try:
        if args.apply and args.os_release_file != "/etc/os-release":
            raise ValueError("custom_os_release_disallowed_for_apply")
        if not args.apply and (args.confirm or args.approve_sha256):
            raise ValueError("approval_only_valid_for_apply")
        plan, sha = make_plan(read_os_release(args.os_release_file), args.profile)
        emit(plan, sha)
        if args.apply:
            install(plan, sha, args.confirm, args.approve_sha256)
        else:
            print("TPM_DEPS_APPLIED=no")
            print("TPM_DEPS_NEXT=review_plan_before_approved_apply")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print("TPM_DEPS_ERROR=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
