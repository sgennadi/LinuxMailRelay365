#!/usr/bin/env python3
"""Candidate service launcher; no filesystem writes or installer.

The copied, separately labeled native interpreter uses -I -B. Verify the
fixed root-owned runtime before adding it to the otherwise isolated sys.path.
Never import modules from a configurable or writable path. A distro Python
upgrade requires a reviewed replacement of the dedicated executable.
"""
import grp
import hashlib
import os
from pathlib import Path
import stat
import sys

RUNTIME = Path("/usr/local/libexec/lmr365-tpm-broker")
EXECUTABLE = RUNTIME / "python3"
NATIVE_PYTHON = Path("/usr/bin/python3")
MODULES = (
    "bootstrap.py",
    "m365_hardware_signer.py",
    "m365_xoauth2_transport.py",
    "m365_tpm_broker_protocol.py",
    "m365_tpm_broker_identity.py",
    "m365_tpm_broker_service.py",
)
MAX_MODULE = 2 * 1024 * 1024
MAX_EXECUTABLE = 64 * 1024 * 1024


class LaunchError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise LaunchError(code)


def directory(meta):
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and
         not meta.st_mode & 0o6022, "broker_runtime_directory_unsafe")


def file_digest(path, mode, maximum):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
         before.st_gid == 0 and before.st_nlink == 1 and
         stat.S_IMODE(before.st_mode) == mode and
         0 < before.st_size <= maximum, "broker_runtime_file_unsafe")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(str(path), flags), "rb") as stream:
        def stamp(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                    s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        expected = stamp(before)
        need(stamp(os.fstat(stream.fileno())) == expected,
             "broker_runtime_file_changed")
        total = 0
        digest = hashlib.sha256()
        while True:
            block = stream.read(65536)
            if not block:
                break
            total += len(block)
            need(total <= maximum, "broker_runtime_file_oversize")
            digest.update(block)
        need(total == before.st_size and
             stamp(os.fstat(stream.fileno())) == expected and
             stamp(path.lstat()) == expected, "broker_runtime_file_changed")
        return digest.digest()


def verify_runtime():
    need(sys.flags.isolated and sys.dont_write_bytecode and
         os.geteuid() > 0 and os.getegid() > 0,
         "broker_isolated_nonroot_python_required")
    need(os.readlink("/proc/self/exe") == str(EXECUTABLE),
         "broker_runtime_executable_mismatch")
    for path in (RUNTIME,) + tuple(RUNTIME.parents):
        directory(path.lstat())
    meta = RUNTIME.lstat()
    need(meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o755,
         "broker_runtime_directory_permissions")
    # No extra modules or preexisting __pycache__ directories. -B disables
    # writes, not reads of cached bytecode, so the directory must be exact.
    need(set(os.listdir(str(RUNTIME))) == set(MODULES) | {"python3"},
         "broker_runtime_inventory_mismatch")
    for name in MODULES:
        file_digest(RUNTIME / name, 0o644, MAX_MODULE)
    native = NATIVE_PYTHON.resolve(strict=True)
    for path in native.parents:
        directory(path.lstat())
    need(file_digest(EXECUTABLE, 0o755, MAX_EXECUTABLE) ==
         file_digest(native, 0o755, MAX_EXECUTABLE),
         "broker_runtime_python_upgrade_required")


def verify_device():
    gid = grp.getgrnam("lmr365-tpm-signer").gr_gid
    meta = Path("/dev/tpmrm0").lstat()
    need(gid > 0 and os.getegid() == gid and stat.S_ISCHR(meta.st_mode) and
         meta.st_uid == 0 and meta.st_gid == gid and
         stat.S_IMODE(meta.st_mode) == 0o660 and
         not os.path.lexists("/dev/tpm0"), "broker_runtime_device_scope")


def main():
    try:
        need(len(sys.argv) == 1, "broker_runtime_arguments")
        verify_runtime()
        verify_device()
        sys.path.insert(0, str(RUNTIME))
        import m365_tpm_broker_service as service
        return service.main(["--serve"])
    except Exception:
        # Do not log paths, credentials, provider configuration or assertions.
        print("LMR365_TPM_BROKER_BOOTSTRAP_FAILED", file=sys.stderr, flush=True)
        return 75


if __name__ == "__main__":
    sys.exit(main())
