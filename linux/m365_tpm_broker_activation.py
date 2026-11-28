"""Native systemd lifecycle stage for the disabled primary TPM broker.

Not an installer CLI. The coordinator must first verify the exact approved
unit, runtime, policy, account, identity, device and udev state, hold
exclusive maintenance and journal intent. This stage starts/enables only
the dedicated unit, never starts or reloads Postfix. It requires a fresh
trusted journald receipt of the local TPM signing self-test and live process
credentials. An active but disabled, failed, or unverified service is a
partial state, not a successful install. Reboot recovery is a separate gate.
Linux/Python 3.6+; first native acceptance must use disposable Rocky 10.3.
"""
from collections import namedtuple
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import m365_tpm_broker_bootstrap as bootstrap
import m365_tpm_broker_files as files
import m365_tpm_broker_policy as policy
import m365_tpm_broker_service as service
import m365_tpm_broker_transaction as tx

UNIT = files.UNIT
UNIT_PATH = Path("/etc/systemd/system") / UNIT
ENABLE_LINK = UNIT_PATH.parent / "multi-user.target.wants" / UNIT
SYSTEMCTL = Path("/usr/bin/systemctl")
JOURNALCTL = Path("/usr/bin/journalctl")
READY = "LMR365_TPM_BROKER_READY"
WAIT_SECONDS = 150
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
KEYS = ("LoadState", "ActiveState", "SubState", "MainPID", "ControlPID",
        "Result", "InvocationID", "UnitFileState", "FragmentPath",
        "DropInPaths", "NeedDaemonReload", "ControlGroup")
SANDBOX = {
    "Type": "exec", "User": service.SIGNER_ACCOUNT, "Group": service.SIGNER_ACCOUNT,
    "SupplementaryGroups": service.MAIL_ACCOUNT,
    "PrivateDevices": "yes", "DevicePolicy": "closed",
    "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
    "PrivateTmp": "yes", "RestrictAddressFamilies": "AF_UNIX",
    "CapabilityBoundingSet": "", "AmbientCapabilities": "",
    "SELinuxContext": "system_u:system_r:lmr365_tpm_signer_t:s0",
    "Restart": "on-failure", "KillMode": "control-group",
}
Spec = namedtuple("ActivationSpec", "unit_sha python_sha signer_uid signer_gid mail_gid")
Refused = tx.Refused
need = tx.need


def validate(spec):
    need(isinstance(spec, Spec) and tx.sha(spec.unit_sha) and tx.sha(spec.python_sha) and
         all(type(n) is int and 0 < n < 65536 for n in spec[2:]) and
         spec.signer_gid != spec.mail_gid, "broker_activation_invalid_spec")
    return spec


def command(tool, args):
    need(os.geteuid() == 0 and tool in (SYSTEMCTL, JOURNALCTL),
         "broker_activation_command_refused")
    with files.open_trusted_directory(tool.parent):
        meta = tool.lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
             not meta.st_mode & 0o6022 and meta.st_mode & 0o111,
             "broker_activation_untrusted_tool")
    try:
        result = subprocess.run([str(tool)] + list(args), input=b"",
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=45, env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("broker_activation_native_command_failed") from None
    need(result.returncode == 0 and len(result.stdout) <= 512 * 1024,
         "broker_activation_native_command_failed")
    return result.stdout


def properties(raw, keys):
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except (UnicodeError, AttributeError):
        raise Refused("broker_activation_properties_unverified") from None
    result = {}
    for line in lines:
        key, sep, value = line.partition("=")
        need(sep and key in keys and key not in result and len(value) <= 8192 and
             not any(ord(c) < 32 for c in value), "broker_activation_properties_unverified")
        result[key] = value
    need(set(result) == set(keys), "broker_activation_properties_incomplete")
    return result


def show(run, keys):
    return properties(run(SYSTEMCTL, ["show", "--all", UNIT] +
                          ["-p" + key for key in keys]), keys)


def unit_verified(spec):
    with files.open_trusted_directory(UNIT_PATH.parent) as fd:
        if not files.exists(fd, UNIT):
            return False
        raw = files.read_regular(fd, UNIT, 0, 0, 0o644, files.MAX_FILE)
        need(files.sha_bytes(raw) == spec.unit_sha, "broker_activation_unit_changed")
    return True


def link_enabled():
    if not os.path.lexists(str(ENABLE_LINK)):
        return False
    with files.open_trusted_directory(ENABLE_LINK.parent) as fd:
        meta = os.stat(UNIT, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISLNK(meta.st_mode) and meta.st_uid == 0 and
             os.readlink(UNIT, dir_fd=fd) in (str(UNIT_PATH), "../" + UNIT) and
             ENABLE_LINK.resolve(strict=True) == UNIT_PATH,
             "broker_activation_enable_link_unverified")
        need(tx.metadata(os.stat(UNIT, dir_fd=fd, follow_symlinks=False)) ==
             tx.metadata(meta), "broker_activation_enable_link_changed")
    return True


def inactive(status):
    return (status["ActiveState"], status["SubState"], status["MainPID"],
            status["ControlPID"]) == ("inactive", "dead", "0", "0")


def loaded(status):
    return (status["LoadState"] == "loaded" and status["FragmentPath"] == str(UNIT_PATH) and
            status["DropInPaths"] == "" and status["NeedDaemonReload"] == "no")


def active(status):
    return (loaded(status) and status["ActiveState"] == "active" and
            status["SubState"] == "running" and status["Result"] == "success" and
            status["ControlPID"] == "0" and
            re.fullmatch(r"[1-9][0-9]{0,9}", status["MainPID"]) is not None and
            int(status["MainPID"]) > 1 and
            re.fullmatch(r"[a-f0-9]{32}", status["InvocationID"]) is not None and
            status["InvocationID"] != "0" * 32 and
            status["ControlGroup"] == "/system.slice/" + UNIT)


def verify_sandbox(run):
    values = show(run, tuple(SANDBOX) + ("DeviceAllow", "BindPaths"))
    need(all(values[key] == expected for key, expected in SANDBOX.items()) and
         values["DeviceAllow"] == "/dev/tpmrm0 rw" and
         values["BindPaths"] in ("/dev/tpmrm0:/dev/tpmrm0",
                                  "/dev/tpmrm0:/dev/tpmrm0:rbind",
                                  "/dev/tpmrm0"), "broker_activation_sandbox_unverified")


def process_fields(raw):
    wanted = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
              "CapBnd", "CapAmb", "NoNewPrivs"}
    result = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if key in wanted:
            need(sep and key not in result, "broker_activation_process_unverified")
            result[key] = value.split()
    need(set(result) == wanted, "broker_activation_process_unverified")
    return result


def verify_live_process(spec, status):
    need(active(status), "broker_activation_process_unverified")
    proc = Path("/proc") / status["MainPID"]
    values = process_fields((proc / "status").read_text(encoding="ascii"))
    need(values["Uid"] == [str(spec.signer_uid)] * 4 and
         values["Gid"] == [str(spec.signer_gid)] * 4 and
         set(values["Groups"]) | {str(spec.signer_gid)} ==
         {str(spec.signer_gid), str(spec.mail_gid)} and
         values["NoNewPrivs"] == ["1"] and
         all(len(values[key]) == 1 and re.fullmatch(r"0+", values[key][0])
             for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
         "broker_activation_process_credentials")
    raw = (proc / "attr/current").read_bytes().rstrip(b"\n")
    need(service.context_type(raw) == service.SIGNER_DOMAIN and
         os.readlink(str(proc / "exe")) == str(bootstrap.EXECUTABLE),
         "broker_activation_process_identity")
    with files.open_trusted_directory(bootstrap.RUNTIME) as fd:
        data = files.read_regular(fd, bootstrap.EXECUTABLE.name,
                                  0, 0, 0o755, bootstrap.MAX_EXECUTABLE)
        expected = os.stat(bootstrap.EXECUTABLE.name, dir_fd=fd, follow_symlinks=False)
        executable = (proc / "exe").stat()
        need(files.sha_bytes(data) == spec.python_sha and
             (expected.st_dev, expected.st_ino) == (executable.st_dev, executable.st_ino),
             "broker_activation_process_executable")
    need((proc / "cgroup").read_text(encoding="ascii").splitlines() ==
         ["0::" + status["ControlGroup"]], "broker_activation_process_cgroup")
    dev = proc / "root/dev"
    node = (dev / "tpmrm0").lstat()
    host = Path("/dev/tpmrm0").lstat()
    need(stat.S_ISCHR(node.st_mode) and stat.S_ISCHR(host.st_mode) and
         node.st_rdev == host.st_rdev and node.st_uid == 0 and
         node.st_gid == spec.signer_gid and stat.S_IMODE(node.st_mode) == 0o660 and
         not os.path.lexists(str(dev / "tpm0")), "broker_activation_process_device")


def receipt(raw, spec, status):
    """Trusted journald metadata for this PID AND current invocation only."""
    if not raw.strip():
        return False
    lines = raw.splitlines()
    need(len(lines) == 1, "broker_activation_ambiguous_ready_receipt")
    try:
        obj = json.loads(lines[0].decode("utf-8"), object_pairs_hook=tx.unique)
    except (ValueError, UnicodeError):
        raise Refused("broker_activation_ready_receipt_unverified") from None
    expected = {"MESSAGE": READY, "_SYSTEMD_UNIT": UNIT,
                "_SYSTEMD_INVOCATION_ID": status["InvocationID"],
                "_PID": status["MainPID"], "_UID": str(spec.signer_uid),
                "_GID": str(spec.signer_gid), "_EXE": str(bootstrap.EXECUTABLE)}
    need(type(obj) is dict and all(obj.get(k) == v for k, v in expected.items()),
         "broker_activation_ready_receipt_unverified")
    return True


def ready_receipt(run, spec, status):
    raw = run(JOURNALCTL, ["--boot", "--no-pager", "--quiet", "--output=json",
                          "--lines=2", "_SYSTEMD_UNIT=" + UNIT,
                          "_SYSTEMD_INVOCATION_ID=" + status["InvocationID"],
                          "_PID=" + status["MainPID"], "MESSAGE=" + READY])
    return receipt(raw, spec, status)


class ActivationStage:
    def __init__(self, spec, guard, run=command, mode=policy.enforcing,
                 verify_unit=unit_verified, enabled=link_enabled,
                 verify_process=verify_live_process):
        self.spec = validate(spec)
        need(all(callable(fn) for fn in (guard, run, mode, verify_unit, enabled,
                                         verify_process)), "broker_activation_guard_required")
        self.guard, self.run, self.mode = guard, run, mode
        self.verify_unit, self.enabled, self.verify_process = verify_unit, enabled, verify_process

    def fingerprint(self, installed):
        return tx.digest({"stage": "activation", "spec": self.spec._asdict(),
                          "installed": installed})

    def stage_plan(self):
        return {"name": "activation", "before": self.fingerprint(False),
                "after": self.fingerprint(True)}

    def state(self):
        self.mode()
        status = show(self.run, KEYS)
        present = self.verify_unit(self.spec)
        enabled = self.enabled()
        if inactive(status) and not enabled and status["UnitFileState"] in ("", "disabled"):
            # Unit may not exist yet, or its exact file may have just been
            # installed and systemd has not been reloaded. No process is live.
            need((status["LoadState"] == "not-found" and not status["FragmentPath"]) or
                 (present and status["LoadState"] == "loaded" and
                  status["FragmentPath"] == str(UNIT_PATH) and not status["DropInPaths"]),
                 "broker_activation_inactive_unit_unverified")
            result = False
        elif present and enabled and status["UnitFileState"] == "enabled" and active(status):
            verify_sandbox(self.run)
            self.verify_process(self.spec, status)
            need(ready_receipt(self.run, self.spec, status),
                 "broker_activation_ready_receipt_missing")
            result = True
        else:
            raise Refused("broker_activation_partial_or_foreign_state")
        need(show(self.run, KEYS) == status and self.enabled() == enabled and
             self.verify_unit(self.spec) == present, "broker_activation_state_changed")
        self.mode()
        return result

    def probe(self):
        return self.fingerprint(self.state())

    def wait_ready(self):
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            self.mode()
            status = show(self.run, KEYS)
            if active(status):
                verify_sandbox(self.run)
                self.verify_process(self.spec, status)
                if ready_receipt(self.run, self.spec, status):
                    need(show(self.run, KEYS) == status, "broker_activation_state_changed")
                    return
            else:
                need(status["ActiveState"] in ("activating", "active") and
                     status["LoadState"] == "loaded",
                     "broker_activation_start_failed")
            time.sleep(0.5)
        raise Refused("broker_activation_ready_timeout")

    def mutate(self, direction):
        need(direction in ("install", "rollback"), "broker_activation_operation_refused")
        self.guard("activation", direction)
        install = direction == "install"
        need(self.state() is not install and self.verify_unit(self.spec),
             "broker_activation_unexpected_state")
        if install:
            self.run(SYSTEMCTL, ["daemon-reload"])
            status = show(self.run, KEYS)
            need(loaded(status) and inactive(status) and
                 status["UnitFileState"] == "disabled" and not self.enabled(),
                 "broker_activation_reload_unverified")
            verify_sandbox(self.run)
            self.guard("activation", direction)
            self.run(SYSTEMCTL, ["enable", UNIT])
            need(self.enabled() and self.verify_unit(self.spec),
                 "broker_activation_enable_unverified")
            self.guard("activation", direction)
            self.run(SYSTEMCTL, ["start", UNIT])
            self.wait_ready()
        else:
            self.run(SYSTEMCTL, ["stop", UNIT])
            status = show(self.run, KEYS)
            need(loaded(status) and inactive(status) and self.enabled(),
                 "broker_activation_stop_unverified")
            self.guard("activation", direction)
            self.run(SYSTEMCTL, ["disable", UNIT])
        self.guard("activation", direction)
        need(self.state() is install, "broker_activation_mutation_unverified")
