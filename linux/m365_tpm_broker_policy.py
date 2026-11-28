"""Native SELinux policy stage for the disabled primary TPM broker.

Linux/Python 3.6+, Rocky 10.3 candidate only. No CLI or automatic activation.
Compile reviewed TE/FC in a private scratch directory, bind both the package
and CIL checksums to a reviewed plan, install/remove only one module at
priority 400, and verify the entire native policy inventory and exact label
of the dedicated Python copy. The coordinator must hold exclusive maintenance,
persist the reviewed spec/artifact, prove runtime integrity and stopped
services, and journal intent before calling mutate. No audit2allow, broad
relabel, setenforce, or changes to Postfix or the system interpreter.
"""
from collections import namedtuple
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import m365_tpm_broker_bootstrap as bootstrap
import m365_tpm_broker_files as files
import m365_tpm_broker_transaction as tx

MODULE = "lmr365_tpm_signer"
PRIORITY = "400"
LABEL = "system_u:object_r:lmr365_tpm_signer_exec_t:s0"
EXECUTABLE = bootstrap.EXECUTABLE
MAX_ARTIFACT = 4 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
TOOLS = {
    "semodule": "/usr/sbin/semodule",
    "make": "/usr/bin/make",
    "pp": "/usr/libexec/selinux/hll/pp",
    "matchpathcon": "/usr/sbin/matchpathcon",
    "restorecon": "/usr/sbin/restorecon",
}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
Spec = namedtuple("PolicySpec", "baseline baseline_label package_sha cil_sha python_sha")
Refused = tx.Refused
need = tx.need


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def enforcing():
    need(os.geteuid() == 0 and
         Path("/sys/fs/selinux/enforce").read_bytes().strip() == b"1" and
         Path("/proc/1/comm").read_text().strip() == "systemd",
         "broker_policy_native_enforcing_required")
    lines = Path("/etc/os-release").read_text(encoding="ascii").splitlines()
    need(("ID=rocky" in lines or 'ID="rocky"' in lines) and
         ("VERSION_ID=10.3" in lines or 'VERSION_ID="10.3"' in lines),
         "broker_policy_rocky10_3_only")


def run_native(name, args, cwd=None):
    need(name in TOOLS and os.geteuid() == 0, "broker_policy_command_refused")
    alias = Path(TOOLS[name])
    with files.open_trusted_directory(alias.parent):
        path = alias.resolve(strict=True)
    with files.open_trusted_directory(path.parent):
        meta = path.lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
             not meta.st_mode & 0o6022 and meta.st_mode & 0o111,
             "broker_policy_untrusted_tool")
    try:
        result = subprocess.run([str(alias)] + list(args), input=b"",
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=120, cwd=cwd, env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("broker_policy_native_command_failed") from None
    limit = MAX_ARTIFACT if name == "pp" else MAX_OUTPUT
    need(result.returncode == 0 and len(result.stdout) <= limit,
         "broker_policy_native_command_failed")
    return result.stdout


def parse_inventory(raw):
    """semodule -lfull -m: all priorities, enabled state and CIL checksums."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT,
         "broker_policy_inventory_size")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Refused("broker_policy_inventory_unverified") from None
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        need(len(fields) in (4, 5), "broker_policy_inventory_unverified")
        priority, name, language = fields[:3]
        enabled = len(fields) == 4
        checksum = fields[-1]
        if checksum.startswith("sha256:"):
            checksum = checksum[7:]
        need(priority.isdigit() and 1 <= int(priority) <= 999 and
             re.fullmatch(r"[A-Za-z0-9_.-]+", name) and language in ("pp", "cil") and
             (enabled or fields[3] == "disabled") and tx.sha(checksum),
             "broker_policy_inventory_unverified")
        key = (str(int(priority)), name)
        need(key not in result, "broker_policy_duplicate_module")
        result[key] = (key[0], name, language, enabled, checksum)
    need(bool(result), "broker_policy_empty_inventory")
    return tuple(sorted(result.values()))


def inventory(run=run_native):
    return parse_inventory(run("semodule", ["-lfull", "-m"]))


def label_value(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 512,
         "broker_policy_context_unverified")
    try:
        value = raw.rstrip(b"\0\n").decode("ascii")
    except UnicodeError:
        raise Refused("broker_policy_context_unverified") from None
    need(re.fullmatch(r"[A-Za-z0-9_]+:object_r:[A-Za-z0-9_]+_t:[A-Za-z0-9_.,:-]+", value)
         is not None, "broker_policy_context_unverified")
    return value


def expected_label(run=run_native):
    return label_value(run("matchpathcon", ["-N", "-n", str(EXECUTABLE)]))


def executable_label(python_sha):
    # Runtime absent before its own stage, or exact reviewed executable.
    if not os.path.lexists(str(bootstrap.RUNTIME)):
        return None
    with files.open_trusted_directory(bootstrap.RUNTIME) as fd:
        raw = files.read_regular(fd, EXECUTABLE.name, 0, 0, 0o755,
                                 bootstrap.MAX_EXECUTABLE)
        need(sha_bytes(raw) == python_sha, "broker_policy_runtime_changed")
        before = os.stat(EXECUTABLE.name, dir_fd=fd, follow_symlinks=False)
        handle = os.open(EXECUTABLE.name, files.READ_FLAGS, dir_fd=fd)
        try:
            need(tx.metadata(os.fstat(handle)) == tx.metadata(before),
                 "broker_policy_runtime_changed")
            value = label_value(os.getxattr(handle, "security.selinux"))
            need(tx.metadata(os.fstat(handle)) == tx.metadata(before) and
                 tx.metadata(os.stat(EXECUTABLE.name, dir_fd=fd, follow_symlinks=False)) ==
                 tx.metadata(before), "broker_policy_runtime_changed")
            return value
        finally:
            os.close(handle)


def validate(spec):
    need(isinstance(spec, Spec) and isinstance(spec.baseline, tuple) and spec.baseline and
         all(tx.sha(value) for value in (spec.package_sha, spec.cil_sha, spec.python_sha)),
         "broker_policy_invalid_spec")
    need(type(spec.baseline_label) is str and
         label_value(spec.baseline_label.encode("ascii")) == spec.baseline_label and
         spec.baseline_label != LABEL and
         not spec.baseline_label.split(":")[2] in ("default_t", "unlabeled_t", "file_t"),
         "broker_policy_invalid_baseline_context")
    seen = set()
    for row in spec.baseline:
        need(type(row) is tuple and len(row) == 5 and
             type(row[0]) is str and row[0].isdigit() and 1 <= int(row[0]) <= 999 and
             type(row[1]) is str and re.fullmatch(r"[A-Za-z0-9_.-]+", row[1]) and
             row[1] != MODULE and row[2] in ("pp", "cil") and
             type(row[3]) is bool and tx.sha(row[4]) and row[:2] not in seen,
             "broker_policy_invalid_baseline")
        seen.add(row[:2])
    need(spec.baseline == tuple(sorted(spec.baseline)), "broker_policy_invalid_baseline")
    return spec


def read_artifact(path, maximum=MAX_ARTIFACT):
    with files.open_trusted_directory(path.parent) as fd:
        # Native make output may be 0644; staging source uses 0600.
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        mode = stat.S_IMODE(info.st_mode)
        need(mode in (0o600, 0o644), "broker_policy_artifact_mode")
        return files.read_regular(fd, path.name, 0, 0, mode, maximum)


def write_artifact(path, raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_ARTIFACT,
         "broker_policy_artifact_size")
    with files.open_trusted_directory(path.parent) as fd:
        # Policy artifacts can exceed the runtime module file-size budget.
        handle = os.open(path.name, files.WRITE_FLAGS, 0o600, dir_fd=fd)
        with os.fdopen(handle, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    need(read_artifact(path) == raw, "broker_policy_artifact_write_unverified")


def compile_candidate(package, source_hashes, guard, run=run_native):
    """Explicitly invoked build step; no SELinux policy is loaded.

    Return reviewed package bytes and expected CIL digest; caller must retain
    these in a protected durable artifact store before approval.
    """
    need(callable(guard) and isinstance(package, Path) and package.is_absolute() and
         type(source_hashes) is dict, "broker_policy_compile_inputs")
    guard("policy", "compile")
    enforcing()
    sources = {}
    for ext in (".te", ".fc"):
        name = MODULE + ext
        path = package / "selinux" / name
        with files.open_trusted_directory(path.parent) as fd:
            raw = files.read_regular(fd, name, 0, 0, 0o644, files.MAX_FILE)
        need(tx.sha(source_hashes.get("policy/" + name)) and
             sha_bytes(raw) == source_hashes["policy/" + name],
             "broker_policy_source_not_approved")
        sources[name] = raw
    with tempfile.TemporaryDirectory(prefix="lmr365-policy-", dir="/run") as folder:
        work = Path(folder)
        for name, raw in sources.items():
            write_artifact(work / name, raw)
        guard("policy", "compile")
        run("make", ["-f", "/usr/share/selinux/devel/Makefile", MODULE + ".pp"],
            cwd=str(work))
        path = work / (MODULE + ".pp")
        pp = read_artifact(path)
        cil = run("pp", [str(path)])
        need(type(cil) is bytes and 0 < len(cil) <= MAX_ARTIFACT and
             b"lmr365_tpm_signer_t" in cil, "broker_policy_cil_unverified")
        need(read_artifact(path) == pp, "broker_policy_compiled_artifact_changed")
    enforcing()
    guard("policy", "compile")
    return pp, sha_bytes(cil)


def prepare_spec(package_bytes, cil_sha, python_sha, run=run_native):
    """Observe a new-install baseline; no policy or file context changes."""
    enforcing()
    need(type(package_bytes) is bytes and 0 < len(package_bytes) <= MAX_ARTIFACT,
         "broker_policy_artifact_size")
    baseline = inventory(run)
    label = expected_label(run)
    need(inventory(run) == baseline and expected_label(run) == label,
         "broker_policy_baseline_changed")
    return validate(Spec(baseline, label, sha_bytes(package_bytes), cil_sha, python_sha))


class PolicyStage:
    def __init__(self, spec, package_bytes, guard, run=run_native,
                 mode=enforcing, read_label=executable_label):
        self.spec = validate(spec)
        need(type(package_bytes) is bytes and 0 < len(package_bytes) <= MAX_ARTIFACT and
             sha_bytes(package_bytes) == spec.package_sha and
             all(callable(fn) for fn in (guard, run, mode, read_label)),
             "broker_policy_unapproved_artifact_or_guard")
        self.package = package_bytes
        self.guard, self.run, self.mode, self.read_label = guard, run, mode, read_label
        self.after = tuple(sorted(spec.baseline +
                     ((PRIORITY, MODULE, "pp", True, spec.cil_sha),)))

    def fingerprint(self, installed):
        return tx.digest({"stage": "policy", "spec": self.spec._asdict(),
                          "installed": installed})

    def stage_plan(self):
        return {"name": "policy", "before": self.fingerprint(False),
                "after": self.fingerprint(True)}

    def classify(self):
        self.mode()
        current = inventory(self.run)
        desired = expected_label(self.run)
        actual = self.read_label(self.spec.python_sha)
        if current == self.spec.baseline and desired == self.spec.baseline_label:
            need(actual in (None, desired), "broker_policy_partial_label")
            state = False
        elif current == self.after and desired == LABEL:
            need(actual == LABEL, "broker_policy_partial_label")
            state = True
        else:
            raise Refused("broker_policy_inventory_or_context_changed")
        need(inventory(self.run) == current and expected_label(self.run) == desired,
             "broker_policy_inventory_or_context_changed")
        self.mode()
        return state

    def probe(self):
        return self.fingerprint(self.classify())

    def mutate(self, direction):
        need(direction in ("install", "rollback"), "broker_policy_operation_refused")
        self.guard("policy", direction)
        self.mode()
        install = direction == "install"
        need(self.classify() is not install, "broker_policy_unexpected_state")
        if install:
            need(self.read_label(self.spec.python_sha) == self.spec.baseline_label,
                 "broker_policy_runtime_required")
            with tempfile.TemporaryDirectory(prefix="lmr365-policy-", dir="/run") as folder:
                artifact = Path(folder) / (MODULE + ".pp")
                write_artifact(artifact, self.package)
                # Recompute the exact CIL digest on the native host BEFORE load.
                cil = self.run("pp", [str(artifact)])
                need(sha_bytes(cil) == self.spec.cil_sha and
                     read_artifact(artifact) == self.package, "broker_policy_compiler_drift")
                self.guard("policy", direction)
                need(self.classify() is False, "broker_policy_unexpected_state")
                self.run("semodule", ["-X", PRIORITY, "-i", str(artifact)])
            expected_inventory, label = self.after, LABEL
        else:
            self.guard("policy", direction)
            need(self.classify() is True, "broker_policy_unexpected_state")
            self.run("semodule", ["-X", PRIORITY, "-r", MODULE])
            expected_inventory, label = self.spec.baseline, self.spec.baseline_label
        self.mode()
        need(inventory(self.run) == expected_inventory and expected_label(self.run) == label,
             "broker_policy_mutation_unverified")
        # Exact copy only; never recursively relabel or modify native Python.
        self.guard("policy", direction)
        need(self.read_label(self.spec.python_sha) is not None,
             "broker_policy_runtime_required")
        self.run("restorecon", ["-F", str(EXECUTABLE)])
        self.guard("policy", direction)
        need(self.classify() is install, "broker_policy_mutation_unverified")
