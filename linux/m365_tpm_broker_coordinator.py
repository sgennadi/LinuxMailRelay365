"""Integrated, disabled first-install coordinator for the primary TPM broker.

Native adapter assembly and guarded journal operations, not a CLI or a
production installer. Only Rocky 10.3 is eligible for native candidate
operations. The caller must supply exclusive maintenance and an independently
reviewed TPM/UID/GID ownership guard, with no concurrent service, NSS,
policy, mail, or udev changes. A root-owned reviewed package must remain
available across recovery. No cloud calls, Postfix changes or TPM key
creation. Reboot changes the device evidence and requires separate recovery.
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

import m365_tpm_broker_account as account
import m365_tpm_broker_activation as activation
import m365_tpm_broker_device as device
import m365_tpm_broker_files as files
import m365_tpm_broker_identity as identity
import m365_tpm_broker_policy as policy
import m365_tpm_broker_transaction as tx

HERE = Path(__file__).absolute().parent
REVIEW = "review.json"
POLICY_PACKAGE = "reviewed-policy.pp"
MAX_REVIEW = 2 * 1024 * 1024
UDEVADM = Path("/usr/bin/udevadm")
Refused = tx.Refused
need = tx.need


def load_preview():
    spec = importlib.util.spec_from_file_location(
        "primary_broker_install_preview", str(HERE / "inspect-primary-tpm-broker-install.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plain(value):
    return json.loads(tx.canonical(value).decode("ascii"))


def checked_keys(obj, fields):
    need(type(obj) is dict and set(obj) == set(fields),
         "broker_coordinator_review_schema")
    return obj


def decode_review(review):
    checked_keys(review, ("schema", "id", "preview", "boot", "identity", "sources",
                          "account", "policy", "device", "activation"))
    need(type(review["schema"]) is int and review["schema"] == 1 and
         type(review["id"]) is str and tx.TXID.fullmatch(review["id"]) and
         tx.sha(review["preview"]) and tx.sha(review["identity"]),
         "broker_coordinator_review_schema")
    try:
        need(type(review["boot"]) is str and
             str(uuid.UUID(review["boot"])) == review["boot"],
             "broker_coordinator_boot")
        a = dict(checked_keys(review["account"], account.Spec._fields))
        p = dict(checked_keys(review["policy"], policy.Spec._fields))
        d = dict(checked_keys(review["device"], device.Spec._fields))
        s = dict(checked_keys(review["activation"], activation.Spec._fields))
        need(type(a["mail_members"]) is list and type(p["baseline"]) is list and
             all(type(row) is list for row in p["baseline"]),
             "broker_coordinator_review_schema")
        a["mail_members"] = tuple(a["mail_members"])
        p["baseline"] = tuple(tuple(row) for row in p["baseline"])
        d["baseline"] = device.Evidence(**checked_keys(d["baseline"], device.Evidence._fields))
        a = account.validate(account.Spec(**a))
        p = policy.validate(policy.Spec(**p))
        d = device.validate(device.Spec(**d))
        s = activation.validate(activation.Spec(**s))
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused("broker_coordinator_review_schema") from None
    sources = review["sources"]
    names = ({"runtime/" + name for name in files.MODES["runtime"]} |
             {"systemd/" + files.UNIT, "udev/" + files.RULE,
              "policy/" + policy.MODULE + ".te", "policy/" + policy.MODULE + ".fc"})
    need(type(sources) is dict and set(sources) == names and
         all(tx.sha(value) for value in sources.values()) and
         p.python_sha == s.python_sha == sources["runtime/python3"] and
         s.unit_sha == sources["systemd/" + files.UNIT] and
         (a.uid, a.gid) == (d.signer_uid, d.signer_gid) ==
         (s.signer_uid, s.signer_gid) and a.mail_gid == s.mail_gid and
         d.baseline.boot == review["boot"], "broker_coordinator_cross_stage_mismatch")
    return a, p, d, s


def make_review(evidence, a, p, d, s, transaction_id=None):
    value = {
        "schema": 1, "id": uuid.uuid4().hex if transaction_id is None else transaction_id,
        "preview": tx.digest(evidence), "boot": evidence["boot"],
        "identity": evidence["identity"], "sources": evidence["sources"],
        "account": a._asdict(), "policy": p._asdict(),
        "device": dict(d._asdict(), baseline=d.baseline._asdict()),
        "activation": s._asdict(),
    }
    value = plain(value)
    decode_review(value)
    return value


def read_fixed(journal, name, limit):
    journal.check()
    need(name in (REVIEW, POLICY_PACKAGE), "broker_coordinator_artifact_name")
    return files.read_regular(journal.fd, name, journal.owner, os.getegid(),
                              0o600, limit)


def write_fixed(journal, name, raw, limit):
    journal.check()
    need(name in (REVIEW, POLICY_PACKAGE) and type(raw) is bytes and
         0 < len(raw) <= limit, "broker_coordinator_artifact_size")
    fd = os.open(name, files.WRITE_FLAGS, 0o600, dir_fd=journal.fd)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(journal.fd)
    need(read_fixed(journal, name, limit) == raw,
         "broker_coordinator_artifact_write_unverified")


def read_review(journal):
    raw = read_fixed(journal, REVIEW, MAX_REVIEW)
    try:
        review = json.loads(raw.decode("ascii"), object_pairs_hook=tx.unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("broker_coordinator_review_unparseable") from None
    unused_a, p, unused_d, unused_s = decode_review(review)
    need(raw == tx.canonical(review), "broker_coordinator_review_noncanonical")
    pp = read_fixed(journal, POLICY_PACKAGE, policy.MAX_ARTIFACT)
    need(policy.sha_bytes(pp) == p.package_sha, "broker_coordinator_policy_artifact_changed")
    return review, pp


def save_review(journal, review, pp):
    """Write once before creating the transaction journal; no blind cleanup."""
    journal.check()
    unused_a, p, unused_d, unused_s = decode_review(review)
    need(journal.read() is None and not files.exists(journal.fd, REVIEW) and
         not files.exists(journal.fd, POLICY_PACKAGE) and type(pp) is bytes and
         policy.sha_bytes(pp) == p.package_sha and len(pp) <= policy.MAX_ARTIFACT,
         "broker_coordinator_review_exists_or_changed")
    # A crash between files leaves an incomplete bundle that must be
    # inspected explicitly; it is never accepted as a reviewed transaction.
    write_fixed(journal, POLICY_PACKAGE, pp, policy.MAX_ARTIFACT)
    write_fixed(journal, REVIEW, tx.canonical(review), MAX_REVIEW)
    need(read_review(journal) == (review, pp), "broker_coordinator_review_write_failed")


def native_guard(review, exclusive, inspector, stage=None, direction=None):
    need(callable(exclusive), "broker_coordinator_exclusive_guard_required")
    exclusive(stage, direction)
    need(inspector.platform() == review["boot"] and
         identity.read_primary_snapshot().approval_digest() == review["identity"],
         "broker_coordinator_boot_or_identity_changed")
    inspector.postfix_evidence()


def udev_command(args):
    need(os.geteuid() == 0, "broker_coordinator_root_required")
    with files.open_trusted_directory(UDEVADM.parent):
        meta = UDEVADM.lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
             not meta.st_mode & 0o6022 and meta.st_mode & 0o111,
             "broker_coordinator_untrusted_udevadm")
    try:
        result = subprocess.run([str(UDEVADM)] + list(args), input=b"",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45,
            env=activation.ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("broker_coordinator_udev_failed") from None
    need(result.returncode == 0, "broker_coordinator_udev_failed")


class Coordinator:
    """Fixed stage dispatch; only the compiled adapters may change the host."""
    def __init__(self, review, file_stage, account_stage, policy_stage,
                 device_stage, activation_stage, guard, udev, systemctl):
        self.review = plain(review)
        a, p, d, s = decode_review(self.review)
        need(all(callable(fn) for fn in (guard, udev, systemctl)),
             "broker_coordinator_guard_required")
        self.files = file_stage
        self.account, self.policy = account_stage, policy_stage
        self.device, self.activation = device_stage, activation_stage
        self.guard, self.udev, self.systemctl = guard, udev, systemctl
        need((account_stage.spec, policy_stage.spec, device_stage.spec,
              activation_stage.spec) == (a, p, d, s),
             "broker_coordinator_adapter_mismatch")
        self.adapters = {"account": self.account, "policy": self.policy,
                         "device": self.device, "activation": self.activation}

    def plan(self):
        return tx.validate_plan({"preview": tx.digest(self.review), "stages": [
            self.files.stage_plan(stage) if stage in files.TARGETS
            else self.adapters[stage].stage_plan() for stage in tx.STAGES]})

    def probe(self, stage):
        need(stage in tx.STAGES, "broker_coordinator_unknown_stage")
        return (self.files.probe(stage) if stage in files.TARGETS
                else self.adapters[stage].probe())

    def assert_device_installed(self):
        need(self.device.probe() == self.device.stage_plan()["after"],
             "broker_coordinator_device_not_installed")

    def mutate(self, stage, direction):
        need(stage in tx.STAGES and direction in ("install", "rollback"),
             "broker_coordinator_operation_refused")
        self.guard(stage, direction)
        if stage == "activation" and direction == "install":
            self.assert_device_installed()
            # Rule file and direct DAC are already installed. The targeted
            # change event is idempotent and prepares the systemd device unit.
            self.udev(["control", "--reload-rules"])
            self.udev(["trigger", "--action=change", "--settle",
                       self.device.spec.baseline.sysfs])
            self.assert_device_installed()
            self.guard(stage, direction)
        if stage == "device" and direction == "rollback":
            # Rule removal precedes device restoration. Reload even if an
            # interrupted file stage was reconciled as already removed.
            need(self.files.probe("udev_rule") ==
                 self.files.stage_plan("udev_rule")["before"],
                 "broker_coordinator_udev_rule_still_present")
            self.udev(["control", "--reload-rules"])
            self.udev(["settle", "--timeout=30"])
            self.guard(stage, direction)
            self.assert_device_installed()
        if stage in files.TARGETS:
            self.files.mutate(stage, direction)
            if stage == "unit" and direction == "rollback":
                self.systemctl(["daemon-reload"])
        else:
            self.adapters[stage].mutate(direction)
        self.guard(stage, direction)

    def global_guard(self):
        self.guard(None, None)

    def apply(self, journal, approved, confirmation):
        journal.check()
        plan = self.plan()
        need(approved == tx.digest(plan) and confirmation == tx.APPLY,
             "broker_coordinator_apply_not_approved")
        review, pp = read_review(journal)
        need(review == self.review and policy.sha_bytes(pp) == self.policy.spec.package_sha,
             "broker_coordinator_review_changed")
        state = journal.read()
        if state is None:
            tx.begin(journal, plan, approved, confirmation, self.global_guard,
                     self.probe, transaction_id=self.review["id"])
        else:
            need(state["id"] == self.review["id"] and state["plan"] == plan,
                 "broker_coordinator_transaction_changed")
        return tx.resume_install(journal, approved, confirmation,
                                 self.global_guard, self.probe, self.mutate)

    def rollback(self, journal, approved, confirmation):
        journal.check()
        plan = self.plan()
        need(approved == tx.digest(plan) and confirmation == tx.ROLLBACK,
             "broker_coordinator_rollback_not_approved")
        review, pp = read_review(journal)
        state = journal.read()
        need(review == self.review and policy.sha_bytes(pp) == self.policy.spec.package_sha and
             state is not None and state["id"] == self.review["id"] and state["plan"] == plan,
             "broker_coordinator_transaction_changed")
        return tx.rollback(journal, approved, confirmation, self.global_guard,
                           self.probe, self.mutate)


@contextmanager
def native_coordinator(review, pp, exclusive, inspector=None):
    """All seven real backends. Caller owns the private journal and approval."""
    need(os.geteuid() == 0 and callable(exclusive), "broker_coordinator_root_guard_required")
    inspector = load_preview() if inspector is None else inspector
    a, p, d, s = decode_review(review)
    def guard(stage, direction):
        native_guard(review, exclusive, inspector, stage, direction)
    guard(None, None)
    with files.open_candidate_files(HERE, review["sources"], review["id"], guard) as f:
        yield Coordinator(review, f, account.AccountStage(a, guard),
            policy.PolicyStage(p, pp, guard), device.DeviceStage(d, guard),
            activation.ActivationStage(s, guard), guard, udev_command,
            lambda args: activation.command(activation.SYSTEMCTL, args))


def prepare_review(journal, uid, gid, exclusive, inspector=None):
    """Explicit candidate preparation; writes review bundle, not host config.

    UID/GID reservation and exclusive TPM ownership are caller-reviewed.
    Returns the exact plan approval to display/confirm before apply.
    """
    journal.check()
    need(os.geteuid() == 0 and callable(exclusive),
         "broker_coordinator_root_guard_required")
    need(journal.read() is None and not files.exists(journal.fd, REVIEW) and
         not files.exists(journal.fd, POLICY_PACKAGE), "broker_coordinator_review_exists")
    inspector = load_preview() if inspector is None else inspector
    exclusive(None, None)
    evidence = inspector.collect()
    mail_uid, mail_gid = evidence["account"]
    original_members = account.members(account.local_inventory()[1][account.MAIL][2])
    a = account.validate(account.Spec(uid, gid, mail_uid, mail_gid, original_members))
    account.ensure_idle(a)
    need(account.observe_native(a) == "absent", "broker_coordinator_account_not_free")
    def compile_guard(stage, direction):
        exclusive(stage, direction)
        need(inspector.collect() == evidence, "broker_coordinator_preview_changed")
    pp, cil_sha = policy.compile_candidate(HERE, evidence["sources"], compile_guard)
    p = policy.prepare_spec(pp, cil_sha, evidence["sources"]["runtime/python3"])
    d = device.prepare_spec(uid, gid)
    s = activation.validate(activation.Spec(evidence["sources"]["systemd/" + files.UNIT],
        p.python_sha, uid, gid, mail_gid))
    # All native adapters will independently sample their exact initial state.
    need(inspector.collect() == evidence, "broker_coordinator_preview_changed")
    review = make_review(evidence, a, p, d, s)
    with native_coordinator(review, pp, exclusive, inspector) as coordinator:
        plan = coordinator.plan()
        coordinator.global_guard()
        for stage in plan["stages"]:
            need(coordinator.probe(stage["name"]) == stage["before"],
                 "broker_coordinator_initial_stage_changed")
        coordinator.global_guard()
        need(inspector.collect() == evidence, "broker_coordinator_preview_changed")
        save_review(journal, review, pp)
        return tx.digest(plan)
