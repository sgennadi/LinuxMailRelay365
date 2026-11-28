"""Integrated candidate coordinator tests: real private journal, simulated stages."""
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
import m365_tpm_broker_coordinator as C


class SimulatedStage:
    def __init__(self, name, spec, events):
        self.name, self.spec, self.events, self.installed = name, spec, events, False

    def stage_plan(self):
        return {"name": self.name, "before": C.tx.digest([self.name, False]),
                "after": C.tx.digest([self.name, True])}

    def probe(self):
        return self.stage_plan()["after" if self.installed else "before"]

    def mutate(self, direction):
        self.events.append((self.name, direction))
        self.installed = direction == "install"


class SimulatedFiles:
    def __init__(self, events):
        self.stages = {name: SimulatedStage(name, None, events) for name in C.files.TARGETS}

    def stage_plan(self, name):
        return self.stages[name].stage_plan()

    def probe(self, name):
        return self.stages[name].probe()

    def mutate(self, name, direction):
        self.stages[name].mutate(direction)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        root.chmod(0o700)
        self.fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.journal = C.tx.Journal(self.fd, owner=os.getuid())
        self.pp = b"reviewed test policy"
        self.boot = "12345678-1234-4234-8234-123456789abc"
        sources = {"runtime/" + name: "a" * 64 for name in C.files.MODES["runtime"]}
        sources.update({"systemd/" + C.files.UNIT: "b" * 64,
                        "udev/" + C.files.RULE: "c" * 64,
                        "policy/" + C.policy.MODULE + ".te": "d" * 64,
                        "policy/" + C.policy.MODULE + ".fc": "e" * 64})
        self.a = C.account.Spec(812, 813, 815, 816, ())
        self.p = C.policy.Spec((("100", "base", "pp", True, "a" * 64),),
            "system_u:object_r:bin_t:s0", C.policy.sha_bytes(self.pp), "f" * 64,
            sources["runtime/python3"])
        self.d = C.device.Spec(C.device.Evidence(self.boot, 12, 33, 253,
            "/sys/devices/platform/tpm/tpmrm/tpmrm0", "system_u:object_r:tpm_device_t:s0",
            0, 810, 0o600), 812, 813)
        self.s = C.activation.Spec(sources["systemd/" + C.files.UNIT],
                                    self.p.python_sha, 812, 813, 816)
        self.review = C.make_review({"boot": self.boot, "identity": "a" * 64,
                                     "sources": sources}, self.a, self.p, self.d,
                                     self.s, "9" * 32)
        self.events = []
        self.files = SimulatedFiles(self.events)
        self.account = SimulatedStage("account", self.a, self.events)
        self.policy = SimulatedStage("policy", self.p, self.events)
        self.device = SimulatedStage("device", self.d, self.events)
        self.activation = SimulatedStage("activation", self.s, self.events)
        self.guard = Mock()
        self.coordinator = C.Coordinator(self.review, self.files, self.account,
            self.policy, self.device, self.activation, self.guard,
            lambda args: self.events.append(("udev", tuple(args))),
            lambda args: self.events.append(("systemctl", tuple(args))))

    def save(self):
        C.save_review(self.journal, self.review, self.pp)

    def approve(self):
        return C.tx.digest(self.coordinator.plan())

    def test_review_roundtrip_and_cross_stage_binding(self):
        self.assertEqual(C.decode_review(self.review), (self.a, self.p, self.d, self.s))
        for key, field, value in (("activation", "signer_gid", 899),
                ("device", "signer_uid", 899), ("activation", "python_sha", "8" * 64)):
            changed = C.plain(self.review)
            changed[key][field] = value
            with self.assertRaises(C.Refused):
                C.decode_review(changed)
        with self.journal.exclusive():
            self.save()
            self.assertEqual(C.read_review(self.journal), (self.review, self.pp))
            with self.assertRaises(C.Refused):
                self.save()

    def test_full_install_and_reverse_with_ordered_native_lifecycle_hooks(self):
        with self.journal.exclusive():
            self.save()
            approved = self.approve()
            result = self.coordinator.apply(self.journal, approved, C.tx.APPLY)
            self.assertEqual(result["phase"], "installed")
            self.assertEqual(result["id"], self.review["id"])
            self.assertEqual(self.coordinator.rollback(
                self.journal, approved, C.tx.ROLLBACK)["phase"], "rolled_back")
        stage_events = [e for e in self.events if e[0] in C.tx.STAGES]
        self.assertEqual(stage_events, [(n, "install") for n in C.tx.STAGES] +
                         [(n, "rollback") for n in reversed(C.tx.STAGES)])
        trigger = ("udev", ("trigger", "--action=change", "--settle", self.d.baseline.sysfs))
        self.assertLess(self.events.index(("device", "install")), self.events.index(trigger))
        self.assertLess(self.events.index(("udev_rule", "install")), self.events.index(trigger))
        self.assertLess(self.events.index(trigger), self.events.index(("activation", "install")))
        self.assertLess(self.events.index(("unit", "rollback")),
                        self.events.index(("systemctl", ("daemon-reload",))))
        self.assertLess(self.events.index(("udev_rule", "rollback")),
                        self.events.index(("udev", ("settle", "--timeout=30"))))
        self.assertLess(self.events.index(("udev", ("settle", "--timeout=30"))),
                        self.events.index(("device", "rollback")))

    def test_refuse_unapproved_or_tampered_bundle_before_mutation(self):
        with self.journal.exclusive():
            self.save()
            with self.assertRaisesRegex(C.Refused, "apply_not_approved"):
                self.coordinator.apply(self.journal, "0" * 64, C.tx.APPLY)
            fd = os.open(C.POLICY_PACKAGE, os.O_WRONLY | os.O_TRUNC, dir_fd=self.fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(b"modified")
            with self.assertRaisesRegex(C.Refused, "artifact_changed"):
                self.coordinator.apply(self.journal, self.approve(), C.tx.APPLY)
        self.assertEqual(self.events, [])

    def test_rule_must_be_removed_before_device_rollback(self):
        self.files.stages["udev_rule"].installed = True
        self.device.installed = True
        with self.assertRaisesRegex(C.Refused, "rule_still_present"):
            self.coordinator.mutate("device", "rollback")
        self.assertEqual(self.events, [])

    def test_failed_udev_trigger_cannot_start_broker(self):
        self.device.installed = True
        self.coordinator.udev = Mock(side_effect=C.Refused("udev_failed"))
        with self.assertRaisesRegex(C.Refused, "udev_failed"):
            self.coordinator.mutate("activation", "install")
        self.assertFalse(self.activation.installed)

    def test_partial_bundle_not_accepted_or_overwritten(self):
        with self.journal.exclusive():
            C.write_fixed(self.journal, C.POLICY_PACKAGE, self.pp, C.policy.MAX_ARTIFACT)
            with self.assertRaises(OSError):
                C.read_review(self.journal)
            with self.assertRaises(C.Refused):
                self.save()

    def test_guard_refuses_reboot_and_identity_change(self):
        inspector = Mock()
        inspector.platform.return_value = self.boot
        exclusive = Mock()
        snapshot = Mock()
        snapshot.approval_digest.return_value = self.review["identity"]
        with patch.object(C.identity, "read_primary_snapshot", return_value=snapshot):
            C.native_guard(self.review, exclusive, inspector)
            inspector.postfix_evidence.assert_called_once()
            inspector.platform.return_value = "different boot"
            with self.assertRaisesRegex(C.Refused, "boot_or_identity_changed"):
                C.native_guard(self.review, exclusive, inspector)
            inspector.platform.return_value = self.boot
            snapshot.approval_digest.return_value = "b" * 64
            with self.assertRaisesRegex(C.Refused, "boot_or_identity_changed"):
                C.native_guard(self.review, exclusive, inspector)


if __name__ == "__main__":
    unittest.main()
