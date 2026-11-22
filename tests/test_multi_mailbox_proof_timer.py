"""Isolated safety tests for the optional Multi-mailbox ingress-proof timer.

No real systemd, root writes, mail service control, TPM or network access.
"""
import contextlib
import importlib.util
import io
import json
import os
import time
import shutil
import subprocess
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "manage-multi-mailbox-proof-timer.py"
SPEC = importlib.util.spec_from_file_location("lmr365_optional_proof_timer", str(SOURCE))
timer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timer)


class OptionalProofTimerTests(unittest.TestCase):
    def test_ci_compiles_timed_proof_entrypoints_before_runtime_execution(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        kvm = (ROOT / ".github/workflows/rocky-enforcing-vm.yml").read_text(
            encoding="utf-8")
        required = (
            "linux/manage-multi-mailbox-proof-timer.py",
            "linux/refresh-multi-mailbox-proof.py",
            "linux/audit-oauth-ingress.py",
            "linux/audit-oauth-sender-map.py",
        )
        for name in required:
            self.assertIn(name, ci)
            self.assertIn(name, kvm)
        self.assertLess(ci.index("python3 -m py_compile linux/manage-multi-mailbox-proof-timer.py"),
                        ci.index("python3 -m unittest discover -v -s tests"))
        self.assertLess(kvm.index("Fail fast on experimental proof-timer source syntax"),
                        kvm.index("Inspect kernel KVM and perform real KVM ioctl"))

    def test_pinned_oneshot_is_local_only_and_not_an_smtp_sender(self):
        sha = "a" * 64
        unit = timer.service_text(sha).decode("ascii")
        schedule = timer.timer_text().decode("ascii")
        self.assertIn("--map-sha256 " + sha, unit)
        self.assertIn("--confirm REFRESH_PRIVILEGED_MULTI_INGRESS_PROOF", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("PrivateNetwork=yes", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        self.assertIn("ReadWritePaths=/etc/linuxmailrelay365", unit)
        self.assertIn("OnUnitActiveSec=60s", schedule)
        self.assertIn("OnBootSec=45s", schedule)
        self.assertIn("Persistent=false", schedule)
        for forbidden in ("ExecStart=/bin/sh", "smtp.office365.com",
                          "postfix.service", "dovecot.service", "curl ",
                          "wget ", "SMTP_DATA", "sendmail "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, unit + schedule)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd analyzer unavailable")
    def test_generated_service_and_timer_pass_native_systemd_verify(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            service = folder / "linuxmailrelay365-multi-proof.service"
            clock = folder / "linuxmailrelay365-multi-proof.timer"
            service.write_bytes(timer.service_text("a" * 64))
            clock.write_bytes(timer.timer_text())
            result = subprocess.run(
                ["systemd-analyze", "verify", str(service), str(clock)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
                universal_newlines=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[:2000])

    def test_systemctl_requires_pinned_loaded_unit_for_every_status(self):
        from subprocess import CompletedProcess
        cases = (
            (("is-active", "--quiet", timer.TIMER.name),
             "ActiveState", "active", "inactive", str(timer.TIMER)),
            (("is-active", "--quiet", timer.SERVICE.name),
             "ActiveState", "active", "inactive", str(timer.SERVICE)),
            (("is-enabled", "--quiet", timer.TIMER.name),
             "UnitFileState", "enabled", "disabled", str(timer.TIMER)),
        )
        with mock.patch.object(Path, "is_file", return_value=True):
            for args, prop, positive, negative, fragment in cases:
                for return_code, required, expected_result in (
                        (0, positive, True), (3, negative, False)):
                    with self.subTest(args=args, code=return_code):
                        values = {prop: required, "LoadState": "loaded",
                                  "FragmentPath": fragment,
                                  "NeedDaemonReload": "no"}
                        def respond(command, **kwargs):
                            if command[1] != "show":
                                return CompletedProcess(command, return_code, stdout="")
                            key = command[2].split("=", 1)[1]
                            return CompletedProcess(
                                command, 0, stdout=values[key] + "\n")
                        with mock.patch.object(timer.subprocess, "run",
                                               side_effect=respond) as run:
                            self.assertIs(
                                timer.systemctl(*args, allow_inactive=True),
                                expected_result)
                            self.assertEqual(run.call_count, 5)

                        # Unknown systemd states, stale fragments and missing
                        # units must be rejected even when quiet returns 0.
                        for key, bad in (
                                (prop, "failed"), (prop, "not-found"),
                                (prop, "masked"), (prop, "activating"),
                                (prop, ""), (prop, required + "\nactive"),
                                ("LoadState", "not-found"),
                                ("LoadState", "masked"),
                                ("FragmentPath",
                                 "/run/systemd/transient/foreign.service"),
                                ("FragmentPath", ""),
                                ("NeedDaemonReload", "yes"),
                                ("NeedDaemonReload", "")):
                            with self.subTest(key=key, bad=bad):
                                old = values[key]
                                values[key] = bad
                                with mock.patch.object(timer.subprocess, "run",
                                                       side_effect=respond):
                                    with self.assertRaisesRegex(
                                            timer.Refused, "unverifiable_systemd"):
                                        timer.systemctl(*args, allow_inactive=True)
                                values[key] = old

    def test_systemctl_refuses_positive_unknown_unit_or_inconsistent_query(self):
        from subprocess import CompletedProcess
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch.object(timer.subprocess, "run",
                                   return_value=CompletedProcess(
                                       ["systemctl"], 0, stdout="")):
                with self.assertRaisesRegex(
                        timer.Refused, "unsupported_systemd_status_probe"):
                    timer.systemctl("is-active", "--quiet", "other.service",
                                    allow_inactive=True)
            def false_properties(command, **kwargs):
                if command[1] != "show":
                    return CompletedProcess(command, 0, stdout="")
                return CompletedProcess(command, 1, stdout="active\n")
            with mock.patch.object(timer.subprocess, "run",
                                   side_effect=false_properties):
                with self.assertRaisesRegex(
                        timer.Refused, "unverifiable_systemd_unit_state"):
                    timer.systemctl("is-active", "--quiet", timer.TIMER.name,
                                    allow_inactive=True)
            def contradictory(command, **kwargs):
                if command[1] != "show":
                    return CompletedProcess(command, 0, stdout="")
                return CompletedProcess(command, 0, stdout="inactive\n")
            with mock.patch.object(timer.subprocess, "run",
                                   side_effect=contradictory):
                with self.assertRaisesRegex(
                        timer.Refused, "unverifiable_systemd_unit_state"):
                    timer.systemctl("is-active", "--quiet", timer.TIMER.name,
                                    allow_inactive=True)

    def test_nonzero_status_requires_explicit_opt_in(self):
        from subprocess import CompletedProcess
        with mock.patch.object(Path, "is_file", return_value=True), \
             mock.patch.object(timer.subprocess, "run",
                 return_value=CompletedProcess(["systemctl"], 3, stdout="")) as run:
            with self.assertRaisesRegex(timer.Refused, "systemd_command_refused"):
                timer.systemctl("is-active", "--quiet", timer.TIMER.name)
            self.assertEqual(run.call_count, 1)

    def test_only_exact_lowercase_sha_can_be_embedded(self):
        for invalid in ("", "A" * 64, "a" * 63, "a" * 65,
                        "a" * 64 + "\nExecStart=/bin/sh", None, 123, []):
            with self.subTest(invalid=repr(invalid)), \
                 self.assertRaises(timer.Refused):
                timer.service_text(invalid)

    def test_nonroot_refuses_every_mode(self):
        with mock.patch.object(timer.os, "geteuid", return_value=1001), \
             mock.patch.object(timer, "plan") as plan, \
             mock.patch.object(timer, "locked") as locked:
            for mode in ("--plan", "--enable-reviewed", "--disable-reviewed",
                         "--status"):
                with self.subTest(mode=mode):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(timer.main([mode]), 2)
            plan.assert_not_called()
            locked.assert_not_called()

    def test_write_modes_need_typed_approval_before_any_mutation(self):
        with mock.patch.object(timer.os, "geteuid", return_value=0), \
             mock.patch.object(timer, "locked") as locked:
            for args in (
                ["--enable-reviewed", "--approve-sha256", "b" * 64],
                ["--enable-reviewed", "--approve-sha256", "b" * 64,
                 "--confirm", "WRONG"],
                ["--disable-reviewed", "--confirm", "WRONG"],
                ["--disable-reviewed", "--approve-sha256", "b" * 64,
                 "--confirm", timer.REVOCATION]):
                with self.subTest(args=args):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(timer.main(args), 2)
            locked.assert_not_called()

    def test_preview_is_deterministic_and_refuses_existing_or_symlinked_files(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(timer, "attest",
                               return_value=("a" * 64, "b" * 64)), \
             mock.patch.object(timer, "parents"):
            parent = Path(td)
            paths = [mock.patch.object(timer, "SERVICE", parent / "proof.service"),
                     mock.patch.object(timer, "TIMER", parent / "proof.timer"),
                     mock.patch.object(timer, "STATE", parent / "state.json"),
                     mock.patch.object(timer, "STATE_ROOT", parent / "state")]
            with contextlib.ExitStack() as stack:
                for p in paths:
                    stack.enter_context(p)
                plan1 = timer.plan()
                self.assertEqual(len(plan1[0]), 64)
                self.assertEqual(plan1, timer.plan())
                (parent / "proof.timer").symlink_to(parent / "not-existing")
                with self.assertRaisesRegex(timer.Refused, "timer_already_present"):
                    timer.plan()

    def test_read_refuses_symlinks_and_writable_files_before_data_read(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(timer, "parents"):
            parent = Path(td)
            source = parent / "file"
            source.write_bytes(b"no sensitive data\n")
            source.chmod(0o600)
            (parent / "link").symlink_to(source)
            with self.assertRaises(timer.Refused):
                timer.read(parent / "link", 32, (0o600,))
            source.chmod(0o666)
            with self.assertRaises(timer.Refused):
                timer.read(source, 32, (0o600,))
            source.chmod(0o600)
            os.link(str(source), str(parent / "hardlink"))
            with self.assertRaises(timer.Refused):
                timer.read(source, 32, (0o600,))

    def test_preview_does_not_generate_bytecode_cache_in_installed_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            code = ("import time\n"
                    "def inspect(sha):\n"
                    "    return {'map_sha256': sha, 'expires_at': int(time.time()) + 120,\n"
                    "            'ingress': 'root_static_audit_consistent_not_live_delivery'}\n"
                    ).encode("ascii")
            filename = root / "refresh-multi-mailbox-proof.py"
            filename.write_bytes(code)
            sender = b"example map"
            config = b"example config"
            sha = timer.digest(sender)
            marker = {"runtime_map_sha256": sha,
                      "active": {"main.cf": timer.digest(config),
                                 "master.cf": timer.digest(config)},
                      "source": {"refresh-multi-mailbox-proof.py": timer.digest(code)}}
            def read(path, maximum, modes, gid=None):
                if path == timer.ACTIVE:
                    return json.dumps(marker).encode("ascii")
                if path == timer.MAP:
                    return sender
                if path in (timer.CONF / "main.cf", timer.CONF / "master.cf"):
                    return config
                if path == root / "refresh-multi-mailbox-proof.py":
                    return code
                raise AssertionError("unexpected local file read")
            with mock.patch.object(timer, "ROOT", root), \
                 mock.patch.object(timer.os, "geteuid", return_value=0), \
                 mock.patch.object(timer.grp, "getgrnam",
                                   return_value=SimpleNamespace(gr_gid=1234)), \
                 mock.patch.object(timer, "read", side_effect=read):
                value, active_hash = timer.attest()
                self.assertEqual(value, sha)
                self.assertEqual(len(active_hash), 64)
                self.assertFalse((root / "__pycache__").exists())
                changed = (
                    "def inspect(sha):\n"
                    "    raise RuntimeError('SECRET_INTERNAL_FILE_PATH_NEVER_LEAK')\n"
                ).encode("ascii")
                filename.write_bytes(changed)
                marker["source"]["refresh-multi-mailbox-proof.py"] = timer.digest(changed)
                code = changed
                with self.assertRaisesRegex(
                        timer.Refused, "installed_ingress_audit_refused") as caught:
                    timer.attest()
                self.assertNotIn("SECRET_INTERNAL_FILE_PATH_NEVER_LEAK",
                                 str(caught.exception))
                self.assertFalse((root / "__pycache__").exists())

    def test_protected_json_rejects_duplicate_keys_and_nonfinite_values(self):
        bad_records = (
            b'{"version":1,"version":2}',
            b'{"outer":{"map":"one","map":"two"}}',
            b'{"version":NaN}',
            b'{"version":Infinity}',
            b'{"version":-Infinity}',
        )
        for value in bad_records:
            with self.subTest(value=value), self.assertRaises(timer.Refused):
                timer.record(value)
        self.assertEqual(timer.record(b'{"version":1}')["version"], 1)

    def test_installed_timer_refuses_boolean_version_even_if_true_equals_one(self):
        state = {"version": True, "plan": "a" * 64, "map": "b" * 64,
                 "service": timer.digest(timer.service_text("b" * 64)),
                 "timer": timer.digest(timer.timer_text())}
        with mock.patch.object(timer, "read",
                               side_effect=lambda *args, **kwargs:
                               json.dumps(state).encode("ascii")):
            with self.assertRaisesRegex(timer.Refused, "invalid_installed_timer"):
                timer.installed()

    def test_receipt_status_distinguishes_fresh_expired_drift_and_missing(self):
        map_bytes = b"test-only sender map\n"
        pinned = timer.digest(map_bytes)
        receipt = {
            "version": 1, "map_sha256": pinned, "issued_at": 1000,
            "expires_at": 1120, "mailboxes": 1,
            "main_meta": [], "master_meta": [],
            "ingress": "root_static_audit_consistent_not_live_delivery",
        }
        def reader(path, maximum, modes, gid=None):
            if path == timer.PROOF:
                return json.dumps(receipt).encode("ascii")
            if path == timer.MAP:
                return map_bytes
            raise AssertionError("unexpected protected file")
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(timer.grp, "getgrnam",
                               return_value=SimpleNamespace(gr_gid=4242)), \
             mock.patch.object(timer, "read", side_effect=reader):
            self.assertEqual(timer.receipt_age_status(pinned, now=1000),
                             "fresh_ttl_only")
            self.assertEqual(timer.receipt_age_status(pinned, now=1119),
                             "fresh_ttl_only")
            self.assertEqual(timer.receipt_age_status(pinned, now=1120),
                             "expired")
            self.assertEqual(timer.receipt_age_status("b" * 64, now=1000),
                             "map_changed")
            with mock.patch.object(timer, "read",
                                   side_effect=lambda path, maximum, modes, gid=None:
                                   json.dumps(receipt).encode("ascii")
                                   if path == timer.PROOF else b"modified map"):
                self.assertEqual(timer.receipt_age_status(pinned, now=1000),
                                 "map_changed")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(timer, "PROOF", Path(td) / "missing"):
            self.assertEqual(timer.receipt_age_status(pinned), "missing")

    def test_receipt_status_rejects_invalid_age_and_boolean_timestamp(self):
        map_bytes = b"test-only-map-for-time-validation"
        pinned = timer.digest(map_bytes)
        data = {"version": 1, "map_sha256": pinned,
                "issued_at": 1010, "expires_at": 1130,
                "mailboxes": 1, "main_meta": [], "master_meta": [],
                "ingress": "root_static_audit_consistent_not_live_delivery"}
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(timer.grp, "getgrnam",
                               return_value=SimpleNamespace(gr_gid=4242)), \
             mock.patch.object(timer, "read",
                               side_effect=lambda path, *args, **kwargs:
                               json.dumps(data).encode("ascii")
                               if path == timer.PROOF else map_bytes):
            with self.assertRaisesRegex(timer.Refused, "receipt_from_future"):
                timer.receipt_age_status(pinned, now=1000)
            data["issued_at"] = True
            with self.assertRaisesRegex(timer.Refused, "invalid_receipt_status_metadata"):
                timer.receipt_age_status(pinned, now=1000)
            data["issued_at"] = 1010
            data["expires_at"] = 1010 + 3600
            with self.assertRaisesRegex(timer.Refused, "invalid_receipt_status_metadata"):
                timer.receipt_age_status(pinned, now=1000)

    def test_status_without_timer_reports_not_installed(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(timer.os, "geteuid", return_value=0):
            root = Path(td)
            patches = [mock.patch.object(timer, "SERVICE", root / "service"),
                       mock.patch.object(timer, "TIMER", root / "timer"),
                       mock.patch.object(timer, "STATE", root / "state.json"),
                       mock.patch.object(timer, "STATE_ROOT", root / "private")]
            with contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                report = io.StringIO()
                with contextlib.redirect_stdout(report):
                    self.assertEqual(timer.main(["--status"]), 0)
                self.assertIn("MULTI_PROOF_TIMER=not_installed", report.getvalue())
                self.assertIn("MULTI_PROOF_RECEIPT=not_applicable", report.getvalue())

    def test_installed_state_and_exact_unit_bytes_must_agree(self):
        data = {"version": 1, "plan": "a" * 64, "map": "b" * 64,
                "service": timer.digest(timer.service_text("b" * 64)),
                "timer": timer.digest(timer.timer_text())}
        def reader(path, maximum, modes, gid=None):
            if path == timer.STATE:
                return json.dumps(data).encode("ascii")
            if path == timer.SERVICE:
                return timer.service_text("b" * 64)
            if path == timer.TIMER:
                return timer.timer_text()
            raise AssertionError("unexpected file")
        with mock.patch.object(timer, "read", side_effect=reader):
            self.assertEqual(timer.installed()["map"], "b" * 64)
            data["service"] = "0" * 64
            with self.assertRaisesRegex(timer.Refused, "unit_record_changed"):
                timer.installed()

    def test_stale_approval_does_not_make_any_changes(self):
        with mock.patch.object(timer, "plan", return_value=(
                "f" * 64, {}, b"service", b"timer")), \
             mock.patch.object(timer, "parents") as parents:
            with self.assertRaisesRegex(timer.Refused, "approval_stale"):
                timer.enable("a" * 64)
            parents.assert_not_called()

    def test_partial_install_failure_removes_only_verified_own_unit(self):
        approved = "e" * 64
        evidence = {"map": "a" * 64, "service": "b" * 64, "timer": "c" * 64}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            service = root / "service"
            timerpath = root / "timer"
            state_dir = root / "private"
            state = state_dir / "state.json"
            def create(path, data, mode):
                if path == timerpath:
                    raise timer.Refused("injected_timer_write_failure")
                path.write_bytes(data)
            def systemctl(*args, **kwargs):
                return False if args and args[0] in ("is-active", "is-enabled") else True
            with mock.patch.object(timer, "SERVICE", service), \
                 mock.patch.object(timer, "TIMER", timerpath), \
                 mock.patch.object(timer, "STATE_ROOT", state_dir), \
                 mock.patch.object(timer, "STATE", state), \
                 mock.patch.object(timer, "plan", return_value=(
                     approved, evidence, b"own-service", b"own-timer")), \
                 mock.patch.object(timer, "parents"), \
                 mock.patch.object(timer, "create_file", side_effect=create), \
                 mock.patch.object(timer, "read",
                     side_effect=lambda path, *args: path.read_bytes()), \
                 mock.patch.object(timer, "systemctl", side_effect=systemctl) as ctl:
                with self.assertRaisesRegex(timer.Refused, "injected_timer_write_failure"):
                    timer.enable(approved)
                self.assertFalse(service.exists())
                self.assertFalse(timerpath.exists())
                self.assertFalse(state_dir.exists())
                self.assertTrue(any(c.args[0] == "disable" for c in ctl.call_args_list))

    def test_failed_first_refresh_revokes_any_issued_receipt(self):
        approved = "e" * 64
        values = {"map": "a" * 64, "service": "b" * 64, "timer": "c" * 64}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            service, timerpath = root / "service", root / "timer"
            private = root / "private"
            state = private / "state.json"
            def create(path, data, mode):
                path.write_bytes(data)
            def systemctl(*args, **kwargs):
                if args[0] == "start":
                    raise timer.Refused("simulated_first_audit_failure")
                return False if args[0] in ("is-active", "is-enabled") else True
            with mock.patch.object(timer, "SERVICE", service), \
                 mock.patch.object(timer, "TIMER", timerpath), \
                 mock.patch.object(timer, "STATE_ROOT", private), \
                 mock.patch.object(timer, "STATE", state), \
                 mock.patch.object(timer, "parents"), \
                 mock.patch.object(timer, "plan", return_value=(
                     approved, values, b"known-service", b"known-timer")), \
                 mock.patch.object(timer, "create_file", side_effect=create), \
                 mock.patch.object(timer, "read",
                     side_effect=lambda path, *args: path.read_bytes()), \
                 mock.patch.object(timer, "systemctl", side_effect=systemctl), \
                 mock.patch.object(timer, "revoke") as revoked:
                with self.assertRaisesRegex(timer.Refused, "simulated_first_audit_failure"):
                    timer.enable(approved)
                revoked.assert_called_once_with("a" * 64)
                self.assertFalse(service.exists())
                self.assertFalse(timerpath.exists())
                self.assertFalse(private.exists())

    def test_changed_unit_blocks_unsafe_rollback_and_requires_review(self):
        approved = "e" * 64
        evidence = {"map": "a" * 64, "service": "b" * 64, "timer": "c" * 64}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            service, timerpath = root / "service", root / "timer"
            state_dir = root / "private"
            def create(path, data, mode):
                if path == timerpath:
                    raise timer.Refused("injected_failure")
                path.write_bytes(b"changed_after_create")
            def systemctl(*args, **kwargs):
                return False if args and args[0] in ("is-active", "is-enabled") else True
            with mock.patch.object(timer, "SERVICE", service), \
                 mock.patch.object(timer, "TIMER", timerpath), \
                 mock.patch.object(timer, "STATE_ROOT", state_dir), \
                 mock.patch.object(timer, "STATE", state_dir / "state.json"), \
                 mock.patch.object(timer, "plan", return_value=(
                     approved, evidence, b"own-service", b"own-timer")), \
                 mock.patch.object(timer, "parents"), \
                 mock.patch.object(timer, "create_file", side_effect=create), \
                 mock.patch.object(timer, "read",
                     side_effect=lambda path, *args: path.read_bytes()), \
                 mock.patch.object(timer, "systemctl", side_effect=systemctl):
                report = io.StringIO()
                with contextlib.redirect_stderr(report):
                    with self.assertRaisesRegex(timer.Refused, "injected_failure"):
                        timer.enable(approved)
                self.assertTrue(service.exists())
                self.assertIn("manual_review_required", report.getvalue())

    def test_disable_rejects_enabled_timer_even_if_inactive(self):
        def status(*args, **kwargs):
            if args[0] == "is-active":
                return False
            if args[0] == "is-enabled":
                return True
            return True
        with mock.patch.object(timer, "installed",
                               return_value={"map": "a" * 64}), \
             mock.patch.object(timer, "systemctl", side_effect=status), \
             mock.patch.object(timer, "revoke") as revoke:
            with self.assertRaisesRegex(timer.Refused, "still_active_or_enabled"):
                timer.disable()
            revoke.assert_not_called()

    def test_disable_refuses_running_worker_without_revoking_receipt(self):
        def status(*args, **kwargs):
            if args[0] == "is-active" and args[-1] == timer.SERVICE.name:
                return True
            return False if args[0] in ("is-active", "is-enabled") else True
        with mock.patch.object(timer, "installed",
                               return_value={"map": "a" * 64}), \
             mock.patch.object(timer, "systemctl", side_effect=status), \
             mock.patch.object(timer, "revoke") as revoke:
            with self.assertRaisesRegex(timer.Refused, "still_active_or_enabled"):
                timer.disable()
            revoke.assert_not_called()

    def test_disable_first_stops_timer_then_revokes_proof_and_removes_known_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            service = root / "service"
            timerpath = root / "timer"
            state_dir = root / "private"
            state_dir.mkdir()
            state = state_dir / "state.json"
            for path in (service, timerpath, state):
                path.write_bytes(b"owned-record")
            def systemctl(*args, **kwargs):
                return False if args and args[0] in ("is-active", "is-enabled") else True
            with mock.patch.object(timer, "SERVICE", service), \
                 mock.patch.object(timer, "TIMER", timerpath), \
                 mock.patch.object(timer, "STATE", state), \
                 mock.patch.object(timer, "STATE_ROOT", state_dir), \
                 mock.patch.object(timer, "installed",
                                   return_value={"map": "a" * 64}), \
                 mock.patch.object(timer, "read",
                     side_effect=lambda path, *args: path.read_bytes()), \
                 mock.patch.object(timer, "systemctl", side_effect=systemctl) as ctl, \
                 mock.patch.object(timer, "revoke") as revoke:
                self.assertTrue(timer.disable())
                revoke.assert_called_once_with("a" * 64)
                self.assertFalse(service.exists())
                self.assertFalse(timerpath.exists())
                self.assertFalse(state_dir.exists())
                self.assertEqual(ctl.call_args_list[0].args[0], "disable")
                self.assertEqual(ctl.call_args_list[1].args[0], "stop")

    def test_timer_uses_shared_multi_route_lock(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('LOCK = Path("/run/linuxmailrelay365-sidecar-auth.lock")', source)
        restore = (ROOT / "linux/restore-multi-mailbox-postfix.py").read_text(
            encoding="utf-8")
        self.assertIn("multi_ingress_timer_must_be_disabled_before_restore", restore)
        self.assertIn("require_proof_timer_absent()", restore)

    def test_windows_stage_contains_manager_but_not_autostart(self):
        embedded = (ROOT / "src/LinuxMailRelay365/EmbeddedAssets.cs").read_text()
        project = (ROOT / "src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text()
        installer = (ROOT / "linux/manage-multi-mailbox-postfix.py").read_text()
        self.assertIn('("manage-multi-mailbox-proof-timer.py", MultiMailboxProofTimer)', embedded)
        self.assertIn("LinuxMailRelay365.linux.multi-mailbox-proof-timer.py", project)
        self.assertIn('"manage-multi-mailbox-proof-timer.py"', installer)
        self.assertNotIn("systemctl start", embedded)
        self.assertNotIn("systemctl enable", embedded)


if __name__ == "__main__":
    unittest.main()
