"""Offline tests for Google's guarded in-place Postfix upstream manager.

Never touches real /etc/postfix and never contacts Google.
"""
import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "linux" / "manage-google-relay.py"
SPEC = importlib.util.spec_from_file_location("lmr_google_route_manager", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class CommandResult:
    def __init__(self, returncode=0, stdout=b""):
        self.returncode = returncode
        self.stdout = stdout


class GooglePostfixRouteTests(unittest.TestCase):
    def request(self, **update):
        default = {
            "profile": "gmail", "port": 587, "operation": "preview",
            "expected_sha": "", "user": "", "secret": ""
        }
        default.update(update)
        return mod.config(default)

    def test_ports_and_no_incoming_port_2525(self):
        self.assertEqual(mod.EXPECTED["gmail"], ("smtp.gmail.com", (465, 587)))
        self.assertEqual(mod.EXPECTED["workspace"], (
            "smtp-relay.gmail.com", (25, 465, 587)))
        with self.assertRaises(ValueError):
            self.request(port=2525)
        with self.assertRaises(ValueError):
            self.request(profile="gmail", port=25)

    def test_provider_auth_and_input_validation(self):
        for option in [
            {"profile": "evil"},
            {"operation": "apply", "expected_sha": "x" * 64},
            {"operation": "apply", "expected_sha": "a" * 64},
            {"operation": "apply", "expected_sha": "a" * 64,
             "user": "mail@example.org", "secret": "secret\nleak"},
            {"profile": "workspace", "port": 587, "operation": "apply",
             "expected_sha": "a" * 64, "user": "mail@example.org", "secret": "secret"},
        ]:
            with self.subTest(option=str(option)[:90]):
                with self.assertRaises(ValueError):
                    self.request(**option)

    def test_config_fingerprint_tracks_exact_main_and_master(self):
        with tempfile.TemporaryDirectory() as folder:
            main = pathlib.Path(folder) / "main.cf"
            master = pathlib.Path(folder) / "master.cf"
            main.write_text("relayhost=[old.example]:587\n")
            master.write_text("smtp inet n - y - - smtpd\n")
            real_stat = pathlib.Path.stat
            def root_stat(file, *args, **kwargs):
                from types import SimpleNamespace
                original = real_stat(file, *args, **kwargs)
                return SimpleNamespace(st_uid=0, st_mode=original.st_mode)
            with mock.patch.object(mod, "MAIN", main), \
                 mock.patch.object(mod, "MASTER", master), \
                 mock.patch.object(pathlib.Path, "stat", autospec=True, side_effect=root_stat):
                before = mod.fingerprint()
                main.write_text("relayhost=[new.example]:465\n")
                after = mod.fingerprint()
            self.assertEqual(len(before), 64)
            self.assertNotEqual(before, after)

    def test_preview_blocks_nonempty_queue_and_transport_maps(self):
        request = self.request(profile="workspace", port=587)
        with mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "route_conflicts", return_value=True), \
             mock.patch.object(mod, "queue_state", return_value="nonempty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "postconf", side_effect=lambda name: {
                 "smtp_sasl_auth_enable": "yes",
                 "smtp_sasl_password_maps": "hash:/etc/postfix/sasl_passwd",
                 "smtp_tls_security_level": "encrypt"
             }.get(name, "")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                mod.preview(request)
        report = output.getvalue()
        self.assertIn("GOOGLE_ROUTE_APPLY_ALLOWED=no", report)
        self.assertIn("GOOGLE_ROUTE_CONFLICTING_MAPS=yes", report)
        self.assertIn("GOOGLE_ROUTE_QUEUE=nonempty", report)
        self.assertIn("GOOGLE_ROUTE_CONFIG_CHANGED=no", report)

    def test_rollback_attempted_after_any_database_mutation(self):
        request = self.request(
            operation="apply", expected_sha="a" * 64,
            user="mail@example.org", secret="APP-PASSWORD-TEST")
        backup_called = []
        with mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "fingerprint", return_value="a" * 64), \
             mock.patch.object(mod, "inbound_snapshot", return_value=(b"unchanged", ())), \
             mock.patch.object(mod.pathlib.Path, "is_file", return_value=True), \
             mock.patch.object(mod, "verified_backup", return_value="20261122T010101Z-abcdef123456"), \
             mock.patch.object(mod, "prepare_gmail_map", side_effect=RuntimeError("synthetic map failure")), \
             mock.patch.object(mod, "restore_backup",
                 side_effect=lambda backup: backup_called.append(backup) or True):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                with self.assertRaises(RuntimeError):
                    mod.apply(request)
        self.assertEqual(backup_called, ["20261122T010101Z-abcdef123456"])
        self.assertIn("GOOGLE_ROUTE_ROLLBACK=ok", output.getvalue())
        self.assertNotIn(request["secret"], output.getvalue())

    def test_outbound_master_overrides_are_distinct_from_inbound_submission(self):
        # SMTP clients (smtp/relay unix) can override main.cf independently
        # of any inbound SMTP listener or submission service.
        for line, expected in (
                (b"", False),
                (b"submission/inet/smtpd_tls_security_level = encrypt\n", False),
                (b"smtp/inet/smtpd_sasl_auth_enable = yes\n", False),
                (b"smtp/unix/smtp_tls_security_level = none\n", True),
                (b"smtp/unix/smtp_sasl_auth_enable = no\n", True),
                (b"relay/unix/smtp_tls_wrappermode = no\n", True),
                (b"smtp/unix/relayhost = [other.example]:25\n", True),
                (b"unexpected master.cf output\n", True)):
            with self.subTest(line=line), mock.patch.object(
                    mod, "run", return_value=CommandResult(stdout=line)) as invoke:
                self.assertEqual(mod.outbound_master_overrides(), expected)
                invoke.assert_called_once_with(["postconf", "-P"])
        with mock.patch.object(mod, "run",
                               return_value=CommandResult(returncode=1)):
            self.assertTrue(mod.outbound_master_overrides())

    def test_route_conflicts_block_tls_policy_and_fallback_routes(self):
        base = {
            "default_transport": "smtp",
            "smtp_tls_secure_cert_match": "nexthop, dot-nexthop",
        }
        def conflicts(overrides):
            values = dict(base, **overrides)
            with mock.patch.object(
                    mod, "postconf", side_effect=lambda name: values.get(name, "")), \
                 mock.patch.object(
                    mod, "run", return_value=CommandResult(stdout=b"")):
                return mod.route_conflicts()
        # The ordinary defaults MUST remain eligible; otherwise every
        # legitimate Postfix host is accidentally blocked by a parser bug.
        self.assertFalse(conflicts({}))
        self.assertFalse(conflicts({"smtp_tls_secure_cert_match": "nexthop"}))
        for key in ("transport_maps", "sender_dependent_relayhost_maps",
                    "sender_dependent_default_transport_maps",
                    "smtp_tls_policy_maps", "smtp_tls_per_site",
                    "smtp_fallback_relay"):
            with self.subTest(parameter=key):
                self.assertTrue(conflicts({key: "hash:/etc/postfix/custom"}))
        self.assertTrue(conflicts({"default_transport": "error"}))
        self.assertTrue(conflicts({"smtp_tls_secure_cert_match": "hostname"}))
        self.assertTrue(conflicts({"smtp_tls_secure_cert_match": ""}))

    def test_unsafe_tls_policy_blocks_preview_and_apply_before_backup(self):
        with mock.patch.object(mod, "postconf", side_effect=lambda name: {
                    "default_transport": "smtp",
                    "smtp_tls_secure_cert_match": "nexthop, dot-nexthop",
                    "smtp_tls_policy_maps": "hash:/etc/postfix/downgrade",
                    "smtp_sasl_auth_enable": "yes",
                    "smtp_tls_security_level": "may",
                }.get(name, "")), \
             mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "verified_backup") as backup:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                mod.preview(self.request())
            self.assertIn("GOOGLE_ROUTE_APPLY_ALLOWED=no", output.getvalue())
            self.assertIn("GOOGLE_ROUTE_CONFLICTING_MAPS=yes", output.getvalue())
            with self.assertRaises(RuntimeError):
                mod.apply(self.request(operation="apply", expected_sha="a" * 64,
                                       user="mail@example.org", secret="test"))
            backup.assert_not_called()

    def test_postfix_scope_refuses_secondary_instance(self):
        with mock.patch.object(mod, "postconf", side_effect=lambda key: {
            "config_directory": "/etc/postfix",
            "multi_instance_enable": "no",
            "multi_instance_directories": "",
        }[key]):
            self.assertEqual(mod.scope_status(), "verified")
        with mock.patch.object(mod, "postconf", side_effect=lambda key: {
            "config_directory": "/etc/postfix/secondary",
            "multi_instance_enable": "yes",
            "multi_instance_directories": "/etc/postfix/secondary",
        }[key]):
            self.assertEqual(mod.scope_status(), "unverified")

    def test_cyrus_client_sasl_checks_and_policy(self):
        def postconf(key):
            return {
                "smtp_sasl_type": "cyrus",
                "smtp_sasl_mechanism_filter": "",
            }[key]

        def mocked_run(args, **kwargs):
            if args == ["postconf", "-A"]:
                return CommandResult(stdout=b"cyrus\n")
            if args == ["/usr/bin/saslpluginviewer", "-c"]:
                return CommandResult(stdout=b"Mechanisms: PLAIN LOGIN\n")
            raise AssertionError("Unexpected command: " + repr(args))

        with mock.patch.object(mod, "postconf", side_effect=postconf), \
             mock.patch.object(mod, "run", side_effect=mocked_run), \
             mock.patch.object(mod.shutil, "which", return_value="/usr/bin/saslpluginviewer"):
            self.assertEqual(mod.client_sasl_status(), "ready")
        with mock.patch.object(mod, "postconf", side_effect=lambda key: {
            "smtp_sasl_type": "cyrus",
            "smtp_sasl_mechanism_filter": "XOAUTH2",
        }[key]), \
             mock.patch.object(mod, "run", side_effect=mocked_run), \
             mock.patch.object(mod.shutil, "which", return_value="/usr/bin/saslpluginviewer"):
            self.assertEqual(mod.client_sasl_status(), "missing")
        with mock.patch.object(mod, "postconf", side_effect=postconf), \
             mock.patch.object(mod, "run", side_effect=mocked_run), \
             mock.patch.object(mod.shutil, "which", return_value=None):
            self.assertEqual(mod.client_sasl_status(), "unverified")

    def test_gmail_apply_blocked_if_local_client_sasl_missing(self):
        request = self.request(operation="apply", expected_sha="a" * 64,
                               user="mail@example.org", secret="test")
        with mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="missing"), \
             mock.patch.object(mod, "verified_backup") as backup:
            with self.assertRaises(RuntimeError):
                mod.apply(request)
            backup.assert_not_called()

    def test_apply_rollback_when_local_mail_policy_changes(self):
        """A verified backup alone is insufficient if inbound settings drift."""
        profile = self.request(operation="apply", expected_sha="a" * 64,
                               user="mail@example.org", secret="one-use")
        reverted = []
        backup_id = "20261122T010101Z-abcdef123456"
        def configured(key):
            return {
                "relayhost": "[smtp.gmail.com]:587",
                "smtp_tls_security_level": "secure",
                "smtp_tls_wrappermode": "no",
                "smtp_sasl_auth_enable": "yes",
            }[key]
        with mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "route_conflicts", return_value=False), \
             mock.patch.object(mod, "queue_state", return_value="empty"), \
             mock.patch.object(mod, "scope_status", return_value="verified"), \
             mock.patch.object(mod, "client_sasl_status", return_value="ready"), \
             mock.patch.object(mod, "fingerprint", return_value="a" * 64), \
             mock.patch.object(mod, "inbound_snapshot", side_effect=[
                 (b"original", ("127.0.0.1",)),
                 (b"unexpected", ("0.0.0.0",))
             ]), \
             mock.patch.object(mod.pathlib.Path, "is_file", return_value=True), \
             mock.patch.object(mod, "verified_backup", return_value=backup_id), \
             mock.patch.object(mod, "prepare_gmail_map"), \
             mock.patch.object(mod, "require_gmail_password_map"), \
             mock.patch.object(mod, "update_postconf"), \
             mock.patch.object(mod, "postconf", side_effect=configured), \
             mock.patch.object(mod, "run", return_value=CommandResult()), \
             mock.patch.object(mod, "restore_backup",
                               side_effect=lambda bid: reverted.append(bid) or True):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(RuntimeError):
                    mod.apply(profile)
        self.assertEqual(reverted, [backup_id])
        self.assertIn("GOOGLE_ROUTE_ROLLBACK=ok", stdout.getvalue())
        self.assertNotIn(profile["secret"], stdout.getvalue())

    def test_google_password_map_requires_root_only_and_never_prints_value(self):
        from types import SimpleNamespace

        class FakeMap:
            def __init__(self, mode):
                self.mode = mode
            def is_file(self):
                return True
            def is_symlink(self):
                return False
            def stat(self):
                return SimpleNamespace(st_uid=0, st_mode=self.mode)

        fake_password_result = CommandResult(
            stdout=b"ci@example.invalid:NONREAL-DUMMY-SECRET")
        output = io.StringIO()
        with mock.patch.object(mod, "MAP", FakeMap(0o100600)), \
             mock.patch.object(mod, "run", return_value=fake_password_result) as lookup, \
             contextlib.redirect_stdout(output):
            mod.require_gmail_password_map(587)
        self.assertEqual(output.getvalue(), "")
        lookup.assert_called_once_with([
            "postmap", "-q", "[smtp.gmail.com]:587",
            "hash:/etc/postfix/lmr365-google-sasl"])
        with mock.patch.object(mod, "MAP", FakeMap(0o100640)), \
             mock.patch.object(mod, "run") as lookup:
            with self.assertRaises(RuntimeError):
                mod.require_gmail_password_map(587)
            lookup.assert_not_called()

    def test_unavailable_postfix_capabilities_never_approve_apply(self):
        with mock.patch.object(mod, "postconf", side_effect=RuntimeError("unavailable")):
            self.assertEqual(mod.scope_status(), "unverified")
            self.assertEqual(mod.client_sasl_status(), "unverified")

    def test_reject_stale_sha_before_any_backup(self):
        request = self.request(
            profile="workspace", port=587, operation="apply",
            expected_sha="a" * 64)
        with mock.patch.object(mod, "prerequisites", return_value="b" * 64), \
             mock.patch.object(mod, "verified_backup") as backup:
            with self.assertRaises(RuntimeError):
                mod.apply(request)
            backup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
