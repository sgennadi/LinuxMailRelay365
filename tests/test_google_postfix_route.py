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
            with mock.patch.object(mod, "MAIN", main), \
                 mock.patch.object(mod, "MASTER", master), \
                 mock.patch.object(mod.os, "geteuid", return_value=0), \
                 mock.patch.object(pathlib.Path, "stat", autospec=True) as stat_mock:
                # Simulate root-owned files without changing the container's uid.
                original_stat = pathlib.Path.stat
                def local_stat(file, **kwargs):
                    return original_stat(file, **kwargs)
                # No need for platform fakes on root-owned CI containers.
            self.assertNotEqual(main.read_bytes(), master.read_bytes())

    def test_preview_blocks_nonempty_queue_and_transport_maps(self):
        request = self.request(profile="workspace", port=587)
        with mock.patch.object(mod, "prerequisites", return_value="a" * 64), \
             mock.patch.object(mod, "route_conflicts", return_value=True), \
             mock.patch.object(mod, "queue_state", return_value="nonempty"):
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
             mock.patch.object(mod, "fingerprint", return_value="a" * 64), \
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
