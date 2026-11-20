"""Per-identity offline signer audit never sends mail or exposes secrets."""
import importlib.util
import hashlib
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "audit-oauth-identity-signing.py"
spec = importlib.util.spec_from_file_location("offline_signer_audit", str(SCRIPT))
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


class StubAuditor:
    MAX_MAP = 65536
    class Refused(Exception):
        pass
    raw = (b'smtp_login\tenvelope_from\tm365_mailbox\tidentity_config_path\n'
           b'app1\ta@example.org\ta@example.org\t'
           b'/etc/linuxmailrelay365/oauth-identities/a.json\n'
           b'app2\tb@example.org\tb@example.org\t'
           b'/etc/linuxmailrelay365/oauth-identities/b.json\n')
    def allowed_path(self, path):
        if path != "/etc/linuxmailrelay365/oauth-senders.tsv":
            raise self.Refused("invalid")
    def audit(self, path):
        return {"MAP_SHA256": hashlib.sha256(self.raw).hexdigest()}
    def secure_read(self, path, *args):
        return self.raw
    def parse_map(self, raw):
        return [("app1", "a@example.org", "a@example.org",
                 "/etc/linuxmailrelay365/oauth-identities/a.json"),
                ("app2", "b@example.org", "b@example.org",
                 "/etc/linuxmailrelay365/oauth-identities/b.json")]


class SignerAuditTests(unittest.TestCase):
    path = "/etc/linuxmailrelay365/oauth-senders.tsv"

    def test_success_without_network(self):
        paths = []
        result = script.audit(self.path, auditor=StubAuditor(),
                              runner=lambda p: paths.append(p) or True)
        self.assertEqual(result["IDENTITIES"], 2)
        self.assertEqual(result["VERIFIED"], 2)
        self.assertEqual(result["ALL_SIGNERS_VALID"], "yes")
        self.assertEqual(len(paths), 2)

    def test_missing_signer_does_not_report_success(self):
        result = script.audit(self.path, auditor=StubAuditor(),
                              runner=lambda p: p.endswith("/a.json"))
        self.assertEqual(result["VERIFIED"], 1)
        self.assertEqual(result["UNVERIFIED"], 1)
        self.assertEqual(result["ALL_SIGNERS_VALID"], "no")

    def test_changed_map_fails_closed(self):
        class Changed(StubAuditor):
            called = 0
            def secure_read(self, *args):
                self.called += 1
                return self.raw if self.called == 1 else self.raw + b'changed'
        with self.assertRaisesRegex(script.Refused, "changed"):
            script.audit(self.path, auditor=Changed(), runner=lambda p: True)

    def test_signer_runs_as_service_account_only(self):
        captured = []
        def fake(argv, **kwargs):
            captured.append((argv, kwargs))
            return SimpleNamespace(returncode=0)
        with patch.object(script.Path, "is_file", return_value=True):
            self.assertTrue(script.probe_as_m365mailer(
                "/etc/linuxmailrelay365/oauth-identities/a.json", runner=fake))
        args, kwargs = captured[0]
        self.assertEqual(args[1:4], ["-u", "m365mailer", "--"])
        self.assertEqual(args[-1], "--signing-check")
        self.assertNotIn("--recipient", args)
        self.assertNotIn("--token-check", args)
        self.assertNotIn("--smtp-auth-check", args)
        self.assertIs(kwargs["stdout"], script.subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], script.subprocess.DEVNULL)

    def test_root_requirements_and_statuses(self):
        with patch.object(script.os, "geteuid", return_value=0), \
             patch.object(script.pwd, "getpwnam",
                          return_value=SimpleNamespace(pw_uid=1001)), \
             patch.object(script, "audit", return_value={
                 "MAP_SHA256": "a" * 64, "IDENTITIES": 1, "VERIFIED": 1,
                 "UNVERIFIED": 0, "ALL_SIGNERS_VALID": "yes"
             }), patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            self.assertEqual(script.main(["--map-path", self.path]), 0)
            self.assertIn("OAUTH_SIGNING_MAIL_SENT=no", out.getvalue())
            self.assertIn("OAUTH_SIGNING_EXCHANGE_SENDAS=not_verified", out.getvalue())


if __name__ == "__main__":
    unittest.main()
