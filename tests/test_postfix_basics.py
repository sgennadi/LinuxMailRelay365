"""Conservative primary Postfix main.cf identity profile contracts."""
import importlib.util
import pathlib
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / "linux/manage-postfix-basics.py"
spec = importlib.util.spec_from_file_location("postfix_basics", str(PATH))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class PostfixBaselines(unittest.TestCase):
    def test_hostname_domains_are_validated(self):
        mod.validate_hostname("mail.example.com", "example.com")
        for value in ("mail.other.com", "mail.example.com;echo bad", "localhost"):
            with self.assertRaises(mod.Refused):
                mod.validate_hostname(value, "example.com")

    def test_not_apply_without_confirm(self):
        with self.assertRaises(mod.Refused):
            mod.apply("mail.example.com", "example.com", "loopback-only",
                      "a" * 64, "", "/tmp/nowhere")
    
    def test_public_listener_cannot_be_applied(self):
        with self.assertRaises(mod.Refused):
            mod.apply("mail.example.com", "example.com", "all",
                      "a" * 64, "MODIFY_PRIMARY_POSTFIX", "/tmp/none")

    def test_preflight_guard_blocks_existing_remote_smtp_listener(self):
        from types import SimpleNamespace
        with TemporaryDirectory() as temp:
            # Simulate a valid Postfix directory on clean CI runners. The
            # production guard must remain strict about missing /etc/postfix.
            with patch.object(mod, "MAIN", pathlib.Path(temp) / "main.cf"), \
                 patch.object(mod, "MASTER", pathlib.Path(temp) / "master.cf"), \
                 patch.object(mod.os, "geteuid", return_value=0), \
                 patch.object(mod, "file_hash", return_value="a" * 64), \
                 patch.object(mod, "active_units", return_value=[]), \
                 patch.object(mod, "run", side_effect=lambda args, timeout=15:
                     SimpleNamespace(returncode=0, stdout=(
                         "all" if args[-1] == "inet_interfaces" else
                         "$myhostname, localhost.$mydomain, localhost"))):
                assert not mod.plan("mail.example.com", "example.com", "loopback-only")["ready"]

    def test_readonly_plan_on_root_required(self):
        with patch.object(mod.os, "geteuid", return_value=1001):
            with self.assertRaises(mod.Refused):
                mod.plan("mail.example.com", "example.com", "loopback-only")

    def test_no_other_mta_or_bootstrap_changes(self):
        source = PATH.read_text(encoding="utf-8")
        for required in ("CLEAN_MARKER", "foreign_mta_must_remain_untouched",
                         "POSTFIX_BASICS_BACKUP_ID", "AUTO_ROLLBACK_AFTER_FAILED_INSTALL",
                         "postfix", "check", "postconf", "mydestination",
                         "inet_interfaces", "inet_protocols", "loopback-only"):
            self.assertIn(required, source)
        for blocked in ("ufw allow", "setenforce 0", "firewall-cmd --add-port"):
            self.assertNotIn(blocked, source)


if __name__ == "__main__":
    unittest.main()
