"""Linux mail-host discovery regression: systemd inactive is not an error."""
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux" / "inspect-mail-host.py"
spec = importlib.util.spec_from_file_location("inspect_mail_host", str(SOURCE))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MailHostInspectorTests(unittest.TestCase):
    def test_systemctl_inactive_nonzero_exit_is_valid_status(self):
        def process(argv, **kwargs):
            return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
        with patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"), \
             patch.object(module.subprocess, "run", side_effect=process):
            self.assertEqual(module.call(["systemctl", "is-active", "exim.service"]), "inactive")
            self.assertFalse(module.service_state("exim.service"))
            self.assertIsNone(module.call(["postconf", "-h", "myhostname"]))

    def test_missing_unit_status_and_failed_service(self):
        def process(argv, **kwargs):
            return SimpleNamespace(returncode=4, stdout="unknown\n", stderr="")
        with patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"), \
             patch.object(module.subprocess, "run", side_effect=process):
            self.assertFalse(module.service_state("sendmail.service"))
        self.assertIsNone(module.service_state("postfix.service",
                                            lambda _: "failed"))

    def test_multiple_active_mta_is_not_automatically_selected(self):
        def fake(argv):
            name = argv[-1]
            return "active" if name in ("postfix.service", "exim.service") else "inactive"
        self.assertEqual(module.mta_status(fake), ("unknown", "manual_review"))


if __name__ == "__main__":
    unittest.main()
