"""Existing Sendmail/Exim must be preserved: no package/service changes."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "mta-coexistence-doctor.py"
spec = importlib.util.spec_from_file_location("lmr_mta_coexist", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def audit(primary, with_postfix, with_sidecar=False):
    orig = mod.SIDECAR_CONF
    active = {"postfix": primary == "postfix", "exim": primary == "exim",
              "sendmail": primary == "sendmail"}
    return mod.audit(46500, services=active,
                     binaries={"postfix": with_postfix, "exim": True, "sendmail": True},
                     paths={"postfix": with_postfix, "exim": True, "sendmail": True},
                     runner=lambda *a, **k: "")


class MultiMtaContracts(unittest.TestCase):
    def test_candidate_requires_preexisting_postfix_for_exim_sendmail(self):
        for name in ("exim", "sendmail"):
            r = audit(name, False)
            self.assertEqual(r["MULTI_MTA_READINESS"],
                             "postfix_not_preinstalled_package_mutation_blocked")
            r = audit(name, True)
            self.assertEqual(r["MULTI_MTA_READINESS"],
                             "preinstalled_postfix_guarded_fixed_sender_candidate")
            self.assertEqual(r["MTA_PACKAGE_INSTALL_ALLOWED"], "no")
            self.assertEqual(r["FOREIGN_MTA_FIXED_SENDER_GUARD"],
                             "available_requires_root_live_verification")
            self.assertEqual(r["PRIMARY_MTA_STOP_OR_RESTART"], "no")

    def test_unknown_or_multiple_mta_fail_closed(self):
        r = mod.audit(46500, services={"postfix": True, "exim": True, "sendmail": False},
                      binaries={"postfix": True}, paths={"postfix": True},
                      runner=lambda *a, **k: "")
        self.assertEqual(r["ACTIVE_PRIMARY_MTA"], "multiple_active_mta")
        r = mod.audit(46500, services={"postfix": None, "exim": False, "sendmail": False},
                      binaries={"postfix": True}, paths={"postfix": True},
                      runner=lambda *a, **k: "")
        self.assertEqual(r["ACTIVE_PRIMARY_MTA"], "unknown_service_state")
        self.assertEqual(r["MULTI_MTA_READINESS"], "active_mta_unknown_manual_review")

    def test_cli_python_36_and_readonly(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for port in ("25", "0", "65536", "bad"):
            x = subprocess.run([sys.executable, str(SCRIPT), "--smtp-port", port],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=8)
            self.assertNotEqual(x.returncode, 0)
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("systemctl stop ", "systemctl restart ", "apt-get install",
                          "dnf install", "setenforce 0", "postconf -e",
                          "subprocess.Popen('", "mail from:", "smtp.login("):
            self.assertNotIn(forbidden, source)
        self.assertIn("CHANGES_APPLIED", source)
        self.assertIn("primary_postfix_preserve_sidecar_candidate", source)


if __name__ == "__main__":
    unittest.main()
