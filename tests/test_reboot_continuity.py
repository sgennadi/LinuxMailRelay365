"""Reboot continuity: no restart command can fake a real kernel boot ID."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"linux"/"verify-reboot-continuity.py"
sp=importlib.util.spec_from_file_location("rebootacceptance",str(FILE))
mod=importlib.util.module_from_spec(sp)
sp.loader.exec_module(mod)


class RebootContinuityTests(unittest.TestCase):
    def test_requires_changed_boot_id(self):
        baseline=dict(version=1,port=46500,boot_id="first",auth=True,
                      primary_main_sha256="a",primary_master_sha256="b",
                      sidecar_main_sha256="c",sidecar_master_sha256="d")
        self.assertEqual(mod.compare(baseline,dict(baseline)),"no_actual_reboot_detected")
        modified=dict(baseline);modified["boot_id"]="second"
        self.assertEqual(mod.compare(baseline,modified),
                         "local_services_continuity_verified")
        modified["auth"]=False
        self.assertEqual(mod.compare(baseline,modified),
                         "configuration_or_service_mode_changed")

    def test_mismatched_port_not_accepted(self):
        a={"version":1,"port":2525}
        self.assertEqual(mod.compare(a,{"version":1,"port":2529}),
                         "invalid_or_mismatched_baseline")

    def test_invalid_custom_port_refused(self):
        for port in ("25","587","1023","65536","invalid"):
            r=subprocess.run([sys.executable,str(FILE),"--verify-after-reboot",
                              "--smtp-port",port],stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,universal_newlines=True,timeout=8)
            self.assertNotEqual(r.returncode,0)

    def test_never_automatically_reboots_or_sends_mail(self):
        source=FILE.read_text(encoding="utf-8")
        for bad in ("systemctl reboot","shutdown -r","sendmail(",
                    "smtp.login(","semanage port -a","setenforce 0","ufw allow"):
            self.assertNotIn(bad,source)
        self.assertIn("baseline_recorded_requires_real_reboot",source)
        self.assertIn("local_services_continuity_verified",source)
        self.assertIn("REBOOT_MICROSOFT365_DELIVERY_VERIFIED=no",source)

if __name__=="__main__":
    unittest.main()
