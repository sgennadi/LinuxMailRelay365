"""SELinux Enforcing read-only acceptance test (Python 3.6 supported)."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"linux"/"rhel-selinux-doctor.py"
spec=importlib.util.spec_from_file_location("rhel_selinux_doctor",str(SCRIPT))
doctor=importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


class RhelSelinuxDoctorTests(unittest.TestCase):
    def test_os_release_id_does_not_execute_data(self):
        for distro in ("rhel", "ol", "rocky", "almalinux", "centos"):
            self.assertEqual(doctor.os_family('ID="'+distro+'"\nVERSION_ID="9.5"\n'),
                             "rhel_family")
        self.assertEqual(doctor.os_family("ID=ubuntu\n"),"debian_family")
        self.assertEqual(doctor.os_family("ID=debian\n"),"debian_family")
        self.assertEqual(doctor.os_family("ID=unknown\n"),"unknown")
        self.assertEqual(doctor.os_family('ID="$(touch /tmp/pwned)"\n'),"unknown")

    def test_custom_port_selinux_labels(self):
        rules="smtp_port_t tcp 25, 465, 587, 2525-2527\nhttp_port_t tcp 80,443, 8443\n"
        self.assertEqual(doctor.port_label(2525,rules),"smtp_port_t")
        self.assertEqual(doctor.port_label(2526,rules),"smtp_port_t")
        self.assertEqual(doctor.port_label(2530,rules),"unmapped")
        self.assertEqual(doctor.port_label(8443,rules),"other_label")
        self.assertEqual(doctor.port_label(46500,None),"unknown")
        defaults = ("reserved_port_t tcp 1-1023\n"
                    "unreserved_port_t tcp 1024-65535\n")
        self.assertEqual(doctor.port_label(25, rules + defaults +
                         "smtp_port_t tcp 25\n"), "smtp_port_t")
        self.assertEqual(doctor.port_label(2525, rules + defaults), "smtp_port_t")
        self.assertEqual(doctor.port_label(46500, rules + defaults), "unmapped")
        self.assertEqual(doctor.port_label(2525, rules + defaults +
                         "http_port_t tcp 2525\n"), "other_label")

    def test_file_context_hints_never_claim_policy_access(self):
        ctx=b"system_u:object_r:postfix_spool_t:s0\x00"
        with patch.object(doctor.os,"getxattr",return_value=ctx),\
             patch.object(doctor.Path,"lstat",return_value=type("Stat",(),{"st_mode":0o100600})()):
            self.assertEqual(doctor.file_label(Path("/tmp/mock")),"present_not_policy_verified")
        with patch.object(doctor.os,"getxattr",return_value=b"system_u:object_r:default_t:s0"),\
             patch.object(doctor.Path,"lstat",return_value=type("Stat",(),{"st_mode":0o100600})()):
            self.assertEqual(doctor.file_label(Path("/tmp/mock")),"bad_default_type")

    def test_enforcing_report_is_always_manual_not_auto_approved(self):
        for mode in ("enforcing","permissive","unknown"):
            with self.subTest(mode=mode),\
                 patch.object(doctor,"OS_RELEASE",new=type("MockRelease",(),{
                     "read_text":lambda *args,**kwargs:"ID=ol\nVERSION_ID=10.1\n"})()),\
                 patch.object(doctor,"selinux_mode",return_value=mode),\
                 patch.object(doctor,"run",return_value="smtp_port_t tcp 2525, 46500\n"),\
                 patch.object(doctor,"file_label",return_value="present_not_policy_verified"),\
                 patch.object(doctor,"unit_state",return_value="active"),\
                 patch.object(doctor,"process_context_state",return_value="both_processes_seen_context_not_verified"):
                report=doctor.audit(46500)
                self.assertEqual(report["SELINUX_AVC_POLICY_ACCESS"],"not_verified")
                self.assertEqual(report["SMTP_AUTH_ENFORCING_TESTED"],"no")
                self.assertEqual(report["CHANGES_APPLIED"],"no")
                self.assertNotIn("ready",report["SELINUX_ACCEPTANCE_STATUS"])
                if mode!="enforcing":
                    self.assertEqual(report["SELINUX_ACCEPTANCE_STATUS"],
                                     "enforcing_mode_required_for_acceptance")

    def test_invalid_ports_fail_without_system_change(self):
        for port in ("25","587","1023","65536","xyz"):
            r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port",port],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             universal_newlines=True,timeout=5)
            self.assertNotEqual(r.returncode,0)
        r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port","46500"],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         universal_newlines=True,timeout=8)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("CUSTOM_SMTP_PORT=46500",r.stdout)
        self.assertIn("CHANGES_APPLIED=no",r.stdout)
        self.assertIn("SMTP_AUTH_ENFORCING_TESTED=no",r.stdout)

if __name__=="__main__":
    unittest.main()
