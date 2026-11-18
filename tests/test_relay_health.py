"""Postfix local health and queue read-only signals, Python 3.6 compatible."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"linux"/"relay-health.py"
spec=importlib.util.spec_from_file_location("relayhealth",str(SCRIPT))
health=importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class RelayHealthTests(unittest.TestCase):
    def test_postqueue_json_lines_only_count_no_sender_addresses(self):
        payload=('{"queue_id":"INTERNAL","queue_name":"deferred","arrival_time":1000,'
                 '"sender":"hidden@example.com","recipients":[{"address":"secret@example.net"}]}\n'
                 '{"queue_id":"OTHER","queue_name":"active","arrival_time":900,'
                 '"sender":"private@example.net","recipients":[]}\n')
        metrics=health.queue_metrics(payload,now=1600)
        self.assertEqual(metrics,(2,1,11))
        self.assertIsNone(health.queue_metrics("private@example.com",now=1600))
        self.assertIsNone(health.queue_metrics('{"arrival_time":"not-number"}',now=1600))
        self.assertIsNone(health.queue_metrics('{"arrival_time":3000}',now=1600))

    def test_empty_queue_is_zero(self):
        self.assertEqual(health.queue_metrics("",now=1600),(0,0,0))
        self.assertIsNone(health.queue_metrics(None,now=1600))

    def test_alerts_are_redacted_and_local_not_m365_proof(self):
        with patch.object(health.Path,"is_file",return_value=True),\
             patch.object(health.Path,"read_text",return_value="2529\n"),\
             patch.object(health,"service",return_value="active"),\
             patch.object(health,"run",side_effect=lambda args,timeout=7: (
                "no\n" if "smtpd_sasl_auth_enable" in args else
                "may\n" if "smtpd_tls_security_level" in args else
                '{"queue_name":"deferred","arrival_time":900,"sender":"secret@example.com","recipients":[]}\\n'
             )),\
             patch.object(health.shutil,"disk_usage",return_value=type("Disk",(),{"free":1024**3*10})()),\
             patch.object(health,"sender_certificate",return_value=100):
            result=health.health(2529,max_deferred=1,max_age=5)
        self.assertEqual(result["HEALTH_STATUS"],"attention")
        self.assertIn("deferred_queue_threshold",result["HEALTH_ALERTS"])
        self.assertNotIn("secret@example.com",str(result))
        self.assertEqual(result["MICROSOFT365_DELIVERY_VERIFIED"],"no")

    def test_empty_without_installation_safe(self):
        with patch.object(health.Path,"is_file",return_value=False):
            report=health.health(46500)
        self.assertEqual(report["HEALTH_STATUS"],"not_installed")
        self.assertEqual(report["CHANGES_APPLIED"],"no")

    def test_custom_port_validation(self):
        for port in ("25","587","1023","65536","test"):
            r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port",port],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             universal_newlines=True,timeout=8)
            self.assertNotEqual(r.returncode,0)
        r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port","46500"],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         universal_newlines=True,timeout=8)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("CUSTOM_SMTP_PORT=46500",r.stdout)

    def test_source_security_contract(self):
        src=SCRIPT.read_text(encoding="utf-8")
        self.assertIn("postqueue",src)
        self.assertIn("MAX_QUEUE_OUTPUT",src)
        self.assertIn("MICROSOFT365_DELIVERY_VERIFIED",src)
        for forbidden in ("smtp.login(","sendmail(","postconf -e","systemctl restart ",
                          "semanage port -a","setenforce 0", "sender\":", "recipient_address="):
            self.assertNotIn(forbidden,src)

if __name__=="__main__":
    unittest.main()
