"""Systemd health timer does not modify primary MTA or open firewall."""
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"linux"/"install-health-monitor.sh"


class HealthTimerTests(unittest.TestCase):
    def run_command(self,*args):
        return subprocess.run(["bash",str(FILE)]+list(args),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              universal_newlines=True,timeout=8)

    def test_shell_and_self_test(self):
        p=subprocess.run(["bash","-n",str(FILE)],stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,universal_newlines=True,timeout=8)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(self.run_command("--self-test").returncode,0)

    def test_only_custom_port_1024_to_65535(self):
        for port in ("587","1023","65536","bad"):
            r=self.run_command("--check-only","--smtp-port",port)
            self.assertIn("HEALTH_TIMER_ERROR=invalid_custom_port",r.stderr)
        for port in ("25","1024","2525","2529","46500","65535"):
            r=self.run_command("--check-only","--smtp-port",port)
            self.assertNotIn("invalid_custom_port",r.stderr)

    def test_apply_requires_confirmation(self):
        result=self.run_command("--install","--smtp-port","46500")
        self.assertIn("HEALTH_TIMER_ERROR=confirmation_required",result.stderr)

    def test_15min_timer_and_no_public_smtp(self):
        code=FILE.read_text(encoding="utf-8")
        for required in ("OnUnitActiveSec=15min", "HEALTH_TIMER_ALERT_CHANNEL=local_journald_only",
                         "HEALTH_TIMER_ROLLBACK=attempted", "systemctl daemon-reload",
                         "HEALTH_TIMER_CUSTOM_PORT=", "CHANGES_APPLIED=no",
                         "ENABLE_PRIVATE_SMTP_MONITOR","PrivateTmp=true"):
            self.assertIn(required,code)
        for unsafe in ("systemctl restart postfix", "systemctl stop postfix",
                       "postconf -e", "ufw allow", "semanage port -a", "setenforce 0"):
            self.assertNotIn(unsafe,code)

if __name__=="__main__":
    unittest.main()
