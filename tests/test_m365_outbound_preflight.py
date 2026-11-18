"""Connector/Direct Send readiness planning without deploying to Microsoft 365."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"linux"/"m365-outbound-mode-preflight.py"
sp=importlib.util.spec_from_file_location("outboundpreflight",str(FILE))
mod=importlib.util.module_from_spec(sp)
sp.loader.exec_module(mod)


class M365OutboundPlanningTests(unittest.TestCase):
    def test_direct_send_internal_only_no_delivery_claim(self):
        for port in (1024,2525,2529,46500,65535):
            plan=mod.plan("direct-send",port,"contoso-com.mail.protection.outlook.com",
                          ["contoso.com"])
            self.assertEqual(plan["RECIPIENT_SCOPE"],"internal_only")
            self.assertEqual(plan["MICROSOFT365_OUTBOUND_PORT"],"25")
            self.assertEqual(plan["SELECTED_LINUX_SMTP_PORT"],str(port))
            self.assertEqual(plan["OUTBOUND_DEPLOYED"],"no")
            self.assertEqual(plan["SMTP_DELIVERY_VERIFIED"],"no")
            self.assertEqual(plan["CHANGES_APPLIED"],"no")

    def test_connector_rejects_missing_compatible_identity(self):
        args=("connector",46500,"contoso-com.mail.protection.outlook.com",["contoso.com"])
        self.assertEqual(mod.plan(*args)["PLAN_READINESS"],"connector_identity_missing")
        with_private=mod.plan(*args, public_ip="192.168.50.20")
        self.assertEqual(with_private["PLAN_READINESS"],"connector_identity_missing")
        with_public=mod.plan(*args, public_ip="8.8.8.8")
        self.assertEqual(with_public["PLAN_READINESS"],
                         "tenant_connector_and_smtp_policy_unverified")
        self.assertEqual(with_public["EXCHANGE_CONNECTOR_EXISTS_AND_MATCHES"],
                         "not_verified")

    def test_unsafe_mx_domain_and_path_validation(self):
        for bad in ("localhost","evil.example.com","1.2.3.4",
                    "contoso-com.mail.protection.outlook.com.evil.net",
                    "192.168.2.10", "0.0.0.0"):
            self.assertFalse(mod.eop_mx_name(bad),bad)
        self.assertTrue(mod.eop_mx_name("contoso-com.mail.protection.outlook.com"))
        for bad in ("127.0.0.1","192.168.1.2","10.0.0.1","::1","not-an-ip"):
            self.assertFalse(mod.external_ipv4(bad))

    def test_cli_invalid_port_fails_without_network(self):
        for port in ("25","587","1023","65536","bad"):
            r=subprocess.run([sys.executable,str(FILE),"--mode","direct-send",
                "--smtp-port",port,"--mx-host","contoso-com.mail.protection.outlook.com",
                "--accepted-domain","contoso.com"],stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,universal_newlines=True,timeout=8)
            self.assertNotEqual(r.returncode,0)
        r=subprocess.run([sys.executable,str(FILE),"--mode","direct-send",
            "--smtp-port","46500","--mx-host","contoso-com.mail.protection.outlook.com",
            "--accepted-domain","contoso.com"],stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,universal_newlines=True,timeout=8)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("CHANGES_APPLIED=no",r.stdout)
        self.assertIn("MICROSOFT365_OUTBOUND_PORT=25",r.stdout)

    def test_no_deployment_or_mail_submission(self):
        source=FILE.read_text(encoding="utf-8")
        for banned in ("sendmail(", "smtp.mail(","smtp.rcpt(","smtp.login(",
                       "New-InboundConnector","Set-InboundConnector","postconf -e",
                       "setenforce 0","ufw allow ","DATA", "smtp.send_message("):
            if banned=="DATA": continue # only safety comments mention DATA
            self.assertNotIn(banned,source)
        self.assertIn("EXCHANGE_CONNECTOR_EXISTS_AND_MATCHES",source)
        self.assertIn("tenant_connector_and_smtp_policy_unverified",source)

if __name__=="__main__":
    unittest.main()
