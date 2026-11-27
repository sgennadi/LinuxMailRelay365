import importlib.util
import pathlib
import unittest
from unittest.mock import Mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("review",ROOT/"linux/review-smtp-acme-issuance.py")
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class IssuanceReviewTests(unittest.TestCase):
    def setUp(self):
        self.request=dict(accepted_domain="example.org",certificate_name="relay.example.org",
                          provider="dns-cloudflare",environment="staging",email="admin@example.org",
                          credentials_path="/etc/private/dns.ini")
        self.check=Mock(return_value={"file_preflight_passed":True,"api_permissions_verified":False})
        self.probe=Mock(return_value={"status":"completed","providers":{"dns-cloudflare":{"registered":True}}})

    def review(self):
        return M.review(self.request,self.check,self.probe)

    def test_ready_is_never_issuance_approval(self):
        result=self.review()
        self.assertTrue(result["local_preflight_passed"])
        self.assertEqual(result["ca_directory"],M.SERVERS["staging"])
        self.assertFalse(result["issuance_supported"])
        self.assertFalse(result["api_permissions_verified"])
        self.assertFalse(result["dns_modified"])
        self.assertNotIn(self.request["credentials_path"],str(result))
        self.assertNotIn(self.request["email"],str(result))

    def test_production_is_preview_only(self):
        self.request["environment"]="production"
        result=self.review()
        self.assertEqual(result["ca_directory"],M.SERVERS["production"])
        self.assertFalse(result["certificate_issued"])
        self.assertFalse(result["postfix_modified"])

    def test_sensitive_parser_exception_not_exported(self):
        self.check.side_effect=ValueError("synthetic secret value")
        result=self.review()
        self.assertEqual(result["credential_file"],"refused")
        self.assertFalse(result["local_preflight_passed"])
        self.assertNotIn("synthetic secret",str(result))

    def test_plugin_unavailable_is_not_ready(self):
        self.probe.return_value={"status":"probe_failed"}
        self.assertEqual(self.review()["plugin"],"unverified")
        self.assertFalse(self.review()["local_preflight_passed"])

    def test_bad_inputs_refused_before_checks(self):
        original=self.request.copy()
        for key,value in (("certificate_name","evil.example.net"),("provider","manual"),
                          ("environment","custom"),("credentials_path","/etc/../root/file"),
                          ("credentials_path","relative"),("credentials_path","/etc/file\n"),
                          ("email","bad email")):
            self.request=dict(original,**{key:value})
            with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                self.review()
        self.check.assert_not_called()
        self.probe.assert_not_called()

    def test_gui_and_resource_wiring(self):
        src=ROOT/"src/LinuxMailRelay365"
        self.assertIn("BuildSmtpAcmeIssuanceReview", (src/"MainForm.DeliveryMiniWizard.cs").read_text())
        self.assertIn("review-smtp-acme-issuance.py", (src/"LinuxMailRelay365.csproj").read_text())
        self.assertIn("new SmtpAcmeIssuanceReviewDialog", (src/"SmtpAcmePlanDialog.cs").read_text())
        self.assertIn("staging", (src/"SmtpAcmeIssuanceReviewDialog.cs").read_text())
