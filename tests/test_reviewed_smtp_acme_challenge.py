import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import Mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"linux"/(name+".py"))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
M=load("reviewed-smtp-acme-challenge")
R=load("review-smtp-acme-issuance")

class ReviewedChallengeTests(unittest.TestCase):
    def setUp(self):
        self.req=dict(accepted_domain="example.org",certificate_name="relay.example.org",
                      provider="dns-cloudflare",environment="staging",email="admin@example.org",
                      credentials_path="/etc/private/dns.ini")
        self.sha="a"*64
        self.envelope={"request":self.req,"confirm":M.CONFIRM,"review_sha256":self.sha}
        self.reviewer=Mock()
        self.reviewer.normalize.side_effect=R.normalize
        self.reviewer.review.return_value={"local_preflight_passed":True,"review_sha256":self.sha}
        self.runner=Mock(return_value=subprocess.CompletedProcess([],0))
        self.identity=Mock(return_value=(1,2))
        self.observe=Mock(side_effect=[[],[]])

    def execute(self):
        return M.execute(self.envelope,self.reviewer,self.observe,self.runner,self.identity,
                         trusted=lambda p:p)

    def test_success_is_staging_only_and_cleanup_is_observation(self):
        report=self.execute()
        self.assertEqual(report["status"],"passed")
        self.assertTrue(report["dns_challenge_verified"])
        self.assertFalse(report["txt_cleanup_verified"])
        self.assertEqual(report["txt_snapshot"]["status"],"unchanged")
        args=self.runner.call_args.args[0]
        self.assertIn(M.STAGING,args)
        self.assertIn("--dry-run",args)
        self.assertIn("--no-directory-hooks",args)
        self.assertEqual(args[args.index("--config")+1],"/dev/null")
        self.assertNotIn("/var/lib/linuxmailrelay365/smtp-acme/config",args)
        self.assertFalse(report["production_certificate_modified"])
        self.assertFalse(report["postfix_modified"])

    def test_production_and_missing_confirmation_never_run(self):
        self.req["environment"]="production"
        with self.assertRaises(ValueError):
            self.execute()
        self.req["environment"]="staging"
        self.envelope["confirm"]="no"
        with self.assertRaises(ValueError):
            self.execute()
        self.runner.assert_not_called()

    def test_stale_review_and_credential_change_refuse(self):
        self.reviewer.review.return_value["review_sha256"]="b"*64
        self.assertEqual(self.execute()["status"],"refused")
        self.reviewer.review.return_value["review_sha256"]=self.sha
        self.identity.side_effect=[(1,2),(1,3)]
        self.assertEqual(self.execute()["status"],"refused")
        self.runner.assert_not_called()

    def test_unavailable_or_existing_txt_never_run(self):
        self.observe.side_effect=None
        for values,status in ((None,"baseline_unverified"),(["existing"],"existing_txt_requires_review")):
            self.observe.return_value=values
            self.assertEqual(self.execute()["status"],status)
        self.runner.assert_not_called()

    def test_failed_and_timed_out_attempt_still_observes_dns(self):
        self.runner.return_value=subprocess.CompletedProcess([],1)
        self.observe.side_effect=[[],["synthetic-secret"]]
        report=self.execute()
        self.assertEqual(report["status"],"failed")
        self.assertEqual(report["txt_snapshot"]["added_count"],1)
        self.assertNotIn("synthetic-secret",str(report))
        self.runner.side_effect=subprocess.TimeoutExpired("certbot",600)
        self.observe.side_effect=[[],None]
        report=self.execute()
        self.assertEqual(report["status"],"outcome_unverified")
        self.assertTrue(report["attempted"])
        self.assertEqual(report["txt_snapshot"]["status"],"unverified")

    def test_dns_parser_refuses_alias_and_foreign_owner(self):
        owner="_acme-challenge.relay.example.org"
        header=b";; status: NOERROR,\n"
        self.assertEqual(M.parse_snapshot(header,owner,"TXT"),[])
        self.assertEqual(M.parse_snapshot(header+(owner+'. 60 IN TXT "token"\n').encode(),owner,"TXT"),['"token"'])
        for data in (b";; status: SERVFAIL,\n",header+b"other.example.org. 60 IN TXT x\n",
                     header+(owner+". 60 IN CNAME other.example.org.\n").encode()):
            with self.assertRaises(ValueError):
                M.parse_snapshot(data,owner,"TXT")

    def test_review_digest_binds_contact_and_path(self):
        check=Mock(return_value={"file_preflight_passed":True,"api_permissions_verified":False})
        probe=Mock(return_value={"status":"completed","providers":{"dns-cloudflare":{"registered":True}}})
        first=R.review(self.req,check,probe)["review_sha256"]
        for key,value in (("email","other@example.org"),("credentials_path","/etc/private/other.ini")):
            self.assertNotEqual(first,R.review(dict(self.req,**{key:value}),check,probe)["review_sha256"])

    def test_gui_explicit_confirmation_and_embedded_helpers(self):
        src=ROOT/"src/LinuxMailRelay365"
        ui=(src/"SmtpAcmeIssuanceReviewDialog.cs").read_text()
        self.assertIn("MessageBoxDefaultButton.Button2",ui)
        self.assertIn('ready && target == "staging"',ui)
        self.assertIn("TEST_PUBLIC_DNS_CHALLENGE",ui)
        self.assertIn("BuildSmtpAcmeStagingChallenge", (src/"MainForm.DeliveryMiniWizard.cs").read_text())
        project=(src/"LinuxMailRelay365.csproj").read_text()
        for name in ("reviewed-smtp-acme-challenge.py","plan-smtp-acme-challenge-test.py","check-smtp-acme-txt-cleanup.py",
                     "issue-smtp-acme-azure.py","issue-smtp-acme-cloudflare.py","issue-smtp-acme-route53.py",
                     "issue-smtp-acme-google.py","issue-smtp-acme-rfc2136.py"):
            self.assertIn("../../linux/"+name,project)
