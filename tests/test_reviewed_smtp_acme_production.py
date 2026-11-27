import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import Mock,patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"linux"/(name+".py"))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
M=load("reviewed-smtp-acme-production")
R=load("review-smtp-acme-issuance")

class ProductionEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.req=dict(accepted_domain="example.org",certificate_name="relay.example.org",
                      provider="dns-cloudflare",environment="production",email="admin@example.org",
                      credentials_path="/etc/private/dns.ini")
        self.envelope=dict(request=self.req,confirm=M.CONFIRM,review_sha256="a"*64)
        self.reviewer=Mock()
        self.reviewer.normalize.side_effect=R.normalize
        self.reviewer.review.return_value=dict(local_preflight_passed=True,review_sha256="a"*64)
        self.runner=Mock(return_value=subprocess.CompletedProcess([],0))
        self.allocate=Mock(return_value=pathlib.Path("/var/lib/linuxmailrelay365/smtp-acme-evaluation/relay.example.org"))
        self.inspect=Mock(return_value=dict(certificate_sha256="b"*64,client_auth_eku="not_explicit",
                          local_sslclient="refused_or_unverified",local_chain_name_key_verified=True))
        self.observe=Mock(side_effect=[[],[]])
    def execute(self):
        return M.execute(self.envelope,reviewer=self.reviewer,runner=self.runner,allocate=self.allocate,
                         inspect=self.inspect,observe=self.observe,trusted=lambda p:p,identity=lambda p:(1,2))
    def test_production_evaluation_is_not_activation(self):
        result=self.execute()
        self.assertEqual(result["status"],"evaluation_complete")
        self.assertTrue(result["certificate_issued"])
        self.assertFalse(result["activation_supported"])
        self.assertFalse(result["postfix_modified"])
        self.assertFalse(result["exchange_acceptance_verified"])
        self.assertEqual(result["local_sslclient"],"refused_or_unverified")
        args=self.runner.call_args.args[0]
        self.assertIn(M.PRODUCTION,args)
        self.assertNotIn("--dry-run",args)
        self.assertIn("--no-directory-hooks",args)
        self.assertIn(str(self.allocate.return_value/"config"),args)
        self.assertNotIn("/var/lib/linuxmailrelay365/smtp-acme/config",args)
    def test_stale_review_and_existing_txt_never_reserve(self):
        self.reviewer.review.return_value["review_sha256"]="b"*64
        self.assertEqual(self.execute()["status"],"refused")
        self.reviewer.review.return_value["review_sha256"]="a"*64
        self.observe.side_effect=None
        self.observe.return_value=["existing"]
        self.assertEqual(self.execute()["status"],"existing_txt_requires_review")
        self.allocate.assert_not_called()
        self.runner.assert_not_called()
    def test_existing_evaluation_never_reissues(self):
        self.allocate.side_effect=FileExistsError()
        self.assertEqual(self.execute()["status"],"evaluation_exists")
        self.runner.assert_not_called()
    def test_staging_or_no_confirmation_refused(self):
        self.req["environment"]="staging"
        with self.assertRaises(ValueError): self.execute()
        self.req["environment"]="production"
        self.envelope["confirm"]="no"
        with self.assertRaises(ValueError): self.execute()
        self.allocate.assert_not_called()
    def test_uncertain_issuance_retains_state_and_observes_dns(self):
        self.runner.side_effect=subprocess.TimeoutExpired("certbot",600)
        result=self.execute()
        self.assertEqual(result["status"],"outcome_unverified")
        self.assertTrue(result["state_reserved"])
        self.assertFalse(result["certificate_issued"])
        self.assertEqual(result["txt_snapshot"]["status"],"unchanged")
    def test_certbot_success_without_valid_material_not_verified(self):
        self.inspect.side_effect=ValueError("invalid certificate")
        result=self.execute()
        self.assertEqual(result["status"],"issued_unverified")
        self.assertFalse(result["certificate_issued"])
        self.assertTrue(result["state_reserved"])
    def test_server_only_certificate_diagnosis_does_not_change_gate(self):
        checker=Mock()
        checker.resolve_ca_bundle.return_value="/trusted/ca"
        def openssl(*args):
            if "-purpose" in args:
                raise subprocess.CalledProcessError(2,"openssl")
            if "-fingerprint" in args:
                return ("sha256 Fingerprint="+":".join(["AB"]*32)+"\n").encode()
            if "-ext" in args:
                return b"X509v3 Extended Key Usage:\n    TLS Web Server Authentication\n"
            return b"same"
        checker.openssl.side_effect=openssl
        with patch.object(M,"lineage",return_value={"cert":"/cert","chain":"/chain","privkey":"/key"}):
            report=M.evaluate(pathlib.Path("/evaluation"),"relay.example.org",checker)
        self.assertTrue(report["local_chain_name_key_verified"])
        self.assertEqual(report["client_auth_eku"],"not_explicit")
        self.assertEqual(report["local_sslclient"],"refused_or_unverified")

    def test_inspect_retained_material_without_issuance(self):
        request={k:self.req[k] for k in ("accepted_domain","certificate_name")}
        with patch.object(M,"directory") as directory, patch.object(M,"command") as command, patch.object(M,"reserve") as reserve:
            result=M.inspect_existing(request,inspect=self.inspect)
            self.assertEqual(result["status"],"material_verified")
            self.assertTrue(result["local_chain_name_key_verified"])
            for flag in ("issuance_attempted","dns_modified","postfix_modified","activation_supported","exchange_acceptance_verified"):
                self.assertFalse(result[flag])
            self.inspect.assert_called_once_with(M.ROOT/"relay.example.org","relay.example.org")
            command.assert_not_called()
            reserve.assert_not_called()
            self.assertEqual(directory.call_count,3)

    def test_inspect_missing_unsafe_or_incomplete_evaluation(self):
        request={k:self.req[k] for k in ("accepted_domain","certificate_name")}
        with patch.object(M,"directory",side_effect=FileNotFoundError):
            self.assertEqual(M.inspect_existing(request,inspect=self.inspect)["status"],"not_found")
        with patch.object(M,"directory",side_effect=ValueError("unsafe directory")):
            self.assertEqual(M.inspect_existing(request,inspect=self.inspect)["status"],"unverified")
        self.inspect.assert_not_called()
        with patch.object(M,"directory"):
            self.inspect.side_effect=FileNotFoundError("missing certificate")
            self.assertEqual(M.inspect_existing(request,inspect=self.inspect)["status"],"unverified")
        with self.assertRaises(ValueError):
            M.inspect_existing(dict(request,certificate_name="../other"),inspect=self.inspect)
        with self.assertRaises(ValueError):
            M.inspect_existing(dict(request,credentials_path="/secret"),inspect=self.inspect)

    def test_read_only_inspection_gui_wiring(self):
        src=ROOT/"src/LinuxMailRelay365"
        self.assertIn('sys.argv[1:]==["--inspect"]',(ROOT/"linux/reviewed-smtp-acme-production.py").read_text())
        self.assertIn('review(payload, "inspect")',(src/"SmtpAcmeIssuanceReviewDialog.cs").read_text())
        self.assertIn('inspectExisting: true',(src/"MainForm.DeliveryMiniWizard.cs").read_text())
        self.assertIn('--inspect',(src/"EmbeddedAssets.cs").read_text())


class StagingReceiptTests(unittest.TestCase):
    def test_binding_changes_with_credentials_or_request(self):
        receipt=load("smtp-acme-staging-receipt")
        req=dict(accepted_domain="example.org",certificate_name="relay.example.org",provider="dns-cloudflare",
                 environment="staging",email="admin@example.org",credentials_path="/root/dns.ini")
        first=receipt.binding(req,(1,2))
        self.assertEqual(first,receipt.binding(dict(req,environment="production"),(1,2)))
        self.assertNotEqual(first,receipt.binding(req,(1,3)))
        self.assertNotEqual(first,receipt.binding(dict(req,email="other@example.org"),(1,2)))

    @unittest.skipUnless(__import__("os").geteuid()==0,"root-only receipt validation")
    def test_receipt_single_use_and_expiration(self):
        import tempfile
        receipt=load("smtp-acme-staging-receipt")
        req={"environment":"production","email":"admin@example.org"}
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/"receipt"
            token=receipt.issue(req,(1,2),path,lambda:100)
            with self.assertRaises(ValueError):
                receipt.consume(req,(1,3),token,path,lambda:101)
            with self.assertRaises(ValueError):
                receipt.consume(req,(1,2),token,path,lambda:1000)
            receipt.consume(req,(1,2),token,path,lambda:101)
            self.assertFalse(path.exists())
            with self.assertRaises(OSError):
                receipt.consume(req,(1,2),token,path,lambda:102)

    def test_production_entry_point_requires_receipt_and_gui_wiring(self):
        source=(ROOT/"linux/reviewed-smtp-acme-production.py").read_text()
        self.assertIn('load("smtp-acme-staging-receipt").consume(req,stamp,token)',source)
        self.assertIn("expected_identity=stamp",source)
        ui=(ROOT/"src/LinuxMailRelay365/SmtpAcmeIssuanceReviewDialog.cs").read_text()
        self.assertIn("staging_receipt = receipt",ui)
        self.assertIn("Issue production evaluation",ui)
        self.assertIn('await review(payload, "production")',ui)
        project=(ROOT/"src/LinuxMailRelay365/LinuxMailRelay365.csproj").read_text()
        self.assertIn("reviewed-smtp-acme-production.py",project)
        self.assertIn("smtp-acme-staging-receipt.py",project)

    def test_bundled_checker_and_review_resource(self):
        src=ROOT/"src/LinuxMailRelay365"
        assets=(src/"EmbeddedAssets.cs").read_text()
        block=assets.split("internal static string BuildSmtpAcmeStagingChallenge",1)[1].split("internal static string BuildSmtpAcmeDryRun",1)[0]
        self.assertIn('"review-smtp-acme-issuance.py"',block)
        self.assertNotIn('"reviewed-smtp-acme-issuance.py"',block)
        self.assertIn('"check-smtp-relay-certificate.py"',block)
        self.assertIn("check-smtp-relay-certificate.py",(src/"LinuxMailRelay365.csproj").read_text())
