import importlib.util
import pathlib
import unittest

spec=importlib.util.spec_from_file_location("planner",str(pathlib.Path(__file__).resolve().parents[1]/"linux"/"plan-smtp-certificate-acme.py"))
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class AcmePlanTests(unittest.TestCase):
    def test_independent_name(self):
        p=M.plan(dict(accepted_domain="ariel.ac.il",certificate_name="relay.ariel.ac.il",provider="manual"))
        self.assertEqual(p["challenge"],"_acme-challenge.relay.ariel.ac.il")
        self.assertEqual(p["renewal_method"],"manual")
        self.assertFalse(p["issuance_supported"])
    def test_reject_invalid(self):
        for name in ("relay.evil-ariel.ac.il","*.ariel.ac.il","--bad.ariel.ac.il"):
            with self.assertRaises(ValueError):
                M.plan(dict(accepted_domain="ariel.ac.il",certificate_name=name,provider="manual"))

    def test_dns_answers_do_not_expose_values(self):
        header=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10\n"
        txt=header+'_acme-challenge.relay.example.org. 60 IN TXT "secret-value"\n'
        self.assertEqual(M.summarize_answer(txt,"TXT"),"answer_present")
        self.assertEqual(M.summarize_answer(txt,"CNAME"),"no_matching_answer")
        self.assertEqual(M.summarize_answer(header.replace("NOERROR","NXDOMAIN"),"TXT"),"nxdomain")
        self.assertEqual(M.summarize_answer(header.replace("NOERROR","SERVFAIL"),"TXT"),"dns_error")
        self.assertEqual(M.summarize_answer("malformed","TXT"),"unverified")

    def test_missing_tools_never_authorize_issuance(self):
        from unittest.mock import patch
        with patch.object(M.shutil,"which",return_value=None):
            report=M.inspect(dict(accepted_domain="example.org",
                certificate_name="relay.example.org",provider="dns-cloudflare"))
        self.assertFalse(report["certbot_executable_detected"])
        self.assertEqual(set(report["dns_observations"].values()),{"dig_missing"})
        for key in ("issuance_supported","accepted_domain_verified",
                    "ca_client_tls_verified","dns_ownership_verified",
                    "effective_caa_policy_verified","automatic_renewal_verified",
                    "dns_provider_credentials_verified"):
            self.assertFalse(report[key])

    def test_dns_query_is_bounded_and_read_only(self):
        from unittest.mock import patch
        import subprocess
        response=subprocess.CompletedProcess([],0,";; status: NOERROR,\n","")
        with patch.object(M.subprocess,"run",return_value=response) as run:
            self.assertEqual(M.query("/usr/bin/dig","relay.example.org","CAA"),"no_matching_answer")
        args,kwargs=run.call_args
        self.assertEqual(args[0][-2:],["relay.example.org.","CAA"])
        self.assertEqual(kwargs["timeout"],6)
        self.assertNotIn("shell",kwargs)

    def test_overlong_challenge_refused(self):
        domain=".".join(["a"*63,"b"*63,"c"*63,"d"*46])
        with self.assertRaises(ValueError):
            M.plan(dict(accepted_domain=domain,certificate_name=domain,provider="manual"))

    def test_gui_wires_embedded_planner_and_preserves_read_only_boundary(self):
        root=pathlib.Path(__file__).resolve().parents[1]/"src/LinuxMailRelay365"
        project=(root/"LinuxMailRelay365.csproj").read_text()
        main=(root/"MainForm.DeliveryMiniWizard.cs").read_text()
        dialog=(root/"SmtpAcmePlanDialog.cs").read_text()
        self.assertIn("../../linux/plan-smtp-certificate-acme.py",project)
        self.assertIn("EmbeddedAssets.SmtpAcmeInspectCommand",main)
        self.assertIn("SshRemote.ExecuteAsync",main)
        self.assertIn("accepted_domain = acceptedValue",dialog)
        self.assertIn("issuance_supported",dialog)
        self.assertIn("automatic_renewal_verified",dialog)
