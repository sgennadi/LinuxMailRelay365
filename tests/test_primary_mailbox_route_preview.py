import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("primary_preview",str(ROOT/"linux/preview-primary-mailbox-route.py"))
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class PrimaryMailboxRouteTests(unittest.TestCase):
    def values(self):
        v=dict.fromkeys(M.SETTINGS,"")
        v.update(config_directory="/etc/postfix",multi_instance_enable="no",default_transport="smtp",
                 relay_transport="relay",mydestination="localhost",m365xoauth2_destination_recipient_limit="")
        return v

    def test_request_and_scope(self):
        req=dict(mailbox="alerts@example.org",nonce="a"*64)
        self.assertEqual(M.parse(M.encode(req)),req)
        for bad in (dict(req,mailbox="a..b@example.org"),dict(req,nonce="wrong"),dict(req,port=2525),
                    dict(req,mailbox="a@"+"b"*250+".org")):
            with self.assertRaises(M.E.Refused):
                M.parse(M.encode(bad))
        values=self.values()
        result=M.classify(("a"*64,values,"",""))
        self.assertEqual(result["route"],"migration_candidate")
        self.assertEqual(result["local_classes"],"configured")
        values["transport_maps"]="hash:/etc/postfix/transport"
        self.assertEqual(M.classify(("a"*64,values,"",""))["route"],"review_required")
        values["multi_instance_enable"]="yes"
        self.assertEqual(M.classify(("a"*64,values,"",""))["scope"],"review_required")
        values["transport_maps"]=""
        self.assertEqual(M.classify(("a"*64,values,"",""))["route"],"review_required")

    def test_existing_transport(self):
        v=self.values()
        v.update(default_transport="m365xoauth2:",relay_transport="m365xoauth2:",
                 m365xoauth2_destination_recipient_limit="1")
        pipe="m365xoauth2 unix - n n - 2 pipe flags=q user=m365mailer argv=/usr/bin/python3 /usr/local/libexec/m365_xoauth2_transport.py --recipient $"+ "{recipient}"
        self.assertEqual(M.classify(("a"*64,v,pipe,""))["route"],"configured")
        self.assertEqual(M.classify(("a"*64,v,pipe,"smtp/unix/foo=bar"))["route"],"review_required")

    def test_read_only_and_changed_configuration(self):
        req=dict(mailbox="alerts@example.org",nonce="a"*64)
        raw=(b"mydestination = localhost\n",b"")
        sample=(M.E.digest(b"\0".join(raw)),self.values(),"","")
        with mock.patch.object(M,"config_bytes",return_value=raw), \
             mock.patch.object(M,"sample",return_value=sample), \
             mock.patch.object(M,"identity_status",return_value="absent"), \
             mock.patch.object(M,"command",return_value=mock.Mock(returncode=0,stdout=b"")) as cmd:
            result=M.inspect(req)
            self.assertFalse(result["apply_supported"] or result["changes"] or result["mail_sent"])
            self.assertEqual(result["queue"],"empty")
            self.assertEqual(result["version"],2)
            self.assertEqual(result["candidate_status"],"ready")
            self.assertRegex(result["plan_sha256"],r"^[a-f0-9]{64}$")
            self.assertEqual([c[0][0] for c in cmd.call_args_list],["systemctl","postqueue"])
        with mock.patch.object(M,"config_bytes",return_value=raw), \
             mock.patch.object(M,"sample",side_effect=[sample,("b"*64,*sample[1:])]), \
             mock.patch.object(M,"identity_status",return_value="absent"), \
             mock.patch.object(M,"command",return_value=mock.Mock(returncode=0,stdout=b"")):
            with self.assertRaisesRegex(M.E.Refused,"configuration_changed"):
                M.inspect(req)

    def test_exact_candidate_preserves_ingress_and_local_delivery(self):
        v=self.values()
        v["relayhost"]="[old.example.org]:2525"
        raw=(b"# original\ninet_interfaces = all\nmydestination = localhost,\n  example.org\n"
             b"smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination\n"
             b"relayhost = [old.example.org]:2525\ndefault_transport = smtp\n",
             b"smtp inet n - y - - smtpd\n  -o syslog_name=postfix/smtp\n")
        sample=(M.E.digest(b"\0".join(raw)),v,"","")
        candidate,changes=M.candidate_configs(raw,sample)
        self.assertIn(raw[0].split(b"relayhost")[0],candidate[0])
        self.assertTrue(candidate[1].startswith(raw[1]))
        self.assertIn(b"relayhost = \n",candidate[0])
        self.assertEqual(changes,[k for k,_ in M.ROUTE_CHANGES]+["master.cf:m365xoauth2"])
        e=M.candidate_evidence(raw,sample,"alerts@example.org","absent")
        self.assertEqual(e["candidate_status"],"ready")
        self.assertNotEqual(e["plan_sha256"],M.candidate_evidence(raw,sample,"other@example.org","absent")["plan_sha256"])
        self.assertNotEqual(e["plan_sha256"],M.candidate_evidence(raw,sample,"alerts@example.org","mailbox_matches")["plan_sha256"])

    def test_candidate_refuses_ambiguous_or_dependent_configuration(self):
        for main,master in (
            (b"relayhost = a\nrelayhost = b\n",b""),
            (b"relayhost =\n  [other.example.org]:25\n",b""),
            (b"myorigin = ${relayhost}\n",b""),
            (b"myorigin = ${relayhost?{example.org}}\n",b""),
            (b"myorigin = example.org\r\n",b""),
            (b"",b"m365xoauth2 inet n - n - - smtpd\n"),
        ):
            raw=(main,master)
            sample=(M.E.digest(b"\0".join(raw)),self.values(),"","")
            report=M.candidate_evidence(raw,sample,"alerts@example.org","absent")
            self.assertEqual(report["candidate_status"],"review_required")
            self.assertEqual(report["change_set"],[])
            self.assertEqual(report["plan_sha256"],"")

    def test_gui_model_selected_before_certificate_and_force_replace_separate(self):
        ui=(ROOT/"src/LinuxMailRelay365/MainForm.cs").read_text(encoding="utf-8")
        wizard=(ROOT/"src/LinuxMailRelay365/MainForm.DeliveryMiniWizard.cs").read_text(encoding="utf-8")
        self.assertIn("if(mailTransport.SelectedIndex==0) ShowOAuthMailboxChoice(page);",ui)
        self.assertIn("mailTransport.SelectedIndex == 0 && oauthSenderMode.SelectedIndex == 0;",wizard)
        self.assertIn("ShowPrimaryMailboxRoutePreviewAction(page",ui)
        self.assertIn("Never use Force Replace to switch the existing relay.",ui)


if __name__=="__main__":
    unittest.main()
