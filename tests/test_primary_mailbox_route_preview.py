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
             mock.patch.object(M,"identity_snapshot",return_value=("absent","","")), \
             mock.patch.object(M,"native_candidate_validation",return_value=("verified","e"*64)), \
             mock.patch.object(M,"command",return_value=mock.Mock(returncode=0,stdout=b"")) as cmd:
            result=M.inspect(req)
            self.assertFalse(result["apply_supported"] or result["changes"] or result["mail_sent"])
            self.assertEqual(result["queue"],"empty")
            self.assertEqual(result["version"],3)
            self.assertEqual(result["native_validation"],"verified")
            self.assertEqual(result["native_sha256"],"e"*64)
            self.assertEqual(result["candidate_status"],"ready")
            self.assertRegex(result["plan_sha256"],r"^[a-f0-9]{64}$")
            self.assertEqual([c[0][0] for c in cmd.call_args_list],["systemctl","postqueue"])
        with mock.patch.object(M,"config_bytes",return_value=raw), \
             mock.patch.object(M,"sample",side_effect=[sample,("b"*64,*sample[1:])]), \
             mock.patch.object(M,"identity_snapshot",return_value=("absent","","")), \
             mock.patch.object(M,"native_candidate_validation",return_value=("verified","e"*64)), \
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

    def test_plan_binds_identity_and_certificate_digests(self):
        raw=(b"mydestination = localhost\n",b"")
        sample=(M.E.digest(b"\0".join(raw)),self.values(),"","")
        identity=("mailbox_matches","a"*64,"b"*64)
        def plan(value):
            return M.candidate_evidence(raw,sample,"alerts@example.org",value)["plan_sha256"]
        self.assertNotEqual(plan(identity),plan(("mailbox_matches","c"*64,"b"*64)))
        self.assertNotEqual(plan(identity),plan(("mailbox_matches","a"*64,"c"*64)))
        req=dict(mailbox="alerts@example.org",nonce="a"*64)
        with mock.patch.object(M,"config_bytes",return_value=raw), \
             mock.patch.object(M,"sample",return_value=sample), \
             mock.patch.object(M,"identity_snapshot",side_effect=[identity,("mailbox_matches","a"*64,"c"*64)]), \
             mock.patch.object(M,"command",return_value=mock.Mock(returncode=0,stdout=b"")):
            with self.assertRaisesRegex(M.E.Refused,"configuration_changed"):
                M.inspect(req)

    def test_apply_preconditions_fail_closed(self):
        plan="a"*64
        report=dict(plan_sha256=plan,scope="primary_only",route="migration_candidate",
                    candidate_status="ready",identity="mailbox_matches",
                    native_validation="verified",native_sha256="e"*64,
                    service="active",queue="empty")
        M.validate_apply_preconditions(report,plan)
        for key,value in (("plan_sha256","b"*64),("scope","review_required"),
                          ("route","review_required"),("candidate_status","already_configured"),
                          ("identity","different_mailbox"),("identity","absent"),
                          ("service","unverified"),("queue","nonempty"),("queue","unverified"),
                          ("native_validation","review_required"),("native_sha256","")):
            with self.assertRaises(M.E.Refused):
                M.validate_apply_preconditions(dict(report,**{key:value}),plan)
        with self.assertRaises(M.E.Refused):
            M.validate_apply_preconditions(report,"invalid")

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


class NativePrimaryCandidateTests(unittest.TestCase):
    def state(self):
        explicit={"mydestination":"localhost, mail.example.org",
                  "inet_interfaces":"loopback-only","relayhost":"[old.example.org]:25"}
        expanded=dict.fromkeys(M.PRESERVED_KEYS,"")
        expanded.update(explicit,config_directory="/etc/postfix",
                        default_transport="smtp",relay_transport="relay",
                        local_transport="local:mail.example.org")
        services={"smtp/inet":["smtp","inet","n","-","n","-","-","smtpd"],
                  "local/unix":["local","unix","-","n","n","-","-","local"]}
        before=dict(explicit=explicit,expanded=expanded,services=services)
        after=dict(explicit=dict(explicit,**dict(M.ROUTE_CHANGES)),
                   expanded=dict(expanded,default_transport="m365xoauth2:",
                                 relay_transport="m365xoauth2:",relayhost=""),
                   services=dict(services,**{"m365xoauth2/unix":M.PIPE.decode("ascii").split()}))
        return before,after

    def test_exact_effective_settings_and_master_preservation(self):
        import copy
        before,after=self.state()
        M.compare_native_candidate(before,after)
        for section,key,value in (
            ("explicit","inet_interfaces","all"),
            ("expanded","mydestination","changed.example.org"),
            ("expanded","relayhost","old.example.org"),
            ("explicit","m365xoauth2_destination_recipient_limit","2"),
            ("services","smtp/inet",["changed"]),
            ("services","m365xoauth2/unix",["unexpected"])):
            bad=copy.deepcopy(after)
            bad[section][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(M.E.Refused):
                M.compare_native_candidate(before,bad)

    def test_native_parameter_spacing_and_empty_rhs(self):
        for assignment in ("multi_instance_directories =\n",
                           "multi_instance_directories = \n",
                           "multi_instance_directories=\n",
                           "multi_instance_directories\t=\t\n"):
            self.assertEqual(M.parameter_map(assignment),{"multi_instance_directories":""})
        self.assertEqual(M.parameter_map("relayhost=[relay.example.org]:587\n"
            "mydestination = localhost, example.org\n"
            "smtp_tls_policy_maps = hash:/etc/postfix/policy=x \n"),
            {"relayhost":"[relay.example.org]:587",
             "mydestination":"localhost, example.org",
             "smtp_tls_policy_maps":"hash:/etc/postfix/policy=x "})
        self.assertEqual(M.parameter_map(""),{})
        for invalid in ("a = x\n\nb = y\n","a = x\n  continued\n",
                        "a = x\n a = y\n","a = x\r\n","a = x\0",
                        "a = x\v","a = x\n a=y","a=x\na = y\n",
                        "a=x\x7f"):
            with self.subTest(invalid=invalid),self.assertRaises(M.E.Refused):
                M.parameter_map(invalid)

    def test_native_parser_rejects_duplicate_or_unexpected_scope(self):
        with self.assertRaises(M.E.Refused):
            M.parameter_map("relayhost = one\nrelayhost = two\n")
        with self.assertRaises(M.E.Refused):
            M.parameter_map("arbitrary native output\n")
        runner=mock.Mock(return_value=mock.Mock(returncode=1,stdout=b"",stderr=b"error"))
        with self.assertRaises(M.E.Refused):
            M.native_snapshot(M.ROOT,runner)
        self.assertEqual(runner.call_args[0][0],"postconf")

    def test_isolated_staging_and_live_drift_check(self):
        import tempfile
        before,after=self.state()
        raw=(b"mydestination = localhost\n",b"smtp inet n - n - - smtpd\n")
        proposed=(raw[0]+b"default_transport = m365xoauth2:\n",raw[1]+M.PIPE)
        with tempfile.TemporaryDirectory() as parent:
            actual=Path(parent)
            original= M.tempfile.TemporaryDirectory
            def tmp(*args,**kwargs):
                return original(prefix="private-",dir=actual)
            paths=[]
            def snapshot(directory):
                if directory==M.ROOT:
                    return before
                paths.append(directory)
                self.assertEqual(directory.stat().st_mode&0o777,0o700)
                blobs=tuple((directory/name).read_bytes() for name in ("main.cf","master.cf"))
                self.assertTrue(all((directory/name).stat().st_mode&0o777==0o600
                                    for name in ("main.cf","master.cf")))
                return before if blobs==raw else after
            with mock.patch.object(M.E,"trusted_directory"), \
                 mock.patch.object(M.tempfile,"TemporaryDirectory",side_effect=tmp), \
                 mock.patch.object(M,"config_bytes",return_value=raw):
                status,sha=M.native_candidate_validation(raw,proposed,snapshot)
            self.assertEqual(status,"verified")
            self.assertRegex(sha,r"^[a-f0-9]{64}$")
            self.assertEqual(paths[0],paths[1])
            self.assertFalse(paths[0].exists())
            with mock.patch.object(M.E,"trusted_directory"), \
                 mock.patch.object(M.tempfile,"TemporaryDirectory",side_effect=tmp), \
                 mock.patch.object(M,"config_bytes",side_effect=[raw,proposed]):
                self.assertEqual(M.native_candidate_validation(raw,proposed,snapshot),
                                 ("review_required",""))


if __name__=="__main__":
    unittest.main()
