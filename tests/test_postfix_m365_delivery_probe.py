import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("probe", ROOT / "linux/review-postfix-m365-delivery.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class PostfixDeliveryProbeTests(unittest.TestCase):
    def setUp(self):
        self.req = {"run_id": "a"*32, "sender": "relay@example.org", "internal": "test@example.org",
                    "external": "test@outside.net", "mx": "example-org.mail.protection.outlook.com",
                    "accepted_domain": "example.org"}
        self.sha = "b"*64

    def test_address_and_domain_checks(self):
        self.assertEqual(M.validate_request(self.req), self.req)
        for change in ({"external": "another@example.org"}, {"sender": "bad\n@foo.org"},
                       {"mx": "evil.example.org"}, {"internal": "-x@example.org"}):
            with self.assertRaises(ValueError):
                M.validate_request(dict(self.req, **change))

    def test_route_requires_exact_mx_and_mandatory_tls(self):
        settings = {"config_directory": "/etc/postfix", "relayhost": "["+self.req["mx"]+"]:25",
                    "default_transport": "smtp", "relay_transport": "relay",
                    "smtp_sasl_auth_enable": "no", "smtp_tls_security_level": "encrypt",
                    "mydestination": "localhost, localhost.localdomain"}
        read = lambda key: settings.get(key, "")
        self.assertEqual(M.route_settings(read, "", self.req)["relayhost"], self.req["mx"])
        for key, value in (("transport_maps", "hash:/etc/postfix/transport"),
                           ("smtp_tls_security_level", "may"), ("mydestination", "example.org"),
                           ("relayhost", "[evil.example.org]:25")):
            changed = dict(settings, **{key: value})
            with self.assertRaises(ValueError):
                M.route_settings(lambda name: changed.get(name, ""), "", self.req)
        with self.assertRaises(ValueError):
            M.route_settings(read, "smtp/unix/smtp_tls_security_level=none", self.req)

    def test_stale_review_does_not_reserve_or_send(self):
        with patch.object(M, "reserve") as reserve:
            runner = Mock()
            with self.assertRaises(ValueError):
                M.submit(self.req, self.sha, lambda _: {"plan_sha256": "c"*64}, runner)
            reserve.assert_not_called()
            runner.assert_not_called()

    def test_reserved_attempt_before_send_and_no_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(M, "ROOT", pathlib.Path(temp)/"ledger"), patch.object(M, "directory"):
                plan = lambda _: {"plan_sha256": self.sha, "_binary": "/usr/sbin/sendmail.postfix"}
                def run(args, **kwargs):
                    raw = M.ledger_file(self.req).read_text()
                    self.assertIn('"event":"attempted","role":"internal"', raw)
                    self.assertEqual(args[-1], self.req["internal"])
                    self.assertIn(M.message_id(self.req, "internal").encode(), kwargs["input"])
                    return Mock(returncode=1)
                runner = Mock(side_effect=run)
                outcome = M.submit(self.req, self.sha, plan, runner)
                self.assertEqual(outcome["outcomes"], {"internal": "submission_uncertain"})
                with self.assertRaises(FileExistsError):
                    M.submit(self.req, self.sha, plan, runner)
                self.assertEqual(runner.call_count, 1)

    def test_trace_requires_exact_id_recipient_and_relay(self):
        marker = M.message_id(self.req, "internal")
        lines = ["ABC123: message-id="+marker,
                 "OTHER1: to=<test@example.org>, relay="+self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent (ok)",
                 "ABC123: to=<test@example.org>, relay="+self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent (ok)"]
        result = M.correlate(self.req, "internal", lines, [], "local_submission_accepted")
        self.assertEqual(result["transport"], "exchange_relay_accepted")
        self.assertEqual(result["queue"], "not_observed")
        self.assertEqual(result["dsn"], "2.0.0")
        self.assertNotIn(self.req["internal"], str(result))
        self.assertEqual(M.correlate(self.req, "internal", lines[:2], [], "attempted")["transport"], "unknown")
        self.assertEqual(M.correlate(self.req, "internal", lines+["OTHER2: message-id="+marker], [], "attempted")["transport"], "correlation_unavailable")

    def test_queue_state_not_delivery(self):
        lines = ["ABC123: message-id="+M.message_id(self.req, "external"),
                 "ABC123: to=<test@outside.net>, relay=none, dsn=4.4.1, status=deferred (private detail)"]
        queue = [{"queue_id": "ABC123", "queue_name": "deferred", "recipients": [{"address": self.req["external"]}]}]
        result = M.correlate(self.req, "external", lines, queue, "local_submission_accepted")
        self.assertEqual(result["transport"], "deferred")
        self.assertEqual(result["queue"], "deferred")
        self.assertNotIn("private detail", str(result))

    def test_package_ownership_requires_native_postfix(self):
        import subprocess
        adapter = Mock()
        adapter.trusted_binary.side_effect = lambda path: path
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b"postfix: /usr/sbin/sendmail\n"))
        M.verify_postfix_package("/usr/sbin/sendmail", adapter, runner)
        runner.return_value = subprocess.CompletedProcess([], 0, b"exim4-daemon-light: /usr/sbin/sendmail\n")
        with self.assertRaises(ValueError):
            M.verify_postfix_package("/usr/sbin/sendmail", adapter, runner)

    def test_remote_response_text_cannot_supply_missing_relay(self):
        lines = ["ABC123: message-id="+M.message_id(self.req, "internal"),
                 "ABC123: to=<test@example.org>, relay=none, dsn=4.4.1, status=deferred (relay="+
                 self.req["mx"]+"[192.0.2.1]:25, dsn=2.0.0, status=sent)"]
        result = M.correlate(self.req, "internal", lines, [], "local_submission_accepted")
        self.assertEqual(result["transport"], "deferred")
        self.assertEqual(result["dsn"], "4.4.1")


class PrimaryAuditTests(unittest.TestCase):
    def setUp(self):
        self.req = {"accepted_domain": "example.org", "mx": "example-org.mail.protection.outlook.com"}
        self.values = dict((key, "") for key in M.AUDIT_KEYS)
        self.values.update(config_directory="/etc/postfix", myhostname="mail.local.example.net",
                           mydomain="local.example.net", myorigin="local.example.net",
                           mydestination="localhost, mail.local.example.net", inet_interfaces="loopback-only",
                           inet_protocols="ipv4", relayhost="["+self.req["mx"]+"]:25",
                           smtp_tls_security_level="encrypt", smtp_sasl_auth_enable="no",
                           default_transport="smtp", relay_transport="relay", local_transport="local",
                           virtual_transport="virtual")
        self.adapter = Mock()
        self.pf = self.adapter.Postfix.return_value
        self.pf.postfix = "postfix"
        self.pf.postconf = "postconf"
        self.overrides = ""
        def run(binary, *args):
            if args[0] == "-x":
                return "\n".join(k+" = "+self.values[k] for k in args[1:])
            if args == ("-P",):
                return self.overrides
            if args == ("status",):
                return ""
            raise AssertionError("unexpected native command")
        self.pf.run.side_effect = run
        self.reader = Mock(return_value=b"config")
        self.queue = Mock(return_value=[])

    def audit(self):
        return M.primary_audit(self.req,self.adapter,self.queue,self.reader)

    def test_basic_route_and_queue_observation_no_mutation(self):
        report = self.audit()
        self.assertEqual(report["status"], "basic_route_observed")
        self.assertEqual(report["queue"]["total"], 0)
        self.assertEqual(report["settings"]["inet_protocols"], "ipv4")
        self.assertEqual(report["settings"]["relayhost"], self.values["relayhost"])
        for flag in ("postfix_modified", "queue_modified", "mail_sent", "apply_supported", "exchange_acceptance_verified"):
            self.assertFalse(report[flag])
        self.assertTrue(all(call.args[1] in ("-x", "-P", "status") for call in self.pf.run.call_args_list))

    def test_complex_route_and_nonempty_queue_refused_without_private_values(self):
        self.values["transport_maps"] = "ldap:/private/secret"
        self.values["mydestination"] = "example.org"
        self.values["relayhost"] = "user:secret@host"
        self.values["smtp_bind_address"] = "10.1.2.3"
        self.queue.return_value = [{"queue_id":"ABC123","queue_name":"deferred","sender":"private@example.org"}]
        report = self.audit()
        self.assertEqual(report["status"], "review_required")
        for blocker in ("routing_or_rewrite_policy","accepted_domain_local_delivery_review","explicit_source_bind_review",
                        "queue_not_empty","unsupported_setting_syntax","relayhost_differs"):
            self.assertIn(blocker, report["blockers"])
        self.assertIsNone(report["settings"]["relayhost"])
        self.assertEqual(report["queue"]["counts"]["deferred"],1)
        self.assertNotIn("secret",str(report))
        self.assertNotIn("private@example.org",str(report))

    def test_unverified_queue_not_empty_claim(self):
        self.values["multi_instance_directories"]="/etc/other"
        report=self.audit()
        self.queue.assert_not_called()
        self.assertIn("not_default_single_instance",report["blockers"])
        self.assertIsNone(report["queue"]["total"])

    def test_configuration_drift_refused(self):
        self.reader.side_effect=[b"a",b"b",b"changed",b"b"]
        with self.assertRaises(ValueError):
            self.audit()

    def test_duplicate_queue_ids_are_unverified(self):
        self.queue.return_value=[dict(queue_id="ABC123",queue_name="active")]*2
        self.assertEqual(self.audit()["queue"]["status"],"unavailable")

    def test_wizard_primary_audit_is_read_only(self):
        src=ROOT/"src/LinuxMailRelay365"
        main=(src/"MainForm.SmtpPrimaryAudit.cs").read_text()
        self.assertIn('BuildPostfixM365DeliveryProbe("audit", request, null)',main)
        self.assertIn('"apply_supported"',main)
        self.assertIn("Inconsistent queue totals",main)
        self.assertIn("No Apply operation",main)
        self.assertIn("OpenPrimaryPostfixAuditAsync(owner, context, mx)",(src/"MainForm.DeliveryMiniWizard.cs").read_text())
        self.assertIn("Inspect primary Postfix configuration / queue",(src/"SmtpCertificateWizardDialog.cs").read_text())


class LocalDeliveryProbeTests(unittest.TestCase):
    def setUp(self):
        self.req={"run_id":"c"*32,"recipient":"testuser@mail.example.org"}
        self.sha="d"*64
        self.policy=dict(config_directory="/etc/postfix",myhostname="mail.example.org",
                         mydestination="localhost, mail.example.org",local_transport="local",
                         local_recipient_maps="proxy:unix:passwd.byname",
                         mail_spool_directory="/var/mail")

    def test_simple_local_route_and_refuse_redirection(self):
        self.assertEqual(M.local_policy(lambda k:self.policy.get(k,""),"",self.req)["mailbox_kind"],"system_spool")
        for key,value in (("alias_maps","ldap:/etc/postfix/aliases"),("forward_path","/var/forward/$user"),
                          ("transport_maps","hash:/etc/postfix/transport"),("mailbox_command","procmail"),
                          ("local_transport","lmtp:unix:private/dovecot"),("always_bcc","other@example.net"),
                          ("mydestination","localhost"),("recipient_delimiter","+-")):
            with self.subTest(key=key):
                changed=dict(self.policy,**{key:value})
                with self.assertRaises(ValueError):
                    M.local_policy(lambda k:changed.get(k,""),"",self.req)
        with self.assertRaises(ValueError):
            M.local_policy(lambda k:self.policy.get(k,""),"local/unix/local_transport=other",self.req)

    def test_invalid_local_recipient(self):
        for recipient in ("-bad@mail.example.org","root+tag@mail.example.org","u@localhost","u@evil.example.org\n"):
            with self.assertRaises(ValueError):
                M.local_request(dict(self.req,recipient=recipient))

    def test_submission_reserved_before_send_and_no_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(M,"ROOT",pathlib.Path(temp)/"ledger"),patch.object(M,"directory"):
                plan=lambda _:{"plan_sha256":self.sha,"_binary":"/usr/sbin/sendmail"}
                def run(args,**kwargs):
                    self.assertEqual(args[-4:],["-f","<>","--",self.req["recipient"]])
                    self.assertIn(M.local_message_id(self.req).encode(),kwargs["input"])
                    self.assertIn('"event":"attempted","role":"local"',M.ledger_file(self.req).read_text())
                    return Mock(returncode=1)
                runner=Mock(side_effect=run)
                result=M.submit_local(self.req,self.sha,plan,runner)
                self.assertEqual(result["submission"],"submission_uncertain")
                self.assertFalse(result["mailbox_verified"])
                self.assertEqual(M.ledger(self.req,("local",))[1]["local"],"submission_uncertain")
                with self.assertRaises(FileExistsError):
                    M.submit_local(self.req,self.sha,plan,runner)
                runner.assert_called_once()

    def test_local_trace_uses_exact_cleanup_and_local_agent(self):
        cleanup=["ABC123: message-id="+M.local_message_id(self.req)]
        local=["ABC123: to=<"+self.req["recipient"]+">, relay=local, dsn=2.0.0, status=sent (delivered to mailbox)"]
        result=M.correlate_local(self.req,cleanup,local,[],"local_submission_accepted")
        self.assertEqual(result["transport"],"local_agent_accepted")
        self.assertEqual(result["queue"],"not_observed")
        self.assertEqual(M.correlate_local(self.req,cleanup+local,[],[],"attempted")["transport"],"unknown")
        fake=["ABC123: to=<"+self.req["recipient"]+">, relay=none, dsn=4.4.1, status=deferred (relay=local, dsn=2.0.0, status=sent)"]
        self.assertEqual(M.correlate_local(self.req,cleanup,fake,[],"attempted")["transport"],"deferred")

    def test_local_probe_gui_separate_from_exchange(self):
        src=ROOT/"src/LinuxMailRelay365"
        ui=(src/"PostfixLocalDeliveryDialog.cs").read_text()
        self.assertIn('remote("local-preview"',ui)
        self.assertIn('remote("local-submit"',ui)
        self.assertIn('remote("local-trace"',ui)
        self.assertIn("Confirm local delivery test",ui)
        self.assertIn("mailbox_verified",ui)
        self.assertIn("attempted.Add",ui)
        self.assertNotIn("Exchange Message Trace",ui)
        self.assertIn("new PostfixLocalDeliveryDialog(remote)",(src/"PostfixM365DeliveryDialog.cs").read_text())


class StandardLocalRouteTests(unittest.TestCase):
    def setUp(self):
        self.req={"run_id":"c"*32,"recipient":"testuser@mail.example.org"}
        self.policy=dict(config_directory="/etc/postfix",myhostname="mail.example.org",
                         mydestination="localhost, mail.example.org",
                         local_transport="local:mail.example.org",
                         alias_maps="hash:/etc/aliases",
                         forward_path=M.FORWARD_PATHS[1],
                         recipient_delimiter="+",
                         local_recipient_maps="proxy:unix:passwd.byname, hash:/etc/aliases",
                         mail_spool_directory="/var/mail")

    def test_standard_policy_only_accepts_supported_map_and_forward_path(self):
        settings=M.local_policy(lambda key:self.policy.get(key,""),"",self.req)
        self.assertEqual(settings["alias_map"],"hash:/etc/aliases")
        self.assertEqual(settings["forward_path"],M.FORWARD_PATHS[1])
        for key,value in (("alias_maps","regexp:/etc/aliases"),
                          ("forward_path","/var/forward/$user"),
                          ("local_recipient_maps","proxy:unix:passwd.byname lmdb:/etc/aliases"),
                          ("recipient_delimiter","+-"),
                          ("local_transport","local:other.example.org")):
            changed=dict(self.policy,**{key:value})
            with self.assertRaises(ValueError):
                M.local_policy(lambda k:changed.get(k,""),"",self.req)
        for user in ("root","postmaster","mailer-daemon","double-bounce","owner-test","test-request"):
            with self.assertRaises(ValueError):
                M.local_request(dict(self.req,recipient=user+"@mail.example.org"))

    def test_native_alias_query_absent_only_and_no_raw_values(self):
        adapter=Mock()
        adapter.trusted_invocation.return_value="/usr/sbin/postalias"
        reader=Mock(return_value=b"private alias content")
        runner=Mock(return_value=Mock(returncode=1,stdout=b"",stderr=b""))
        for alias in ("hash:/etc/aliases","lmdb:/etc/postfix/aliases"):
            result=M.alias_evidence(alias,"testuser",adapter,runner,reader)
            self.assertEqual(result["status"],"recipient_not_found")
            self.assertNotIn("private alias content",str(result))
            self.assertEqual(runner.call_args[0][0],["/usr/sbin/postalias","-c","/etc/postfix","-q","testuser",alias])
        for code,out,err in ((0,b"forward@example.net",b""),(1,b"",b"warning"),(2,b"",b""),(1,b"unexpected",b"")):
            runner.return_value=Mock(returncode=code,stdout=out,stderr=err)
            with self.assertRaises(ValueError):
                M.alias_evidence("hash:/etc/aliases","testuser",adapter,runner,reader)
        runner.return_value=Mock(returncode=1,stdout=b"",stderr=b"")
        reader.side_effect=[b"a",b"b",b"a",b"changed"]
        with self.assertRaises(ValueError):
            M.alias_evidence("hash:/etc/aliases","testuser",adapter,runner,reader)

    def test_forward_not_configured_without_filesystem_lookup(self):
        self.assertEqual(M.forward_evidence({},{"forward_path":""},Mock(),Mock()),{"status":"not_configured"})

    def test_forward_entries_and_unsafe_paths_refused(self):
        from types import SimpleNamespace
        import stat
        home="/home/testuser"
        account={"uid":1000,"home":home}
        settings={"forward_path":M.FORWARD_PATHS[1]}
        def stats(uid,mode,ino):
            return SimpleNamespace(st_uid=uid,st_mode=stat.S_IFDIR|mode,st_dev=1,st_ino=ino)
        parent=stats(0,0o755,1)
        owned=stats(1000,0o700,2)
        def lstat(path):
            return owned if str(path)==home else parent
        default=lambda:"filter"
        with patch.object(M.Path,"lstat",lstat),patch.object(M.os,"open",return_value=7), \
             patch.object(M.os,"close"),patch.object(M.os,"fstat",return_value=owned), \
             patch.object(M.os,"stat",side_effect=FileNotFoundError) as lookup:
            result=M.forward_evidence(account,settings,default,default)
            self.assertEqual(result["status"],"no_forward_file_observed")
            self.assertEqual([call.args[0] for call in lookup.call_args_list],[".forward",".forward+"])
            self.assertTrue(all(not call.kwargs["follow_symlinks"] for call in lookup.call_args_list))
            lookup.side_effect=[FileNotFoundError(),SimpleNamespace()]
            with self.assertRaises(ValueError):
                M.forward_evidence(account,settings,default,default)
            with self.assertRaises(ValueError):
                M.forward_evidence(account,settings,default,lambda:"changed")
            with self.assertRaises(ValueError):
                M.forward_evidence(dict(account,home="/home/../root"),settings,default,default)
        with patch.object(M.Path,"lstat",return_value=stats(1000,0o777,1)):
            with self.assertRaises(ValueError):
                M.forward_evidence(account,settings,default,default)

    def test_preflight_sha_includes_alias_and_forward_observations(self):
        source=(ROOT/"linux/review-postfix-m365-delivery.py").read_text()
        self.assertIn('"redirection_evidence":routing',source)
        self.assertIn("redirects()!=routing",source)
        ui=(ROOT/"src/LinuxMailRelay365/PostfixLocalDeliveryDialog.cs").read_text()
        self.assertIn('StringField(root,"alias_status")',ui)
        self.assertIn('StringField(root,"forward_status")',ui)
        self.assertIn("including any queued retries",ui)
