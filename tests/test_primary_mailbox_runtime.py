"""Synthetic runtime/SMTP acceptance and review-only CLI tests."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("primary_offline_cli",
    ROOT/"linux/manage-primary-mailbox-offline.py")
CLI=importlib.util.module_from_spec(spec)
spec.loader.exec_module(CLI)
A=CLI.A
TENANT="11111111-1111-1111-1111-111111111111"
CLIENT="22222222-2222-2222-2222-222222222222"
MAIL="alerts@example.org"


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.state={"uid":998,"gid":998,"groups":[998],"identity_sha256":"a"*64}
        self.snapshot=Mock(side_effect=lambda *args:dict(self.state))
        self.auth=Mock()
        self.time=10
        self.guard=A.RuntimeGuard(TENANT,CLIENT,A.CONFIRM,self.snapshot,self.auth,lambda:self.time)

    def test_reuses_only_recent_identical_runtime(self):
        sha=self.guard(MAIL)
        self.assertRegex(sha,r"^[a-f0-9]{64}$")
        self.auth.assert_called_once_with(self.state)
        self.snapshot.assert_called_with(MAIL,TENANT,CLIENT)
        self.time+=89
        self.assertEqual(self.guard(MAIL),sha)
        self.assertEqual(self.auth.call_count,1)
        self.time+=1
        self.assertEqual(self.guard(MAIL),sha)
        self.assertEqual(self.auth.call_count,2)

    def test_drift_refuses_instead_of_reauthorizing(self):
        self.guard(MAIL)
        self.state["identity_sha256"]="b"*64
        with self.assertRaises(A.Refused):
            self.guard(MAIL)
        self.state["identity_sha256"]="a"*64
        with self.assertRaises(A.Refused):
            self.guard(MAIL)
        self.auth.assert_called_once()

    def test_auth_failure_or_drift_during_auth_never_returns_sha(self):
        self.auth.side_effect=lambda _:self.state.update(identity_sha256="c"*64)
        with self.assertRaisesRegex(A.Refused,"changed_during_smtp_auth"):
            self.guard(MAIL)
        with self.assertRaises(A.Refused):
            self.guard(MAIL)
        self.auth.assert_called_once()
        guard=A.RuntimeGuard(TENANT,CLIENT,A.CONFIRM,self.snapshot,
                             Mock(side_effect=A.Refused("AUTH failed")))
        with self.assertRaises(A.Refused):
            guard(MAIL)

    def test_expected_runtime_sha_refuses_drift_before_auth(self):
        expected=A.digest(self.state)
        guard=A.RuntimeGuard(TENANT,CLIENT,A.CONFIRM,self.snapshot,self.auth,
                             lambda:self.time,expected_sha=expected)
        self.state["identity_sha256"]="b"*64
        with self.assertRaisesRegex(A.Refused,"installed_runtime_changed"):
            guard(MAIL)
        self.auth.assert_not_called()
        self.state["identity_sha256"]="a"*64
        with self.assertRaises(A.Refused):
            guard(MAIL)
        fresh=A.RuntimeGuard(TENANT,CLIENT,A.CONFIRM,self.snapshot,self.auth,
                             lambda:self.time,expected_sha=expected)
        self.assertEqual(fresh(MAIL),expected)
        self.auth.assert_called_once()
        with self.assertRaises(A.Refused):
            A.RuntimeGuard(TENANT,CLIENT,A.CONFIRM,expected_sha="invalid")

    def test_confirmation_and_selected_guids_required(self):
        for tenant,confirm in ((TENANT,"wrong"),("invalid",A.CONFIRM),
                               ("00000000-0000-0000-0000-000000000000",A.CONFIRM)):
            with self.assertRaises(A.Refused):
                A.RuntimeGuard(tenant,CLIENT,confirm,self.snapshot,self.auth)
        self.snapshot.assert_not_called()
        self.auth.assert_not_called()

    def test_auth_command_is_exact_and_never_sends_a_message(self):
        runner=Mock(return_value=Mock(returncode=0,stdout=A.SUCCESS,stderr=b""))
        with patch.object(A.os,"geteuid",return_value=0):
            A.run_auth(self.state,runner)
            args=runner.call_args[0][0]
            self.assertEqual(args,["/usr/bin/python3","-E","-s","-B",
                "/usr/local/libexec/m365_xoauth2_transport.py","--smtp-auth-check",
                "--config","/etc/postfix/m365-oauth/app.json"])
            kw=runner.call_args[1]
            self.assertEqual(kw["env"],A.ENV)
            self.assertEqual(kw["input"],b"")
            self.assertEqual(kw["timeout"],120)
            self.assertTrue(callable(kw["preexec_fn"]))
            for rc,out,err in ((1,A.SUCCESS,b""),(0,b"prefix"+A.SUCCESS,b""),
                               (0,A.SUCCESS,b"warning"),(0,b"",b"")):
                runner.return_value=Mock(returncode=rc,stdout=out,stderr=err)
                with self.assertRaises(A.Refused):
                    A.run_auth(self.state,runner)
            runner.side_effect=subprocess.TimeoutExpired(args,120)
            with self.assertRaises(A.Refused):
                A.run_auth(self.state,runner)

    def test_runtime_snapshot_matches_bundle_and_exact_identity(self):
        account=Mock(pw_name="m365mailer",pw_uid=998,pw_gid=998)
        group=Mock(gr_gid=998)
        identity={"mailbox":MAIL,"tenant_id":TENANT,"client_id":CLIENT}
        current={"identity":identity,"raw":b"private identity",
                 "key_sha":"b"*64,"cert_sha":"c"*64}
        inventory={"mailbox":MAIL,"tenant":TENANT,"client":CLIENT,
                   "identity_sha":A.C.sha(current["raw"]),"certificate_sha":"d"*64}
        with patch.object(A.os,"geteuid",return_value=0), \
             patch.object(A.pwd,"getpwnam",return_value=account), \
             patch.object(A.grp,"getgrnam",return_value=group), \
             patch.object(A.os,"getgrouplist",return_value=[998]), \
             patch.object(A.R.E,"trusted_directory"), \
             patch.object(A,"read_active",return_value=(current["raw"],identity)), \
             patch.object(A.C,"current",return_value=current), \
             patch.object(A.R.E,"active_inventory",return_value=inventory), \
             patch.object(A.R.E,"secure_read",return_value=b"same code") as reader, \
             patch.object(A,"reject_import_artifacts"), \
             patch.object(A,"system_executable",return_value=["trusted"]):
            result=A.installed_snapshot(MAIL,TENANT,CLIENT)
            self.assertEqual(result["key_sha256"],"b"*64)
            self.assertNotIn("private identity",str(result))
            self.assertEqual(reader.call_count,4)
            with self.assertRaises(A.Refused):
                A.installed_snapshot(MAIL,CLIENT,TENANT)
            reader.side_effect=[b"bundle",b"modified"]
            with self.assertRaisesRegex(A.Refused,"runtime_version_mismatch"):
                A.installed_snapshot(MAIL,TENANT,CLIENT)


class ManagedTpmRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identity={"mailbox":MAIL,"tenant_id":TENANT,"client_id":CLIENT,
                       "certificate":"/etc/postfix/m365-oauth/hardware-app.crt",
                       "signer":{"type":"openssl-provider","provider":"tpm2",
                                 "key_ref":"handle:0x81010001",
                                 "provider_config":"/etc/postfix/m365-oauth/tpm2.cnf"}}
        self.config=A.T.PROVIDER_TEMPLATE.encode("ascii")
        self.cert=b"public certificate"
        self.public={"public_key_sha256":"a"*64,"device":[1,2,3,0,998,0o20660],
                     "readpublic":["trusted"]}

    def test_exact_managed_tpm_dependencies_and_no_pem_fallback(self):
        def read(path,*args,**kwargs):
            if str(path)==self.identity["certificate"]:
                return self.cert
            self.assertEqual(str(path),self.identity["signer"]["provider_config"])
            return self.config
        with patch.object(A.R.E,"secure_read",side_effect=read), \
             patch.object(A.R.E,"der_from_pem",return_value=b"der"), \
             patch.object(A,"tpm_public_evidence",return_value=self.public) as public:
            result=A.managed_tpm_snapshot(self.identity,998)
            self.assertEqual(result["hardware"]["provider"],"tpm2")
            self.assertEqual(result["hardware"]["key_ref"],"handle:0x81010001")
            self.assertNotIn("key_sha256",result)
            public.assert_called_once_with("0x81010001",self.identity["certificate"])
            for change in ({"provider":"pkcs11"},{"key_ref":"handle:0x81000001"},
                           {"key_ref":"/etc/postfix/m365-oauth/tpm2-app.key"},
                           {"provider_config":"/etc/postfix/m365-oauth/other.cnf"}):
                with self.assertRaises(A.Refused):
                    A.managed_tpm_snapshot(dict(self.identity,signer=dict(self.identity["signer"],**change)),998)
            with self.assertRaises(A.Refused):
                A.managed_tpm_snapshot(dict(self.identity,private_key="/tmp/pem"),998)
            self.config+=b"\n.include /tmp/unreviewed.cnf\n"
            with self.assertRaises(A.Refused):
                A.managed_tpm_snapshot(self.identity,998)
            self.assertEqual(public.call_count,1)

    def test_active_tpm_snapshot_uses_installed_identity_not_staged_pem(self):
        raw=b"active hardware identity"
        cert_sha="c"*64
        inventory={"mailbox":MAIL,"tenant":TENANT,"client":CLIENT,
                   "identity_sha":A.C.sha(raw),"certificate_sha":cert_sha}
        credentials={"certificate_sha256":cert_sha,"certificate_file_sha256":"d"*64,
                     "hardware":{"provider":"tpm2","public_key_sha256":"b"*64}}
        account=Mock(pw_name="m365mailer",pw_uid=998,pw_gid=998)
        with patch.object(A.os,"geteuid",return_value=0), \
             patch.object(A.pwd,"getpwnam",return_value=account), \
             patch.object(A.grp,"getgrnam",return_value=Mock(gr_gid=998)), \
             patch.object(A.os,"getgrouplist",return_value=[998]), \
             patch.object(A.R.E,"trusted_directory"), \
             patch.object(A,"read_active",return_value=(raw,self.identity)), \
             patch.object(A.R.E,"active_inventory",return_value=inventory), \
             patch.object(A,"managed_tpm_snapshot",return_value=credentials), \
             patch.object(A.C,"current",side_effect=AssertionError("no PEM fallback")), \
             patch.object(A.R.E,"secure_read",return_value=b"same installed code"), \
             patch.object(A,"reject_import_artifacts"), \
             patch.object(A,"system_executable",return_value=["trusted"]):
            state=A.installed_snapshot(MAIL,TENANT,CLIENT)
            self.assertEqual(state["version"],2)
            self.assertEqual(state["hardware"]["provider"],"tpm2")
            self.assertNotIn("key_sha256",state)
            self.assertNotIn(raw.decode(),str(state))
            first=A.digest(state)
            credentials["hardware"]["public_key_sha256"]="e"*64
            self.assertNotEqual(A.digest(A.installed_snapshot(MAIL,TENANT,CLIENT)),first)
            credentials["certificate_sha256"]="f"*64
            with self.assertRaises(A.Refused):
                A.installed_snapshot(MAIL,TENANT,CLIENT)

    def test_tpm_public_read_only_command_and_certificate_match(self):
        import stat
        device=Mock(st_dev=1,st_ino=2,st_rdev=3,st_uid=0,st_gid=998,
                    st_mode=stat.S_IFCHR|0o660)
        with patch.object(A.T,"check_hardware"), \
             patch.object(A.T,"DEVICE",Mock(lstat=Mock(return_value=device))), \
             patch.object(A,"system_executable",return_value=["trusted"]), \
             patch.object(A.tempfile,"TemporaryDirectory") as temporary, \
             patch.object(A.T,"run_command") as runner, \
             patch.object(A.R.E,"secure_read",return_value=b"public key\n"), \
             patch.object(A.C,"openssl",side_effect=[b"public key\n",b""]) as openssl:
            temporary.return_value.__enter__.return_value="/run/test-private"
            result=A.tpm_public_evidence("0x81010001",self.identity["certificate"])
            self.assertRegex(result["public_key_sha256"],r"^[a-f0-9]{64}$")
            args=runner.call_args.args[0]
            self.assertEqual(args,["/usr/bin/tpm2_readpublic","-c","0x81010001","-f","pem",
                                   "-o","/run/test-private/public.pem"])
            openssl.side_effect=[b"different public key",b""]
            with self.assertRaises(A.Refused):
                A.tpm_public_evidence("0x81010001",self.identity["certificate"])


class PrimarySelinuxReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("primary_label_probe",
            ROOT/"linux/inspect-primary-mailbox-selinux.py")
        cls.S=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.S)

    def test_ports_are_policy_metadata_not_network_permission(self):
        S=self.S
        raw=("SELinux Port Type Proto Port Number\n"
             "http_port_t tcp 80, 443\nsmtp_port_t tcp 25, 465, 587\n"
             "unreserved_port_t tcp 1024-65535\nreserved_port_t tcp 1-1023\n")
        self.assertEqual(S.port_states(raw),{"443":"expected_type","587":"expected_type"})
        self.assertEqual(S.port_states(raw+"other_t tcp 587\n")["587"],"different_or_ambiguous_type")
        self.assertEqual(S.port_states(raw.replace("465, 587","465"))["587"],"no_specific_type")
        with self.assertRaises(ValueError):
            S.port_states(raw+"bad_t tcp 70000\n")

    def test_fixed_credential_references_and_hardware_scope(self):
        S=self.S
        identity=dict(tenant_id=TENANT,client_id=CLIENT,mailbox=MAIL,
                      certificate=S.ROOT+"/app.crt",private_key=S.ROOT+"/app.key")
        self.assertEqual(S.credential_paths(identity)[0],"pem")
        with self.assertRaises(ValueError):
            S.credential_paths(dict(identity,private_key="/tmp/key"))
        with self.assertRaises(ValueError):
            S.credential_paths(dict(identity,private_key=S.ROOT+"/../key"))
        hardware=dict(identity)
        hardware.pop("private_key")
        hardware["certificate"]=S.ROOT+"/hardware-app.crt"
        hardware["signer"]={"type":"openssl-provider","provider":"tpm2",
            "provider_config":S.ROOT+"/tpm2.cnf","key_ref":"handle:0x81010001"}
        self.assertEqual(S.credential_paths(hardware)[0],"managed_tpm2_reference")
        hardware["signer"]["provider"]="pkcs11"
        self.assertEqual(S.credential_paths(hardware)[0],"custom_hardware")

    def test_report_is_read_only_and_fails_on_observed_drift(self):
        S=self.S
        identity=dict(tenant_id=TENANT,client_id=CLIENT,mailbox=MAIL,
                      certificate=S.ROOT+"/app.crt",private_key=S.ROOT+"/app.key")
        raw="SELinux Port Type Proto Port Number\nhttp_port_t tcp 443\nsmtp_port_t tcp 587\n"
        sample=Mock(return_value=("policy_match",{"label":"test","metadata":[1,2]}))
        with patch.object(S.A.grp,"getgrnam",return_value=Mock(gr_gid=998)), \
             patch.object(S.A.pwd,"getpwnam",return_value=Mock(pw_uid=999)), \
             patch.object(S.os,"lstat",return_value=Mock(st_uid=999)):
            result=S.collect("a"*64,lambda:"enforcing",Mock(return_value=raw),sample,
                             Mock(return_value=(b"private config",identity)))
            self.assertEqual(result["status"],"manual_runtime_review_required")
            self.assertRegex(result["config_metadata_sha256"],r"^[a-f0-9]{64}$")
            for flag in ("write_allowed","runtime_verified","changes_applied","mail_sent","network_attempted"):
                self.assertFalse(result[flag])
            self.assertNotIn("private config",str(result))
            self.assertNotIn(S.ROOT,str(result))
            sample.side_effect=[("policy_match",{"label":"one"})]*len(result["labels"])+[("policy_mismatch",None)]*len(result["labels"])
            with self.assertRaises(ValueError):
                S.collect("a"*64,lambda:"enforcing",Mock(return_value=raw),sample,
                          Mock(return_value=(b"private config",identity)))
        inactive=S.collect("a"*64,lambda:"inactive_or_unavailable",Mock(side_effect=AssertionError("no commands")),
                           Mock(side_effect=AssertionError("no files")))
        self.assertFalse(inactive["write_allowed"])
        self.assertIsNone(inactive["config_metadata_sha256"])

    def test_gui_bundle_does_not_unlock_enforcing_apply(self):
        src=ROOT/"src/LinuxMailRelay365"
        self.assertIn("BuildPrimaryMailboxSelinuxReadiness",(src/"EmbeddedAssets.cs").read_text())
        self.assertIn("inspect-primary-mailbox-selinux.py",(src/"LinuxMailRelay365.csproj").read_text())
        self.assertIn("InspectPrimaryMailboxSelinuxAsync",(src/"MainForm.PrimaryMailboxRoute.cs").read_text())
        self.assertIn("PrimaryMailboxSelinuxClient.SelfTest",(src/"Program.cs").read_text())
        self.assertIn('need(not os.path.exists("/sys/fs/selinux/enforce")',
                      (ROOT/"linux/manage-conditional-postfix-offline.py").read_text())


class OfflineReviewIntegrationTests(unittest.TestCase):
    def test_review_host_supplies_actual_guard_to_transaction(self):
        runtime=Mock(return_value="a"*64)
        def review(config,uid,mailbox,maintenance,guard):
            self.assertEqual((config,uid,mailbox),(7,0,MAIL))
            self.assertIs(guard,runtime)
            maintenance()
            self.assertEqual(guard(mailbox),"a"*64)
            return "b"*64,{"runtime_sha256":"a"*64},{}
        with patch.object(CLI.O,"mail_identity",return_value=(12,12)), \
             patch.object(CLI.O,"maintenance") as maintenance, \
             patch.object(CLI,"verify_scope"), \
             patch.object(A,"RuntimeGuard",return_value=runtime) as factory, \
             patch.object(CLI.X,"review",side_effect=review), \
             patch.object(CLI.X,"apply") as apply, \
             patch.object(CLI.X,"restore") as restore:
            result=CLI.review_host(7,8,MAIL,TENANT,CLIENT,A.CONFIRM)
            self.assertEqual(result,("b"*64,"a"*64))
            factory.assert_called_once_with(TENANT,CLIENT,A.CONFIRM)
            self.assertGreaterEqual(maintenance.call_count,3)
            apply.assert_not_called()
            restore.assert_not_called()

    def test_apply_wires_fresh_native_review_and_auth_guard(self):
        runtime=Mock(return_value="a"*64)
        plan=("b"*64,{"runtime_sha256":"a"*64},{})
        maintenance=Mock()
        def apply(config,parent,revision,uid,confirmation,guard,fresh,native,auth):
            self.assertEqual((config,parent,revision,uid,confirmation),(7,9,"b"*64,0,CLI.X.APPLY))
            self.assertIs(guard,maintenance)
            self.assertIs(auth,runtime)
            self.assertEqual(fresh(),plan)
            self.assertEqual(auth(MAIL),"a"*64)
            self.assertEqual(native(),{"sample":"native"})
            return revision
        with patch.object(CLI,"host_guard",return_value=maintenance) as make_guard, \
             patch.object(A,"RuntimeGuard",return_value=runtime) as factory, \
             patch.object(CLI.X,"review",return_value=plan) as review, \
             patch.object(CLI.X,"apply",side_effect=apply), \
             patch.object(CLI.X.R,"native_snapshot",return_value={"sample":"native"}):
            self.assertEqual(CLI.apply_host(7,8,9,MAIL,TENANT,CLIENT,"b"*64,
                                           CLI.X.APPLY,A.CONFIRM),"b"*64)
            make_guard.assert_called_once_with(7,8,9)
            factory.assert_called_once_with(TENANT,CLIENT,A.CONFIRM)
            review.assert_called_once_with(7,0,MAIL,maintenance,runtime)

    def test_restore_does_not_require_working_credentials_or_network(self):
        guard=Mock()
        with patch.object(CLI,"host_guard",return_value=guard), \
             patch.object(A,"RuntimeGuard",side_effect=AssertionError("no auth in restore")), \
             patch.object(CLI.X,"restore",return_value="b"*64) as restore:
            self.assertEqual(CLI.restore_host(7,8,9,"b"*64,CLI.X.RESTORE),"b"*64)
            restore.assert_called_once_with(7,9,"b"*64,0,CLI.X.RESTORE,guard,CLI.read_native)

    def test_verify_scope_uses_actual_expanded_queue_and_single_instance(self):
        def output(values):
            return Mock(returncode=0,stderr=b"",stdout="".join(
                key+" = "+value+"\n" for key,value in values.items()).encode())
        # Real postconf empty settings are printed as "key = " plus LF.
        values=dict(CLI.SCOPE)
        with patch.object(CLI.X,"snapshot",return_value=("main","master")), \
             patch.object(CLI.X.R,"command",return_value=output(values)) as command:
            CLI.verify_scope(7)
            self.assertEqual(command.call_args[0][0],"postconf")
            for key,value in (("queue_directory","/var/spool/another"),
                              ("multi_instance_enable","yes"),
                              ("mail_owner","other")):
                command.return_value=output(dict(values,**{key:value}))
                with self.assertRaises(CLI.X.Refused):
                    CLI.verify_scope(7)

    def test_backup_inspection_does_not_verify_mixed_pair_as_ready(self):
        guard=Mock()
        with patch.object(CLI,"host_guard",return_value=guard), \
             patch.object(CLI.X,"load_backup",return_value=({},{})), \
             patch.object(CLI.X,"phase",return_value="pipe_only"), \
             patch.object(CLI.X,"verify") as verify, \
             patch.object(CLI.X,"restore") as restore:
            self.assertEqual(CLI.inspect_backup_host(7,8,9,"b"*64),"pipe_only")
            verify.assert_not_called()
            restore.assert_not_called()

    def test_verify_applied_rechecks_native_pair_and_runtime_without_writes(self):
        revision="b"*64
        info={"mailbox":MAIL,"runtime_sha256":"a"*64}
        runtime=Mock(return_value="a"*64)
        guard=Mock()
        with patch.object(CLI,"host_guard",return_value=guard), \
             patch.object(CLI.X,"load_backup",return_value=(info,{})), \
             patch.object(CLI.X,"verify") as verify, \
             patch.object(CLI.X,"phase",return_value="after") as phase, \
             patch.object(A,"RuntimeGuard",return_value=runtime) as factory, \
             patch.object(CLI.X,"apply") as apply, \
             patch.object(CLI.X,"restore") as restore:
            self.assertEqual(CLI.verify_applied_host(7,8,9,revision,MAIL,TENANT,CLIENT,A.CONFIRM),"a"*64)
            factory.assert_called_once_with(TENANT,CLIENT,A.CONFIRM,expected_sha="a"*64)
            self.assertEqual(verify.call_count,2)
            self.assertEqual(runtime.call_count,2)
            self.assertTrue(all(call[0][4]=="after" for call in verify.call_args_list))
            runtime.reset_mock()
            factory.reset_mock()
            verify.side_effect=CLI.X.Refused("not applied")
            with self.assertRaises(CLI.X.Refused):
                CLI.verify_applied_host(7,8,9,revision,MAIL,TENANT,CLIENT,A.CONFIRM)
            factory.assert_not_called()
            runtime.assert_not_called()
            verify.side_effect=None
            with self.assertRaises(CLI.X.Refused):
                CLI.verify_applied_host(7,8,9,revision,"other@example.org",TENANT,CLIENT,A.CONFIRM)
            factory.assert_not_called()
            runtime.return_value="c"*64
            with self.assertRaisesRegex(CLI.X.Refused,"applied_runtime_changed"):
                CLI.verify_applied_host(7,8,9,revision,MAIL,TENANT,CLIENT,A.CONFIRM)
            runtime.return_value="a"*64
            phase.return_value="pipe_only"
            with self.assertRaisesRegex(CLI.X.Refused,"applied_configuration_changed"):
                CLI.verify_applied_host(7,8,9,revision,MAIL,TENANT,CLIENT,A.CONFIRM)
            apply.assert_not_called()
            restore.assert_not_called()

    def test_controlled_start_order_and_no_rollback_after_uncertain_start(self):
        revision="b"*64
        state={"identity_sha256":"a"*64}
        info={"mailbox":MAIL,"runtime_sha256":A.digest(state)}
        runtime=Mock(return_value=info["runtime_sha256"])
        events=[]
        guard=Mock()
        def verify(config,uid,manifest,files,phase,check,native):
            self.assertEqual(phase,"after")
            check()
        with patch.object(CLI,"host_guard",return_value=guard), \
             patch.object(CLI.O,"mail_identity",return_value=(12,12)), \
             patch.object(CLI.O,"same_directory"), \
             patch.object(CLI.O.M,"check_directory"), \
             patch.object(CLI.os,"listxattr",return_value=[]), \
             patch.object(CLI.os.path,"exists",return_value=False), \
             patch.object(CLI,"verify_scope"), \
             patch.object(CLI,"running_status",side_effect=lambda:events.append("running")), \
             patch.object(CLI.X,"load_backup",return_value=(info,{})), \
             patch.object(CLI.X,"verify",side_effect=verify), \
             patch.object(CLI.X,"phase",return_value="after"), \
             patch.object(A,"RuntimeGuard",return_value=runtime) as factory, \
             patch.object(A,"installed_snapshot",return_value=state), \
             patch.object(CLI.X,"restore") as restore:
            def call(checker,starter):
                return CLI.start_applied_host(7,8,9,revision,MAIL,TENANT,CLIENT,
                    CLI.START,A.CONFIRM,lambda:events.append("mark_check"),
                    lambda:events.append("mark_start"),checker,starter)
            checker=Mock(side_effect=lambda action:events.append(action))
            starter=Mock(side_effect=lambda:events.append("start"))
            self.assertEqual(call(checker,starter),info["runtime_sha256"])
            self.assertEqual(events[:4],["mark_check","check","mark_start","start"])
            self.assertIn("running",events)
            factory.assert_called_once_with(TENANT,CLIENT,A.CONFIRM,expected_sha=info["runtime_sha256"])
            restore.assert_not_called()
            events.clear()
            checker.side_effect=CLI.X.Refused("check failed")
            starter.reset_mock()
            with self.assertRaises(CLI.X.Refused):
                call(checker,starter)
            self.assertEqual(events,["mark_check"])
            starter.assert_not_called()
            events.clear()
            checker.side_effect=lambda action:events.append(action)
            starter.side_effect=subprocess.TimeoutExpired("start",60)
            with self.assertRaises(subprocess.TimeoutExpired):
                call(checker,starter)
            self.assertEqual(events,["mark_check","check","mark_start"])
            restore.assert_not_called()

    def test_cli_modes_confirmations_and_failure_report(self):
        from contextlib import redirect_stdout
        from io import StringIO
        base=["--maintenance-confirmation",CLI.O.MAINTENANCE]
        identity=["--mailbox",MAIL,"--tenant-id",TENANT,"--client-id",CLIENT]
        with patch.object(CLI.os,"geteuid",return_value=0), \
             patch.object(CLI.A.R.E,"trusted_directory"), \
             patch.object(CLI.os,"umask"),patch.object(CLI.os,"close"), \
             patch.object(CLI.signal,"signal"),patch.object(CLI.signal,"alarm"), \
             patch.object(CLI.O,"route_lock",return_value=3) as lock, \
             patch.object(CLI.A.C,"lock",return_value=4), \
             patch.object(CLI.O.P,"open_directory",side_effect=lambda *a,**k:5), \
             patch.object(CLI,"apply_host",return_value="b"*64) as apply, \
             patch.object(CLI,"restore_host",return_value="b"*64) as restore, \
             patch.object(CLI,"inspect_backup_host",return_value="pipe_only") as inspect, \
             patch.object(CLI,"verify_applied_host",return_value="a"*64) as verify_applied, \
             patch.object(CLI,"start_applied_host") as start:
            def call(args):
                stream=StringIO()
                with redirect_stdout(stream):
                    result=CLI.main(base+args)
                return result,stream.getvalue()
            rc,report=call(["--apply","--expected-sha256","b"*64,"--confirm",CLI.X.APPLY]+identity)
            self.assertEqual(rc,2)
            lock.assert_not_called()
            apply.assert_not_called()
            rc,report=call(["--apply","--expected-sha256","b"*64,"--confirm",CLI.X.APPLY,
                            "--auth-confirmation",A.CONFIRM]+identity)
            self.assertEqual(rc,0)
            self.assertIn("POSTFIX_CHANGED=yes",report)
            self.assertIn("BACKUP_SHA256="+"b"*64,report)
            self.assertIn("MAIL_SUBMITTED=no",report)
            apply.side_effect=CLI.X.T.RollbackRequired("private detail")
            rc,report=call(["--apply","--expected-sha256","b"*64,"--confirm",CLI.X.APPLY,
                            "--auth-confirmation",A.CONFIRM]+identity)
            self.assertEqual(rc,2)
            self.assertIn("manual_recovery_required",report)
            self.assertIn("POSTFIX_CHANGED=inspect_recovery",report)
            self.assertIn("RECOVERY_SHA256="+"b"*64,report)
            self.assertNotIn("private detail",report)
            rc,report=call(["--restore","b"*64,"--confirm",CLI.X.RESTORE])
            self.assertEqual(rc,0)
            self.assertIn("SMTP_AUTH=not_attempted",report)
            self.assertIn("POSTFIX_CHANGED=restored",report)
            restore.assert_called_once()
            rc,report=call(["--inspect-backup","b"*64])
            self.assertEqual(rc,0)
            self.assertIn("PHASE=pipe_only",report)
            self.assertIn("POSTFIX_CHANGED=no",report)
            inspect.assert_called_once()
            rc,report=call(["--verify-applied","b"*64]+identity)
            self.assertEqual(rc,2)
            verify_applied.assert_not_called()
            rc,report=call(["--verify-applied","b"*64,"--confirm",A.CONFIRM]+identity)
            self.assertEqual(rc,0)
            self.assertIn("STATUS=applied_runtime_reverified_not_started",report)
            self.assertIn("RUNTIME_SHA256="+"a"*64,report)
            self.assertIn("PHASE=after",report)
            self.assertIn("POSTFIX_CHANGED=no",report)
            self.assertIn("SERVICE_STARTED=no",report)
            verify_applied.assert_called_once_with(5,5,5,"b"*64,MAIL,TENANT,CLIENT,A.CONFIRM)
            rc,report=call(["--start","b"*64,"--confirm",CLI.START]+identity)
            self.assertEqual(rc,2)
            start.assert_not_called()
            def observe(*args):
                args[-2]()
                args[-1]()
                return "a"*64
            start.side_effect=observe
            request=["--start","b"*64,"--confirm",CLI.START,"--auth-confirmation",A.CONFIRM]+identity
            rc,report=call(request)
            self.assertEqual(rc,0)
            self.assertIn("STATUS=started_running_observed",report)
            self.assertIn("SERVICE_STARTED=observed_running",report)
            self.assertIn("QUEUE_MODIFIED=not_verified",report)
            def uncertain(*args):
                args[-2]()
                args[-1]()
                raise subprocess.TimeoutExpired("start",60)
            start.side_effect=uncertain
            rc,report=call(request)
            self.assertEqual(rc,2)
            self.assertIn("STATUS=start_outcome_unverified",report)
            self.assertIn("SERVICE_STARTED=unverified",report)
            self.assertIn("RECOVERY_SHA256="+"b"*64,report)
            restore.assert_called_once()

    def test_cli_keeps_both_locks_and_only_explicit_start_controls_service(self):
        source=(ROOT/"linux/manage-primary-mailbox-offline.py").read_text()
        self.assertIn("fds.append(O.route_lock())",source)
        self.assertIn("fds.append(A.C.lock())",source)
        self.assertIn('elif args.start is not None:',source)
        self.assertIn('"start","postfix.service"',source)
        self.assertNotIn('"stop","postfix.service"',source)
        self.assertNotIn('"restart","postfix.service"',source)


class OfflineGuiContracts(unittest.TestCase):
    def test_bundle_has_all_required_resources_and_no_service_control(self):
        src=ROOT/"src/LinuxMailRelay365"
        assets=(src/"EmbeddedAssets.cs").read_text()
        bundle=assets.split("internal static string BuildPrimaryMailboxOffline(",1)[1].split(
            "internal static string BuildPrimaryMailboxRoutePreviewBundle",1)[0]
        project=(src/"LinuxMailRelay365.csproj").read_text()
        for file in ("manage-primary-mailbox-offline.py","primary-mailbox-transaction.py",
                     "primary-mailbox-runtime.py","preview-primary-mailbox-route.py","smtp-tls-postfix.py",
                     "manage-tpm-oauth-key.py",
                     "manage-primary-oauth-rotation.py","m365_xoauth2_transport.py",
                     "m365_hardware_signer.py","export-hardware-oauth-cert.py",
                     "manage-conditional-postfix-offline.py","inspect-conditional-postfix-activation.py",
                     "conditional-postfix-transaction.py","stage-conditional-postfix-maps.py"):
            self.assertIn('"'+file+'"',bundle)
            self.assertIn("../../linux/"+file,project)
        self.assertIn("PrimaryMailboxOfflineClient.Arguments",bundle)
        self.assertIn("/run/lmr365-primary-mailbox.",bundle)
        self.assertNotIn("systemctl start",bundle)

    def test_gui_uses_separate_approvals_and_recovery_inspection(self):
        src=ROOT/"src/LinuxMailRelay365"
        ui=(src/"MainForm.PrimaryMailboxOffline.cs").read_text()
        self.assertIn("RequireSameArchiveConnection(endpoint)",ui)
        self.assertIn("ConfirmDestructive",ui)
        self.assertIn('LinuxAsync("review",identity,null,PrimaryMailboxOfflineClient.Auth)',ui)
        self.assertIn('LinuxAsync("apply",identity,plan.Sha,PrimaryMailboxOfflineClient.Apply,PrimaryMailboxOfflineClient.Auth)',ui)
        self.assertIn('LinuxAsync("inspect-backup",null,sha,null)',ui)
        self.assertIn('LinuxAsync("verify-applied",identity,sha,PrimaryMailboxOfflineClient.Auth)',ui)
        self.assertIn('LinuxAsync("start",identity,evidence.Sha,PrimaryMailboxOfflineClient.Start,PrimaryMailboxOfflineClient.Auth)',ui)
        self.assertIn('bool ready=!busy && !startAttempted && maintenance.Checked',ui)
        self.assertIn('start.Enabled=verifyApplied.Enabled && verifiedApplied is not null',ui)
        self.assertIn('result.RuntimeSha!=evidence.RuntimeSha',ui)
        start_handler=ui.split("start.Click+=",1)[1].split("restore.Click+=",1)[0]
        self.assertLess(start_handler.index("startAttempted=true"),start_handler.index('LinuxAsync("start"'))
        self.assertIn("mutationAttempted=true",start_handler)
        self.assertNotIn('LinuxAsync("restore"',start_handler)
        self.assertIn("Postfix MAY be running",ui)
        self.assertIn('inspectedPhase=="after" && target',ui)
        self.assertIn('LinuxAsync("restore",null,sha,PrimaryMailboxOfflineClient.Restore)',ui)
        self.assertIn('inspectedPhase is "after" or "pipe_only"',ui)
        self.assertIn("mutationAttempted=true",ui)
        self.assertIn("discoveredMailIdentity=null",ui)
        self.assertIn("OpenPrimaryMailboxOfflineAsync",(src/"MainForm.PrimaryMailboxRoute.cs").read_text())
        self.assertIn("PrimaryMailboxOfflineClient.SelfTest",(src/"Program.cs").read_text())


class PrimaryMailboxDeliveryGuiContracts(unittest.TestCase):
    def test_delivery_bundle_dialog_and_trace_lock(self):
        src=ROOT/"src/LinuxMailRelay365"
        assets=(src/"EmbeddedAssets.cs").read_text()
        project=(src/"LinuxMailRelay365.csproj").read_text()
        ui=(src/"MainForm.PrimaryMailboxDelivery.cs").read_text()
        for file in ("probe-primary-mailbox-delivery.py","review-postfix-m365-delivery.py"):
            self.assertIn('"'+file+'"',assets)
            self.assertIn("../../linux/"+file,project)
        self.assertIn("PrimaryMailboxBundle(true)",assets)
        self.assertIn("RequireSameArchiveConnection(endpoint)",ui)
        self.assertIn("ConfirmDestructive",ui)
        send=ui.split("send.Click+=",1)[1].split("trace.Click+=",1)[0]
        self.assertLess(send.index("LockTrace(request,sha)"),send.index('Remote("submit"'))
        self.assertIn("review.Enabled=!busy && !traceOnly",ui)
        self.assertIn("LockTrace(request,null)",ui)
        self.assertIn("Copy trace request",ui)
        self.assertIn('ReadPrimaryMailboxExchangeTraceAsync(request,local,Guard)',ui)
        cloud=ui.split("cloudTrace.Click+=",1)[1].split("copy.Click+=",1)[0]
        self.assertLess(cloud.index('Remote("trace"'),cloud.index("ReadPrimaryMailboxExchangeTraceAsync"))
        self.assertNotIn('Remote("submit"',cloud)
        shared=(src/"MainForm.PostfixExchangeTrace.cs").read_text()
        self.assertIn("CheckCloudTenant(id)",shared)
        self.assertIn("ExchangeTracePayload(request,local,DateTimeOffset.UtcNow)",shared)
        self.assertIn("RunRecordedExchangeTraceAsync(id,request.RunId,attempted,payload,Guard)",shared)
        parser=(src/"PrimaryMailboxDeliveryClient.cs").read_text()
        self.assertIn("requestSha==request.RequestSha()",parser)
        self.assertIn("now.AddDays(-7)",parser)
        self.assertIn("JavaScriptEncoder.UnsafeRelaxedJsonEscaping",parser)
        self.assertIn("PrimaryMailboxDeliveryClient.SelfTest",(src/"Program.cs").read_text())
        self.assertIn("OpenPrimaryMailboxDeliveryAsync",(src/"MainForm.PrimaryMailboxRoute.cs").read_text())
        self.assertIn("BuildPrimaryMailboxLocalProbe",assets)
        self.assertIn("new PostfixLocalDeliveryDialog(LocalRemote,recoverySha)",ui)
        self.assertIn("localMailbox.Enabled=!busy && PrimaryMailboxOfflineClient.IsSha",ui)
        local=(src/"PostfixLocalDeliveryDialog.cs").read_text()
        self.assertIn('fields["backup_sha256"]=primaryBackupSha',local)
        self.assertIn("DiscoveryRequest()",local)


class PrimaryMailboxDeliveryProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("primary_delivery_probe",
            ROOT/"linux/probe-primary-mailbox-delivery.py")
        cls.D=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.D)

    def setUp(self):
        self.req={"run_id":"1"*32,"sender":MAIL,"internal":"test@example.org",
                  "external":"test@example.net","accepted_domain":"example.org",
                  "backup_sha256":"b"*64,"tenant_id":TENANT,"client_id":CLIENT}

    def row(self,kind,message):
        return {"SYSLOG_IDENTIFIER":"postfix/"+kind,"_COMM":kind,
                "_EXE":"/usr/lib/postfix/sbin/"+kind,"MESSAGE":message}

    def test_request_and_conservative_route_policy(self):
        D=self.D
        self.assertEqual(D.validate_request(self.req),self.req)
        for key,value in (("backup_sha256","bad"),("external","other@example.org"),
                          ("internal","x@example.net"),("sender","x\n@example.org")):
            with self.assertRaises(Exception):
                D.validate_request(dict(self.req,**{key:value}))
        values={key:"" for key in D.EMPTY}
        values.update(D.C.SCOPE,default_transport="m365xoauth2:",relay_transport="m365xoauth2:",
                      relayhost="",syslog_name="postfix",cleanup_service_name="cleanup",
                      mydestination="localhost, server.example.net",relay_domains="",
                      m365xoauth2_destination_recipient_limit="1",sendmail_path="/usr/sbin/sendmail")
        self.assertEqual(D.policy(values.__getitem__,"",self.req),values)
        for key,value in (("always_bcc","x@example.net"),("mydestination","example.net"),
                          ("default_transport","smtp"),("relayhost","old.example.net"),
                          ("syslog_name","other"),("transport_maps","hash:/etc/postfix/routes")):
            with self.assertRaises(ValueError):
                D.policy(dict(values,**{key:value}).__getitem__,"",self.req)
        with self.assertRaises(ValueError):
            D.policy(values.__getitem__,"m365xoauth2/unix/argv=other",self.req)

    def test_trace_binds_full_request_and_ledger_time_for_cloud_query(self):
        D=self.D
        events={"internal":"attempted","external":"not_attempted"}
        adapter=Mock()
        with patch.object(D.P,"ledger",return_value=(123,events,"a"*64)) as ledger, \
             patch.object(D,"journal_rows",return_value=([],"journal_unavailable")), \
             patch.object(D.P,"queue_rows",return_value=None):
            report=D.trace(self.req,adapter)
        ledger.assert_called_once_with(self.req,include_plan=True)
        self.assertEqual(report["request_sha256"],D.P.digest(D.P.canonical(self.req)))
        self.assertEqual(report["started_unix"],123)
        self.assertEqual(report["plan_sha256"],"a"*64)
        self.assertEqual(report["outcomes"]["internal"]["submission"],"attempted")
        self.assertEqual(report["outcomes"]["external"]["submission"],"not_attempted")
        self.assertFalse(report["inbox_verified"])
        self.assertFalse(report["automatic_retry"])

    def test_exact_pipe_trace_and_no_inbox_claim(self):
        D=self.D
        qid="ABC12345"
        cleanup=self.row("cleanup",qid+": message-id="+D.P.message_id(self.req,"internal"))
        prefix=qid+": to=<test@example.org>, relay=m365xoauth2, delay=1, "
        success=self.row("pipe",prefix+"dsn=2.0.0, status=sent (delivered via m365xoauth2 service (2.0.0 Accepted by Microsoft 365 SMTP))")
        result=D.correlate(self.req,"internal",[cleanup,success],[],"local_submission_accepted")
        self.assertEqual(result["queue_id"],qid)
        self.assertEqual(result["transport"],"exchange_smtp_accepted")
        self.assertNotIn("inbox_verified",result)
        spoof=dict(success,_EXE="/tmp/pipe")
        self.assertEqual(D.correlate(self.req,"internal",[cleanup,spoof],[],"attempted")["transport"],"unknown")
        forged=dict(success,MESSAGE=prefix+"dsn=2.0.0, status=sent (untrusted text 2.0.0 Accepted by Microsoft 365 SMTP)")
        self.assertEqual(D.correlate(self.req,"internal",[cleanup,forged],[],"attempted")["transport"],
                         "pipe_sent_exchange_unverified")
        deferred=self.row("pipe",prefix+"dsn=4.3.0, status=deferred (secret diagnostics)")
        result=D.correlate(self.req,"internal",[cleanup,deferred],[],"attempted")
        self.assertEqual(result["transport"],"deferred")
        self.assertNotIn("secret",str(result))
        bounce=self.row("pipe",prefix+"dsn=5.0.0, status=bounced (failed)")
        self.assertEqual(D.correlate(self.req,"internal",[cleanup,success,bounce],[],"attempted")["transport"],
                         "correlation_unavailable")
        self.assertEqual(D.correlate(self.req,"internal",[cleanup,success],[],"not_attempted")["transport"],
                         "not_attempted")

    def test_submit_requires_exact_approval_and_reuses_durable_ledger(self):
        D=self.D
        fresh=Mock()
        runner=Mock()
        with patch.object(D.P,"submit",return_value={"status":"submission_recorded"}) as submit:
            for confirm,sha in (("wrong","a"*64),(D.CONFIRM,"wrong")):
                with self.assertRaises(ValueError):
                    D.submit(self.req,sha,confirm,fresh,runner)
            submit.assert_not_called()
            self.assertEqual(D.submit(self.req,"a"*64,D.CONFIRM,fresh,runner)["status"],"submission_recorded")
            submit.assert_called_once_with(self.req,"a"*64,prepare_fn=fresh,runner=runner)

    def test_local_migration_review_binds_backup_without_oauth(self):
        D=self.D
        req={"run_id":"1"*32,"recipient":"testuser@server.example.org","backup_sha256":"b"*64}
        local={"run_id":req["run_id"],"recipient":req["recipient"]}
        verify=Mock()
        prepare=Mock(return_value={"plan_sha256":"a"*64,"_binary":"sendmail","_mailbox":{}})
        with patch.object(D,"applied_local_guard",return_value=(verify,"c"*64)), \
             patch.object(D.A,"installed_snapshot",side_effect=AssertionError("no OAuth for local")):
            result=D.prepare_local_migration(req,7,8,9,prepare)
            self.assertNotEqual(result["plan_sha256"],"a"*64)
            prepare.assert_called_once_with(local)
            verify.assert_called_once()
            self.assertNotEqual(D.prepare_local_migration(dict(req,backup_sha256="d"*64),7,8,9,prepare)["plan_sha256"],
                                result["plan_sha256"])
        with self.assertRaises(ValueError):
            D.local_context(dict(req,backup_sha256="wrong"),"local-preview")

    def test_local_submission_and_mailbox_ledger_bind_full_migration(self):
        D=self.D
        req={"run_id":"1"*32,"recipient":"testuser@server.example.org","backup_sha256":"b"*64}
        local={"run_id":req["run_id"],"recipient":req["recipient"]}
        with patch.object(D.P,"submit_local",return_value={"status":"local_submission_recorded"}) as submit:
            with self.assertRaises(ValueError):
                D.local_operation("local-submit",req,7,8,9,"a"*64,"wrong")
            submit.assert_not_called()
            self.assertEqual(D.local_operation("local-submit",req,7,8,9,"a"*64,D.LOCAL_CONFIRM)["status"],
                             "local_submission_recorded")
            self.assertEqual(submit.call_args.args[:2],(local,"a"*64))
            self.assertEqual(submit.call_args.kwargs["ledger_request"],req)
        def observe(request,ledger_fn,prepare_fn):
            self.assertEqual(request,local)
            ledger_fn(request,("local",),include_plan=True)
            return {"request_sha256":"old"}
        with patch.object(D.P,"observe_local_mailbox",side_effect=observe), \
             patch.object(D.P,"ledger") as ledger:
            report=D.local_operation("local-mailbox",req,7,8,9,None,None)
            ledger.assert_called_once_with(req,("local",),include_plan=True)
            self.assertEqual(report["request_sha256"],D.P.digest(D.P.canonical(req)))

    def test_local_migration_trace_uses_local_agent_and_exact_ledger(self):
        D=self.D
        req={"run_id":"1"*32,"recipient":"testuser@server.example.org","backup_sha256":"b"*64}
        local={"run_id":req["run_id"],"recipient":req["recipient"]}
        qid="ABC12345"
        cleanup=self.row("cleanup",qid+": message-id="+D.P.local_message_id(local))
        agent=self.row("local",qid+": to=<"+local["recipient"]+">, relay=local, dsn=2.0.0, status=sent (delivered to mailbox)")
        adapter=Mock()
        with patch.object(D.P,"ledger",return_value=(123,{"local":"attempted"},"a"*64)) as ledger, \
             patch.object(D,"journal_rows",return_value=([cleanup,agent],"journal_recent_only")) as journal, \
             patch.object(D.P,"queue_rows",return_value=[]):
            report=D.trace_local_migration(req,adapter)
        ledger.assert_called_once_with(req,("local",),include_plan=True)
        journal.assert_called_once_with(123,adapter,transport="local")
        self.assertEqual(report["outcome"]["transport"],"local_agent_accepted")
        self.assertEqual(report["request_sha256"],D.P.digest(D.P.canonical(req)))
        self.assertFalse(report["mailbox_verified"])

    def test_source_uses_running_backup_guard_and_never_flushes_or_retries(self):
        source=(ROOT/"linux/probe-primary-mailbox-delivery.py").read_text()
        self.assertIn('X.verify(config,0,info,files,"after",guard,C.read_native)',source)
        self.assertIn('A.installed_snapshot(req["sender"],req["tenant_id"],req["client_id"])',source)
        self.assertIn('fds.append(O.route_lock())',source)
        self.assertIn('fds.append(A.C.lock())',source)
        self.assertIn('P.submit(req,expected,prepare_fn=prepare_fn,runner=runner)',source)
        self.assertNotIn("postqueue -f",source)
        self.assertNotIn("systemctl start",source)


if __name__=="__main__":
    unittest.main()
