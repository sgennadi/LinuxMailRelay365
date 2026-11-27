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
            args=runner.call_args.args[0]
            self.assertEqual(args,["/usr/bin/python3","-E","-s","-B",
                "/usr/local/libexec/m365_xoauth2_transport.py","--smtp-auth-check",
                "--config","/etc/postfix/m365-oauth/app.json"])
            kw=runner.call_args.kwargs
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
            self.assertEqual(command.call_args.args[0],"postconf")
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
             patch.object(CLI,"inspect_backup_host",return_value="pipe_only") as inspect:
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

    def test_cli_keeps_both_locks_and_never_starts_service(self):
        source=(ROOT/"linux/manage-primary-mailbox-offline.py").read_text()
        self.assertIn("fds.append(O.route_lock())",source)
        self.assertIn("fds.append(A.C.lock())",source)
        self.assertIn("PRIMARY_MAILBOX_OFFLINE_MAIL_SUBMITTED=no",source)
        self.assertNotIn("systemctl start",source)


if __name__=="__main__":
    unittest.main()
