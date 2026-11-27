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

    def test_cli_has_no_apply_or_restore_operation(self):
        source=(ROOT/"linux/manage-primary-mailbox-offline.py").read_text()
        self.assertNotIn('parser.add_argument("--apply"',source)
        self.assertNotIn('parser.add_argument("--restore"',source)
        self.assertIn("fds.append(O.route_lock())",source)
        self.assertIn("fds.append(A.C.lock())",source)
        self.assertIn("PRIMARY_MAILBOX_OFFLINE_MAIL_SUBMITTED=no",source)


if __name__=="__main__":
    unittest.main()
