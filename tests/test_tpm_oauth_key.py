"""Mocked TPM2 provisioning tests: never access hardware, Postfix or Entra."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "manage-tpm-oauth-key.py"
SPEC = importlib.util.spec_from_file_location("tpm_oauth_provision", str(SOURCE))
TPM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TPM)
REAL_REQUIRE_ROOT = TPM.require_root
REAL_PROVIDER_READY = TPM.provider_ready
REAL_READ_CAPABILITIES = TPM.read_capabilities
ACTIVE = {
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "mailbox": "app@example.org",
    "certificate": "/etc/linuxmailrelay365/sidecar-identity/app.crt",
    "private_key": "/etc/linuxmailrelay365/sidecar-identity/app.key"
}


class TpmRuntimeUtilityTests(unittest.TestCase):
    @staticmethod
    def metadata(mode,uid=0,inode=10):
        return SimpleNamespace(st_dev=1,st_ino=inode,st_mode=mode,
                               st_uid=uid,st_gid=0,st_size=128,
                               st_mtime_ns=100,st_ctime_ns=101)

    def test_native_multicall_alias_and_regular_executable(self):
        alias=TPM.COMMANDS["getcap"]
        common=Path("/usr/bin/tpm2")
        link=self.metadata(stat.S_IFLNK|0o777)
        binary=self.metadata(stat.S_IFREG|0o755,inode=11)
        for value in ("tpm2","/usr/bin/tpm2"):
            with self.subTest(link=value), \
                 mock.patch.object(TPM,"check_dir") as directory, \
                 mock.patch.object(Path,"lstat",lambda p:link if p==alias else binary), \
                 mock.patch.object(TPM.os,"readlink",return_value=value):
                result=TPM.trusted_runtime_tool(alias)
                self.assertEqual(result[0],str(alias))
                self.assertEqual(result[2],value)
                self.assertEqual(result[3],str(common))
                directory.assert_called_once_with(Path("/usr/bin"))
        with mock.patch.object(TPM,"check_dir"), \
             mock.patch.object(Path,"lstat",return_value=binary), \
             mock.patch.object(TPM.os,"readlink") as readlink:
            result=TPM.trusted_runtime_tool(alias)
            self.assertEqual(result[3],str(alias))
            self.assertIsNone(result[2])
            readlink.assert_not_called()

    def test_rejects_untrusted_alias_target_and_drift(self):
        alias=TPM.COMMANDS["getcap"]
        link=self.metadata(stat.S_IFLNK|0o777)
        binary=self.metadata(stat.S_IFREG|0o755,inode=11)
        for value in ("../bin/tpm2","/tmp/tpm2","/usr/bin/other","tpm2_getcap"):
            with mock.patch.object(TPM,"check_dir"), \
                 mock.patch.object(Path,"lstat",return_value=link), \
                 mock.patch.object(TPM.os,"readlink",return_value=value), \
                 self.assertRaisesRegex(TPM.Refused,"unsafe_tpm"):
                TPM.trusted_runtime_tool(alias)
        for target in (link,self.metadata(stat.S_IFREG|0o775),
                       self.metadata(stat.S_IFREG|0o755,uid=1000),
                       self.metadata(stat.S_IFREG|0o4755),
                       self.metadata(stat.S_IFREG|0o644)):
            with mock.patch.object(TPM,"check_dir"), \
                 mock.patch.object(Path,"lstat",side_effect=[link,target]), \
                 mock.patch.object(TPM.os,"readlink",return_value="tpm2"), \
                 self.assertRaisesRegex(TPM.Refused,"unsafe_tpm"):
                TPM.trusted_runtime_tool(alias)
        with mock.patch.object(TPM,"check_dir"), \
             mock.patch.object(Path,"lstat",return_value=self.metadata(stat.S_IFLNK|0o777,uid=1000)), \
             self.assertRaisesRegex(TPM.Refused,"unsafe_tpm"):
            TPM.trusted_runtime_tool(alias)
        with mock.patch.object(TPM,"check_dir"), \
             mock.patch.object(Path,"lstat",return_value=link), \
             mock.patch.object(TPM.os,"readlink",return_value="tpm2"), \
             self.assertRaisesRegex(TPM.Refused,"unsafe_tpm"):
            TPM.trusted_runtime_tool(TPM.COMMANDS["openssl"])
        changed=self.metadata(stat.S_IFLNK|0o777,inode=99)
        with mock.patch.object(TPM,"check_dir"), \
             mock.patch.object(Path,"lstat",side_effect=[link,binary,changed]), \
             mock.patch.object(TPM.os,"readlink",return_value="tpm2"), \
             self.assertRaisesRegex(TPM.Refused,"utility_changed"):
            TPM.trusted_runtime_tool(alias)
        with mock.patch.object(TPM,"check_dir"), \
             mock.patch.object(Path,"lstat",side_effect=FileNotFoundError()), \
             self.assertRaisesRegex(TPM.Refused,"missing_tpm"):
            TPM.trusted_runtime_tool(alias)


class TpmOAuthKeyTests(unittest.TestCase):
    def setUp(self):
        self.handle = "0x81010001"
        self.active = (json.dumps(ACTIVE) + "\n").encode("ascii")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for obj, name, kwargs in [
            (TPM, "require_root", {}),
            (TPM, "check_dir", {}),
            (TPM, "check_hardware", {"return_value": "2"}),
            (TPM, "check_runtime_files", {"return_value":{"getcap":["trusted_fixture"]}}),
            (TPM, "read_checked", {"return_value": self.active}),
            (TPM, "check_empty_destination", {}),
            (TPM, "provider_ready", {"return_value": "OpenSSL 3.0.9"})]:
            self.stack.enter_context(mock.patch.object(obj, name, **kwargs))
        self.stack.enter_context(mock.patch.object(TPM.grp, "getgrnam",
                                 return_value=SimpleNamespace(gr_gid=999)))
        self.stack.enter_context(mock.patch.object(TPM.pwd, "getpwnam",
                                 return_value=SimpleNamespace(pw_uid=999)))
        self.handles = self.stack.enter_context(
            mock.patch.object(TPM, "read_capabilities", return_value=set()))

    def plan(self, handle="0x81010001"):
        return TPM.prepare("sidecar", handle)

    def test_readonly_plan_stable_and_handle_allowlist(self):
        p = self.plan()
        self.assertEqual(p["sha"], self.plan()["sha"])
        self.assertEqual(len(p["sha"]), 64)
        self.assertEqual(p["handle"], self.handle)
        self.assertEqual(p["evidence"]["tpm_major"], "2")
        self.assertEqual(p["evidence"]["active_sha256"], TPM.sha(self.active))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            TPM.report(p)
        result = buf.getvalue()
        self.assertIn("TPM_PROVISION_KEY_CREATED=no", result)
        self.assertIn("TPM_PROVISION_ACTIVE_OAUTH_CHANGED=no", result)
        self.assertIn("TPM_PROVISION_ENTRA_CONTACTED=no", result)
        self.assertNotIn(ACTIVE["mailbox"], result)
        for bad in ("0x81000000", "0x81020000", "0x8101fffg",
                    "0x81010000;rm", "0x810100010", "", "/etc/passwd"):
            with self.subTest(handle=bad), self.assertRaises(TPM.Refused):
                self.plan(bad)

    def test_primary_preflight_is_bound_and_sidecar_plan_unchanged(self):
        original=self.plan()["sha"]
        access={"uid":999,"gid":999,"groups":[999],"device":[1,2,3,0,999,0o20660]}
        with mock.patch.object(TPM,"primary_service_device_evidence",return_value=access) as probe:
            primary=TPM.prepare("primary",self.handle)
            self.assertEqual(primary["evidence"]["primary_service_access"],access)
            self.assertEqual(primary["evidence"]["primary_runtime_utilities"],
                             {"getcap":["trusted_fixture"]})
            with mock.patch.object(TPM,"check_runtime_files",return_value={"getcap":["changed"]}):
                with self.assertRaisesRegex(TPM.Refused,"utility_changed"):
                    TPM.verify_primary_creation_access(primary)
            self.assertEqual(probe.call_count,3)
            probe.return_value=dict(access,device=[1,2,4,0,999,0o20660])
            self.assertNotEqual(TPM.prepare("primary",self.handle)["sha"],primary["sha"])
            with self.assertRaisesRegex(TPM.Refused,"service_access_changed"):
                TPM.verify_primary_creation_access(primary)
            probe.side_effect=TPM.Refused("primary_tpm_service_device_access_requires_review")
            with self.assertRaisesRegex(TPM.Refused,"device_access_requires_review"):
                TPM.prepare("primary",self.handle)
            probe.reset_mock()
            self.assertEqual(self.plan()["sha"],original)
            probe.assert_not_called()
            TPM.verify_primary_creation_access(self.plan())
            probe.assert_not_called()

    def test_primary_access_denied_before_any_tpm_creation(self):
        access={"uid":999,"gid":999,"groups":[999]}
        with mock.patch.object(TPM,"primary_service_device_evidence",return_value=access) as probe:
            primary=TPM.prepare("primary",self.handle)
            with mock.patch.object(TPM,"lock",return_value=77), \
                 mock.patch.object(TPM.os,"close"), \
                 mock.patch.object(TPM,"run_command") as command, \
                 contextlib.redirect_stdout(io.StringIO()):
                # Two fresh plans (four access observations) pass. The
                # final access check before CreatePrimary refuses.
                probe.side_effect=[access]*4+[TPM.Refused("primary_tpm_service_device_access_requires_review")]
                with self.assertRaisesRegex(TPM.Refused,"device_access_requires_review"):
                    TPM.apply("primary",self.handle,primary["sha"],TPM.CONFIRM)
                command.assert_not_called()

    def test_primary_device_probe_uses_exact_credentials_and_rejects_drift(self):
        account=SimpleNamespace(pw_name="m365mailer",pw_uid=999,pw_gid=999)
        device=SimpleNamespace(st_dev=1,st_ino=2,st_rdev=3,st_uid=0,st_gid=999,
                               st_mode=stat.S_IFCHR|0o660,st_ctime_ns=10)
        runner=mock.Mock(return_value=SimpleNamespace(
            returncode=0,stdout=b"TPM_RESOURCE_MANAGER_OPEN_CLOSE_OK\n",stderr=b""))
        with mock.patch.object(TPM.pwd,"getpwnam",return_value=account), \
             mock.patch.object(TPM.os,"getgrouplist",return_value=[999]) as groups, \
             mock.patch.object(TPM,"DEVICE",mock.Mock(lstat=mock.Mock(return_value=device))) as node, \
             mock.patch.object(TPM,"primary_python_fingerprint",return_value=["trusted"]):
            evidence=TPM.primary_service_device_evidence(999,runner)
            self.assertEqual(evidence["device"],TPM.primary_device_fingerprint(device))
            argv=runner.call_args[0][0]
            self.assertEqual(argv[:5],["/usr/bin/python3","-I","-B","-c",TPM.TPM_OPEN_PROBE])
            self.assertEqual(argv[5:7],["999","999"])
            compile(TPM.TPM_OPEN_PROBE,"fixed-device-probe","exec")
            drop=runner.call_args[1]["preexec_fn"]
            with mock.patch.object(TPM.os,"setgroups") as sg, \
                 mock.patch.object(TPM.os,"setgid") as gid, \
                 mock.patch.object(TPM.os,"setuid") as uid, \
                 mock.patch.object(TPM.os,"getresuid",return_value=(999,999,999)), \
                 mock.patch.object(TPM.os,"getresgid",return_value=(999,999,999)), \
                 mock.patch.object(TPM.os,"getgroups",return_value=[]):
                drop()
                sg.assert_called_once_with([])
                gid.assert_called_once_with(999)
                uid.assert_called_once_with(999)
            groups.return_value=[999,1000]
            runner.reset_mock()
            with self.assertRaisesRegex(TPM.Refused,"service_account_or_groups"):
                TPM.primary_service_device_evidence(999,runner)
            runner.assert_not_called()
            groups.return_value=[999]
            runner.return_value=SimpleNamespace(returncode=1,stdout=b"",stderr=b"denied")
            with self.assertRaisesRegex(TPM.Refused,"device_access_requires_review"):
                TPM.primary_service_device_evidence(999,runner)
            runner.return_value=SimpleNamespace(
                returncode=0,stdout=b"TPM_RESOURCE_MANAGER_OPEN_CLOSE_OK\n",stderr=b"")
            changed=SimpleNamespace(**dict(vars(device),st_ctime_ns=11))
            node.lstat.side_effect=[device,changed]
            with self.assertRaisesRegex(TPM.Refused,"service_access_changed"):
                TPM.primary_service_device_evidence(999,runner)

    def test_plan_changes_when_tpm_inventory_changes(self):
        first = self.plan()
        self.handles.return_value = {"0x81000001"}
        self.assertNotEqual(first["sha"], self.plan()["sha"])
        self.handles.return_value = {self.handle}
        with self.assertRaisesRegex(TPM.Refused, "occupied"):
            self.plan()

    def test_real_root_gate_and_openssl3_gate(self):
        with mock.patch.object(TPM.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(TPM.Refused, "root_required"):
                REAL_REQUIRE_ROOT()
        with mock.patch.object(TPM, "run_command",
                               side_effect=[b"OpenSSL 1.1.1k\n"]) as runner:
            with self.assertRaisesRegex(TPM.Refused, "openssl3"):
                REAL_PROVIDER_READY()
            self.assertEqual(runner.call_count, 1)
        with mock.patch.object(TPM, "run_command",
                               side_effect=[b"OpenSSL 3.0.7\n",
                                            TPM.Refused("tpm2_openssl_provider_missing")]):
            with self.assertRaisesRegex(TPM.Refused, "provider_missing"):
                REAL_PROVIDER_READY()

    def test_capability_inventory_parse_and_failclosed(self):
        with mock.patch.object(TPM, "run_command",
                               return_value=b"- 0x81010001\n- 0x81000002\n"):
            self.assertEqual(REAL_READ_CAPABILITIES(),
                             {"0x81010001", "0x81000002"})
        with mock.patch.object(TPM, "run_command", return_value=b"invalid\n"):
            with self.assertRaisesRegex(TPM.Refused, "unparseable"):
                REAL_READ_CAPABILITIES()

    def test_approval_denied_before_tpm_change(self):
        with mock.patch.object(TPM, "lock") as lock, \
             mock.patch.object(TPM, "run_command") as run:
            with self.assertRaisesRegex(TPM.Refused, "approval"):
                TPM.apply("sidecar", self.handle, "a" * 64, "WRONG")
            lock.assert_not_called()
            run.assert_not_called()

    def test_command_order_and_no_evict_of_permanent_handle(self):
        p = self.plan()
        events = []
        persisted = {"yes": False}
        def fake_command(argv, **kwargs):
            name = Path(argv[0]).name
            if name == "tpm2_createprimary":
                self.assertIn("-u", argv)
                raw = Path(argv[argv.index("-u") + 1]).read_bytes()
                self.assertEqual(len(raw), 34)
                self.assertEqual(raw[:2], b"\x20\x00")
                self.assertIn("rsa2048:null:null", argv)
                events.append("create")
            elif name == "tpm2_readpublic":
                Path(argv[argv.index("-o") + 1]).write_bytes(b"same-public-key")
                events.append("readpublic")
            elif name == "tpm2_evictcontrol":
                self.assertIn("-c", argv)
                self.assertTrue(argv[argv.index("-c") + 1].endswith("primary.ctx"))
                self.assertEqual(argv[-1], self.handle)
                self.assertFalse(persisted["yes"])
                persisted["yes"] = True
                events.append("persist_transient")
            elif name == "openssl":
                self.assertIn("req", argv)
                Path(argv[argv.index("-out") + 1]).write_bytes(
                    b"-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n")
                events.append("cert")
            return b""

        def caps():
            return {self.handle} if persisted["yes"] else set()

        def write(path, raw, gid, mode):
            events.append("publish_" + path.name)

        self.handles.side_effect = caps
        with mock.patch.object(TPM, "lock", return_value=77), \
             mock.patch.object(TPM.os, "close"), \
             mock.patch.object(TPM, "run_command", side_effect=fake_command), \
             mock.patch.object(TPM, "write_exclusive", side_effect=write), \
             mock.patch.object(TPM, "verify_service_signature",
                               side_effect=lambda *args: events.append("verify_as_m365mailer")), \
             mock.patch.object(TPM, "fsync_directory"), \
             contextlib.redirect_stdout(io.StringIO()) as report:
            TPM.apply("sidecar", self.handle, p["sha"], TPM.CONFIRM)
        self.assertEqual(events, ["create", "readpublic",
                                  "persist_transient", "readpublic",
                                  "publish_tpm2.cnf", "cert",
                                  "publish_hardware-app.crt", "verify_as_m365mailer"])
        output = report.getvalue()
        self.assertIn("TPM_PROVISION_PERSISTENT_KEY_CREATED=yes", output)
        self.assertIn("TPM_PROVISION_HARDWARE_ATTESTATION_VERIFIED=no", output)
        self.assertIn("TPM_PROVISION_ACTIVE_OAUTH_CHANGED=no", output)
        self.assertIn("TPM_PROVISION_TPM_OBJECTS_REMOVED=no", output)

    def test_failure_does_not_delete_tpm_object(self):
        p = self.plan()
        with mock.patch.object(TPM, "lock", return_value=77), \
             mock.patch.object(TPM.os, "close"), \
             mock.patch.object(TPM, "run_command",
                               side_effect=TPM.Refused("tpm_primary_key_creation_failed")) as run, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(TPM.Refused, "creation_failed"):
                TPM.apply("sidecar", self.handle, p["sha"], TPM.CONFIRM)
        self.assertNotIn("tpm2_evictcontrol", str(run.call_args_list))
        self.assertIn("TPM_PROVISION_KEY_MAY_EXIST=unknown", out.getvalue())

    def test_cli_plan_only_and_no_secret_leaks(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(TPM.main(["--target", "sidecar", "--handle",
                                       self.handle, "--plan"]), 0)
            self.assertEqual(TPM.main(["--target", "sidecar", "--handle",
                                       self.handle, "--plan", "--confirm",
                                       TPM.CONFIRM]), 2)
        self.assertIn("TPM_PROVISION_ERROR=approval_forbidden_in_readonly_mode",
                      output.getvalue())
        code = SOURCE.read_text(encoding="utf-8")
        for blocked in ("tpm2_clear", "dnf install", "apt-get install",
                        "systemctl restart", "postconf -e", "openssl genrsa"):
            self.assertNotIn(blocked, code)


if __name__ == "__main__":
    unittest.main()
