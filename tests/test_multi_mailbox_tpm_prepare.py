"""Mocked TPM provisioning boundaries. No physical TPM or tenant accessed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mapped_tpm",str(ROOT/"linux/prepare-multi-mailbox-tpm.py"))
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MappedTpmTests(unittest.TestCase):
    def job(self):
        return dict(action="preview",handle="0x81010001",confirm="",identity=dict(
            tenant="11111111-1111-4111-8111-111111111111",client="22222222-2222-4222-8222-222222222222",
            mailbox="alice@example.org",days=365,source_sha="",nonce="a"*64,approval="",confirm=""))

    def test_discovery_does_not_allocate(self):
        with mock.patch.object(M,"hardware",return_value=("absent","OpenSSL 3.0.9",{"0x81010000"})), \
             mock.patch.object(M,"persist") as persist:
            result=M.discover(123)
            self.assertEqual(result["handle"],"0x81010001")
            self.assertFalse(result["key_created"])
            persist.assert_not_called()
        with mock.patch.object(M,"hardware",side_effect=M.Refused("service_tpm_access_unavailable")):
            self.assertFalse(M.discover(123)["available"])

    def test_request_and_approval_guard(self):
        job=self.job()
        self.assertEqual(M.parse(M.P.encode(job)),job)
        for bad in (dict(job,handle="0x81020000"),dict(job,action="apply"),dict(job,confirm=M.CONFIRM)):
            with self.assertRaises(M.Refused):
                M.parse(M.P.encode(bad))
        with mock.patch.object(M.T,"lock") as lock:
            with self.assertRaises(M.Refused):
                M.apply(job,123)
            lock.assert_not_called()

    def test_plan_binds_handle_and_inventory(self):
        job=self.job()
        with mock.patch.object(M,"hardware",return_value=("absent","OpenSSL 3.0.9",set())) as hw, \
             mock.patch.object(M.P,"route_state",return_value=["",""]), \
             mock.patch.object(M.P,"missing",return_value=True):
            first=M.plan(job,123)
            self.assertNotEqual(first["plan_sha"],M.plan(dict(job,handle="0x81010002"),123)["plan_sha"])
            hw.return_value=("absent","OpenSSL 3.0.9",{"0x81010009"})
            self.assertNotEqual(first["plan_sha"],M.plan(job,123)["plan_sha"])
            hw.return_value=("absent","OpenSSL 3.0.9",{job["handle"]})
            with self.assertRaisesRegex(M.Refused,"occupied"):
                M.plan(job,123)

    def test_persist_never_evicts_existing_handle(self):
        handle=self.job()["handle"]
        calls=[]
        persisted=False
        def run(argv,**kwargs):
            nonlocal persisted
            name=Path(argv[0]).name
            calls.append(name)
            if name=="tpm2_readpublic":
                Path(argv[argv.index("-o")+1]).write_bytes(b"same public")
            if name=="tpm2_evictcontrol":
                self.assertTrue(argv[argv.index("-c")+1].endswith("primary.ctx"))
                self.assertEqual(argv[-1],handle)
                persisted=True
            return b""
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(M.T,"run_command",side_effect=run), \
             mock.patch.object(M.T,"read_capabilities",side_effect=lambda:{handle} if persisted else set()):
            M.persist(handle,Path(folder))
        self.assertEqual(calls,["tpm2_createprimary","tpm2_readpublic","tpm2_evictcontrol","tpm2_readpublic"])
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(M.T,"run_command",return_value=b"") as runner, \
             mock.patch.object(M.T,"read_capabilities",return_value={handle}):
            with self.assertRaisesRegex(M.Refused,"occupied"):
                M.persist(handle,Path(folder))
            self.assertEqual(runner.call_count,1)


if __name__=="__main__":
    unittest.main()
