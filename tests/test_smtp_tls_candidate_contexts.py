import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import stat

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("labels", ROOT / "linux/smtp-tls-selinux-prepare.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class CandidateContextTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path("/etc/postfix/lmr365-smtp-tls")
        self.name = "candidate-" + "a"*64
        self.paths = [self.root / self.name] + [self.root / self.name / p for p in
            ("client-chain.pem","fullchain.pem","key.pem")]
        self.actual = {str(p): b"unconfined_u:object_r:postfix_etc_t:s0" for p in self.paths}
        self.expected = b"system_u:object_r:postfix_etc_t:s0"
        self.gen = Mock()

    def run_prepare(self):
        def check(args, **kwargs):
            self.actual[args[-1]] = self.expected
        with patch.object(M,"private_identity",return_value=(1,2,3,0,0,1)), \
             patch.object(M.subprocess,"check_output",return_value=self.expected), \
             patch.object(M.os,"getxattr",side_effect=lambda path,*args,**kw:self.actual[path]+b"\x00"), \
             patch.object(M.subprocess,"check_call",side_effect=check) as call:
            M.restore_candidate_contexts(self.root,self.name,self.gen,lambda p:p,{})
            return call

    def test_full_context_restored_on_exact_paths(self):
        call = self.run_prepare()
        self.assertEqual([args.args[0] for args in call.call_args_list],
            [["/usr/sbin/restorecon","-F",str(p)] for p in self.paths])
        self.assertEqual(self.gen.validate.call_count,2)

    def test_matching_context_no_relabel(self):
        self.actual = dict.fromkeys(self.actual,self.expected)
        self.run_prepare().assert_not_called()

    def test_range_difference_refused_before_any_write(self):
        self.actual[str(self.paths[-1])] = b"system_u:object_r:postfix_etc_t:s0:c2"
        with patch.object(M.subprocess,"check_call") as call:
            # run_prepare patches the call internally; the first observe pass
            # must refuse before entering its relabel loop.
            with patch.object(M,"private_identity",return_value=(1,2,3,0,0,1)), \
                 patch.object(M.subprocess,"check_output",return_value=self.expected), \
                 patch.object(M.os,"getxattr",side_effect=lambda path,*a,**k:self.actual[path]):
                with self.assertRaises(ValueError):
                    M.restore_candidate_contexts(self.root,self.name,self.gen,lambda p:p,{})
            call.assert_not_called()

    def test_unsafe_inode_refused(self):
        for mode,links in ((stat.S_IFLNK|0o777,1),(stat.S_IFREG|0o600,2),(stat.S_IFREG|0o644,1)):
            with patch.object(M.Path,"lstat",return_value=SimpleNamespace(
                    st_mode=mode,st_uid=0,st_nlink=links,st_dev=1,st_ino=2,st_gid=0)):
                with self.assertRaises(ValueError):
                    M.private_identity(self.paths[-1])

    def test_recheck_requires_actual_match(self):
        with patch.object(M,"private_identity",return_value=(1,2,3,0,0,1)), \
             patch.object(M.subprocess,"check_output",return_value=self.expected), \
             patch.object(M.os,"getxattr",side_effect=lambda path,*a,**k:self.actual[path]), \
             patch.object(M.subprocess,"check_call"):
            with self.assertRaises(RuntimeError):
                M.restore_candidate_contexts(self.root,self.name,self.gen,lambda p:p,{})
