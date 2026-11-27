import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"linux"/(name+".py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

B=load("smtp-tls-initial-backup")
C=load("smtp-tls-initial-candidate")

def digest(data):
    return hashlib.sha256(data).hexdigest()

class InitialBackupTests(unittest.TestCase):
    def setUp(self):
        self.data=b"# fixture\nrelayhost = [localhost]:25\n"
        self.old=digest(self.data)
        self.new=digest(C.build(self.data))
        self.meta={"sha256":self.old,"uid":0,"gid":0,"mode":0o644}

    def test_journal_requires_exact_original_and_candidate(self):
        with patch.object(B,"verify",return_value=(self.data,self.meta)):
            self.assertEqual(B.verify_for_journal("backup",self.old,self.new,C.build),(self.data,self.meta))
            for original,candidate in (("a"*64,self.new),(self.old,"b"*64),(self.old,self.old)):
                with self.assertRaises(ValueError):
                    B.verify_for_journal("backup",original,candidate,C.build)

    def test_duplicate_and_invalid_metadata_refused(self):
        with self.assertRaises(ValueError):
            B.strict_object([("uid",0),("uid",0)])
        for key,value in (("uid",False),("uid",1000),("gid",-1),("mode",0o666),("mode",0o4644),("sha256","invalid")):
            with self.assertRaises(ValueError):
                B.metadata(dict(self.meta,**{key:value}))
        self.assertEqual(B.metadata(self.meta),self.meta)

    @unittest.skipUnless(os.geteuid()==0,"root-only file validation")
    def test_private_file_refuses_symlink_hardlink_and_public_mode(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(B,"private_directory"):
            path=pathlib.Path(tmp)/"data"
            path.write_bytes(self.data)
            path.chmod(0o600)
            self.assertEqual(B.read_private(path,1024),self.data)
            with self.assertRaises(ValueError):
                B.read_private(path,1)
            link=path.with_name("link")
            link.symlink_to(path)
            with self.assertRaises(OSError):
                B.read_private(link,1024)
            link.unlink()
            os.link(path,link)
            with self.assertRaises(ValueError):
                B.read_private(path,1024)
            link.unlink()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                B.read_private(path,1024)

    @unittest.skipUnless(os.geteuid()==0,"root-only file validation")
    def test_backup_modes_independent_of_umask(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(B,"private_directory"):
            root=pathlib.Path(tmp)
            source=root/"main.cf"
            source.write_bytes(self.data)
            source.chmod(0o644)
            before=os.umask(0)
            try:
                saved=B.backup(root,source)
            finally:
                os.umask(before)
            for name in ("main.cf","manifest.json"):
                self.assertEqual((saved/name).stat().st_mode & 0o777,0o600)
            self.assertEqual(B.verify_for_journal(saved,self.old,self.new,C.build)[0],self.data)

    def test_prestart_checks_before_mutating(self):
        source=(ROOT/"linux/manage-smtp-tls-initial.py").read_text()
        self.assertIn("backup.read_private(path,16384)",source)
        self.assertLess(source.index('backup.verify_for_journal(ROOT/name'),source.index('result=journal.recover('))
        self.assertIn('backup.verify_for_journal(saved,state["original_sha256"]',source)
        self.assertIn('overlapping deployment transaction',source)
