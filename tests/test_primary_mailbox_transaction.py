"""Disposable two-file transaction fixtures; no live MTA or SMTP."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("primary_mailbox_transaction",
    ROOT/"linux/primary-mailbox-transaction.py")
X=importlib.util.module_from_spec(spec)
spec.loader.exec_module(X)


class PrimaryMailboxTransactionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.config=self.root/"postfix"
        self.config.mkdir(mode=0o700)
        self.fd=os.open(str(self.config),X.M.DIR_FLAGS)
        self.parent=os.open(str(self.root),X.M.DIR_FLAGS)
        self.addCleanup(os.close,self.fd)
        self.addCleanup(os.close,self.parent)
        self.uid=os.getuid()
        self.raw=(b"# preserve local mail\nmydestination = localhost, mail.example.net\n"
                  b"inet_interfaces = loopback-only\nrelayhost = [relay.example.net]:25\n",
                  b"smtp inet n - n - - smtpd\nlocal unix - n n - - local\n")
        for name,data in zip(X.NAMES,self.raw):
            file=self.config/name
            file.write_bytes(data)
            file.chmod(0o640)
        values=dict.fromkeys(X.R.SETTINGS,"")
        values.update(config_directory="/etc/postfix",multi_instance_enable="no",
            default_transport="smtp",relay_transport="relay",mydestination="localhost, mail.example.net",
            relayhost="[relay.example.net]:25",m365xoauth2_destination_recipient_limit="")
        self.sample=(X.R.E.digest(b"\0".join(self.raw)),values,"","")
        self.guard=Mock()
        self.runtime=Mock(return_value="a"*64)
        self.identity=Mock(return_value=("mailbox_matches","b"*64,"c"*64))
        self.mailbox="alerts@example.org"
        explicit={"mydestination":values["mydestination"],"inet_interfaces":"loopback-only",
                  "relayhost":values["relayhost"]}
        expanded=dict.fromkeys(X.R.PRESERVED_KEYS,"")
        expanded.update(explicit,config_directory="/etc/postfix",
                        default_transport="smtp",relay_transport="relay")
        services={"smtp/inet":self.raw[1].splitlines()[0].decode().split(),
                  "local/unix":self.raw[1].splitlines()[1].decode().split()}
        self.before=dict(explicit=explicit,expanded=expanded,services=services)
        self.after=dict(explicit=dict(explicit,**dict(X.R.ROUTE_CHANGES)),
            expanded=dict(expanded,default_transport="m365xoauth2:",relay_transport="m365xoauth2:",relayhost=""),
            services=dict(services,**{"m365xoauth2/unix":X.R.PIPE.decode().split()}))
        self.compare=Mock(return_value=(self.before,self.after))
        self.candidate=X.R.candidate_configs(self.raw,self.sample)[0]

    def pair(self):
        return tuple((self.config/name).read_bytes() for name in X.NAMES)

    def native(self):
        current=self.pair()
        if current==self.raw:
            return self.before
        if current==self.candidate:
            return self.after
        raise AssertionError("No native readback in mixed state")

    def review(self):
        return X.review(self.fd,self.uid,self.mailbox,self.guard,self.runtime,
                        lambda:self.sample,self.identity,self.compare)

    def apply(self,revision):
        return X.apply(self.fd,self.parent,revision,self.uid,X.APPLY,self.guard,
                       self.review,self.native,self.runtime)

    def restore(self,revision):
        return X.restore(self.fd,self.parent,revision,self.uid,X.RESTORE,self.guard,self.native)

    def test_apply_restore_order_and_backup(self):
        revision,info,files=self.review()
        writes=[]
        original=X.T.atomic_write
        def write(fd,name,*args,**kwargs):
            writes.append(name)
            return original(fd,name,*args,**kwargs)
        with patch.object(X.T,"atomic_write",side_effect=write):
            self.assertEqual(self.apply(revision),revision)
            self.assertEqual(self.pair(),self.candidate)
            self.assertEqual(X.load_backup(self.parent,revision,self.uid),(info,files))
            self.assertEqual(self.restore(revision),revision)
            self.assertEqual(self.restore(revision),revision)
        self.assertEqual(writes,["master.cf","main.cf","main.cf","master.cf"])
        self.assertEqual(self.pair(),self.raw)
        folder=self.root/X.BASE/revision
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in folder.iterdir()))
        self.assertTrue(all((self.config/n).stat().st_mode&0o777==0o640 for n in X.NAMES))

    def test_interruption_between_files_recovers(self):
        revision,info,files=self.review()
        original=X.T.atomic_write
        def crash(fd,name,*args,**kwargs):
            original(fd,name,*args,**kwargs)
            if name=="master.cf":
                raise KeyboardInterrupt()
        with patch.object(X.T,"atomic_write",side_effect=crash),self.assertRaises(KeyboardInterrupt):
            self.apply(revision)
        self.assertEqual(X.phase(self.fd,self.uid,info,files),"pipe_only")
        self.assertEqual(self.restore(revision),revision)
        self.assertEqual(self.pair(),self.raw)

    def test_native_failure_rolls_back(self):
        revision,_,_=self.review()
        def native():
            return {"unexpected":True} if self.pair()==self.candidate else self.native()
        with self.assertRaisesRegex(X.Refused,"native_effective_configuration_mismatch"):
            X.apply(self.fd,self.parent,revision,self.uid,X.APPLY,self.guard,
                    self.review,native,self.runtime)
        self.assertEqual(self.pair(),self.raw)

    def test_stale_plan_identity_and_runtime_refused(self):
        revision,_,_=self.review()
        self.runtime.return_value="d"*64
        with self.assertRaisesRegex(X.Refused,"reviewed_plan_changed"):
            self.apply(revision)
        self.assertFalse((self.root/X.BASE).exists())
        self.identity.return_value=("different_mailbox","b"*64,"c"*64)
        with self.assertRaises(X.Refused):
            self.review()
        self.assertEqual(self.pair(),self.raw)

    def test_runtime_drift_after_pipe_rolls_back(self):
        revision,_,_=self.review()
        self.runtime.side_effect=lambda _: "a"*64 if self.pair()==self.raw else "f"*64
        with self.assertRaisesRegex(X.Refused,"runtime_changed_before_route_switch"):
            self.apply(revision)
        self.assertEqual(self.pair(),self.raw)

    def test_foreign_or_impossible_state_refused(self):
        revision,_,_=self.review()
        self.apply(revision)
        foreign=self.candidate[0]+b"# unrelated edit\n"
        (self.config/"main.cf").write_bytes(foreign)
        with self.assertRaisesRegex(X.Refused,"foreign_or_impossible"):
            self.restore(revision)
        self.assertEqual(self.pair()[0],foreign)
        (self.config/"main.cf").write_bytes(self.candidate[0])
        (self.config/"master.cf").write_bytes(self.raw[1])
        with self.assertRaisesRegex(X.Refused,"foreign_or_impossible"):
            self.restore(revision)
        self.assertEqual(self.pair(),(self.candidate[0],self.raw[1]))

    def test_corrupt_backup_and_guard_failure_refuse_restore(self):
        revision,_,_=self.review()
        self.apply(revision)
        self.guard.side_effect=X.Refused("service running")
        with self.assertRaisesRegex(X.Refused,"service running"):
            self.restore(revision)
        self.guard.side_effect=None
        (self.root/X.BASE/revision/"main.before").write_bytes(b"tampered")
        with self.assertRaises(X.Refused):
            self.restore(revision)
        self.assertEqual(self.pair(),self.candidate)

    def test_guard_failure_after_write_retains_recovery(self):
        revision,_,_=self.review()
        def guard():
            if self.pair()!=self.raw:
                raise X.Refused("maintenance lost")
        self.guard.side_effect=guard
        with self.assertRaisesRegex(X.T.RollbackRequired,"manual_recovery_required"):
            self.apply(revision)
        self.assertEqual(self.pair(),(self.raw[0],self.candidate[1]))
        self.guard.side_effect=None
        self.restore(revision)
        self.assertEqual(self.pair(),self.raw)

    def test_wrong_confirmation_never_writes(self):
        revision,_,_=self.review()
        with self.assertRaises(X.Refused):
            X.apply(self.fd,self.parent,revision,self.uid,"wrong",self.guard,
                    self.review,self.native,self.runtime)
        self.assertFalse((self.root/X.BASE).exists())
        self.assertEqual(self.pair(),self.raw)


if __name__=="__main__":
    unittest.main()
