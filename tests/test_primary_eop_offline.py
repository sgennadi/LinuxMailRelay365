"""Primary EOP exact-byte offline transaction tests; no live MTA."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("primary_eop",ROOT/"linux/manage-primary-eop-offline.py")
E=importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


class PrimaryEopOfflineTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.config=self.root/"postfix"
        self.config.mkdir(mode=0o700)
        self.fd=os.open(str(self.config),E.M.DIR_FLAGS)
        self.parent=os.open(str(self.root),E.M.DIR_FLAGS)
        self.addCleanup(os.close,self.fd)
        self.addCleanup(os.close,self.parent)
        self.uid=os.getuid()
        self.main=b"# keep this comment\nmydestination = localhost, mail.local.example.net\nrelayhost = [relay.example.net]:25\n"
        self.master=b"smtp unix - - n - - smtp\n"
        for name,data in (("main.cf",self.main),("master.cf",self.master)):
            file=self.config/name
            file.write_bytes(data)
            file.chmod(0o640)
        self.mx="example-org.mail.protection.outlook.com"
        self.domain="example.org"
        self.guard=Mock()
        self.master_check=Mock()
        self.ca=Mock(return_value="a"*64)
        self.network=Mock()
        self.values=dict((key,"") for key in E.KEYS)
        self.values.update(E.P.FIXED_SETTINGS)
        self.values.update(myhostname="mail.local.example.net",mydomain="local.example.net",
                           myorigin="local.example.net",mydestination="localhost, mail.local.example.net",
                           local_transport="local:mail.local.example.net",virtual_transport="virtual",
                           smtp_tls_CAfile="/etc/ssl/certs/ca-certificates.crt",
                           smtp_tls_mandatory_protocols=">=TLSv1.2",inet_protocols="ipv4",
                           relayhost="[relay.example.net]:25")

    def reader(self):
        values=dict(self.values)
        lines=(self.config/"main.cf").read_text().splitlines()
        values["relayhost"]=next((line.split("=",1)[1].strip() for line in lines
                                  if line.startswith("relayhost =")),"")
        return values

    def review(self):
        return E.review(self.fd,self.uid,self.mx,self.domain,self.guard,
                        self.reader,self.master_check,self.ca)

    def apply(self,sha):
        return E.apply(self.fd,self.parent,self.uid,sha,E.CONFIRM,self.guard,
                       self.review,self.network,self.reader,self.master_check,self.ca)

    def restore(self,sha):
        return E.restore(self.fd,self.parent,sha,self.uid,E.RESTORE,self.guard,
                         self.reader,self.master_check,self.ca)

    def test_apply_and_restore_preserve_exact_other_bytes(self):
        sha,info,files=self.review()
        self.assertEqual(files["main.after"],self.main.replace(b"[relay.example.net]:25",
                         ("["+self.mx+"]:25").encode()))
        self.assertEqual(self.apply(sha),sha)
        self.network.assert_called_once_with(info)
        self.assertEqual((self.config/"main.cf").read_bytes(),files["main.after"])
        self.assertEqual((self.config/"master.cf").read_bytes(),self.master)
        self.assertEqual((self.config/"main.cf").stat().st_mode&0o777,0o640)
        self.assertEqual(E.load_backup(self.parent,sha,self.uid),(info,files))
        self.assertEqual(self.restore(sha),sha)
        self.assertEqual((self.config/"main.cf").read_bytes(),self.main)
        self.assertEqual(self.restore(sha),sha)

    def test_stale_sha_or_failed_network_no_backup_or_write(self):
        sha,_,_=self.review()
        with self.assertRaises(E.Refused):
            self.apply("f"*64)
        self.network.assert_not_called()
        self.network.side_effect=E.Refused("TLS failed")
        with self.assertRaises(E.Refused):
            self.apply(sha)
        self.assertFalse((self.root/E.BASE).exists())
        self.assertEqual((self.config/"main.cf").read_bytes(),self.main)

    def test_complex_or_unsafe_configuration_refused(self):
        for key,value in (("transport_maps","hash:/etc/postfix/transport"),
                          ("mydestination","example.org"),("inet_protocols","all"),
                          ("smtp_sasl_auth_enable","yes"),("smtp_tls_security_level","encrypt"),
                          ("smtp_tls_mandatory_protocols","!SSLv2,!SSLv3"),
                          ("smtp_bind_address","10.1.2.3"),("smtp_tls_chain_files","/private/key.pem")):
            with self.subTest(key=key):
                old=self.values[key]
                self.values[key]=value
                with self.assertRaises(E.Refused):
                    self.review()
                self.values[key]=old

    def test_ambiguous_assignments_and_references_refused(self):
        for data in (b"relayhost = old.example.org\n  next.example.org\n",
                     b"relayhost = old.example.org\nrelayhost = other.example.org\n",
                     b"relayhost = old.example.org\nmyorigin = $relayhost\n",
                     b"  relayhost = old.example.org\n"):
            with self.assertRaises(E.Refused):
                E.proposed(data,"old.example.org",self.mx)

    def test_failure_after_write_rolls_back_and_keeps_backup(self):
        sha,_,_=self.review()
        original=E.verify
        def verify(*args,**kwargs):
            if args[4]=="after" and not getattr(verify,"failed",False):
                verify.failed=True
                raise E.Refused("injected postcheck failure")
            return original(*args,**kwargs)
        with patch.object(E,"verify",side_effect=verify):
            with self.assertRaises(E.Refused):
                self.apply(sha)
        self.assertEqual((self.config/"main.cf").read_bytes(),self.main)
        self.assertTrue((self.root/E.BASE/sha/E.MANIFEST).is_file())

    def test_restore_refuses_drift_and_changed_trust(self):
        sha,_,_=self.review()
        self.apply(sha)
        original=(self.config/"main.cf").read_bytes()
        self.ca.return_value="b"*64
        with self.assertRaises(E.Refused):
            self.restore(sha)
        self.ca.return_value="a"*64
        (self.config/"main.cf").write_bytes(original+b"# unrelated admin edit\n")
        with self.assertRaises(E.Refused):
            self.restore(sha)
        self.assertIn(b"unrelated admin edit",(self.config/"main.cf").read_bytes())

    def test_apply_guard_failure_never_publishes(self):
        sha,_,_=self.review()
        self.guard.side_effect=E.Refused("queue or stopped state changed")
        with self.assertRaises(E.Refused):
            self.apply(sha)
        self.assertEqual((self.config/"main.cf").read_bytes(),self.main)

    def test_native_check_only_after_verified_apply(self):
        sha,_,_=self.review()
        check=Mock()
        with self.assertRaises(FileNotFoundError):
            E.check_backup(self.fd,self.parent,sha,self.uid,E.CHECK,self.guard,
                           check,self.reader,self.master_check,self.ca)
        check.assert_not_called()
        self.apply(sha)
        with self.assertRaises(E.Refused):
            E.check_backup(self.fd,self.parent,sha,self.uid,"wrong",self.guard,
                           check,self.reader,self.master_check,self.ca)
        check.assert_not_called()
        self.assertEqual(E.check_backup(self.fd,self.parent,sha,self.uid,E.CHECK,self.guard,
                                        check,self.reader,self.master_check,self.ca),sha)
        check.assert_called_once()
        self.restore(sha)
        check.reset_mock()
        with self.assertRaises(E.Refused):
            E.check_backup(self.fd,self.parent,sha,self.uid,E.CHECK,self.guard,
                           check,self.reader,self.master_check,self.ca)
        check.assert_not_called()

    def test_native_check_drift_detected(self):
        sha,_,_=self.review()
        self.apply(sha)
        def drift():
            with (self.config/"main.cf").open("ab") as stream:
                stream.write(b"# changed during native check\n")
        with self.assertRaises(E.Refused):
            E.check_backup(self.fd,self.parent,sha,self.uid,E.CHECK,self.guard,
                           drift,self.reader,self.master_check,self.ca)

    def test_gui_resource_and_maintenance_contract(self):
        src=ROOT/"src/LinuxMailRelay365"
        self.assertIn("manage-primary-eop-offline.py",(src/"LinuxMailRelay365.csproj").read_text())
        assets=(src/"EmbeddedAssets.cs").read_text()
        self.assertIn("CHECK_STOPPED_PRIMARY_EOP",assets)
        self.assertIn(E.O.MAINTENANCE,assets)
        ui=(src/"MainForm.PrimaryEopOffline.cs").read_text()
        self.assertIn("maintenance.Checked",ui)
        self.assertIn("ConfirmDestructive",ui)
        self.assertIn('RunTenantConnectorManagerAsync(options, "Inspect")',ui)
        self.assertIn("No automatic service start",ui)
        self.assertIn("OpenPrimaryEopOfflineAsync(owner, context, mx)",(src/"MainForm.DeliveryMiniWizard.cs").read_text())


if __name__=="__main__":
    unittest.main()
