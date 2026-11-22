"""Read-only/unit contracts for LinuxMailRelay365 per-app SMTP accounts."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"linux"/"manage-sidecar-smtp-accounts.py"
spec=importlib.util.spec_from_file_location("lmr365_accounts",str(SCRIPT))
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

HASH_A="{SHA512-CRYPT}$6$abcdefgh$"+("A"*86)
HASH_B="{SHA512-CRYPT}$6$abcdefgh$"+("B"*86)
HASH_C="{SHA512-CRYPT}$6$abcdefgh$"+("C"*86)


class AccountsTests(unittest.TestCase):
    def test_parser_roundtrip_avoids_plaintext(self):
        original=("app01:"+HASH_A+"\napp02:"+HASH_B+"\n").encode("ascii")
        accounts=mod.load_accounts(original)
        self.assertEqual(len(accounts),2)
        self.assertEqual(mod.load_accounts(mod.output(accounts)),accounts)
        self.assertEqual(mod.mutate(accounts,"rotate","app02",HASH_C)["app02"],HASH_C)
        self.assertEqual(len(mod.mutate(accounts,"revoke","app01",None)),1)
        self.assertEqual(len(mod.mutate(accounts,"add","app03",HASH_C)),3)

    def test_duplicate_usernames_rejected_case_insensitive(self):
        for s in ("App01:"+HASH_A+"\napp01:"+HASH_B+"\n",
                  "app01:plaintext\n",
                  "app01:"+HASH_A+"\napp01:"+HASH_A+"\n",
                  "x:"+HASH_A+"\n", "app01:"+HASH_A+"\n\n",
                  "app01:"+HASH_A+"\r\n"):
            with self.subTest(record=s):
                with self.assertRaises(ValueError):
                    mod.load_accounts(s.encode("ascii"))

    def test_fail_closed_on_last_account_and_duplicate_add(self):
        one={"client01":HASH_A}
        with self.assertRaisesRegex(ValueError,"last_account"):
            mod.mutate(one,"revoke","client01",None)
        with self.assertRaisesRegex(ValueError,"account_already_exists"):
            mod.mutate(one,"add","CLIENT01",HASH_B)
        with self.assertRaisesRegex(ValueError,"account_not_found"):
            mod.mutate(one,"rotate","unknown",HASH_B)
        with self.assertRaisesRegex(ValueError,"new_hash_must_differ"):
            mod.mutate(one,"rotate","client01",HASH_A)

    def test_custom_port_and_confirmations(self):
        for port in ("25","587","1023","65536","hi"):
            r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port",port],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             universal_newlines=True,timeout=8)
            self.assertNotEqual(r.returncode,0)
        r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port","46500"],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         universal_newlines=True,timeout=8)
        self.assertNotIn("SMTP_ACCOUNT_CHANGED=yes",r.stdout)
        r=subprocess.run([sys.executable,str(SCRIPT),"--smtp-port","46500",
                          "--operation","revoke","--username","client01",
                          "--apply","--expected-state-sha256","a"*64],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         universal_newlines=True,timeout=8)
        self.assertNotEqual(r.returncode,0)
        self.assertIn("Apply requires exact state",r.stderr)

    def test_security_contract(self):
        s=SCRIPT.read_text(encoding="utf-8")
        for needed in ("os.replace(","fcntl.LOCK_EX","credentials_changed_since_preview",
                       "service_restart_failed_rolled_back","service_restart_failed_manual_recovery_required",
                       "rhel_selinux_permissive_not_integration_verified",
                       "CHANGE_PRIVATE_SMTP_ACCOUNT","MICROSOFT365_DELIVERY_VERIFIED",
                       "hash_source_must_be_separate","last_account_cannot_be_revoked"):
            self.assertIn(needed,s)
        for forbidden in ("setenforce 0","ufw allow ","postconf -e ",
                          "systemctl restart postfix","smtp.login(","sendmail(",
                          "outlook.office365.com","smtp.office365.com"):
            self.assertNotIn(forbidden,s)

if __name__=="__main__":
    unittest.main()
