"""One-time password generation must be root-owned, salted and never logged."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "generate-smtp-client-credential.py"
spec = importlib.util.spec_from_file_location("lmr_secret_generator", str(SCRIPT))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


class SecretGenerationContract(unittest.TestCase):
    def test_preview_never_generates_or_echoes_secret(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--check-only",
                            "--username", "smtp-app01"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("SMTP_PASSWORD_EMITTED=no", p.stdout)
        self.assertIn("CHANGES_APPLIED=no", p.stdout)
        self.assertNotIn("SMTP_GENERATED_SECRET=", p.stdout)
        p = subprocess.run([sys.executable, str(SCRIPT), "--generate",
                            "--username", "smtp-app01"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=8)
        self.assertEqual(p.returncode, 2)
        self.assertIn("typed_confirmation_required", p.stdout)

    def test_legacy_rhel_python_36_safe_and_hashed(self):
        src = SCRIPT.read_text(encoding="utf-8")
        for token in ("secrets.token_urlsafe(36)", "openssl", "passwd", '"-6"',
                      '"-stdin"', "os.O_EXCL", "O_NOFOLLOW", "0o600",
                      "GENERATE_ONE_TIME_SMTP_PASSWORD",
                      "SMTP_SECRET_SAVED_TO_DISK"):
            self.assertIn(token, src)
        for disallowed in ("crypt.crypt(", "random.random(", "pickle",
                           "password = '", "setenforce 0", "sudo postfix"):
            self.assertNotIn(disallowed, src)
        self.assertTrue(gen.PASSWORD.fullmatch("A"*48))
        self.assertFalse(gen.PASSWORD.fullmatch("short"))
        self.assertTrue(gen.LOGIN.fullmatch("app-abc1"))
        self.assertFalse(gen.LOGIN.fullmatch("bad;command"))
        self.assertEqual(subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=8).returncode, 0)

    def test_sha512_crypt_compatible_with_existing_smtp_accounts(self):
        from unittest.mock import Mock
        sample = "$6$abcdefghijklmnop$" + "A"*86
        with patch.object(gen.subprocess, "run", return_value=Mock(returncode=0,
                                                                   stdout=sample+"\n")) as run:
            h = gen.generate_hash("VeryLongRandomPassword_12345678901")
            self.assertEqual(h, "{SHA512-CRYPT}"+sample)
            self.assertEqual(run.call_args[1]["input"],
                             "VeryLongRandomPassword_12345678901\n")

    def test_compatibility_with_existing_auth_sources(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('username+":"+salt_hash+"\\n"', source)
        self.assertIn('salt_hash+"\\n"', source)
        self.assertIn('generated-accounts', source)
        self.assertNotIn("log.info", source)


if __name__ == "__main__":
    unittest.main()
