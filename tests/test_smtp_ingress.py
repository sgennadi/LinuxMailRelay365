from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'linux/install-postfix-m365-xoauth2.sh'

class IngressPolicyTests(unittest.TestCase):
    def validate(self,*args):
        return subprocess.run(['bash',str(SCRIPT),'--validate-network-only',*args],
            capture_output=True,text=True,timeout=10)
    def test_local_default(self):
        r=self.validate()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('loopback SMTP only',r.stdout)
    def test_valid_trusted_internal_clients(self):
        r=self.validate('--listen-ip','192.168.1.10','--trusted-network','192.168.1.0/24',
                        '--trusted-network','10.42.0.0/16')
        self.assertEqual(r.returncode,0,r.stderr)
    def test_forbidden_open_relay_and_public_ranges(self):
        cases=[
            ('--listen-ip','0.0.0.0','--trusted-network','10.0.0.0/8'),
            ('--listen-ip','192.168.1.10','--trusted-network','0.0.0.0/0'),
            ('--listen-ip','192.168.1.10','--trusted-network','8.8.8.0/24'),
            ('--listen-ip','192.168.1.10','--trusted-network','172.0.0.0/8'),
            ('--listen-ip','192.168.1.10'),
            ('--trusted-network','10.0.0.0/8'),
            ('--listen-ip','127.0.0.1','--trusted-network','10.0.0.0/8'),
            ('--listen-ip','192.168.1.10','--trusted-network','192.168.1.7/24'),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertNotEqual(self.validate(*args).returncode,0)
    def test_server_guard(self):
        text=SCRIPT.read_text()
        self.assertIn('Refusing to change ANY live mail routes',text)
        self.assertIn('smtpd_client_restrictions = permit_mynetworks, reject',text)
        self.assertIn('ip -o -4 addr show',text)

if __name__=='__main__': unittest.main()
