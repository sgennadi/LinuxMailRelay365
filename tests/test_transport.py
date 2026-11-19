import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "linux"))
import m365_xoauth2_transport as mt


class FakeSMTP:
    calls = []
    refuse_auth = False
    def __init__(self, host, port, timeout):
        self.__class__.calls.append(('connect', host, port, timeout))
        self.esmtp_features = {'auth': 'LOGIN XOAUTH2'}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def ehlo(self): return 250, b'OK'
    def has_extn(self, name): return name == 'starttls'
    def starttls(self, context):
        self.__class__.calls.append(('starttls',))
        return 220, b'OK'
    def docmd(self, command, args=''):
        if command == 'AUTH':
            self.__class__.calls.append(('auth', args.split(' ', 1)[0]))
            payload = base64.b64decode(args.split(' ', 1)[1]).decode('utf-8')
            assert payload == 'user=alerts@example.com\x01auth=Bearer test-token\x01\x01'
            if self.refuse_auth: return 535, b'auth rejected'
            return 235, b'OK'
        return 535, b'auth rejected'
    def sendmail(self, sender, recipients, message):
        self.__class__.calls.append(('sendmail', sender, recipients, message))
        return {}


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls.folder = Path(cls._td.name)
        key = cls.folder / 'app.key'
        crt = cls.folder / 'app.crt'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-days', '2', '-subj', '/CN=test',
                        '-keyout', str(key), '-out', str(crt)],
                       capture_output=True, check=True)
        subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(key),
                        '-pubout', '-out', str(cls.folder / 'pub.pem')],
                       capture_output=True, check=True)
        cls.cfg = {'tenant_id': '11111111-1111-1111-1111-111111111111',
                   'client_id': '22222222-2222-2222-2222-222222222222',
                   'mailbox': 'alerts@example.com', 'certificate': str(crt),
                   'private_key': str(key)}

    @classmethod
    def tearDownClass(cls): cls._td.cleanup()

    def test_signed_ps256_assertion(self):
        endpoint, assertion = mt.make_client_assertion(self.cfg, now=1800000000)
        header, claims, sig = assertion.split('.')
        self.assertEqual(endpoint, 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token')
        def decoded(part):
            return base64.urlsafe_b64decode(part + '===' )
        h = json.loads(decoded(header))
        c = json.loads(decoded(claims))
        self.assertEqual(h['alg'], 'PS256')
        self.assertIn('x5t#S256', h)
        self.assertEqual(c['aud'], endpoint)
        self.assertEqual(c['exp']-c['nbf'], 660)
        signature_path = self.folder / 'signature.bin'
        signature_path.write_bytes(decoded(sig))
        verified = subprocess.run(['/usr/bin/openssl', 'dgst', '-sha256', '-verify',
                                   str(self.folder/'pub.pem'), '-signature', str(signature_path),
                                   '-sigopt', 'rsa_padding_mode:pss',
                                   '-sigopt', 'rsa_pss_saltlen:32'],
                                  input=(header+'.'+claims).encode('ascii'),
                                  capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        self.assertIn(b'Verified OK', verified.stdout)

    def test_token_scope_and_no_token_dump(self):
        class Reply(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *_): self.close()
        def fake_open(request, **kw):
            payload = request.data.decode()
            self.assertIn('https%3A%2F%2Foutlook.office365.com%2F.default', payload)
            self.assertIn('grant_type=client_credentials', payload)
            self.assertNotIn('client_secret', payload)
            return Reply(b'{"access_token":"test-token"}')
        with mock.patch.object(mt.urllib.request, 'urlopen', side_effect=fake_open):
            self.assertEqual(mt.acquire_token(self.cfg), 'test-token')

    def test_rewrite_from_and_hide_bcc(self):
        raw = (b'From: root@host.invalid\nFrom: attacker@host.invalid\n'
               b'To: test@example.net\nBcc: private@example.net\n'
               b'Subject: Hi\n\nMessage body\n')
        output = mt.build_message(raw, 'alerts@example.com')
        self.assertIn(b'From: alerts@example.com', output)
        self.assertNotIn(b'root@host.invalid', output)
        self.assertNotIn(b'attacker@host.invalid', output)
        self.assertNotIn(b'private@example.net', output)
        self.assertIn(b'Message-ID:', output)
        self.assertIn(b'Date:', output)
        self.assertIn(b'\r\n\r\nMessage body', output)

    def test_smtp_auth_and_mail(self):
        FakeSMTP.calls = []
        FakeSMTP.refuse_auth = False
        with mock.patch.object(mt.smtplib, 'SMTP', FakeSMTP):
            mt.send_smtp(self.cfg, 'to@example.net', b'Subject: test\n\nHi\n', 'test-token')
        self.assertIn(('auth', 'XOAUTH2'), FakeSMTP.calls)
        mailcalls = [x for x in FakeSMTP.calls if x[0] == 'sendmail']
        self.assertEqual(mailcalls[0][1:3], ('alerts@example.com', ['to@example.net']))
        self.assertIn(b'From: alerts@example.com', mailcalls[0][3])

    def test_staged_smtp_auth_only_never_sends_mail(self):
        FakeSMTP.calls = []
        FakeSMTP.refuse_auth = False
        with mock.patch.object(mt.smtplib, 'SMTP', FakeSMTP):
            mt.check_smtp_auth(self.cfg, 'test-token')
        self.assertIn(('starttls',), FakeSMTP.calls)
        self.assertIn(('auth', 'XOAUTH2'), FakeSMTP.calls)
        self.assertNotIn('sendmail', [entry[0] for entry in FakeSMTP.calls])
        self.assertNotIn('mail', [entry[0] for entry in FakeSMTP.calls])

    def test_staged_smtp_auth_rejects_token_and_never_sends_mail(self):
        FakeSMTP.calls = []
        FakeSMTP.refuse_auth = True
        with mock.patch.object(mt.smtplib, 'SMTP', FakeSMTP):
            with self.assertRaisesRegex(mt.TransientError, 'XOAUTH2'):
                mt.check_smtp_auth(self.cfg, 'test-token')
        self.assertNotIn('sendmail', [entry[0] for entry in FakeSMTP.calls])

    def test_staged_smtp_auth_cli_uses_only_candidate_config(self):
        config = dict(self.cfg, signer={'type': 'openssl-provider'})
        path = str(mt.STAGED_CONF_FILES[1])
        with mock.patch.object(mt, 'load_config', return_value=config) as loaded, \
             mock.patch.object(mt, 'acquire_token', return_value='test-token') as acquire, \
             mock.patch.object(mt, 'check_smtp_auth') as auth, \
             mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(mt.run(['--candidate-config', path, '--smtp-auth-check']), 0)
        loaded.assert_called_once_with(path)
        acquire.assert_called_once_with(config)
        auth.assert_called_once_with(config, 'test-token')
        self.assertIn('no message submitted', output.getvalue())
        self.assertNotIn('test-token', output.getvalue())

    def test_candidate_must_not_use_smtp_auth_check_with_recipient(self):
        with self.assertRaises(SystemExit):
            mt.run(['--candidate-config', str(mt.STAGED_CONF_FILES[0]),
                    '--smtp-auth-check', '--recipient', 'recipient@example.org'])

    def test_acceptance_fixed_message_and_single_recipient(self):
        accepted = []
        request = {'recipient': 'internal@example.com',
                   'run_id': 'a' * 32, 'role': 'internal'}
        with mock.patch.object(mt, 'acquire_token', return_value='shortlived'), \
             mock.patch.object(mt, 'send_smtp',
                               side_effect=lambda *a: accepted.append(a)):
            mt.submit_acceptance_message(self.cfg, request)
        self.assertEqual(len(accepted), 1)
        config, recipient, data, token = accepted[0]
        self.assertEqual(recipient, request['recipient'])
        self.assertEqual(token, 'shortlived')
        self.assertIn(b'X-LinuxMailRelay365-Test-ID: ' + b'a' * 32, data)
        self.assertIn(b'Message-ID: <lmr365-' + b'a' * 32 + b'-internal@example.com>', data)
        self.assertNotIn(b'Bcc:', data)
        self.assertLess(len(data), 2048)
        self.assertNotIn(b'shortlived', data)

    def test_acceptance_rejects_invalid_sender_recipient_role_and_injection(self):
        bad_requests = [
            {'recipient': 'external@outside.net', 'run_id': 'a' * 32,
             'role': 'internal'},
            {'recipient': 'internal@example.com', 'run_id': 'a' * 32,
             'role': 'external'},
            {'recipient': 'a@outside.net\nBcc:evil@outside.net',
             'run_id': 'a' * 32, 'role': 'external'},
            {'recipient': 'valid@outside.net', 'run_id': 'not_hex',
             'role': 'external'},
            {'recipient': 'valid@outside.net', 'run_id': 'a' * 32,
             'role': 'external', 'body': 'injected'},
        ]
        with mock.patch.object(mt, 'acquire_token') as acquire, \
             mock.patch.object(mt, 'send_smtp') as send:
            for case in bad_requests:
                with self.subTest(case=case), self.assertRaises(mt.PermanentError):
                    mt.submit_acceptance_message(self.cfg, case)
            acquire.assert_not_called()
            send.assert_not_called()

    def test_acceptance_cli_active_only_and_no_recipient_argument(self):
        request = {'recipient': 'external@outside.net', 'run_id': 'b' * 32,
                   'role': 'external'}
        raw = json.dumps(request).encode('ascii')
        with mock.patch.object(mt, 'load_config', return_value=self.cfg) as load, \
             mock.patch.object(mt, 'acquire_token', return_value='secret-token'), \
             mock.patch.object(mt, 'send_smtp') as send, \
             mock.patch.object(mt.sys, 'stdin',
                               io.TextIOWrapper(io.BytesIO(raw))), \
             mock.patch.object(mt.sys, 'stdout', new_callable=io.StringIO) as output:
            status = mt.run(['--acceptance-test', '--config', str(mt.SIDECAR_CONF_FILE)])
            self.assertEqual(status, 0)
            load.assert_called_once_with(str(mt.SIDECAR_CONF_FILE))
            send.assert_called_once()
            self.assertNotIn('secret-token', output.getvalue())
            self.assertIn('recipient delivery not verified', output.getvalue())
        for disallowed in (
            ['--acceptance-test', '--recipient', 'victim@example.com'],
            ['--acceptance-test', '--candidate-config',
             str(mt.STAGED_CONF_FILES[0])],
        ):
            with self.subTest(argv=disallowed), self.assertRaises(SystemExit):
                mt.run(disallowed)

    def test_auth_failure_is_temporary(self):
        FakeSMTP.calls = []
        FakeSMTP.refuse_auth = True
        with mock.patch.object(mt.smtplib, 'SMTP', FakeSMTP):
            with self.assertRaises(mt.TransientError):
                mt.send_smtp(self.cfg, 'to@example.net', b'Subject: test\n\nHi\n', 'test-token')


if __name__ == '__main__': unittest.main()
