#!/usr/bin/env python3
"""Postfix pipe transport -> Exchange Online SMTP using app-only OAuth2 XOAUTH2.

Uses Python stdlib + OpenSSL CLI. Does not write OAuth tokens to disk.
The private signing key remains usable by a privileged local attacker.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from email import policy
from email.parser import BytesParser
from email.utils import formatdate, make_msgid
from pathlib import Path
from m365_hardware_signer import HardwareSignerError, validate_spec, sign_ps256

CONF_FILE = Path('/etc/postfix/m365-oauth/app.json')
SIDECAR_CONF_FILE = Path('/etc/linuxmailrelay365/sidecar-identity/app.json')
STAGED_CONF_FILES = (
    Path('/etc/postfix/m365-oauth/hardware-staged.json'),
    Path('/etc/linuxmailrelay365/sidecar-identity/hardware-staged.json'),
)
EX_TEMPFAIL = 75
EX_OK = 0
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
EMAIL_RE = re.compile(r'^[^\s<>@\x00-\x1f]+@[^\s<>@\x00-\x1f]+$')


class TransientError(Exception):
    pass


class PermanentError(Exception):
    pass


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def run_openssl(*args, data=None):
    result = subprocess.run(
        ['/usr/bin/openssl', *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=20, check=False,
    )
    if result.returncode:
        raise TransientError('OpenSSL operation failed; verify the certificate and key')
    return result.stdout


def validate_guid(value):
    return str(uuid.UUID(value))


def load_config(path=None):
    path = CONF_FILE if path is None else Path(path)
    if path not in (CONF_FILE, SIDECAR_CONF_FILE) + STAGED_CONF_FILES:
        raise ValueError('Unsupported XOAUTH2 configuration path')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Invalid XOAUTH2 JSON identity')
    for required in ('tenant_id', 'client_id', 'mailbox', 'certificate'):
        if not data.get(required):
            raise ValueError('Missing configuration entry: ' + required)
    data['tenant_id'] = validate_guid(data['tenant_id'])
    data['client_id'] = validate_guid(data['client_id'])
    if not EMAIL_RE.fullmatch(data['mailbox']):
        raise ValueError('Invalid configured mailbox')
    if not Path(data['certificate']).is_file():
        raise ValueError('Certificate file is missing')
    if 'signer' in data:
        validate_spec(data, path)
        data['_identity_path'] = str(path)
    else:
        if not data.get('private_key') or not Path(data['private_key']).is_file():
            raise ValueError('PEM private key file is missing')
    return data


def make_client_assertion(config, now=None):
    now = int(time.time()) if now is None else int(now)
    endpoint = (f"https://login.microsoftonline.com/{config['tenant_id']}"
                '/oauth2/v2.0/token')
    certificate_der = run_openssl(
        'x509', '-in', config['certificate'], '-outform', 'DER'
    )
    header = {
        'alg': 'PS256', 'typ': 'JWT',
        'x5t#S256': base64url(hashlib.sha256(certificate_der).digest()),
    }
    claims = {
        'aud': endpoint, 'iss': config['client_id'],
        'sub': config['client_id'], 'jti': str(uuid.uuid4()),
        'nbf': now - 60, 'iat': now, 'exp': now + 600,
    }
    def enc(obj):
        return base64url(json.dumps(obj, separators=(',', ':')).encode('utf-8'))
    unsigned = f'{enc(header)}.{enc(claims)}'.encode('ascii')
    if 'signer' in config:
        signature = sign_ps256(config, unsigned)
    else:
        signature = run_openssl(
            'dgst', '-sha256', '-sign', config['private_key'],
            '-sigopt', 'rsa_padding_mode:pss',
            '-sigopt', 'rsa_pss_saltlen:32', data=unsigned,
        )
    return endpoint, unsigned.decode('ascii') + '.' + base64url(signature)


def acquire_token(config):
    endpoint, assertion = make_client_assertion(config)
    data = urllib.parse.urlencode({
        'client_id': config['client_id'],
        'grant_type': 'client_credentials',
        'scope': 'https://outlook.office365.com/.default',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': assertion,
    }).encode('ascii')
    request = urllib.request.Request(
        endpoint, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        # Intentionally no body dump: do not expose credentials, assertions or tokens.
        raise TransientError(f'Entra token endpoint HTTP {exc.code}') from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise TransientError('Cannot reach Entra token endpoint: ' + type(exc).__name__) from None
    token = result.get('access_token')
    if not isinstance(token, str) or not token:
        raise TransientError('Entra did not issue an access token')
    return token


def build_message(raw_message, mailbox):
    try:
        message = BytesParser(policy=policy.SMTP).parsebytes(raw_message)
        if message.is_multipart() and not message.get_boundary():
            raise ValueError('Multipart message has no boundary')
        if 'From' in message:
            del message['From']
        message['From'] = mailbox
        if 'Sender' in message:
            del message['Sender']
        if 'Return-Path' in message:
            del message['Return-Path']
        if 'Bcc' in message:
            del message['Bcc']
        if 'Date' not in message:
            message['Date'] = formatdate(localtime=False)
        if 'Message-ID' not in message:
            message['Message-ID'] = make_msgid(domain=mailbox.split('@', 1)[1])
        return message.as_bytes(policy=policy.SMTP)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PermanentError('Invalid RFC 5322 message') from exc


def send_smtp(config, recipient, raw_message, token):
    if not EMAIL_RE.fullmatch(recipient):
        raise PermanentError('Invalid recipient address')
    mailbox = config['mailbox']
    message = build_message(raw_message, mailbox)
    auth_text = f'user={mailbox}\x01auth=Bearer {token}\x01\x01'
    auth_value = base64.b64encode(auth_text.encode('utf-8')).decode('ascii')
    host = 'smtp.office365.com'
    with smtplib.SMTP(host, 587, timeout=45) as client:
        client.ehlo()
        if not client.has_extn('starttls'):
            raise TransientError('Microsoft 365 did not offer STARTTLS')
        client.starttls(context=ssl.create_default_context())
        client.ehlo()
        mechanisms = client.esmtp_features.get('auth', '').upper().split()
        if 'XOAUTH2' not in mechanisms:
            raise TransientError('Microsoft 365 did not advertise AUTH XOAUTH2')
        code, _ = client.docmd('AUTH', 'XOAUTH2 ' + auth_value)
        if code == 334:
            # Clear SASL failure challenge without disclosing contents.
            client.docmd('')
            raise TransientError('Microsoft 365 rejected the XOAUTH2 token (334)')
        if code != 235:
            raise TransientError(f'Microsoft 365 XOAUTH2 authentication failed (SMTP {code})')
        refused = client.sendmail(mailbox, [recipient], message)
        if refused:
            code, _ = refused[recipient]
            if 400 <= code < 500:
                raise TransientError(f'SMTP recipient temporarily refused: {code}')
            raise PermanentError(f'SMTP recipient rejected: {code}')


def check_smtp_auth(config, token):
    """Complete real Exchange Online SMTP STARTTLS/XOAUTH2 authentication only.

    Never issues MAIL FROM, RCPT TO or DATA, never submits a message, and
    never prints the bearer token, SASL exchange or server's challenge.
    """
    mailbox = config['mailbox']
    if not EMAIL_RE.fullmatch(mailbox):
        raise PermanentError('Invalid configured sender mailbox')
    sasl = ('user=' + mailbox + '\x01auth=Bearer ' + token + '\x01\x01')
    encoded = base64.b64encode(sasl.encode('utf-8')).decode('ascii')
    with smtplib.SMTP('smtp.office365.com', 587, timeout=45) as client:
        client.ehlo()
        if not client.has_extn('starttls'):
            raise TransientError('Microsoft 365 did not offer STARTTLS')
        client.starttls(context=ssl.create_default_context())
        client.ehlo()
        offered = client.esmtp_features.get('auth', '').upper().split()
        if 'XOAUTH2' not in offered:
            raise TransientError('Microsoft 365 did not advertise AUTH XOAUTH2')
        code, _ = client.docmd('AUTH', 'XOAUTH2 ' + encoded)
        if code == 334:
            # Consume an RFC 7628 error challenge without exposing its body.
            client.docmd('')
            raise TransientError('Microsoft 365 rejected staged XOAUTH2 token (334)')
        if code != 235:
            raise TransientError('Microsoft 365 staged XOAUTH2 authentication failed (SMTP {})'.format(code))
    # Closing authenticated session sends QUIT only. No sendmail(), no DATA.


def run(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--recipient', help='Single envelope recipient from Postfix')
    ap.add_argument('--token-check', action='store_true', help='Check Entra token acquisition without printing token')
    ap.add_argument('--smtp-auth-check', action='store_true', help='Verify real Microsoft 365 XOAUTH2 AUTH without MAIL/RCPT/DATA')
    ap.add_argument('--signing-check', action='store_true', help='Verify local PS256 signing without Entra traffic')
    ap.add_argument('--config-check', action='store_true', help='Check local configuration only')
    ap.add_argument('--config', choices=[str(CONF_FILE), str(SIDECAR_CONF_FILE)],
                    default=str(CONF_FILE), help='Explicit installed identity configuration')
    ap.add_argument('--candidate-config', choices=[str(x) for x in STAGED_CONF_FILES],
                    help='Root-staged hardware identity, usable only for signing/token checks')
    args = ap.parse_args(argv)
    try:
        if sum((bool(args.token_check), bool(args.signing_check), bool(args.config_check),
                bool(args.smtp_auth_check))) > 1:
            ap.error('Select only one non-delivery diagnostic action')
        if args.candidate_config is not None:
            if not (args.token_check or args.signing_check or args.config_check or args.smtp_auth_check) or args.recipient:
                ap.error('Candidate identity cannot send mail or accept a recipient')
            config = load_config(args.candidate_config)
            if 'signer' not in config:
                raise ValueError('Candidate hardware identity missing signer')
        else:
            config = load_config(args.config)
        if args.config_check:
            print('Local configuration OK (no network connection attempted)')
            return EX_OK
        if args.signing_check:
            make_client_assertion(config)
            print('Local PS256 signing and certificate match verified; no token requested')
            return EX_OK
        if args.token_check:
            acquire_token(config)
            print('Entra application token acquired (token not displayed)')
            return EX_OK
        if args.smtp_auth_check:
            token = acquire_token(config)
            check_smtp_auth(config, token)
            print('Microsoft 365 STARTTLS and SMTP AUTH XOAUTH2 verified; no message submitted')
            return EX_OK
        if not args.recipient:
            ap.error('--recipient is required for delivery')
        raw = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise PermanentError('Message is too large for this transport')
        if not raw:
            raise PermanentError('Empty message')
        if not EMAIL_RE.fullmatch(args.recipient):
            raise PermanentError('Invalid recipient address')
        token = acquire_token(config)
        send_smtp(config, args.recipient, raw, token)
        print('2.0.0 Accepted by Microsoft 365 SMTP')
        return EX_OK
    except PermanentError as exc:
        print('5.0.0 ' + str(exc), file=sys.stderr)
        return 69
    except (TransientError, HardwareSignerError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired,
            smtplib.SMTPException, ssl.SSLError) as exc:
        if isinstance(exc, smtplib.SMTPResponseException):
            text = f'Exchange SMTP error {exc.smtp_code}'
        elif isinstance(exc, (OSError, ValueError, json.JSONDecodeError)):
            text = type(exc).__name__ + ': ' + str(exc)[:160]
        else:
            text = str(exc)[:160]
        print('4.3.0 ' + text, file=sys.stderr)
        return EX_TEMPFAIL


if __name__ == '__main__':
    sys.exit(run())
