"""Read-only local SMTP Auth/From Guard versus OAuth sender map checks.

Mock the installed OS state; never start Postfix, open network sockets or read
user data. The result must never be mistaken for a live SMTP authorization.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "audit-oauth-ingress.py"
POLICY = ROOT / "linux" / "audit-oauth-sender-map.py"


def module_from_file(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


AUDIT = module_from_file(SCRIPT, "audit_oauth_ingress")
MAP = module_from_file(POLICY, "audit_oauth_sender_map_for_ingress")


class IngressAuditTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            ("alice", "alice@example.org", "alice@example.org",
             "/etc/linuxmailrelay365/oauth-identities/alice.json"),
            ("bob", "bob@example.org", "service@example.org",
             "/etc/linuxmailrelay365/oauth-identities/service.json"),
        ]
        salted = "{SHA512-CRYPT}$6$abcdefgh$" + "A" * 86
        self.blobs = {
            AUDIT.HASHES: ("alice:" + salted + "\nbob:" + salted + "\n").encode("ascii"),
            AUDIT.GUARD: b"alice@example.org alice\nbob@example.org bob\n",
        }
        self.cfg = dict(
            smtpd_sasl_auth_enable="yes",
            smtpd_tls_security_level="encrypt",
            smtpd_tls_auth_only="yes",
            smtpd_sasl_type="dovecot",
            smtpd_sasl_path="private/auth",
            smtpd_relay_restrictions="permit_sasl_authenticated, reject",
            smtpd_client_restrictions="permit_mynetworks, reject",
            smtpd_recipient_restrictions=(
                "check_recipient_access regexp:" + AUDIT.CONF +
                "/eop-recipients.regexp, reject"),
            smtpd_sender_login_maps=AUDIT.OWNER_MAP,
            smtpd_sender_restrictions=AUDIT.SENDER_POLICY,
            smtpd_milters=AUDIT.MILTER,
            milter_protocol="6",
            milter_default_action="tempfail",
            milter_mail_macros="i {mail_addr} {auth_authen} {auth_type}",
            non_smtpd_milters="",
            smtpd_milter_maps="",
            authorized_submit_users="",
            default_transport="smtp:[example-org.mail.protection.outlook.com]:25",
        )

    def evaluate(self):
        return AUDIT.assess(
            self.rows, MAP,
            read_file=lambda path, limit, mode, gid: self.blobs[path],
            config=lambda key: self.cfg.get(key),
            active=lambda unit: True,
            gids=(141, 142),
            socket_check=lambda: True)

    def test_exact_matches_are_only_static_compatibility(self):
        results = self.evaluate()
        self.assertEqual(results["AUTH_ACCOUNTS"], "exact_match")
        self.assertEqual(results["FROM_GUARD_POLICY"], "exact_match")
        self.assertEqual(results["SASL_TLS_CONFIG"], "configured_only")
        self.assertEqual(results["SENDER_LOGIN_CONFIG"], "configured_only")
        self.assertEqual(results["FROM_GUARD_MILTER_CONFIG"],
                         "configured_fail_closed_only")
        self.assertEqual(results["SERVICES"], "all_report_active")
        self.assertEqual(results["MILTER_SOCKET"], "metadata_matches_only")
        self.assertEqual(results["TRANSPORT"], "eop_smtp_not_xoauth2_multi")
        self.assertEqual(results["OVERALL"],
                         "ingress_config_consistent_not_live_verified")
        self.assertNotIn("alice@", repr(results))
        self.assertNotIn("service@", repr(results))

    def test_login_mismatch_and_duplicate_are_not_reported_ready(self):
        self.blobs[AUDIT.HASHES] = self.blobs[AUDIT.HASHES].replace(b"bob:", b"eve:")
        result = self.evaluate()
        self.assertEqual(result["AUTH_ACCOUNTS"], "different")
        self.assertEqual(result["OVERALL"], "not_ready")
        self.blobs[AUDIT.HASHES] = b"alice:invalid_password_hash\n"
        self.assertEqual(self.evaluate()["AUTH_ACCOUNTS"], "unavailable_or_unsafe")

    def test_from_guard_missing_or_changed_is_not_ready(self):
        self.blobs[AUDIT.GUARD] = b"alice@example.org bob\nbob@example.org alice\n"
        self.assertEqual(self.evaluate()["FROM_GUARD_POLICY"], "different")
        self.assertEqual(self.evaluate()["OVERALL"], "not_ready")
        self.blobs[AUDIT.GUARD] = b"alice@example.org bob\nalice@example.org alice\n"
        self.assertEqual(self.evaluate()["FROM_GUARD_POLICY"], "unavailable_or_unsafe")

    def test_config_drift_cannot_be_reported_as_consistent(self):
        mutations = (
            ("smtpd_sasl_auth_enable", "no", "SASL_TLS_CONFIG"),
            ("smtpd_tls_security_level", "may", "SASL_TLS_CONFIG"),
            ("smtpd_tls_auth_only", "no", "SASL_TLS_CONFIG"),
            ("smtpd_relay_restrictions", "permit_mynetworks, reject", "SASL_TLS_CONFIG"),
            ("smtpd_client_restrictions", "permit", "SASL_TLS_CONFIG"),
            ("smtpd_recipient_restrictions", "permit", "SASL_TLS_CONFIG"),
            ("smtpd_sender_login_maps", "", "SENDER_LOGIN_CONFIG"),
            ("smtpd_sender_restrictions", "permit_mynetworks", "SENDER_LOGIN_CONFIG"),
            ("smtpd_milters", "", "FROM_GUARD_MILTER_CONFIG"),
            ("milter_default_action", "accept", "FROM_GUARD_MILTER_CONFIG"),
            ("milter_protocol", "2", "FROM_GUARD_MILTER_CONFIG"),
            ("authorized_submit_users", "static:anyone", "FROM_GUARD_MILTER_CONFIG"),
            ("non_smtpd_milters", AUDIT.MILTER, "FROM_GUARD_MILTER_CONFIG"),
            ("smtpd_milter_maps", "static:DISABLE", "FROM_GUARD_MILTER_CONFIG"),
        )
        for key, value, status in mutations:
            with self.subTest(parameter=key):
                old = self.cfg[key]
                self.cfg[key] = value
                try:
                    result = self.evaluate()
                    self.assertEqual(result[status], "not_verified")
                    self.assertEqual(result["OVERALL"], "not_ready")
                finally:
                    self.cfg[key] = old

    def test_missing_service_and_socket_is_static_failure(self):
        result = AUDIT.assess(
            self.rows, MAP,
            read_file=lambda path, limit, mode, gid: self.blobs[path],
            config=lambda key: self.cfg.get(key),
            active=lambda unit: unit != "linuxmailrelay365-from-guard.service",
            gids=(141, 142),
            socket_check=lambda: False)
        self.assertEqual(result["SERVICES"], "not_all_active")
        self.assertEqual(result["MILTER_SOCKET"], "not_verified")
        self.assertEqual(result["OVERALL"], "not_ready")

    def test_existing_account_limit_more_than_64_is_refused(self):
        rows = [
            ("user" + str(i), "user" + str(i) + "@example.org",
             "box@example.org", "/etc/linuxmailrelay365/oauth-identities/box.json")
            for i in range(65)
        ]
        result = AUDIT.assess(rows, MAP, config=lambda key: self.cfg.get(key),
                              active=lambda unit: True,
                              gids=(141, 142), socket_check=lambda: True)
        self.assertEqual(result["AUTH_ACCOUNTS"], "over_64_account_limit")
        self.assertEqual(result["FROM_GUARD_POLICY"], "over_64_account_limit")
        self.assertEqual(result["OVERALL"], "not_ready")

    def test_refuses_nonroot_and_never_logs_sensitive_data(self):
        with mock.patch.object(AUDIT.os, "geteuid", return_value=1102), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            code = AUDIT.main(["--map-path",
                               "/etc/linuxmailrelay365/oauth-senders.tsv"])
        self.assertEqual(code, 2)
        self.assertIn("OAUTH_INGRESS_ERROR=root_required", err.getvalue())
        self.assertNotIn("example.org", err.getvalue())

    def test_read_only_argv_contract(self):
        src = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("smtplib", "urllib.request", "postconf -e",
                          "systemctl start", "systemctl restart",
                          "tpm2_clear", "tpm2_evictcontrol"):
            self.assertNotIn(forbidden, src)
        self.assertIn("OAUTH_INGRESS_MULTI_MAILBOX_ENABLED=no", src)
        self.assertIn("OAUTH_INGRESS_MESSAGES_SENT=no", src)
        self.assertIn("OAUTH_INGRESS_REAL_SMTP_LOGIN_VERIFIED=no", src)


if __name__ == "__main__":
    unittest.main()
