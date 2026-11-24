"""Synthetic raw audit events, with no real logs, mail or policy changes."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "avc", str(ROOT / "linux/inspect-conditional-transport-selinux-avc.py"))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
RULES = [
    dict(selector="exact-envelope-sender", pattern="one@example.org",
         host="smtp.example.net", port=2526, tls="starttls", auth="password"),
    dict(selector="exact-envelope-sender", pattern="two@example.org",
         host="smtp.example.net", port=465, tls="implicit", auth="none"),
]


def avc(event=1, port=2526, mode="0", domain="postfix_smtp_t",
        permission="name_connect", kind="tcp_socket", decision="denied", comm='"smtp"'):
    tail = "" if mode is None else " permissive=" + mode
    return ('type=AVC msg=audit(1780000000.123:{}): avc: {} {{ {} }} for '
            'pid=42 comm={} dest={} scontext=system_u:system_r:{}:s0 '
            'tcontext=system_u:object_r:smtp_port_t:s0 tclass={}{}\n'
            .format(event, decision, permission, comm, port, domain, kind, tail)).encode("ascii")


class AvcTests(unittest.TestCase):
    def test_separate_modes_domains_and_ports(self):
        records = (avc() + avc() + avc(2, mode="1") + avc(3, mode=None) +
                   avc(4, port=465) + avc(5, port=25) +
                   avc(6, domain="postfix_smtpd_t") +
                   avc(7, permission="name_bind") +
                   avc(8, kind="udp_socket") + avc(9, decision="granted") +
                   b'type=SYSCALL msg=audit(1780000000.123:1): exe="/private/fixture"\n')
        self.assertEqual(A.summarize(records, [465, 2526]), {465: (1, 0, 0), 2526: (1, 1, 1)})

    def test_quoted_fields_do_not_inject_destination_or_domain(self):
        data = avc(port=25, comm='"smtp dest=2526 scontext=system_u:system_r:postfix_smtp_t:s0"')
        self.assertEqual(A.summarize(data, [2526]), {2526: (0, 0, 0)})

    def test_invalid_truncated_or_duplicate_fields_fail_closed(self):
        for raw in (b"", avc()[:-1], b"type=AVC garbage\n",
                    avc().replace(b"dest=2526", b"dest=2526 dest=465"),
                    avc().replace(b"dest=2526", b"dest=65536"),
                    b"type=SYSCALL fixture\n", b"x" * (A.MAX_OUTPUT + 1)):
            with self.assertRaises(A.L.Refused):
                A.summarize(raw, [2526])

    def test_report_is_aggregate_only(self):
        result = A.report(RULES, "enforcing", lambda: (0, avc(comm='"fixture private"')))
        self.assertEqual(result["STATUS"], "records_read")
        self.assertEqual(result["PORTS"], "465:0:0:0,2526:1:0:0")
        self.assertEqual(result["WINDOW"], "recent")
        for flag in ("WRITE_ALLOWED", "RUNTIME_VERIFIED", "CHANGES_APPLIED", "MAIL_SENT"):
            self.assertEqual(result[flag], "no")
        self.assertNotIn("fixture", str(result))
        self.assertNotIn("postfix_smtp_t", str(result))
        self.assertNotIn("1780000000", str(result))

    def test_ambiguous_no_matches_not_clean(self):
        for code, raw, expected in ((1, b"", "no_matches_or_unavailable"),
                                    (1, avc(), "unverified"),
                                    (2, b"", "unverified"),
                                    (0, b"", "unverified")):
            result = A.report(RULES, "enforcing", lambda: (code, raw))
            self.assertEqual(result["STATUS"], expected)
            self.assertEqual(result["PORTS"], "465:0:0:0,2526:0:0:0")

    def test_inactive_and_unknown_do_not_query_audit(self):
        def forbidden():
            self.fail("audit queried")
        for mode in ("inactive_or_unavailable", "unverified"):
            result = A.report(RULES, mode, forbidden)
            self.assertEqual(result["STATUS"], "not_checked")

    def test_missing_tool_is_unverified(self):
        def missing():
            raise OSError("private path")
        result = A.report(RULES, "permissive", missing)
        self.assertEqual(result["STATUS"], "unverified")
        self.assertNotIn("private path", str(result))


if __name__ == "__main__":
    unittest.main()
