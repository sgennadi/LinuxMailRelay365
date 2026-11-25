"""Read-only route lookup tests; no real messages or production map updates."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("installed_route", str(ROOT / "linux/inspect-postfix-route.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class RouteTests(unittest.TestCase):
    def values(self):
        values = dict((k, "") for k in M.KEYS)
        values.update(default_transport="smtp", relay_transport="relay",
                      local_transport="local:localhost", virtual_transport="virtual",
                      mydestination="localhost, local.example.org",
                      relay_domains="relay.example.org", recipient_delimiter="+")
        return values

    def test_address_classes(self):
        v = self.values()
        self.assertEqual(M.literal_class("local.example.org", v), "local")
        self.assertEqual(M.literal_class("relay.example.org", v), "relay")
        self.assertEqual(M.literal_class("external.example.org", v), "default")
        v["virtual_mailbox_domains"] = "hash:/etc/postfix/virtual_domains"
        self.assertEqual(M.literal_class("external.example.org", v), "unknown")
        v["virtual_mailbox_domains"] = "local.example.org"
        self.assertEqual(M.literal_class("local.example.org", v), "unknown")

    def test_keys_and_lookup_precedence(self):
        self.assertEqual(M.transport_keys("user+tag@dept.example.org", "+", False),
            [("user+tag@dept.example.org", "exact"), ("user@dept.example.org", "extension"),
             ("dept.example.org", "domain"), (".example.org", "parent"), (".org", "parent"),
             ("*", "wildcard")])
        self.assertIn(("example.org", "parent"), M.transport_keys("user@dept.example.org", "", True))
        self.assertEqual(M.sender_keys("user@example.org"), [("user@example.org", "exact"), ("@example.org", "domain")])
        v = self.values()
        absent = ("not_declared", None)
        t = ("matched_domain", "smtp:[tenant.mail.protection.outlook.com]:25")
        s = ("matched_exact", "m365xoauth2:")
        h = ("matched_exact", "[smtp.office365.com]:587")
        self.assertEqual(M.classify(v, "default", [t,s,h], b""),
                         ("transport_maps", "smtp_m365_eop", "[tenant.mail.protection.outlook.com]:25"))
        self.assertEqual(M.classify(v, "default", [absent,s,h], b""),
                         ("sender_transport_map", "oauth_pipe", ""))
        self.assertEqual(M.classify(v, "default", [absent,absent,h], b""),
                         ("sender_relay_map", "smtp_m365_submission", "[smtp.office365.com]:587"))
        self.assertEqual(M.classify(v, "local", [absent,s,h], b""),
                         ("local_transport", "local", ""))
        self.assertEqual(M.classify(v, "relay", [absent,s,h], b"")[0], "sender_relay_map")
        self.assertEqual(M.classify(v, "default", [absent,("matched_exact","DUNNO"),absent], b""),
                         ("default_transport", "smtp_dns", ""))
        for evidence in ([("unsupported",None),s,h], [absent,s,("unverified",None)],
                         [("matched_exact",":unsafe"),s,h]):
            self.assertEqual(M.classify(v,"default",evidence,b"")[1], "unknown")
        self.assertEqual(M.classify(v,"default",[absent,s,h],b"smtp override")[1], "unknown")
        v["virtual_alias_maps"] = "hash:secret-not-returned"
        self.assertEqual(M.classify(v,"default",[absent,s,h],b"")[1], "unknown")

    def test_allowlist_and_no_credentials(self):
        root = Path("/etc/postfix")
        self.assertEqual(M.map_spec(root,M.MAPS[0],"hash:/etc/postfix/transport"),
                         ("hash",root/"transport.db"))
        self.assertEqual(M.map_spec(root,M.MAPS[1],"lmdb:/etc/postfix/lmr365-"+"a"*64+"-sender-transport")[0],"lmdb")
        for value in ("hash:/etc/postfix/sasl_passwd", "ldap:/etc/postfix/transport",
                      "hash:/etc/postfix/../transport", "hash:/etc/postfix/transport, hash:/etc/postfix/transport2",
                      "proxy:hash:/etc/postfix/transport","hash:/tmp/transport"):
            with self.assertRaises(M.Refused):
                M.map_spec(root,M.MAPS[0],value)
        self.assertIsNone(M.endpoint("user:secret@smtp.example.org:587"))
        self.assertIsNone(M.endpoint("smtp.office365.com:99999"))

    def test_snapshot_queries_only_private_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            calls = []
            def runner(name,args):
                calls.append((name,args))
                self.assertEqual((work/"route-0.db").read_bytes(),b"fixture")
                self.assertEqual(args[:3],["-c",str(work),"-q"])
                self.assertEqual(args[-1],"hash:"+str(work/"route-0"))
                return (1,b"") if len(calls)==1 else (0,b"smtp:[relay.example.org]:587\n")
            self.assertEqual(M.query_copy(work,0,"hash",b"fixture",M.sender_keys("user@example.org"),runner),
                             ("matched_domain","smtp:[relay.example.org]:587"))

    def test_drift_fails_closed(self):
        v=self.values()
        req={"target":"primary","sender":"user@example.org","recipient":"dest@example.net"}
        with mock.patch.object(M,"config",side_effect=[(("a",),v,b""),(("b",),v,b"")]):
            with self.assertRaisesRegex(M.Refused,"configuration_drift"):
                M.inspect(req)

    def test_native_hash_query_when_available(self):
        # Actual postmap against a private fixture, never the installed map.
        if not Path("/usr/sbin/postmap").is_file():
            self.skipTest("native postmap not installed")
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder)
            (work/"main.cf").write_text("myhostname = fixture.example.org\nmydomain = example.org\n")
            (work/"master.cf").write_text("# fixture\n")
            source=work/"fixture"
            source.write_text("user@example.org smtp:[smtp.office365.com]:587\n")
            code,_=M.native("postmap",["-c",str(work),"hash:"+str(source)])
            self.assertEqual(code,0)
            data=(work/"fixture.db").read_bytes()
            self.assertEqual(M.query_copy(work,0,"hash",data,M.sender_keys("user@example.org")),
                ("matched_exact","smtp:[smtp.office365.com]:587"))
            self.assertEqual(M.query_copy(work,1,"hash",data,M.sender_keys("other@example.org")),
                ("no_match",None))


if __name__ == "__main__":
    unittest.main()
