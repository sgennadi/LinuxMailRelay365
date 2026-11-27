import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import Mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("wizard",ROOT/"linux/discover-smtp-acme-wizard.py")
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class ProviderDiscoveryTests(unittest.TestCase):
    def query(self,zone,kind):
        if zone=="example.org" and kind=="NS":
            return ["one.ns.cloudflare.com."]
        return []

    def plugins(self):
        return {"status":"completed","providers":{"dns-cloudflare":{"registered":True}}}

    def test_registered_matching_provider_is_only_hint(self):
        result=M.inspect("relay.example.org","example.org",self.query,self.plugins())
        self.assertEqual(result["recommendation"]["recommended_provider"],"dns-cloudflare")
        self.assertFalse(result["automatic_issuance_allowed"])
        self.assertFalse(result["postfix_modified"])

    def test_direct_challenge_ns_requires_manual_review(self):
        def query(zone,kind):
            if zone=="_acme-challenge.relay.example.org" and kind=="NS":
                return ["other.ns.cloudflare.com."]
            return self.query(zone,kind)
        result=M.inspect("relay.example.org","example.org",query,self.plugins())
        self.assertTrue(result["delegation"]["delegated"])
        self.assertIsNone(result["recommendation"]["recommended_provider"])

    def test_failed_plugin_inventory_cannot_recommend(self):
        result=M.inspect("relay.example.org","example.org",self.query,{"status":"probe_failed"})
        self.assertIsNone(result["recommendation"]["recommended_provider"])

    def test_exact_owner_and_record_type(self):
        data=b";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.org. 60 IN NS one.ns.cloudflare.com.\nother.example.org. 60 IN NS ignored.example.org.\n"
        self.assertEqual(M.parse_answer(data,"example.org","NS"),["one.ns.cloudflare.com."])
        with self.assertRaises(ValueError):
            M.parse_answer(data.replace(b"NOERROR",b"SERVFAIL"),"example.org","NS")

    def test_absolute_queries_cached_and_bounded(self):
        runner=Mock(return_value=subprocess.CompletedProcess([],0,b";; status: NOERROR,\n"))
        query=M.make_query("/usr/bin/dig",runner,lambda:0)
        self.assertEqual(query("example.org","NS"),[])
        self.assertEqual(query("example.org.","NS"),[])
        runner.assert_called_once()
        self.assertIn("example.org.",runner.call_args.args[0])
        self.assertIn("-r",runner.call_args.args[0])
        for i in range(23):
            query("zone"+str(i)+".example.org","NS")
        with self.assertRaises(ValueError):
            query("last.example.org","NS")
        self.assertEqual(runner.call_count,24)

    def test_invalid_domain_never_queries_dns(self):
        query=Mock()
        with self.assertRaises(ValueError):
            M.inspect("evil.test","example.org",query,self.plugins())
        query.assert_not_called()

    def test_gui_and_resources_are_wired(self):
        src=ROOT/"src/LinuxMailRelay365"
        self.assertIn("BuildSmtpAcmeProviderDiscovery", (src/"MainForm.DeliveryMiniWizard.cs").read_text())
        self.assertIn("Select recommended provider", (src/"SmtpAcmePlanDialog.cs").read_text())
        project=(src/"LinuxMailRelay365.csproj").read_text()
        for name in ("discover-smtp-acme-wizard.py","discover-smtp-public-dns.py",
                     "inspect-smtp-acme-delegation.py","probe-smtp-acme-plugins.py",
                     "recommend-smtp-acme-provider.py"):
            self.assertIn("../../linux/"+name,project)
