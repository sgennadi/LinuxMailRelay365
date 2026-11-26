import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location("azure",str(pathlib.Path(__file__).resolve().parents[1]/"linux/issue-smtp-acme-azure.py"))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class AzureTests(unittest.TestCase):
    def test_command(self):
        args=m.command("smtp.example.com","example.com","https://ca.example.com/directory","admin@example.com","/root/azure.ini")
        self.assertEqual(args[args.index("--authenticator")+1],"dns-azure")
        self.assertEqual(args[args.index("--dns-azure-config")+1],"/root/azure.ini")
        self.assertIn("--keep-until-expiring",args)
    def test_domain(self):
        with self.assertRaises(ValueError):
            m.command("smtp.other.com","example.com","https://ca.example.com/directory","admin@example.com","/root/azure.ini")
