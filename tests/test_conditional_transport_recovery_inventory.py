"""Read-only recovery inventory over disposable multi-transport transactions."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "recovery_inventory", str(ROOT / "linux/inspect-conditional-transport-recovery.py"))
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)
fixture_spec = importlib.util.spec_from_file_location(
    "transaction_fixture", str(ROOT / "tests/test_conditional_transport_transaction.py"))
F = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(F)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.MultiTransportTransactionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def scan(self):
        f = self.fixture
        return I.inventory(f.fd, f.parent, f.uid, f.gid)

    def test_empty_inventory_does_not_create_backup(self):
        self.assertEqual(self.scan(), [])
        self.assertFalse((self.fixture.root / I.R.BASE).exists())

    def test_snapshot_apply_restore_and_missing_map(self):
        f = self.fixture
        revision = f.apply()
        self.assertEqual(self.scan(), [(revision, "configured_owned_maps")])
        path = f.config / next(iter(f.maps))
        path.unlink()
        self.assertEqual(self.scan(), [(revision, "configured_maps_missing")])
        f.restore(revision)
        self.assertEqual(self.scan(), [(revision, "original_no_maps")])

    def test_unrelated_edit_is_observed_not_overwritten(self):
        f = self.fixture
        revision = f.apply()
        path = f.config / "master.cf"
        value = path.read_bytes() + b"# unrelated edit\n"
        path.write_bytes(value)
        self.assertEqual(self.scan(), [(revision, "configuration_drift")])
        self.assertEqual(path.read_bytes(), value)

    def test_snapshot_only(self):
        f = self.fixture
        revision = I.R.backup(f.fd, f.parent, f.reviewed, I.R.CONFIRM,
                              f.uid, f.guard, f.review)
        self.assertEqual(self.scan(), [(revision, "snapshot_only")])


    def installed_state(self, f):
        info = f.info
        values = dict.fromkeys(I.P.KEYS, "")
        values.update(I.P.FIXED_SETTINGS)
        values.update(local_transport="local:$myhostname", virtual_transport="virtual",
                      smtp_tls_CAfile=info["ca"])
        route = info["backend"] + ":/etc/postfix/" + info["map_names"][0]
        values[I.H.C.PARAMETER] = route
        extra = dict.fromkeys(I.H.EXTRA, "")
        extra.update(smtp_host_lookup="dns", disable_dns_lookups="no")
        _, _, routes, generated, _ = I.H.C.render(
            info["rules"], info["plan"], I.P.CONFIG, info["backend"], info["ca"])
        services = {(name, "unix"): name + " unix - - n - - " + command
                    for name, command in (("smtp", "smtp"), ("relay", "smtp"),
                                          ("rewrite", "trivial-rewrite"))}
        services.update({(name, "unix"): name + " unix - - n - - smtp"
                         for name in generated})
        overrides = {service + "/unix/" + key: value
                     for service, options in generated.items() for key, value in options.items()}
        return (values, extra, {I.H.C.PARAMETER: route}, services, overrides), routes

    def test_installed_discovery_returns_only_non_secret_rule_data(self):
        f = self.fixture
        revision = f.apply()
        state, routes = self.installed_state(f)
        calls = []
        def lookup(spec, expected):
            calls.append(spec)
            self.assertEqual(expected, routes)
            self.assertNotIn("-sasl", spec)
            return True
        result = I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid),
                             lambda: state, lookup)
        self.assertEqual(result, {"status": "installed_owned", "revision": revision,
                                  "plan": f.info["plan"], "backend": "hash", "rules": f.rules})
        self.assertEqual(len(calls), 2)
        wire = I.M.canonical(result)
        self.assertNotIn(b"synthetic private", wire)
        self.assertNotIn(b"sha256", wire)

    def test_installed_foreign_map_or_no_map(self):
        f = self.fixture
        state, _ = self.installed_state(f)
        self.assertEqual(I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid),
                         lambda: state, lambda *_: False), {"status": "external_or_unverified"})
        state[0][I.H.C.PARAMETER] = ""
        self.assertEqual(I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid),
                         lambda: state, lambda *_: False), {"status": "no_effective_transport_map"})

    def test_installed_native_override_drift_refused(self):
        f = self.fixture
        f.apply()
        state, _ = self.installed_state(f)
        key = next(iter(state[4]))
        state[4][key] = "changed"
        with self.assertRaises(I.H.Refused):
            I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid), lambda: state,
                        lambda *_: True)

    def test_installed_native_route_lookup_drift_refused(self):
        f = self.fixture
        f.apply()
        state, _ = self.installed_state(f)
        with self.assertRaises(I.H.Refused):
            I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid),
                        lambda: state, lambda *_: False)

    def test_installed_missing_credential_db_is_not_owned(self):
        f = self.fixture
        f.apply()
        state, _ = self.installed_state(f)
        name = next(name for name in f.maps if "-sasl" in name)
        (f.config / name).unlink()
        self.assertEqual(I.installed(f.fd, f.parent, f.uid, (f.uid, f.gid),
                         lambda: state, lambda *_: True), {"status": "external_or_unverified"})


if __name__ == "__main__":
    unittest.main()
