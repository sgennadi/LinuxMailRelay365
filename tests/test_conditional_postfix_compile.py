"""Native candidate compiler tests, using a fake tool unless in real smoke."""
import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conditional_compile", str(ROOT / "linux/stage-conditional-postfix-maps.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class FakePostfix:
    def __init__(self, backends=b"hash\nlmdb\n", fault=None):
        self.backends = backends
        self.fault = fault
        self.calls = []

    def __call__(self, tool, args, data=None):
        self.calls.append((tool, list(args)))
        assert args[0] == "-c"
        work = pathlib.Path(args[1])
        assert (work / "main.cf").read_bytes() == M.NATIVE_CONFIG
        if tool == "postconf":
            assert args[2:] == ["-m"]
            return 0, self.backends
        assert tool == "postmap"
        backend, filename = args[-1].split(":", 1)
        source = pathlib.Path(filename)
        assert source.parent == work
        db = pathlib.Path(filename + M.MAP_SUFFIX[backend])
        if len(args) == 3:
            if self.fault == "compile":
                return 2, b""
            db.write_bytes(M.canonical(M.candidate_rows(source.read_bytes())))
            db.chmod(0o600)
            return 0, b""
        rows = M.decode(db.read_bytes())
        output = "".join(k + "\t" + v + "\n" for k, v in rows.items()).encode("ascii")
        if args[2] == "-s":
            return 0, output + (b"extra\tbad\n" if self.fault == "extra" else b"")
        assert args[2] == "-q"
        if args[3] == "-":
            assert set(data.decode("ascii").split()) == set(rows)
            return (1, b"") if self.fault == "positive" else (0, output)
        assert args[3] == M.NEGATIVE_KEY
        return (0, b"bad\n") if self.fault == "negative" else (1, b"")


class NativeCompileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.fd = os.open(str(self.root), M.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        self.uid = os.getuid()
        self.plan = [
            dict(selector="exact-envelope-sender", pattern="user@example.org",
                 host="relay.example.net", port=587, tls="starttls", auth="none"),
            dict(selector="exact-envelope-sender", pattern="other@example.org",
                 host="other.example.net", port=46500, tls="starttls", auth="none"),
        ]
        self.sha, _ = M.build(self.plan)
        _, self.receipt = M.stage(self.fd, self.plan, self.sha,
                                  "STAGE_CONDITIONAL_MAPS_ONLY", self.uid)

    def compile(self, runner, receipt=None):
        return M.compile_stage(self.fd, self.sha, receipt or self.receipt,
                               "COMPILE_CONDITIONAL_MAPS_ONLY", self.uid,
                               str(self.root), runner)

    def test_native_hash_compile_and_verified_copy(self):
        runner = FakePostfix()
        stage_sha, compiled_sha, backend, count = self.compile(runner)
        self.assertEqual((stage_sha, backend, count), (self.receipt, "hash", 2))
        self.assertEqual(len(compiled_sha), 64)
        directory = self.root / M.COMPILED_BASE / self.sha
        self.assertEqual(set(x.name for x in directory.iterdir()),
                         {"sender-candidates.txt.db", M.COMPILED_MANIFEST})
        self.assertEqual(M.verify_compiled(self.fd, self.sha, self.uid,
                                           str(self.root), runner),
                         (stage_sha, compiled_sha, backend, count))
        with self.assertRaises(M.Refused):
            self.compile(runner)
        self.assertEqual(len(list(self.root.glob("lmr365-map-check-*"))), 0)

    def test_lmdb_fallback(self):
        _, _, backend, count = self.compile(FakePostfix(b"regexp\nlmdb\n"))
        self.assertEqual((backend, count), ("lmdb", 2))
        self.assertTrue((self.root / M.COMPILED_BASE / self.sha /
                         "sender-candidates.txt.lmdb").is_file())

    def test_refuse_native_errors_before_compiled_publication(self):
        for runner in (FakePostfix(b"regexp\n"), FakePostfix(fault="compile"),
                       FakePostfix(fault="extra"), FakePostfix(fault="positive"),
                       FakePostfix(fault="negative")):
            with self.subTest(fault=runner.fault, backends=runner.backends):
                with self.assertRaises(M.Refused):
                    self.compile(runner)
                self.assertFalse((self.root / M.COMPILED_BASE).exists())

    def test_refuse_unreviewed_stage(self):
        runner = FakePostfix()
        with self.assertRaises(M.Refused):
            self.compile(runner, "0" * 64)
        self.assertEqual(runner.calls, [])

    def test_refuse_tampered_compiled_db_before_lookup(self):
        self.compile(FakePostfix())
        path = self.root / M.COMPILED_BASE / self.sha / "sender-candidates.txt.db"
        path.write_bytes(path.read_bytes() + b"x")
        runner = FakePostfix()
        with self.assertRaises(M.Refused):
            M.verify_compiled(self.fd, self.sha, self.uid, str(self.root), runner)
        self.assertEqual(runner.calls, [])

    def test_refuse_tampered_source_before_compilation(self):
        path = self.root / M.BASE_NAME / self.sha / "sender-candidates.txt"
        path.write_bytes(path.read_bytes() + b"unexpected")
        runner = FakePostfix()
        with self.assertRaises(M.Refused):
            self.compile(runner)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
