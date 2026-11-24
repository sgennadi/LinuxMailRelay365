"""Orchestration tests using disposable files and explicit host adapters.

No installed Postfix, network, credentials other than synthetic strings, or
repository modules are needed. Run the repository/native tests separately.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
CLI = HERE / 'manage-conditional-transport-rotation.py'
if not CLI.is_file():
    CLI = HERE.parent / 'linux' / CLI.name
spec = importlib.util.spec_from_file_location('rotation_host_under_test', CLI)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class Refused(Exception):
    pass


class RotationFailed(Refused):
    def __init__(self, revision, rolled_back):
        self.revision = revision
        self.rolled_back = rolled_back


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def valid_sha(value):
    return type(value) is str and len(value) == 64 and all(x in '0123456789abcdef' for x in value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


class HostTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='rc14-host-test-')
        self.addCleanup(folder.cleanup)
        self.path = pathlib.Path(folder.name)
        for name in ('main.cf', 'master.cf'):
            (self.path / name).write_bytes(b'fixture config\n')
        self.fd = os.open(str(self.path), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.rev = 'a' * 64
        self.plan = 'b' * 64
        self.cred = {'username': 'test-user', 'password': 'synthetic-sensitive-test'}
        self.info = {'plan': self.plan, 'backend': 'hash', 'ca': '/fixture/ca', 'rules': [
            {'host': 'one.example.net', 'port': 587, 'auth': 'password', 'tls': 'starttls'},
            {'host': 'two.example.net', 'port': 46500, 'auth': 'password', 'tls': 'implicit'},
            {'host': 'three.example.net', 'port': 25, 'auth': 'none', 'tls': 'starttls'}]}
        self.record = (self.info, {'private': b'configuration'},
                       {'maps': {'first.db': 'secret-hash-first', 'second.db': 'secret-hash-second'}},
                       {'first.db': [1, 2, 3, 4, 5], 'second.db': [6, 7, 8, 9, 10]})
        self.marker = {'name': 'second.db', 'generation': 'c' * 64, 'phase': 'replace',
                       'old_hash': 'old-private-hash', 'new_hash': 'new-private-hash'}
        self.retained = 'new_retained'
        self.current_state = {'native': 'unchanged'}
        self.guard = Mock()
        self.q = NS(X=NS(need=need), R=NS(valid_sha=valid_sha), M=NS(digest=digest, canonical=canonical),
                    T=NS(file_identity=identity), C=NS(credentials=Mock(side_effect=self.credentials)),
                    CONFIRM='rotate-approved', RECOVER='recover-approved', RotationFailed=RotationFailed,
                    target_name=self.target, pending_review=Mock(side_effect=self.pending),
                    compile_rotation_candidate=Mock(return_value=b'verified candidate'),
                    verify_retained_native=Mock(), rotate=Mock(side_effect=self.perform_rotation),
                    recover=Mock(side_effect=self.perform_recovery))
        self.h = NS(state=Mock(side_effect=lambda: copy.deepcopy(self.current_state)),
                    network=Mock(return_value=('d' * 64, 1)),
                    P=NS(CONFIG=str(self.path), local_addresses=Mock(return_value=set())))
        self.i = NS(H=self.h, O=NS(native_unprivileged=Mock()),
                    installed_record=Mock(side_effect=lambda *a: copy.deepcopy(self.record)),
                    verify_installed_policy=Mock(), route_lookup=Mock(return_value=True))
        self.host = A.RotationHost(self.q, self.i, self.fd, 9, (100, 101), 0, self.guard)

    def target(self, info, index):
        need(type(index) is int and 1 <= index <= len(info['rules']) and
             info['rules'][index - 1]['auth'] == 'password', 'password_transport_required')
        return ['first.db', 'second.db'][index - 1]

    def credentials(self, rules, slots):
        need(len(rules) == len(slots) == 1 and slots == [self.cred], 'invalid_credential')
        return ['synthetic value']

    def pending(self, *args):
        return copy.deepcopy((self.record, self.marker, [6, 7, 8, 9, 10], self.retained))

    def perform_rotation(self, config, parent, revision, index, record, db, gid,
                         confirm, uid, guard, verify, fresh):
        self.assertEqual(fresh(), record)
        self.assertEqual(db, b'verified candidate')
        self.assertEqual(index, 2)
        self.assertEqual(gid, 101)
        self.assertEqual(confirm, self.q.CONFIRM)
        guard()
        verify(True, self.info, 'second.db', db)
        verify(False, self.info, 'second.db', b'old database')
        return 'e' * 64

    def perform_recovery(self, config, parent, revision, reviewed, gid, confirm,
                         uid, guard, verify):
        self.assertEqual(reviewed, self.pending())
        self.assertEqual(confirm, self.q.RECOVER)
        guard()
        verify(True, self.info, 'second.db', b'retained database')
        return self.retained

    def review(self):
        return self.host.inspect(self.rev, 2, network=True)

    def recover_review(self):
        return self.host.inspect(self.rev, pending=True)

    def apply(self, review=None, credential=None):
        review = review or self.review()
        return self.host.rotate(self.rev, 2, review['token'], self.plan,
                                self.cred if credential is None else credential)

    def test_review_exact_tls_target_and_no_secret_receipt(self):
        reviewed = self.review()
        self.h.network.assert_called_once_with([self.info['rules'][1]], self.info['ca'], set())
        self.q.compile_rotation_candidate.assert_not_called()
        self.q.verify_retained_native.assert_not_called()
        self.assertEqual(reviewed['status'], 'rotation_ready')
        receipt = self.host.receipt(self.rev, reviewed)
        self.assertEqual(set(receipt), {'revision','plan_sha256','index','backend','review_sha256','retained'})
        self.assertNotIn('secret', str(receipt))
        self.assertNotIn('configuration', str(receipt))

    def test_approval_not_derived_from_private_hashes(self):
        first = self.review()['token']
        # Adapter models unchanged file identities but different private values.
        # Real installed-record validation would also check those values on disk.
        self.record[2]['maps']['second.db'] = 'different-private-hash'
        self.assertEqual(first, self.review()['token'])

    def test_identity_change_invalidates_approval(self):
        review = self.review()
        self.record[3]['second.db'][1] = 99
        with self.assertRaisesRegex(Refused, 'review_changed'):
            self.apply(review)
        self.q.compile_rotation_candidate.assert_not_called()

    def test_configuration_replacement_invalidates_review(self):
        review = self.review()
        new = self.path / 'replacement'
        new.write_bytes((self.path / 'main.cf').read_bytes())
        os.replace(new, self.path / 'main.cf')
        with self.assertRaisesRegex(Refused, 'review_changed'):
            self.apply(review)
        self.q.compile_rotation_candidate.assert_not_called()

    def test_wrong_plan_or_review_never_compiles(self):
        review = self.review()
        for token, plan in [('f' * 64, self.plan), (review['token'], 'f' * 64)]:
            with self.assertRaisesRegex(Refused, 'review_changed'):
                self.host.rotate(self.rev, 2, token, plan, self.cred)
        self.q.compile_rotation_candidate.assert_not_called()

    def test_one_slot_and_exact_verification_in_both_directions(self):
        self.assertEqual(self.apply(), 'e' * 64)
        self.q.C.credentials.assert_called_once_with([self.info['rules'][1]], [self.cred])
        self.q.compile_rotation_candidate.assert_called_once_with(self.info, 2, self.cred)
        new, old = self.q.verify_retained_native.call_args_list
        self.assertEqual(new.args[-1], self.cred)
        self.assertIsNone(old.args[-1])
        self.assertEqual(new.args[3], 'second.db')
        self.assertEqual(old.args[3], 'second.db')

    def test_native_policy_changes_after_compilation_refused(self):
        def compile_candidate(*args):
            self.current_state['native'] = 'changed after compiler'
            return b'candidate'
        self.q.compile_rotation_candidate.side_effect = compile_candidate
        with self.assertRaisesRegex(Refused, 'review_changed_after_compilation'):
            self.apply()
        self.q.rotate.assert_not_called()

    def test_tls_change_after_compile_refused(self):
        self.h.network.side_effect = [('d'*64,1), ('d'*64,1), ('f'*64,1)]
        with self.assertRaisesRegex(Refused, 'review_changed_after_compilation'):
            self.apply()
        self.q.rotate.assert_not_called()

    def test_no_auth_rule_not_eligible(self):
        with self.assertRaisesRegex(Refused, 'password_transport_required'):
            self.host.inspect(self.rev, 3, network=True)
        self.h.network.assert_not_called()

    def test_recovery_never_compiles_reads_password_input_or_checks_network(self):
        reviewed = self.recover_review()
        self.assertEqual(reviewed['index'], 2)
        self.assertEqual(self.host.recover(self.rev, reviewed['token'], self.plan), 'new_retained')
        self.h.network.assert_not_called()
        self.q.compile_rotation_candidate.assert_not_called()
        self.q.C.credentials.assert_not_called()
        self.assertEqual(self.q.verify_retained_native.call_args.args[3], 'second.db')
        self.assertEqual(len(self.q.verify_retained_native.call_args.args), 8)

    def test_pending_generation_or_actual_status_changes_review(self):
        reviewed = self.recover_review()
        self.marker['generation'] = 'e'*64
        with self.assertRaisesRegex(Refused, 'review_changed'):
            self.host.recover(self.rev, reviewed['token'], self.plan)
        self.q.recover.assert_not_called()

    def test_pending_foreign_target_refused(self):
        self.marker['name'] = 'foreign.db'
        with self.assertRaisesRegex(Refused, 'pending_target_unverified'):
            self.recover_review()

    def test_native_verification_failure_not_suppressed_by_controller(self):
        self.q.verify_retained_native.side_effect = Refused('native refusal')
        with self.assertRaisesRegex(Refused, 'native refusal'):
            self.apply()

    def test_wrong_credential_slot_does_not_compile(self):
        with self.assertRaisesRegex(Refused, 'invalid_credential'):
            self.apply(credential={'username':'test-user','password':'wrong'})
        self.q.compile_rotation_candidate.assert_not_called()


class CliContractTests(unittest.TestCase):
    def setUp(self):
        self.rev = 'a'*64
        self.plan = 'b'*64
        self.proof = 'c'*64
        self.q = NS(X=NS(need=need), R=NS(valid_sha=valid_sha),
                    M=NS(decode=json.loads, MAX_BYTES=4096), CONFIRM='ROTATE',
                    RECOVER='RECOVER', RotationFailed=RotationFailed)
        self.i = NS(O=NS(MAINTENANCE='MAINTENANCE', route_lock=Mock(return_value=10),
                         maintenance=Mock(), same_directory=Mock(), mail_identity=Mock(return_value=(1,2))),
                    P=NS(CONFIG='/etc/postfix', QUEUE='/var/spool/postfix',
                         open_directory=Mock(side_effect=[11,12,13])))
        self.read = Mock(return_value=b'{"username":"account","password":"synthetic-private"}')
        self.emit = Mock()
        self.host = Mock()
        self.host.rotate.return_value = 'd'*64
        self.host.recover.return_value = 'old_retained'
        self.host.receipt.return_value = {'revision':self.rev, 'review_sha256':self.proof}
        for obj, attr, val in [(A.os,'geteuid',0),(A.os,'umask',None),(A.os,'close',None),
                               (A.resource,'setrlimit',None),(A,'RotationHost',self.host)]:
            if attr=='RotationHost':
                ctx = patch.object(obj, attr, return_value=val)
            else:
                ctx = patch.object(obj, attr, return_value=val)
            ctx.start(); self.addCleanup(ctx.stop)

    def call(self, *args):
        return A.run(A.arguments(args), self.q, self.i, self.read, self.emit)

    def approval(self, confirm):
        return ('--approve-plan-sha256',self.plan,'--approve-review-sha256',self.proof,
                '--confirm',confirm,'--maintenance-confirmation','MAINTENANCE')

    def test_wrong_maintenance_no_lock_no_input(self):
        self.assertEqual(self.call('--review-rotation',self.rev,'--index','2',
                                   '--maintenance-confirmation','WRONG'),2)
        self.i.O.route_lock.assert_not_called(); self.read.assert_not_called()

    def test_review_no_input(self):
        self.assertEqual(self.call('--review-rotation',self.rev,'--index','2',
                                   '--maintenance-confirmation','MAINTENANCE'),0)
        self.read.assert_not_called()
        self.host.inspect.assert_called_once_with(self.rev, 2, pending=False, network=True)

    def test_recovery_no_input(self):
        self.assertEqual(self.call('--recover',self.rev,*self.approval('RECOVER')),0)
        self.read.assert_not_called()
        self.host.recover.assert_called_once_with(self.rev,self.proof,self.plan)

    def test_rotate_bounded_input_and_no_secret_output(self):
        self.assertEqual(self.call('--rotate',self.rev,'--index','1',*self.approval('ROTATE')),0)
        self.read.assert_called_once_with(4097)
        self.host.rotate.assert_called_once_with(self.rev,1,self.proof,self.plan,
                                                {'username':'account','password':'synthetic-private'})
        self.assertNotIn('synthetic-private',str(self.emit.call_args))
        self.assertEqual(self.emit.call_args.args[0],'rotated_offline_not_started')

    def test_oversized_input_refused_before_compilation(self):
        self.read.return_value = b'x'*4097
        self.assertEqual(self.call('--rotate',self.rev,'--index','1',*self.approval('ROTATE')),2)
        self.host.rotate.assert_not_called()

    def test_native_exception_redacted(self):
        self.host.rotate.side_effect = OSError('synthetic-private')
        self.assertEqual(self.call('--rotate',self.rev,'--index','1',*self.approval('ROTATE')),2)
        self.assertEqual(self.emit.call_args.args[0],'refused_or_failed')
        self.assertNotIn('synthetic-private',str(self.emit.call_args))

    def test_rollback_receipt(self):
        self.host.rotate.side_effect = RotationFailed(self.rev, True)
        self.assertEqual(self.call('--rotate',self.rev,'--index','1',*self.approval('ROTATE')),2)
        self.emit.assert_called_once_with('rolled_back',revision=self.rev,postfix_changed='restored')

    def test_argument_parser_never_echoes_unrecognized_secret(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            A.arguments(['--password','synthetic-private'])
        self.assertNotIn('synthetic-private',stderr.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
