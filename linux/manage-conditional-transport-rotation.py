#!/usr/bin/env python3
"""Experimental stopped-host single-account rotation and crash reconciliation.

No daemon control, queue changes, SMTP AUTH, or mail submission. Use only
with the matching RC14 recovery patch and exclusive offline maintenance.
"""
import argparse
import importlib.util
import os
import pathlib
import resource
import signal
import sys

sys.dont_write_bytecode = True


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(pathlib.Path(__file__).with_name(filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RotationHost:
    """Orchestrate existing transaction libraries; no permissive guard defaults."""
    def __init__(self, rotation, inventory, config, parent, identity, uid, guard):
        self.q, self.i = rotation, inventory
        self.h, self.x = inventory.H, rotation.X
        self.m, self.r, self.t = rotation.M, rotation.R, rotation.T
        self.config, self.parent = config, parent
        self.identity, self.uid, self.guard = identity, uid, guard

    def need(self, condition, reason):
        self.x.need(condition, reason)

    def config_ids(self):
        # No configuration contents or password-derived hashes enter approvals.
        return [self.t.file_identity(os.stat(name, dir_fd=self.config,
                                             follow_symlinks=False))
                for name in ('main.cf', 'master.cf')]

    def lookup(self, spec, rows):
        return self.i.route_lookup(spec, rows, self.identity)

    def inspect(self, revision, index=None, pending=False, network=False):
        self.need(self.r.valid_sha(revision), 'invalid_revision')
        self.guard()
        first = self.h.state()
        config_ids = self.config_ids()
        if pending:
            self.need(index is None and not network, 'unexpected_recovery_argument')
            observation = self.q.pending_review(self.config, self.parent, revision,
                                                self.uid, self.identity[1])
            record, marker, actual, retained = observation
            info = record[0]
            matches = [n for n, rule in enumerate(info['rules'], 1)
                       if rule['auth'] == 'password' and
                       self.q.target_name(info, n) == marker['name']]
            self.need(len(matches) == 1, 'pending_target_unverified')
            index = matches[0]
            self.i.verify_installed_policy(record, first, self.lookup)
        else:
            record = self.i.installed_record(self.config, self.parent, self.uid,
                                             self.identity[1], revision, first, self.lookup)
            info = record[0]
            self.q.target_name(info, index)
            observation, marker, actual, retained = None, None, None, 'rotation_ready'
        proof = None
        if network:
            proof, count = self.h.network([info['rules'][index - 1]], info['ca'],
                                          self.h.P.local_addresses())
            self.need(count == 1 and self.r.valid_sha(proof), 'tls_review_unverified')
        self.guard()
        self.need(self.h.state() == first and self.config_ids() == config_ids,
                  'native_or_configuration_state_changed')
        if pending:
            self.need(self.q.pending_review(self.config, self.parent, revision,
                                            self.uid, self.identity[1]) == observation,
                      'pending_observation_changed')
            self.i.verify_installed_policy(record, first, self.lookup)
        else:
            self.need(self.i.installed_record(self.config, self.parent, self.uid,
                                              self.identity[1], revision, first, self.lookup) == record,
                      'installed_observation_changed')
        self.guard()
        self.need(self.h.state() == first and self.config_ids() == config_ids,
                  'native_or_configuration_state_changed')
        # Public approval only binds non-secret identifiers and file identities.
        # It is not authentication, not a secret-bearing journal digest, and
        # never replaces a fresh ownership and effective-policy check.
        token = self.m.digest(self.m.canonical({
            'format': 'LMR365-ROTATION-REVIEW-V1', 'revision': revision,
            'plan': info['plan'], 'index': index, 'backend': info['backend'],
            'account': list(self.identity), 'config_ids': config_ids,
            'map_ids': record[3], 'retained': retained, 'tls': proof,
            'generation': marker['generation'] if marker else None,
            'phase': marker['phase'] if marker else None,
            'actual': actual,
        }))
        return {'record': record, 'observation': observation, 'state': first,
                'config_ids': config_ids, 'index': index, 'status': retained,
                'token': token}

    def receipt(self, revision, review):
        info = review['record'][0]
        return {'revision': revision, 'plan_sha256': info['plan'],
                'index': review['index'], 'backend': info['backend'],
                'review_sha256': review['token'], 'retained': review['status']}

    def same_policy(self, review):
        self.guard()
        self.need(self.h.state() == review['state'] and
                  self.config_ids() == review['config_ids'], 'native_policy_changed')
        self.i.verify_installed_policy(review['record'], review['state'], self.lookup)
        self.guard()
        self.need(self.h.state() == review['state'] and
                  self.config_ids() == review['config_ids'], 'native_policy_changed')

    def rotate(self, revision, index, approved, plan, credential):
        self.need(self.r.valid_sha(approved) and self.r.valid_sha(plan), 'invalid_approval')
        review = self.inspect(revision, index, network=True)
        info = review['record'][0]
        self.need(review['token'] == approved and info['plan'] == plan, 'review_changed')
        # Validate only this rule's slot. Never load other accounts into stdin.
        self.q.C.credentials([info['rules'][index - 1]], [credential])
        candidate = self.q.compile_rotation_candidate(info, index, credential)
        self.need(self.inspect(revision, index, network=True) == review,
                  'review_changed_after_compilation')

        def fresh():
            self.same_policy(review)
            record = self.i.installed_record(self.config, self.parent, self.uid,
                                             self.identity[1], revision,
                                             review['state'], self.lookup)
            self.need(record == review['record'], 'installed_review_changed')
            return record

        def verify(active, recorded, name, data):
            self.same_policy(review)
            self.need(recorded == info and name == self.q.target_name(info, index),
                      'rotation_target_changed')
            self.q.verify_retained_native(self.config, self.h.P.CONFIG, info, name,
                                          data, self.uid, self.identity,
                                          self.i.O.native_unprivileged,
                                          credential if active else None)
            self.same_policy(review)

        return self.q.rotate(self.config, self.parent, revision, index, review['record'],
                             candidate, self.identity[1], self.q.CONFIRM,
                             self.uid, self.guard, verify, fresh)

    def recover(self, revision, approved, plan):
        self.need(self.r.valid_sha(approved) and self.r.valid_sha(plan), 'invalid_approval')
        review = self.inspect(revision, pending=True)
        info = review['record'][0]
        self.need(review['token'] == approved and info['plan'] == plan, 'review_changed')

        def verify(active, recorded, name, data):
            self.same_policy(review)
            self.need(recorded == info and name == review['observation'][1]['name'],
                      'recovery_target_changed')
            self.q.verify_retained_native(self.config, self.h.P.CONFIG, info, name,
                                          data, self.uid, self.identity,
                                          self.i.O.native_unprivileged)
            self.same_policy(review)

        return self.q.recover(self.config, self.parent, revision, review['observation'],
                              self.identity[1], self.q.RECOVER, self.uid, self.guard, verify)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unrecognized arguments. Never do that
        # for a credential-oriented command.
        self.exit(2, "Invalid rotation command arguments. See --help.\n")


def arguments(argv=None):
    p = SafeParser(description=__doc__, allow_abbrev=False)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--review-rotation', metavar='REVISION')
    mode.add_argument('--rotate', metavar='REVISION')
    mode.add_argument('--review-recovery', metavar='REVISION')
    mode.add_argument('--recover', metavar='REVISION')
    p.add_argument('--index', type=int)
    p.add_argument('--approve-plan-sha256')
    p.add_argument('--approve-review-sha256')
    p.add_argument('--confirm')
    p.add_argument('--maintenance-confirmation', required=True)
    return p.parse_args(argv)


def output(status, **fields):
    print('ROTATION_STATUS=' + status)
    for k, v in fields.items():
        print('ROTATION_' + k.upper() + '=' + str(v))
    print('ROTATION_SERVICE_STARTED=no')
    print('ROTATION_MAIL_SENT=no')
    print('ROTATION_QUEUE_MODIFIED=no')
    print('ROTATION_SMTP_AUTH_ATTEMPTED=no')


def run(args, q, i, read_input, emit=output):
    o, p = i.O, i.P
    revision = args.review_rotation or args.rotate or args.review_recovery or args.recover
    attempted = False
    fds = []
    try:
        q.X.need(os.geteuid() == 0 and q.R.valid_sha(revision) and
                 args.maintenance_confirmation == o.MAINTENANCE,
                 'exclusive_maintenance_required')
        write = args.rotate is not None or args.recover is not None
        rotation = args.review_rotation is not None or args.rotate is not None
        q.X.need((rotation and type(args.index) is int and 1 <= args.index <= 8) or
                 (not rotation and args.index is None), 'invalid_index')
        if write:
            q.X.need(q.R.valid_sha(args.approve_plan_sha256) and
                     q.R.valid_sha(args.approve_review_sha256) and
                     args.confirm == (q.CONFIRM if rotation else q.RECOVER),
                     'invalid_write_approval')
        else:
            q.X.need(all(v is None for v in (args.approve_plan_sha256,
                                           args.approve_review_sha256, args.confirm)),
                     'unexpected_write_approval')
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        fds.append(o.route_lock())
        for path in ('/var/lib', p.CONFIG, p.QUEUE):
            fds.append(p.open_directory(path, strict=path != p.QUEUE))
        _, parent, config, queue = fds
        identity = o.mail_identity()

        def guard():
            o.maintenance(config, queue, identity)
            o.same_directory(parent, '/var/lib')

        guard()
        host = RotationHost(q, i, config, parent, identity, 0, guard)
        if not write:
            review = host.inspect(revision, args.index, pending=not rotation, network=rotation)
            emit('reviewed_experimental', **host.receipt(revision, review), postfix_changed='no')
        elif rotation:
            # Read only after confirming the exclusive stopped-host guard.
            # JSON must contain exactly username/password, validated by compiler.
            raw = read_input(q.M.MAX_BYTES + 1)
            q.X.need(type(raw) is bytes and 0 < len(raw) <= q.M.MAX_BYTES,
                     'invalid_credential_request_size')
            credential = q.M.decode(raw)
            q.X.need(type(credential) is dict and set(credential) == {'username', 'password'},
                     'invalid_credential_slot')
            attempted = True
            generation = host.rotate(revision, args.index, args.approve_review_sha256,
                                     args.approve_plan_sha256, credential)
            q.X.need(q.R.valid_sha(generation), 'invalid_rotation_generation')
            emit('rotated_offline_not_started', revision=revision, index=args.index,
                 generation=generation, postfix_changed='credential_only')
        else:
            attempted = True
            status = host.recover(revision, args.approve_review_sha256, args.approve_plan_sha256)
            q.X.need(status in ('old_retained', 'old_restored', 'new_retained'), 'invalid_recovery_status')
            emit('reconciled_offline_not_started', revision=revision, retained=status,
                 postfix_changed='ownership_record_only')
        return 0
    except q.RotationFailed as exc:
        emit('rolled_back' if exc.rolled_back else 'manual_recovery_required',
             revision=revision, postfix_changed='restored' if exc.rolled_back else 'unknown')
    except Exception:
        # Do not emit native output, tracebacks, supplied credential values,
        # private hashes, or even the contents of the request or exception.
        emit('refused_or_failed', postfix_changed='inspect_recovery' if attempted else 'no')
    finally:
        for fd in reversed(fds):
            os.close(fd)
    return 2


def main(argv=None):
    args = arguments(argv)
    try:
        q = sibling('rotation_core', 'conditional-transport-rotation.py')
        i = sibling('installed_inventory', 'inspect-conditional-transport-recovery.py')
        def timed_out(signum, frame):
            raise TimeoutError('rotation_timeout')
        signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(300)
        return run(args, q, i, sys.stdin.buffer.read)
    except Exception:
        output('refused_or_failed', postfix_changed='inspect_recovery')
        return 2
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
