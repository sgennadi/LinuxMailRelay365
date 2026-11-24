#!/usr/bin/env python3
"""Experimental stopped-host manager for new sender-specific SMTP transports.

Review never reads credentials. Apply compiles independently supplied
credentials via stdin, verifies the same non-secret review, and invokes the
guarded transaction. No daemon control or mail submission. Do not use on a
production host before full stopped-instance and runtime delivery acceptance.
"""
import argparse
import importlib.util
import os
import pathlib
import resource
import signal
import smtplib
import socket
import ssl
import sys

sys.dont_write_bytecode = True


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(pathlib.Path(__file__).with_name(filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


X = sibling("multi_transport_transaction", "conditional-transport-transaction.py")
O = sibling("offline_host_guard", "manage-conditional-postfix-offline.py")
P, C, R, M = O.P, X.C, X.R, X.M
Refused = M.Refused
MAX_PEERS = 16
# Inherited client certificate/key or debug settings could leak an existing
# identity or enable verbose logging on a newly chosen provider.
EMPTY_EXTRA = ("debug_peer_list", "smtp_tls_chain_files", "smtp_tls_cert_file",
               "smtp_tls_key_file", "smtp_tls_dcert_file", "smtp_tls_dkey_file",
               "smtp_tls_eccert_file", "smtp_tls_eckey_file")
EXTRA = EMPTY_EXTRA + ("smtp_host_lookup", "disable_dns_lookups")


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def native(args):
    return C.command(M.native_command, "postconf", ["-c", P.CONFIG] + args)


def service_table(raw):
    result = {}
    for line in raw.decode("ascii").splitlines():
        fields = line.split()
        need(len(fields) >= 8 and (fields[0], fields[1]) not in result,
             "native_service_inventory_unverified")
        result[(fields[0], fields[1])] = line
    need(bool(result), "native_service_inventory_empty")
    return result


def state():
    return (P.postconf_values(),
            P.key_values(native(["-x"] + list(EXTRA)).decode("ascii"), EXTRA),
            C.parameters(native(["-n"])),
            service_table(native(["-M"])),
            C.parameters(native(["-P"])))


def policy(baseline):
    values, extra, _, _, _ = baseline
    ca = P.inspect_policy(values)
    need(not values["proxy_interfaces"], "proxy_interfaces_need_separate_review")
    need(all(not extra[key] for key in EMPTY_EXTRA) and
         extra["smtp_host_lookup"] == "dns" and
         extra["disable_dns_lookups"] == "no", "inherited_client_policy_conflict")
    P.inspect_master()
    return ca


def backend_for(rules, selected):
    types = native(["-m"]).decode("ascii").split()
    backend = selected or next((b for b in ("hash", "lmdb") if b in types), None)
    need(backend in M.MAP_SUFFIX and backend in types, "indexed_backend_unavailable")
    if any(rule["auth"] == "password" for rule in rules):
        need("cyrus" in native(["-A"]).decode("ascii").split(),
             "native_client_sasl_unavailable")
    return backend


class PinnedImplicitSMTP(smtplib.SMTP_SSL):
    def __init__(self, host, port, peer, context):
        self.peer = str(peer)
        smtplib.SMTP_SSL.__init__(self, host, port, timeout=8, context=context,
                                 local_hostname="lmr365-transport-review.example.invalid")

    def _get_socket(self, host, port, timeout):
        raw = socket.create_connection((self.peer, port), timeout)
        try:
            return self.context.wrap_socket(raw, server_hostname=host)
        except BaseException:
            raw.close()
            raise


def tls_peer(host, port, mode, peer, context):
    if mode == "starttls":
        return P.tls_peer(host, port, peer, context)
    need(mode == "implicit", "unsupported_tls_mode")
    client = None
    try:
        client = PinnedImplicitSMTP(host, port, peer, context)
        need(P.address(client.sock.getpeername()[0]) == peer, "connected_peer_changed")
        code, _ = client.ehlo()
        need(code == 250, "tls_smtp_protocol_failed")
        cert = client.sock.getpeercert(binary_form=True)
        need(bool(cert), "tls_peer_certificate_missing")
        return M.digest(cert)
    finally:
        if client is not None:
            client.close()


def network(rules, ca, local, resolve=socket.getaddrinfo, check=tls_peer):
    # TLS mode is part of endpoint identity, not just host:port.
    destinations = sorted({(r["host"], r["port"], r["tls"]) for r in rules})
    need(1 <= len(destinations) <= C.MAX_RULES, "destination_count_unverified")
    trust = P.trust_store_digest(ca)
    context = ssl.create_default_context(cafile=ca)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    observations, total = [], 0
    for host, port, mode in destinations:
        peers = {P.address(row[4][0]) for row in
                 resolve(host, port, type=socket.SOCK_STREAM)}
        total += len(peers)
        need(peers and total <= MAX_PEERS and
             all(P.safe_destination(peer, local) for peer in peers),
             "local_or_unverified_destination")
        certificates = []
        for peer in sorted(peers, key=str):
            proof = check(host, port, mode, peer, context)
            need(R.valid_sha(proof), "invalid_tls_evidence")
            certificates.append([str(peer), proof])
        observations.append([host, port, mode, certificates])
    need(P.trust_store_digest(ca) == trust, "trust_store_changed")
    return M.digest(M.canonical({"trust": trust, "destinations": observations})), len(destinations)


def state_digest(baseline):
    values, extra, explicit, services, overrides = baseline
    return M.digest(M.canonical([values, extra, explicit,
                                 sorted([list(k), v] for k, v in services.items()),
                                 overrides]))


def review(config, rules, selected, identity, guard):
    guard()
    rules, plan = C.plan(rules)
    baseline = state()
    ca = policy(baseline)
    backend = backend_for(rules, selected)
    snapshot = R.observe(config, rules, backend, ca, 0, guard)
    proof, count = network(rules, ca, P.local_addresses())
    guard()
    need(state() == baseline and policy(baseline) == ca and
         backend_for(rules, backend) == backend and
         R.observe(config, rules, backend, ca, 0, guard) == snapshot,
         "review_changed_during_tls")
    evidence = M.digest(M.canonical({
        "format": "LMR365-MULTI-HOST-REVIEW-V1", "plan": plan, "backend": backend,
        "snapshot": M.digest(M.canonical(snapshot[0])),
        "native_policy": state_digest(baseline), "tls": proof, "account": list(identity)}))
    return snapshot, baseline, evidence, count


def verify_state(active, info, baseline, identity, passwords, guard):
    guard()
    actual = state()
    if not active:
        need(actual == baseline, "original_native_state_not_restored")
        policy(actual)
        return
    values, extra, explicit, services, overrides = baseline
    backend, rules, plan = info["backend"], info["rules"], info["plan"]
    _, _, routes, generated, auth = C.render(rules, plan, P.CONFIG, backend, info["ca"])
    route_spec = backend + ":" + P.CONFIG + "/" + info["map_names"][0]
    need(actual[0] == dict(values, **{C.PARAMETER: route_spec}) and
         actual[1] == extra and actual[2] == dict(explicit, **{C.PARAMETER: route_spec}),
         "native_main_policy_changed")
    expected_services = set(services) | {(name, "unix") for name in generated}
    need(set(actual[3]) == expected_services and
         all(actual[3][key] == value for key, value in services.items()),
         "existing_native_service_changed")
    for name in generated:
        need(actual[3][(name, "unix")].split()[1:8] ==
             ["unix", "-", "-", "n", "-", "-", "smtp"], "generated_service_unverified")
    expected_overrides = dict(overrides)
    expected_overrides.update({name + "/unix/" + key: value
                               for name, options in generated.items()
                               for key, value in options.items()})
    need(actual[4] == expected_overrides, "native_service_policy_changed")

    def check_map(name, expected):
        spec = backend + ":" + P.CONFIG + "/" + name
        prefix = ["-c", P.CONFIG]
        code, found = O.native_unprivileged(prefix + ["-s", spec], identity)
        need(code == 0 and M.native_rows(found) == expected, "native_map_enumeration_failed")
        keys = ("\n".join(sorted(expected)) + "\n").encode("ascii")
        code, found = O.native_unprivileged(prefix + ["-q", "-", spec], identity, keys)
        need(code == 0 and M.native_rows(found) == expected, "native_map_lookup_failed")
        code, found = O.native_unprivileged(prefix + ["-q", M.NEGATIVE_KEY, spec], identity)
        need(code == 1 and not found.strip(), "native_negative_lookup_failed")

    check_map(info["map_names"][0], routes)
    for index, name in auth.items():
        check_map(name, {C.endpoint(rules[index - 1]): passwords[index - 1]})
    guard()


def apply_reviewed(config, parent, request, plan, approved, backend, identity, guard):
    need(type(request) is dict and set(request) == {"rules", "credentials"},
         "invalid_apply_request")
    rules, actual_plan = C.plan(request["rules"])
    need(actual_plan == plan and R.valid_sha(approved), "approved_plan_required")
    passwords = C.credentials(rules, request["credentials"])
    snapshot, baseline, evidence, _ = review(config, rules, backend, identity, guard)
    need(evidence == approved, "review_evidence_changed")
    info = snapshot[0]
    published = []

    def consume(checked, checked_plan, checked_backend, ca, dbs):
        need((checked, checked_plan, checked_backend, ca) ==
             (rules, plan, info["backend"], info["ca"]), "compiled_context_changed")
        # Recheck DNS/TLS and native state after compilation, before backup
        # and any write. Review never incorporates passwords in its digest.
        need(review(config, rules, backend, identity, guard)[:3] ==
             (snapshot, baseline, approved), "review_changed_after_compilation")

        def fresh():
            guard()
            need(state() == baseline and policy(baseline) == ca and
                 backend_for(rules, backend) == backend, "native_policy_changed")
            return R.observe(config, rules, backend, ca, 0, guard)

        def verify(active, recorded):
            verify_state(active, recorded, baseline, identity, passwords, guard)

        published.append(X.apply(config, parent, snapshot, dbs, identity[1],
                                 X.APPLY, 0, guard, verify, fresh))

    C.compile_profiles(request, plan, C.CONFIRM, 0, C.tmpfs_parent(), info["ca"],
                       forced_backend=info["backend"], verified_consumer=consume)
    need(len(published) == 1, "transaction_receipt_missing")
    return published[0]


def restore_reviewed(config, parent, revision, identity, guard):
    guard()
    info, _, journal, _ = X.load(parent, revision, 0)
    need(journal["gid"] == identity[1], "postfix_group_changed")

    def verify(active, recorded):
        need(not active and recorded == info, "unexpected_restore_context")
        guard()
        baseline = state()
        policy(baseline)
        need(not baseline[0][C.PARAMETER], "original_route_not_restored")
        guard()

    return X.restore(config, parent, revision, X.RESTORE, 0, guard, verify)


def output(status, **fields):
    print("MULTI_TRANSPORT_STATUS=" + status)
    for key, value in fields.items():
        print("MULTI_TRANSPORT_" + key.upper() + "=" + str(value))
    print("MULTI_TRANSPORT_SERVICE_STARTED=no")
    print("MULTI_TRANSPORT_MAIL_SENT=no")
    print("MULTI_TRANSPORT_QUEUE_MODIFIED=no")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--review", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--restore", metavar="REVISION")
    parser.add_argument("--backend", choices=("hash", "lmdb"))
    parser.add_argument("--approve-plan-sha256")
    parser.add_argument("--approve-review-sha256")
    parser.add_argument("--confirm")
    parser.add_argument("--maintenance-confirmation", required=True)
    args = parser.parse_args(argv)
    fds = []
    attempted = False
    try:
        need(os.geteuid() == 0 and args.maintenance_confirmation == O.MAINTENANCE,
             "exclusive_maintenance_required")
        if args.restore is not None:
            need(R.valid_sha(args.restore) and args.confirm == X.RESTORE and
                 all(x is None for x in (args.backend, args.approve_plan_sha256,
                                         args.approve_review_sha256)), "invalid_restore_approval")
        elif args.apply:
            need(args.backend in M.MAP_SUFFIX and args.confirm == X.APPLY and
                 R.valid_sha(args.approve_plan_sha256) and
                 R.valid_sha(args.approve_review_sha256), "invalid_apply_approval")
        else:
            need(all(x is None for x in (args.confirm, args.approve_plan_sha256,
                                         args.approve_review_sha256)), "unexpected_review_approval")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        def timeout(signum, frame):
            raise Refused("multi_transport_timeout")
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(300)
        request = None if args.restore is not None else M.decode(sys.stdin.buffer.read(M.MAX_BYTES + 1))
        fds.append(O.route_lock())
        for path in ("/var/lib", P.CONFIG, P.QUEUE):
            fds.append(P.open_directory(path, strict=path != P.QUEUE))
        _, parent, config, queue = fds
        identity = O.mail_identity()

        def guard():
            O.maintenance(config, queue, identity)
            O.same_directory(parent, "/var/lib")

        guard()
        if args.review:
            snapshot, _, evidence, count = review(config, request, args.backend, identity, guard)
            output("reviewed_experimental", plan_sha256=snapshot[0]["plan"],
                   backend=snapshot[0]["backend"], review_sha256=evidence,
                   tls_destinations=count, postfix_changed="no")
        elif args.apply:
            attempted = True
            revision = apply_reviewed(config, parent, request, args.approve_plan_sha256,
                                       args.approve_review_sha256, args.backend, identity, guard)
            output("applied_offline_not_started", recovery_revision=revision, postfix_changed="yes")
        else:
            attempted = True
            revision = restore_reviewed(config, parent, args.restore, identity, guard)
            output("restored_offline_not_started", recovery_revision=revision, postfix_changed="restored")
        return 0
    except X.ApplyFailed as error:
        output("rolled_back" if error.rolled_back else "manual_recovery_required",
               recovery_revision=error.revision,
               postfix_changed="restored" if error.rolled_back else "unknown")
    except Exception:
        # Never emit a traceback, native stderr, credential, private DB hash,
        # configuration content, endpoint or upstream server response.
        output("refused_or_failed", postfix_changed="inspect_recovery" if attempted else "no")
    finally:
        signal.alarm(0)
        for fd in reversed(fds):
            os.close(fd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
