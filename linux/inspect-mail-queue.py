#!/usr/bin/env python3
"""Privacy-safe, read-only native queue sampling; Python 3.6+.

No message submission, retry/flush, deletion, body reading, or service changes.
No message IDs, addresses, raw delay reasons or command output leave this tool.
The result is a non-atomic sample, NOT an offline-restore preflight.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import time

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CONFIG = "/etc/postfix"
SIDECAR_CONFIG = "/etc/linuxmailrelay365/sidecar-postfix"
SIDECAR_QUEUE = "/var/spool/linuxmailrelay365-sidecar"
LIMIT = 8 * 1024 * 1024
MAX_POSTFIX = 50000
MAX_VISIBLE_MESSAGES = 500
MAX_MESSAGE_SIZE = 1099511627776
MAX_COUNT = 999999999
RESULTS = ("ok", "tool_unavailable", "timeout", "output_limit",
           "command_failed", "invalid_output", "scope_unverified", "sample_changed")
COUNTERS = ("total", "active", "deferred", "held", "incoming", "maildrop",
            "other", "oldest_minutes", "auth", "tls", "dns", "network",
            "temporary", "permanent", "mixed", "other_reason", "no_reason")
REASONS = COUNTERS[8:]
QUEUES = {"active": "active", "deferred": "deferred", "hold": "held",
          "incoming": "incoming", "maildrop": "maildrop"}
TOOLS = {
    "postconf": ("postconf",),
    "postqueue": ("postqueue",),
    "exim": ("exim", "exim4"),
    "sendmail": ("sendmail", "sendmail.sendmail"),
}


class Unavailable(Exception):
    def __init__(self, result):
        super().__init__(result)
        self.result = result


def secure_directory(path):
    """Reject symlinked or writable ancestors, including config/queue aliases."""
    p = Path(path)
    if not p.is_absolute() or str(p) != path or ".." in p.parts:
        raise Unavailable("scope_unverified")
    try:
        for node in list(reversed(p.parents)) + [p]:
            st = node.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise Unavailable("scope_unverified")
        return p.stat()
    except OSError:
        raise Unavailable("scope_unverified")


def config_file(directory):
    secure_directory(directory)
    try:
        st = (Path(directory) / "main.cf").lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Unavailable("scope_unverified")
    except OSError:
        raise Unavailable("scope_unverified")


def native_binary(tool):
    """Resolve only known distribution native binaries, not mailq alternatives."""
    for name in TOOLS[tool]:
        for directory in PATH.split(":"):
            path = os.path.join(directory, name)
            try:
                resolved = os.path.realpath(path)
                if os.path.basename(resolved) not in TOOLS[tool]:
                    continue
                # Debian/Ubuntu package-native Sendmail may live in libexec.
                # Do not accept a generic mailq/sendmail alternative elsewhere.
                if (os.path.dirname(resolved) not in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
                        and not (tool == "sendmail" and resolved in (
                            "/usr/libexec/sendmail/sendmail", "/usr/lib/sm.bin/sendmail"))):
                    continue
                secure_directory(os.path.dirname(resolved))
                meta = os.stat(resolved)
                if (stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                        not meta.st_mode & 0o022 and meta.st_mode & 0o111):
                    return resolved
            except (OSError, Unavailable):
                continue
    raise Unavailable("tool_unavailable")


def allowed_args(tool, args):
    if tool == "postconf":
        return (len(args) == 4 and args[0] == "-c" and args[1] in (CONFIG, SIDECAR_CONFIG)
                and args[2] == "-h" and args[3] in ("queue_directory", "enable_long_queue_ids", "myhostname"))
    if tool == "postqueue":
        return len(args) == 3 and args[0] == "-c" and args[1] in (CONFIG, SIDECAR_CONFIG) and args[2] == "-j"
    return (tool == "exim" and args in (["-bpc"], ["-bp"])) or (
        tool == "sendmail" and args in (["-bp"], ["-Ac", "-bp"]))


def run_native(tool, args, timeout=12, limit=LIMIT):
    """Bound stdout DURING capture; discard stderr, use a fixed environment."""
    if not allowed_args(tool, args):
        raise ValueError("non_read_only_queue_command")
    binary = native_binary(tool)
    proc = None
    try:
        proc = subprocess.Popen([binary] + args, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={"PATH": PATH, "LC_ALL": "C"}, start_new_session=True)
        deadline = time.monotonic() + timeout
        raw = bytearray()
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([proc.stdout], [], [], left)[0]:
                raise Unavailable("timeout")
            part = os.read(proc.stdout.fileno(), min(65536, limit - len(raw) + 1))
            if not part:
                break
            raw.extend(part)
            if len(raw) > limit:
                raise Unavailable("output_limit")
        try:
            code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Unavailable("timeout")
        if code != 0:
            raise Unavailable("command_failed")
        try:
            return raw.decode("utf-8")
        except UnicodeError:
            raise Unavailable("invalid_output")
    except OSError:
        raise Unavailable("command_failed")
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            proc.stdout.close()


def configured_queue(directory, runner):
    config_file(directory)
    value = runner("postconf", ["-c", directory, "-h", "queue_directory"]).strip()
    if not re.fullmatch(r"/[A-Za-z0-9_.+/-]{1,511}", value):
        raise Unavailable("scope_unverified")
    meta = secure_directory(value)
    return value, (meta.st_dev, meta.st_ino)


def verify_postfix_scope(scope, runner):
    directory = SIDECAR_CONFIG if scope == "sidecar" else CONFIG
    value, identity = configured_queue(directory, runner)
    if scope == "sidecar" and value != SIDECAR_QUEUE:
        raise Unavailable("scope_unverified")
    if scope == "postfix" and value == SIDECAR_QUEUE:
        raise Unavailable("scope_unverified")
    # If another instance is present, independently check that the two
    # queue roots are different (also catches a shared bind-mounted root).
    other = CONFIG if scope == "sidecar" else SIDECAR_CONFIG
    if os.path.lexists(os.path.join(other, "main.cf")):
        _, other_identity = configured_queue(other, runner)
        if identity == other_identity:
            raise Unavailable("scope_unverified")
    return directory, value, identity


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_field")
        result[key] = value
    return result


def reason_category(value):
    # Heuristics only; return a fixed category, never the diagnostic text.
    if not value:
        return "no_reason"
    v = value.lower()
    if re.search(r"\b(?:auth(?:entication)?|sasl|xoauth2|oauth2)\b|(?:^|\D)5\.7\.8(?:\D|$)", v):
        return "auth"
    if re.search(r"\b(?:tls|ssl|starttls|certificate)\b", v):
        return "tls"
    if re.search(r"\b(?:dns|nxdomain|name service|name resolution|host not found|temporary failure in name resolution)\b", v):
        return "dns"
    if re.search(r"timed out|timeout|connection refused|network is unreachable|no route to host|connection reset", v):
        return "network"
    if re.search(r"(?<!\d)4[0-9]{2}(?!\d)|(?<!\d)4\.\d\.\d{1,3}(?!\d)", v):
        return "temporary"
    if re.search(r"(?<!\d)5[0-9]{2}(?!\d)|(?<!\d)5\.\d\.\d{1,3}(?!\d)", v):
        return "permanent"
    return "other_reason"


def postfix_counts(output, now=None):
    if len(output.encode("utf-8")) > LIMIT:
        raise Unavailable("output_limit")
    now = time.time() if now is None else now
    result = dict((name, 0) for name in COUNTERS)
    seen = set()
    try:
        for line in output.splitlines():
            if not line.strip():
                continue
            item = json.loads(line, object_pairs_hook=unique_json)
            if not isinstance(item, dict):
                raise ValueError()
            ident = item.get("queue_id")
            name = item.get("queue_name")
            arrival = item.get("arrival_time")
            recipients = item.get("recipients")
            if (not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9]{1,128}", ident)
                    or ident in seen or not isinstance(name, str) or not re.fullmatch(r"[a-z_]{1,32}", name)
                    or type(arrival) is not int or arrival < 0 or arrival > now + 300
                    or not isinstance(recipients, list) or len(recipients) > 10000):
                raise ValueError()
            seen.add(ident)
            result["total"] += 1
            if result["total"] > MAX_POSTFIX:
                raise Unavailable("output_limit")
            result[QUEUES.get(name, "other")] += 1
            age = max(0, int((now - arrival) // 60))
            if age > MAX_COUNT:
                raise ValueError()
            result["oldest_minutes"] = max(result["oldest_minutes"], age)
            categories = set()
            for recipient in recipients:
                if not isinstance(recipient, dict):
                    raise ValueError()
                delay = recipient.get("delay_reason", "")
                if not isinstance(delay, str) or len(delay) > 16384:
                    raise ValueError()
                if delay:
                    categories.add(reason_category(delay))
            if name == "deferred":
                category = "no_reason" if not categories else next(iter(categories)) if len(categories) == 1 else "mixed"
                result[category] += 1
        return result
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise Unavailable("invalid_output")


def exim_count(output):
    value = output.strip()
    if not re.fullmatch(r"[0-9]{1,9}", value):
        raise Unavailable("invalid_output")
    return int(value)


def exim_details(output, expected):
    """Documented Exim -bp header format; ignore envelope text, never emit it.

    Count only unique native message headers, and require the separate
    native count to agree. The queue can still change during a sample.
    """
    seen = set()
    frozen = 0
    oldest = 0
    header = re.compile(
        r"^\s*([0-9]{1,9})([smhdw])\s+"
        r"[0-9]+(?:\.[0-9]+)?[KMGT]?\s+"
        r"([A-Za-z0-9]{6}-[A-Za-z0-9]{6,16}-[A-Za-z0-9]{2,8})"
        r"\s+(?:\([^()\r\n]{1,256}\)\s+)?<[^>\r\n]*>"
        r"(?:\s+(\*\*\* frozen \*\*\*))?\s*$")
    factors = {"s": 1 / 60, "m": 1, "h": 60, "d": 1440, "w": 10080}
    in_message = False
    for line in output.splitlines():
        if not line.strip():
            in_message = False
            continue
        match = header.fullmatch(line)
        if match:
            ident = match.group(3)
            if ident in seen:
                raise Unavailable("sample_changed")
            seen.add(ident)
            if len(seen) > MAX_POSTFIX:
                raise Unavailable("output_limit")
            age = int(int(match.group(1)) * factors[match.group(2)])
            if age > MAX_COUNT:
                raise Unavailable("invalid_output")
            oldest = max(oldest, age)
            frozen += int(match.group(4) is not None)
            in_message = True
        elif not in_message or not line[:1].isspace():
            raise Unavailable("invalid_output")
    if len(seen) != expected:
        raise Unavailable("sample_changed")
    return frozen, oldest


def sendmail_summary(output):
    """Native -bp group headers, optional final total, optional print limit.

    A single native queue need not print Total requests. For multiple
    groups, cross-check their counts against the required final total.
    Message rows and private paths never leave this function.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise Unavailable("invalid_output")
    group = re.compile(r"(?:Mail [Qq]ueue|/[^\r\n]+?)\s+\(([0-9]{1,9}) requests?(?:, only ([0-9]{1,9}) printed)?\)")
    empty = re.compile(r"(?:Mail queue is empty|/[^\r\n]+ is empty)\.?", re.I)
    total_pattern = re.compile(r"Total requests:\s*([0-9]{1,9})", re.I)
    counts = []
    group_keys = set()
    truncated = False
    footer = None
    has_rows = False
    for i, line in enumerate(lines):
        match = total_pattern.fullmatch(line)
        if match:
            if i != len(lines) - 1 or footer is not None:
                raise Unavailable("invalid_output")
            footer = int(match.group(1))
            continue
        match = group.fullmatch(line)
        if match or empty.fullmatch(line):
            key = line.split(" (", 1)[0] if match else re.sub(r" is empty\.?$", "", line, flags=re.I)
            if key in group_keys:
                raise Unavailable("invalid_output")
            group_keys.add(key)
            count = int(match.group(1)) if match else 0
            if match and match.group(2) is not None:
                printed = int(match.group(2))
                if not 0 <= printed < count:
                    raise Unavailable("invalid_output")
                truncated = True
            counts.append(count)
            has_rows = count > 0
        elif re.search(r"\b(?:unknown number of entries|only [0-9]+ printed)\b", line, re.I):
            raise Unavailable("invalid_output")
        elif not has_rows:
            raise Unavailable("invalid_output")
    if not counts:
        # Legacy footer-only format is a count, not group/detail evidence.
        if footer is not None and len(lines) == 1:
            return footer, "unknown", "unknown"
        raise Unavailable("invalid_output")
    total = sum(counts)
    if (total > MAX_COUNT or len(counts) > MAX_COUNT or
            (footer is not None and footer != total) or
            (len(counts) > 1 and footer is None)):
        raise Unavailable("invalid_output")
    return total, len(counts), "yes" if truncated else "no"


def sendmail_count(output):
    return sendmail_summary(output)[0]


def sample(scope, runner=run_native, scope_check=verify_postfix_scope):
    if scope not in ("postfix", "sidecar", "exim", "sendmail"):
        raise ValueError("unknown_queue_scope")
    report = dict((key, "unknown") for key in COUNTERS)
    report.update(version="2", scope=scope, result="ok", client_result="not_applicable",
                  client_total="unknown", changes_applied="no", atomic="no",
                  delivery_verified="no", detail_result="not_applicable",
                  frozen="unknown", exim_oldest_minutes="unknown",
                  groups="unknown", client_groups="unknown",
                  listing_truncated="unknown", client_listing_truncated="unknown")
    try:
        if scope in ("postfix", "sidecar"):
            before = scope_check(scope, runner)
            counts = postfix_counts(runner("postqueue", ["-c", before[0], "-j"]))
            if scope_check(scope, runner) != before:
                raise Unavailable("scope_unverified")
            report.update(counts)
        elif scope == "exim":
            report["total"] = exim_count(runner("exim", ["-bpc"]))
            try:
                frozen, oldest = exim_details(runner("exim", ["-bp"]), report["total"])
                if exim_count(runner("exim", ["-bpc"])) != report["total"]:
                    raise Unavailable("sample_changed")
                report.update(detail_result="ok", frozen=frozen, exim_oldest_minutes=oldest)
            except Unavailable as error:
                # Keep the separately obtained count, not a misleading zero.
                report["detail_result"] = error.result
        else:
            total, groups, truncated = sendmail_summary(runner("sendmail", ["-bp"]))
            report.update(total=total, groups=groups, listing_truncated=truncated)
    except Unavailable as error:
        report["result"] = error.result
        if scope == "exim":
            report["detail_result"] = "not_applicable"
    if scope == "sendmail":
        try:
            total, groups, truncated = sendmail_summary(runner("sendmail", ["-Ac", "-bp"]))
            report.update(client_total=total, client_groups=groups,
                          client_listing_truncated=truncated, client_result="ok")
        except Unavailable as error:
            report["client_result"] = error.result
    return report


# Long IDs have a time component, a 'z' separator and an inode component.
# Existing short IDs may remain even with long IDs enabled. No short-ID
# candidate is accepted; clock rollback still prevents any atomic guarantee.
LONG_ID = re.compile(r"[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,100}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-y]{1,24}")
SHA = re.compile(r"[a-f0-9]{64}")
REVIEW_TTL = 300


def retry_context(scope, runner, before):
    directory = before[0]
    enabled = runner("postconf", ["-c", directory, "-h", "enable_long_queue_ids"]).strip()
    if enabled != "yes":
        raise Unavailable("long_ids_required")
    hostname = runner("postconf", ["-c", directory, "-h", "myhostname"]).strip()
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise Unavailable("scope_unverified")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", hostname) or not re.fullmatch(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot):
        raise Unavailable("scope_unverified")
    return (scope, before, hostname, boot)


def message_fingerprint(item, context, nonce, sampled_at):
    if (context is None or item["queue_name"] != "deferred" or
            not LONG_ID.fullmatch(item["queue_id"]) or item["arrival_time"] > sampled_at):
        return "-"
    sender = item.get("sender")
    addresses = [r.get("address") for r in item["recipients"]]
    if (not isinstance(sender, str) or len(sender) > 4096 or not addresses or
            any(not isinstance(address, str) or not address or len(address) > 4096
                for address in addresses)):
        return "-"
    # HMAC covers the private native identity and immutable-enough envelope
    # metadata without returning the queue ID/address. The nonce is ephemeral
    # client context, not a remote credential or a write capability.
    evidence = [context, sampled_at, item["queue_id"], item["queue_name"],
                item["arrival_time"], item["message_size"], sender, sorted(addresses)]
    raw = json.dumps(evidence, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hmac.new(bytes.fromhex(nonce), raw, hashlib.sha256).hexdigest()


def postfix_inventory(output, now=None, selection=None):
    """Validate the complete bounded sample before emitting any message row.

    References are display ordinals, not queue IDs, and are never reusable
    across samples. Sender/recipient identities and raw reasons remain local.
    """
    now = time.time() if now is None else now
    counts = postfix_counts(output, now)
    rows = []
    try:
        for line in output.splitlines():
            if not line.strip():
                continue
            item = json.loads(line, object_pairs_hook=unique_json)
            size = item.get("message_size")
            if type(size) is not int or not 0 <= size <= MAX_MESSAGE_SIZE:
                raise ValueError("invalid_message_size")
            age = max(0, int((now - item["arrival_time"]) // 60))
            state = QUEUES.get(item["queue_name"], "other")
            categories = set(reason_category(r["delay_reason"]) for r in item["recipients"]
                             if r.get("delay_reason"))
            reason = ("not_applicable" if state != "deferred" else
                      "no_reason" if not categories else
                      next(iter(categories)) if len(categories) == 1 else "mixed")
            row = (item["arrival_time"], item["queue_id"],
                   state, age, size, len(item["recipients"]), reason)
            if selection is not None:
                context, nonce, sampled_at = selection
                row += (message_fingerprint(item, context, nonce, sampled_at),)
            rows.append(row)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise Unavailable("invalid_output")
    if len(rows) != counts["total"]:
        raise Unavailable("sample_changed")
    rows.sort(key=lambda row: (row[0], row[1]))
    # Discard native IDs, arrival timestamps and all raw metadata before return.
    return counts["total"], [(i + 1,) + row[2:]
                             for i, row in enumerate(rows[:MAX_VISIBLE_MESSAGES])]


def message_inventory(scope, runner=run_native, scope_check=verify_postfix_scope):
    if scope not in ("postfix", "sidecar"):
        raise ValueError("unsupported_message_inventory_scope")
    try:
        before = scope_check(scope, runner)
        total, rows = postfix_inventory(runner("postqueue", ["-c", before[0], "-j"]))
        if scope_check(scope, runner) != before:
            raise Unavailable("scope_unverified")
        return "ok", total, rows
    except Unavailable as error:
        return error.result, None, []


def inventory_lines(scope, result, total, rows, selection_time=None, retry_state=None):
    # Version 1 is unchanged for existing CLI clients. V2 adds non-authorizing
    # ephemeral fingerprints and a server sample time.
    yield "MAIL_ITEMS_VERSION=" + ("1" if selection_time is None else "2")
    yield "MAIL_ITEMS_SCOPE=" + scope
    yield "MAIL_ITEMS_RESULT=" + result
    yield "MAIL_ITEMS_TOTAL=" + ("unknown" if total is None else str(total))
    yield "MAIL_ITEMS_LISTED=" + str(len(rows))
    yield "MAIL_ITEMS_TRUNCATED=" + ("unknown" if total is None else
                                    "yes" if total > len(rows) else "no")
    yield "MAIL_ITEMS_CHANGES_APPLIED=no"
    yield "MAIL_ITEMS_ATOMIC=no"
    yield "MAIL_ITEMS_DELIVERY_VERIFIED=no"
    yield "MAIL_ITEMS_REFERENCE_KIND=sample_ordinal_only"
    if selection_time is not None:
        yield "MAIL_ITEMS_SAMPLED_AT=" + str(selection_time)
        yield "MAIL_ITEMS_RETRY_STATE=" + retry_state
    for row in rows:
        yield "MAIL_ITEMS_ROW=" + "|".join(str(value) for value in row)


def reviewable_inventory(scope, nonce, runner=run_native, scope_check=verify_postfix_scope,
                         context_check=retry_context, now=None):
    now = int(time.time()) if now is None else now
    if scope not in ("postfix", "sidecar") or not SHA.fullmatch(nonce):
        raise ValueError("invalid_retry_inventory_context")
    try:
        before = scope_check(scope, runner)
        context = None
        state = "unverified"
        try:
            context = context_check(scope, runner, before)
            state = "review_only"
        except Unavailable as error:
            if error.result == "long_ids_required":
                state = "long_ids_required"
        total, rows = postfix_inventory(runner("postqueue", ["-c", before[0], "-j"]),
                                        now, (context, nonce, now))
        if scope_check(scope, runner) != before:
            raise Unavailable("scope_unverified")
        if context is not None and context_check(scope, runner, before) != context:
            raise Unavailable("scope_unverified")
        return "ok", total, rows, now, state
    except Unavailable as error:
        return (error.result if error.result in RESULTS else "scope_unverified",
                None, [], now, "unverified")


def retry_review(scope, nonce, sampled_at, token, runner=run_native,
                 scope_check=verify_postfix_scope, context_check=retry_context, now=None):
    if (scope not in ("postfix", "sidecar") or not SHA.fullmatch(nonce)
            or not SHA.fullmatch(token) or type(sampled_at) is not int or sampled_at <= 0):
        raise ValueError("invalid_retry_review_context")
    now = int(time.time()) if now is None else now
    if now < sampled_at or now - sampled_at > REVIEW_TTL:
        return "expired", None
    try:
        before = scope_check(scope, runner)
        context = context_check(scope, runner, before)
        _, rows = postfix_inventory(runner("postqueue", ["-c", before[0], "-j"]),
                                    now, (context, nonce, sampled_at))
        if scope_check(scope, runner) != before or context_check(scope, runner, before) != context:
            raise Unavailable("scope_unverified")
        matches = [row for row in rows if hmac.compare_digest(row[-1], token)]
        if len(matches) != 1:
            return "sample_changed", None
        # Revalidation is read-only and not atomic; a candidate is not a
        # command authorization. A row outside the 500-row sample is refused.
        return "candidate_review_only", matches[0]
    except Unavailable as error:
        return error.result, None


def retry_lines(scope, token, sampled_at, result, row):
    yield "MAIL_RETRY_VERSION=1"
    yield "MAIL_RETRY_SCOPE=" + scope
    yield "MAIL_RETRY_FINGERPRINT=" + token
    yield "MAIL_RETRY_SAMPLED_AT=" + str(sampled_at)
    yield "MAIL_RETRY_RESULT=" + result
    yield "MAIL_RETRY_CHANGES_APPLIED=no"
    yield "MAIL_RETRY_APPLY_AUTHORIZED=no"
    yield "MAIL_RETRY_DELIVERY_VERIFIED=no"
    if row is not None:
        yield "MAIL_RETRY_ROW=" + "|".join(str(value) for value in row[1:-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, choices=("postfix", "sidecar", "exim", "sendmail"))
    parser.add_argument("--messages", action="store_true",
                        help="read-only bounded Postfix message metadata, no native IDs")
    parser.add_argument("--selection-nonce")
    parser.add_argument("--retry-plan")
    parser.add_argument("--sampled-at", type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        return 2
    if args.retry_plan is not None:
        if (args.messages or args.scope not in ("postfix", "sidecar") or
                not SHA.fullmatch(args.selection_nonce or "") or not SHA.fullmatch(args.retry_plan) or
                args.sampled_at is None or not 0 < args.sampled_at <= 9999999999):
            parser.error("invalid read-only retry review")
        result, row = retry_review(args.scope, args.selection_nonce, args.sampled_at, args.retry_plan)
        for line in retry_lines(args.scope, args.retry_plan, args.sampled_at, result, row):
            print(line)
        return 0
    if args.sampled_at is not None or (args.selection_nonce is not None and
            (not args.messages or not SHA.fullmatch(args.selection_nonce))):
        parser.error("invalid selection context")
    if args.messages:
        if args.scope not in ("postfix", "sidecar"):
            parser.error("message inventory is supported only for Postfix instances")
        if args.selection_nonce is not None:
            result, total, rows, sampled_at, retry_state = reviewable_inventory(args.scope, args.selection_nonce)
            lines = inventory_lines(args.scope, result, total, rows, sampled_at, retry_state)
        else:
            result, total, rows = message_inventory(args.scope)
            lines = inventory_lines(args.scope, result, total, rows)
        for line in lines:
            print(line)
        return 0
    report = sample(args.scope)
    for name, value in sorted(report.items()):
        print("MAIL_QUEUE_" + name.upper() + "=" + str(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
