#!/usr/bin/env python3
"""Privacy-safe native queue sampling and explicitly confirmed selected Retry.

Default actions are read-only. The separate experimental Retry Apply can
request immediate delivery of one reidentified deferred long-ID message.
Separate experimental Flush, Hold and Release require scoped fresh plans.
Delete is a separate irreversible action for one held long-ID message.
No bulk deletion, new submission, body reading or service/config changes.
Native IDs, addresses and raw reasons stay on the server. No atomic
compare-and-act or delivery guarantee; this is not Restore preflight.
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
    "postsuper": ("postsuper",),
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
    return (tool == "exim" and args in (["-bpc"], ["-bp"],
        ["-bP", "spool_directory"], ["-bP", "config_file"])) or (
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


EXIM_ID = re.compile(r"[A-Za-z0-9]{6}-[A-Za-z0-9]{6,16}-[A-Za-z0-9]{2,8}")
EXIM_HEADER = re.compile(
    r"^\s*([0-9]{1,9})([smhdw])\s+"
    r"([0-9]{1,12}(?:\.[0-9]{1,3})?[KMGT]?)\s+"
    r"(" + EXIM_ID.pattern + r")"
    r"\s+((?:\([^()\r\n]{1,256}\)\s+)?<[^>\r\n]*>)"
    r"(?:\s+(\*\*\* frozen \*\*\*))?\s*$")
EXIM_ACTIONS = {"freeze": "FREEZE_SELECTED_EXIM_MESSAGE",
                "thaw": "THAW_SELECTED_EXIM_MESSAGE",
                "retry": "RETRY_SELECTED_EXIM_MESSAGE",
                "flush": "FLUSH_DEFAULT_EXIM_QUEUE",
                "delete": "PERMANENTLY_DELETE_SELECTED_FROZEN_EXIM_MESSAGE"}


def exim_rows(output, expected):
    """Keep native IDs and envelope lines local. 'Queued' is not 'active'."""
    if len(output.encode("utf-8")) > LIMIT or expected > MAX_POSTFIX:
        raise Unavailable("output_limit")
    seen = set()
    rows = []
    current = None
    factors = {"s": 1 / 60, "m": 1, "h": 60, "d": 1440, "w": 10080}
    for line in output.splitlines():
        if not line.strip():
            current = None
            continue
        match = EXIM_HEADER.fullmatch(line)
        if match:
            ident = match.group(4)
            if ident in seen:
                raise Unavailable("sample_changed")
            seen.add(ident)
            if len(seen) > MAX_POSTFIX:
                raise Unavailable("output_limit")
            age = int(int(match.group(1)) * factors[match.group(2)])
            if age > MAX_COUNT:
                raise Unavailable("invalid_output")
            current = [ident, "frozen" if match.group(6) else "queued",
                       age, match.group(3), match.group(5), []]
            rows.append(current)
        elif current is not None and line[:1].isspace():
            text = line.strip()
            if not text or len(text) > 4096 or len(current[5]) >= 10000 or any(
                    ord(char) < 32 for char in text):
                raise Unavailable("invalid_output")
            current[5].append(text)
        else:
            raise Unavailable("invalid_output")
    if len(rows) != expected:
        raise Unavailable("sample_changed")
    return sorted(rows, key=lambda row: (-row[2], row[0]))


def exim_details(output, expected):
    rows = exim_rows(output, expected)
    return sum(row[1] == "frozen" for row in rows), max((row[2] for row in rows), default=0)


def exim_context(runner):
    """Default configured queue only; no custom -C or named queue arguments."""
    def setting(name):
        value = runner("exim", ["-bP", name]).strip()
        prefix = re.match(r"^(?:" + name + r"|configure_file)\s*=\s*", value)
        if prefix:
            value = value[prefix.end():]
        if not re.fullmatch(r"/[A-Za-z0-9_.+/-]{1,511}", value) or ".." in Path(value).parts:
            raise Unavailable("scope_unverified")
        return value
    directory = setting("spool_directory")
    config = setting("config_file")
    try:
        secure_directory(str(Path(directory).parent))
        secure_directory(str(Path(config).parent))
        spool = os.lstat(directory)
        cfg = os.lstat(config)
        binary = native_binary("exim")
        executable = os.stat(binary)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if (not stat.S_ISDIR(spool.st_mode) or spool.st_mode & 0o022 or
                not stat.S_ISREG(cfg.st_mode) or cfg.st_uid != 0 or cfg.st_mode & 0o022 or
                not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot)):
            raise Unavailable("scope_unverified")
        # Configuration identity is metadata only; included file changes are
        # not comprehensively detected. No config text is returned or read.
        def identity(st):
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_uid, st.st_mode)
        return (directory, spool.st_dev, spool.st_ino, config, identity(cfg),
                binary, identity(executable), boot)
    except (OSError, UnicodeError):
        raise Unavailable("scope_unverified")


def exim_snapshot(runner):
    first = exim_count(runner("exim", ["-bpc"]))
    if first > MAX_POSTFIX:
        raise Unavailable("output_limit")
    rows = exim_rows(runner("exim", ["-bp"]), first)
    if exim_count(runner("exim", ["-bpc"])) != first:
        raise Unavailable("sample_changed")
    return rows


def exim_token(row, context, nonce, sampled):
    # Age display changes over time; identity, state and envelope do not
    # have to be exposed to the client to correlate a selected message.
    evidence = [context, sampled, row[0], row[1], row[3], row[4], sorted(row[5])]
    encoded = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hmac.new(bytes.fromhex(nonce), encoded, hashlib.sha256).hexdigest()


def exim_inventory(nonce, runner=run_native, context_check=exim_context, now=None):
    if not SHA.fullmatch(nonce):
        raise ValueError("invalid_exim_nonce")
    now = int(time.time()) if now is None else now
    context = None
    try:
        context = context_check(runner)
    except Unavailable:
        pass
    try:
        rows = exim_snapshot(runner)
        if context is not None and context_check(runner) != context:
            raise Unavailable("scope_unverified")
        public = []
        for index, row in enumerate(rows[:MAX_VISIBLE_MESSAGES], 1):
            delivered = sum(text.startswith("D ") for text in row[5])
            public.append((index, row[1], row[2], row[3], len(row[5]) - delivered,
                           delivered, exim_token(row, context, nonce, now) if context else "-"))
        return "ok", now, len(rows), public, "verified" if context else "unverified"
    except Unavailable as error:
        return error.result, now, None, [], "unverified"


def exim_inventory_lines(nonce, result, sampled, total, rows, context):
    values = (("VERSION", 1), ("SCOPE", "exim"), ("NONCE", nonce), ("RESULT", result),
              ("SAMPLED_AT", sampled), ("TOTAL", "unknown" if total is None else total),
              ("LISTED", len(rows)), ("TRUNCATED", "unknown" if total is None else
               "yes" if total > len(rows) else "no"), ("CONTEXT", context),
              ("CHANGES_APPLIED", "no"), ("ATOMIC", "no"), ("DELIVERY_VERIFIED", "no"))
    for key, value in values:
        yield "EXIM_ITEMS_" + key + "=" + str(value)
    for row in rows:
        yield "EXIM_ITEMS_ROW=" + "|".join(str(value) for value in row)


def exim_candidate(action, nonce, sampled, token, now, runner, context_check):
    if action not in EXIM_ACTIONS or not SHA.fullmatch(nonce) or type(sampled) is not int:
        raise ValueError("invalid_exim_selection")
    if action == "flush":
        if sampled != 0 or token != "-":
            raise ValueError("flush_is_default_queue_wide")
    elif sampled <= 0 or not SHA.fullmatch(token):
        raise ValueError("invalid_exim_selection")
    if action != "flush" and (now < sampled or now - sampled > REVIEW_TTL):
        return "expired", None, None
    try:
        context = context_check(runner)
        rows = exim_snapshot(runner)
        if context_check(runner) != context:
            raise Unavailable("scope_unverified")
        if action == "flush":
            frozen = sum(row[1] == "frozen" for row in rows)
            if len(rows) == frozen:
                return "no_queued_messages", None, None
            # Bind the entire validated native listing, not just visible rows.
            # The display age changes naturally; no raw identity leaves Linux.
            canonical = [[row[0], row[1], row[3], row[4], sorted(row[5])]
                         for row in sorted(rows, key=lambda item: item[0])]
            digest = hmac.new(bytes.fromhex(nonce), json.dumps(canonical,
                ensure_ascii=True, separators=(",", ":")).encode("ascii"), hashlib.sha256).hexdigest()
            return "candidate", [None, len(rows), frozen], (context, digest, len(rows), frozen)
        state = "queued" if action in ("freeze", "retry") else "frozen"
        matches = [row for row in rows[:MAX_VISIBLE_MESSAGES] if row[1] == state and
                   hmac.compare_digest(exim_token(row, context, nonce, sampled), token)]
        if len(matches) != 1:
            return "sample_changed", None, None
        return "candidate", matches[0], context
    except Unavailable as error:
        return error.result, None, None


def exim_plan_digest(action, nonce, sampled, token, prepared, context):
    return hashlib.sha256(json.dumps(
        ["exim_queue_action_v1", action, nonce, sampled, token, prepared, context],
        ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def exim_prepare_details(action, nonce, sampled, token, runner=run_native, context_check=exim_context,
                         clock=time.time):
    prepared = int(clock())
    result, row, context = exim_candidate(action, nonce, sampled, token, prepared, runner, context_check)
    if result != "candidate":
        return result, prepared, "-", "-"
    detail = "{}|{}".format(row[1], row[2]) if action == "flush" else "-"
    return result, prepared, exim_plan_digest(action, nonce, sampled, token, prepared, context), detail


def exim_prepare(action, nonce, sampled, token, runner=run_native, context_check=exim_context,
                 clock=time.time):
    return exim_prepare_details(action, nonce, sampled, token, runner, context_check, clock)[:3]


def exim_execute(action, ident):
    if (action not in EXIM_ACTIONS or (action == "flush" and ident is not None) or
            (action != "flush" and (not isinstance(ident, str) or not EXIM_ID.fullmatch(ident)))):
        raise ValueError("invalid_exim_action")
    binary = native_binary("exim")
    if action == "flush":
        args = [binary, "-qf"]
    elif action == "retry":
        # Limit the primary queue-run ID range. Exim may reuse SMTP
        # connections for other mail; never promise an exclusive delivery.
        args = [binary, "-qf", ident, ident]
    else:
        args = [binary, {"freeze": "-Mf", "thaw": "-Mt", "delete": "-Mrm"}[action], ident]
    try:
        completed = subprocess.run(args,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,
                                   timeout=60 if action in ("retry", "flush") else 12, check=False,
                                   env={"PATH": PATH, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return "outcome_unknown"
    return "command_completed" if completed.returncode == 0 else "outcome_unknown"


def exim_apply(action, nonce, sampled, token, prepared, approved, confirmation,
               runner=run_native, context_check=exim_context, executor=exim_execute,
               clock=time.time, monotonic=time.monotonic):
    if (action not in EXIM_ACTIONS or confirmation != EXIM_ACTIONS[action] or
            not SHA.fullmatch(approved) or type(prepared) is not int or prepared <= 0 or
            not sampled <= prepared):
        raise ValueError("exim_confirmation_required")
    started = int(clock())
    tick = monotonic()
    def fresh():
        now = int(clock())
        elapsed = monotonic() - tick
        return (0 <= elapsed <= RETRY_PLAN_TTL and abs(now - started - elapsed) <= 2
                and prepared <= now <= prepared + RETRY_PLAN_TTL
                and (action == "flush" or sampled <= prepared <= now <= sampled + REVIEW_TTL))
    if not fresh():
        return "not_requested", "expired"
    ident = None
    for _ in range(2):
        result, row, context = exim_candidate(action, nonce, sampled, token, int(clock()),
                                               runner, context_check)
        if result != "candidate":
            return "not_requested", result
        digest = exim_plan_digest(action, nonce, sampled, token, prepared, context)
        if not hmac.compare_digest(approved, digest) or (ident is not None and ident != row[0]):
            return "not_requested", "plan_changed"
        ident = row[0]
    if not fresh():
        return "not_requested", "expired"
    try:
        result = executor(action, ident)
    except Unavailable as error:
        return "not_requested", error.result
    return (("command_completed", "none") if result == "command_completed"
            else ("outcome_unknown", "native_result_unconfirmed"))


def exim_action_lines(action, nonce, sampled, token, phase, prepared, plan, outcome, reason, detail="-"):
    for key, value in (("VERSION", 1), ("SCOPE", "exim"), ("ACTION", action), ("NONCE", nonce),
                       ("SAMPLED_AT", sampled), ("FINGERPRINT", token), ("PHASE", phase),
                       ("PREPARED_AT", prepared), ("PLAN_SHA256", plan), ("OUTCOME", outcome),
                       ("REASON", reason), ("COMMAND_COUNT", "1" if outcome == "command_completed"
                        else "unknown" if outcome == "outcome_unknown" else "0"),
                       ("EFFECT_VERIFIED", "no"), ("DELIVERY_VERIFIED", "no"), ("ATOMIC", "no"),
                       ("DELETE_REQUESTED", ("yes" if outcome == "command_completed" else
                        "unknown" if outcome == "outcome_unknown" else "no")
                        if action == "delete" and phase == "apply" else "no"),
                       ("NEW_MESSAGE_SUBMITTED", "no"),
                       ("CONFIG_CHANGED", "no"), ("SERVICE_CHANGED", "no")):
        yield "EXIM_ACTION_" + key + "=" + str(value)
    if action == "flush":
        yield "EXIM_ACTION_DETAIL=" + detail


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


# Normal non-verbose mailq (-bp) listing, LC_ALL=C. The printed date
# has no year or timezone. Never manufacture a precise age from it.
SM_GROUP = re.compile(r"(?:Mail [Qq]ueue|/[^\r\n]+?)\s+\(([0-9]{1,9}) requests?(?:, only ([0-9]{1,9}) printed)?\)")
SM_EMPTY = re.compile(r"(?:Mail queue is empty|/[^\r\n]+ is empty)\.?", re.I)
SM_HEADER = re.compile(r"-+Q-ID-+\s+-+Size-+\s+-+Q-Time-+\s+-+Sender/Recipient-+")
SM_ROW = re.compile(r"^[ ]{0,3}([A-Za-z0-9]{6,64})[ ]*([*X-]?)\s+([0-9]{1,13})\s+"
                    r"((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                    r"\s+(?:[1-9]|[12][0-9]|3[01])\s+(?:[01][0-9]|2[0-3]):[0-5][0-9])\s+.*$")
SM_STATUS = {"": "queued", "*": "processing_mark", "X": "load_limited", "-": "too_young"}


def sendmail_rows(output):
    """Validate native per-group print counts, then discard all private text.

    A native listing may be incomplete due to MaxQueueRunSize. This is
    distinct from the GUI's display cap. Unknown formats fail closed.
    Normal -bp excludes lost/quarantined queue classes; no queue files
    or message bodies are opened by this helper.
    """
    if len(output.encode("utf-8")) > LIMIT:
        raise Unavailable("output_limit")
    total, group_count, native_truncated = sendmail_summary(output)
    if total > MAX_POSTFIX or (isinstance(group_count, int) and group_count > MAX_POSTFIX):
        raise Unavailable("output_limit")
    if group_count == "unknown":
        raise Unavailable("invalid_output")
    rows = []
    seen = set()
    group = 0
    expected = 0
    printed = 0
    header = False
    current = None

    def finish_group():
        if printed != expected or (expected and not header):
            raise Unavailable("invalid_output")

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        match = SM_GROUP.fullmatch(text)
        if match or SM_EMPTY.fullmatch(text):
            finish_group()
            group += 1
            expected = int(match.group(2) or match.group(1)) if match else 0
            printed = 0
            header = False
            current = None
            continue
        if re.fullmatch(r"Total requests:\s*[0-9]{1,9}", text, re.I):
            finish_group()
            current = None
            continue
        if not group or not expected:
            raise Unavailable("invalid_output")
        if SM_HEADER.fullmatch(text):
            if header or printed:
                raise Unavailable("invalid_output")
            header = True
            continue
        if not header:
            raise Unavailable("invalid_output")
        match = SM_ROW.fullmatch(line)
        if match:
            if printed >= expected:
                raise Unavailable("invalid_output")
            ident, mark, size, date = match.groups()
            key = (group, ident)
            if key in seen:
                raise Unavailable("sample_changed")
            seen.add(key)
            size = int(size)
            if size > MAX_MESSAGE_SIZE:
                raise Unavailable("invalid_output")
            # Canonical native date, containing no address or ID.
            date = " ".join(date.split())
            weekday, month, day, clock = date.split()
            maximum = {"Feb": 29, "Apr": 30, "Jun": 30, "Sep": 30, "Nov": 30}.get(month, 31)
            if int(day) > maximum:
                raise Unavailable("invalid_output")
            current = [group, SM_STATUS[mark], size, date, "no_reason"]
            rows.append(current)
            printed += 1
        elif current is not None and line[:1].isspace():
            # Only recognize the native status-line layout, not arbitrary
            # recipient text. A reason is a heuristic, never a raw string.
            diagnostic = re.fullmatch(r" .{10} \((.{1,16384})\)", line)
            legacy = re.fullmatch(r"\s{1,20}Deferred:\s+(.{1,16384})", line)
            if diagnostic or legacy:
                category = reason_category((diagnostic or legacy).group(1))
                if current[4] not in ("no_reason", category):
                    current[4] = "mixed"
                else:
                    current[4] = category
            elif len(line) > 16384 or any(ord(ch) < 32 and ch != "\t" for ch in line):
                raise Unavailable("invalid_output")
            # Sender, recipient, body-type and unrecognized continuation
            # text stay local; no recipient count is guessed.
        else:
            raise Unavailable("invalid_output")
    finish_group()
    if group != group_count or len(rows) > total or ((len(rows) < total) != (native_truncated == "yes")):
        raise Unavailable("invalid_output")
    # Preserve native queue/group order; no year means no oldest-first claim.
    return total, group_count, len(rows), native_truncated, [
        (i + 1,) + tuple(row) for i, row in enumerate(rows[:MAX_VISIBLE_MESSAGES])]


def sendmail_inventory(queue, nonce, runner=run_native):
    if queue not in ("mta", "msp") or not SHA.fullmatch(nonce):
        raise ValueError("invalid_sendmail_inventory_context")
    args = ["-bp"] if queue == "mta" else ["-Ac", "-bp"]
    try:
        total, groups, native_listed, truncated, rows = sendmail_rows(runner("sendmail", args))
        return "ok", total, groups, native_listed, truncated, rows
    except Unavailable as error:
        return error.result, None, None, None, "unknown", []


def sendmail_inventory_lines(queue, nonce, result, total, groups, native_listed, truncated, rows):
    values = (("VERSION", 1), ("SCOPE", "sendmail"), ("QUEUE", queue), ("NONCE", nonce),
              ("RESULT", result), ("TOTAL", "unknown" if total is None else total),
              ("GROUPS", "unknown" if groups is None else groups),
              ("NATIVE_LISTED", "unknown" if native_listed is None else native_listed),
              ("NATIVE_TRUNCATED", truncated), ("LISTED", len(rows)),
              ("DISPLAY_TRUNCATED", "unknown" if native_listed is None else
               "yes" if native_listed > len(rows) else "no"),
              ("REFERENCE_KIND", "sample_ordinal_only"), ("QUEUE_CLASS", "normal"),
              ("DATE_KIND", "native_local_no_year"), ("CHANGES_APPLIED", "no"),
              ("ATOMIC", "no"), ("DELIVERY_VERIFIED", "no"))
    for key, value in values:
        yield "SENDMAIL_ITEMS_" + key + "=" + str(value)
    for row in rows:
        yield "SENDMAIL_ITEMS_ROW=" + "|".join(str(value) for value in row)


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
RETRY_PLAN_TTL = 60
RETRY_CONFIRM = "RETRY_SELECTED_DEFERRED_MESSAGE"


def instance_context(scope, runner, before):
    directory = before[0]
    hostname = runner("postconf", ["-c", directory, "-h", "myhostname"]).strip()
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise Unavailable("scope_unverified")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", hostname) or not re.fullmatch(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot):
        raise Unavailable("scope_unverified")
    return (scope, before, hostname, boot)


def retry_context(scope, runner, before):
    enabled = runner("postconf", ["-c", before[0], "-h", "enable_long_queue_ids"]).strip()
    if enabled != "yes":
        raise Unavailable("long_ids_required")
    return instance_context(scope, runner, before)


def message_fingerprint(item, context, nonce, sampled_at):
    if (context is None or item["queue_name"] not in ("deferred", "hold") or
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


def _postfix_inventory_rows(output, now=None, selection=None):
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
    return counts["total"], rows[:MAX_VISIBLE_MESSAGES]


def postfix_inventory(output, now=None, selection=None):
    total, rows = _postfix_inventory_rows(output, now, selection)
    # Discard native IDs, arrival timestamps and raw metadata before return.
    return total, [(i + 1,) + row[2:] for i, row in enumerate(rows)]


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


def _retry_candidate(scope, nonce, sampled_at, token, runner, scope_check, context_check, now,
                     expected_state="deferred"):
    if (scope not in ("postfix", "sidecar") or not SHA.fullmatch(nonce)
            or not SHA.fullmatch(token) or type(sampled_at) is not int or sampled_at <= 0):
        raise ValueError("invalid_retry_review_context")
    if now < sampled_at or now - sampled_at > REVIEW_TTL:
        return "expired", None, None, None
    try:
        before = scope_check(scope, runner)
        context = context_check(scope, runner, before)
        _, rows = _postfix_inventory_rows(runner("postqueue", ["-c", before[0], "-j"]),
                                         now, (context, nonce, sampled_at))
        if scope_check(scope, runner) != before or context_check(scope, runner, before) != context:
            raise Unavailable("scope_unverified")
        matches = [(i + 1, row) for i, row in enumerate(rows)
                   if row[2] == expected_state and hmac.compare_digest(row[-1], token)]
        if len(matches) != 1:
            return "sample_changed", None, None, None
        index, row = matches[0]
        return "candidate_review_only", (index,) + row[2:], row[1], context
    except Unavailable as error:
        return error.result, None, None, None


def retry_review(scope, nonce, sampled_at, token, runner=run_native,
                 scope_check=verify_postfix_scope, context_check=retry_context, now=None):
    now = int(time.time()) if now is None else now
    result, row, _, _ = _retry_candidate(scope, nonce, sampled_at, token, runner,
                                         scope_check, context_check, now)
    return result, row


def retry_plan_digest(scope, nonce, sampled_at, token, prepared_at, row, context):
    # Age and ordinal may change between samples. Bind state, bytes,
    # recipient count, current delay category and the original fingerprint.
    evidence = ["selected_retry_v1", scope, nonce, sampled_at, token, prepared_at,
                row[1], row[3], row[4], row[5], context]
    return hashlib.sha256(json.dumps(evidence, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()


def retry_prepare(scope, nonce, sampled_at, token, runner=run_native,
                  scope_check=verify_postfix_scope, context_check=retry_context, now=None):
    now = int(time.time()) if now is None else now
    result, row, _, context = _retry_candidate(scope, nonce, sampled_at, token, runner,
                                                scope_check, context_check, now)
    plan = retry_plan_digest(scope, nonce, sampled_at, token, now, row, context) if row else None
    return result, row, now, plan


def schedule_selected_retry(directory, native_id):
    """Only one native long ID, no shell, no raw output, no automatic retry."""
    if directory not in (CONFIG, SIDECAR_CONFIG) or not LONG_ID.fullmatch(native_id):
        raise ValueError("invalid_selected_retry_target")
    binary = native_binary("postqueue")
    try:
        completed = subprocess.run([binary, "-c", directory, "-i", native_id],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=12, check=False,
                                   env={"PATH": PATH, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return "outcome_unknown"
    # Nonzero/timeout is not proof the daemon didn't receive the request.
    return "request_accepted" if completed.returncode == 0 else "outcome_unknown"


def retry_apply(scope, nonce, sampled_at, token, prepared_at, approved, confirm,
                runner=run_native, scope_check=verify_postfix_scope,
                context_check=retry_context, scheduler=schedule_selected_retry,
                clock=time.time, monotonic=time.monotonic):
    if (confirm != RETRY_CONFIRM or not SHA.fullmatch(approved)
            or type(prepared_at) is not int or prepared_at < sampled_at):
        raise ValueError("retry_confirmation_required")
    started = int(clock())
    tick = monotonic()

    def fresh():
        current = int(clock())
        elapsed = monotonic() - tick
        # Refuse a visible wall-clock jump during this operation, as well
        # as an expired sample/plan. Historical clock monotonicity and the
        # final native daemon race still cannot be proven.
        return (0 <= elapsed <= RETRY_PLAN_TTL and abs((current - started) - elapsed) <= 2
                and sampled_at <= prepared_at <= current
                and current - sampled_at <= REVIEW_TTL
                and current - prepared_at <= RETRY_PLAN_TTL)

    if not fresh():
        return "not_requested", "expired"
    try:
        result, row, native_id, context = _retry_candidate(
            scope, nonce, sampled_at, token, runner, scope_check, context_check, started)
        if result != "candidate_review_only":
            return "not_requested", result
        if not hmac.compare_digest(retry_plan_digest(scope, nonce, sampled_at, token,
                                                     prepared_at, row, context), approved):
            return "not_requested", "plan_changed"
        # Independent final sample; do not substitute a newly selected ID,
        # a different reason/instance or any other message.
        result, final, final_id, final_context = _retry_candidate(
            scope, nonce, sampled_at, token, runner, scope_check, context_check, int(clock()))
        if result != "candidate_review_only":
            return "not_requested", result
        if (final_id != native_id or final_context != context or
                not hmac.compare_digest(retry_plan_digest(scope, nonce, sampled_at, token,
                                                         prepared_at, final, final_context), approved)):
            return "not_requested", "plan_changed"
        if not fresh():
            return "not_requested", "expired"
        directory = SIDECAR_CONFIG if scope == "sidecar" else CONFIG
        # Last scope check is inside _retry_candidate. No atomic comparison
        # and delivery request exists in Postfix; this is an experimental path.
        outcome = scheduler(directory, final_id)
        if outcome == "request_accepted":
            return outcome, "none"
        return "outcome_unknown", "native_result_unconfirmed"
    except Unavailable as error:
        return "not_requested", error.result


MAINTENANCE_CONFIRM = {
    "flush": "FLUSH_SELECTED_POSTFIX_INSTANCE",
    "hold": "HOLD_SELECTED_DEFERRED_MESSAGE",
    "release": "RELEASE_SELECTED_HELD_MESSAGE",
    "delete": "PERMANENTLY_DELETE_SELECTED_HELD_MESSAGE",
}
MAINTENANCE_COUNTS = ("total", "active", "deferred", "held", "incoming", "maildrop", "other")


def maintenance_config_identity(directory):
    """Bind root-owned configuration bytes, without returning their contents."""
    if directory not in (CONFIG, SIDECAR_CONFIG):
        raise Unavailable("scope_unverified")
    secure_directory(directory)
    evidence = []
    for name in ("main.cf", "master.cf"):
        path = os.path.join(directory, name)
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                    or st.st_size > 1024 * 1024):
                raise Unavailable("scope_unverified")
            raw = bytearray()
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > 1024 * 1024:
                    raise Unavailable("scope_unverified")
            end = os.fstat(fd)
            current = os.lstat(path)
            def identity(meta):
                return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns,
                        meta.st_ctime_ns, meta.st_uid, meta.st_mode)
            if identity(st) != identity(end) or identity(st) != identity(current) or len(raw) != st.st_size:
                raise Unavailable("scope_unverified")
            evidence.append((name, identity(st), hashlib.sha256(raw).hexdigest()))
        except OSError:
            raise Unavailable("scope_unverified")
        finally:
            if fd is not None:
                os.close(fd)
    return evidence


def maintenance_sample(action, scope, nonce, sampled_at, token, now, runner=run_native,
                       scope_check=verify_postfix_scope, context_check=retry_context,
                       instance_check=instance_context, config_check=maintenance_config_identity):
    if (action not in MAINTENANCE_CONFIRM or scope not in ("postfix", "sidecar")
            or not SHA.fullmatch(nonce)):
        raise ValueError("invalid_maintenance_context")
    if action == "flush":
        if sampled_at != 0 or token != "-":
            raise ValueError("flush_is_instance_wide")
    elif not SHA.fullmatch(token) or sampled_at <= 0:
        raise ValueError("selected_message_required")
    try:
        before = scope_check(scope, runner)
        directory = SIDECAR_CONFIG if scope == "sidecar" else CONFIG
        if before[0] != directory:
            raise Unavailable("scope_unverified")
        config = config_check(directory)
        if action == "flush":
            context = instance_check(scope, runner, before)
            output = runner("postqueue", ["-c", directory, "-j"])
            counts = postfix_counts(output, now)
            # Require a useful deferred queue; never start a periodic flush.
            if counts["deferred"] == 0:
                return "no_deferred_messages", None, None
            # Bind the complete validated bounded native listing, independent
            # of its order. Raw queue IDs, envelopes and reasons never leave.
            objects = [json.loads(line, object_pairs_hook=unique_json)
                       for line in output.splitlines() if line.strip()]
            canonical = json.dumps(sorted(objects, key=lambda item: item["queue_id"]),
                                   sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            queue_digest = hmac.new(bytes.fromhex(nonce), canonical, hashlib.sha256).hexdigest()
            public = [counts[key] for key in MAINTENANCE_COUNTS]
            evidence = [context, config, queue_digest, public]
            native_id = None
            if instance_check(scope, runner, before) != context:
                raise Unavailable("scope_unverified")
        else:
            state = "deferred" if action == "hold" else "held"
            result, row, native_id, context = _retry_candidate(
                scope, nonce, sampled_at, token, runner, scope_check, context_check, now,
                expected_state=state)
            if result != "candidate_review_only":
                return result, None, None
            if context[1] != before:
                raise Unavailable("scope_unverified")
            public = [row[1], row[3], row[4]]
            evidence = [context, config, token, public, row[5]]
        if scope_check(scope, runner) != before or config_check(directory) != config:
            raise Unavailable("scope_unverified")
        return "candidate", (public, evidence), native_id
    except Unavailable as error:
        return error.result, None, None
    except (ValueError, TypeError, OverflowError, RecursionError):
        return "invalid_output", None, None


def maintenance_digest(action, scope, nonce, sampled_at, token, prepared_at, evidence):
    return hashlib.sha256(json.dumps(
        ["queue_maintenance_v1", action, scope, nonce, sampled_at, token, prepared_at, evidence],
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def maintenance_prepare(action, scope, nonce, sampled_at, token, clock=time.time, **sample_options):
    prepared = int(clock())
    result, sample_data, _ = maintenance_sample(
        action, scope, nonce, sampled_at, token, prepared, **sample_options)
    if result != "candidate":
        return result, prepared, "-", "-"
    public, evidence = sample_data
    plan = maintenance_digest(action, scope, nonce, sampled_at, token, prepared, evidence)
    return result, prepared, plan, "|".join(str(value) for value in public)


def execute_maintenance(action, directory, native_id):
    if directory not in (CONFIG, SIDECAR_CONFIG) or action not in MAINTENANCE_CONFIRM:
        raise ValueError("invalid_maintenance_target")
    if action == "flush":
        if native_id is not None:
            raise ValueError("flush_target_must_be_instance")
        args = [native_binary("postqueue"), "-c", directory, "-f"]
    else:
        if not isinstance(native_id, str) or not LONG_ID.fullmatch(native_id):
            raise ValueError("invalid_selected_message")
        flag = {"hold": "-h", "release": "-H", "delete": "-d"}[action]
        args = [native_binary("postsuper"), "-c", directory, flag, native_id,
                "deferred" if action == "hold" else "hold"]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=12, check=False,
                                env={"PATH": PATH, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return "outcome_unknown"
    # postsuper success can mean the target vanished; no movement or delivery
    # is claimed from a zero exit code alone.
    return "command_completed" if result.returncode == 0 else "outcome_unknown"


def maintenance_apply(action, scope, nonce, sampled_at, token, prepared_at, approved, confirm,
                      executor=execute_maintenance, clock=time.time, monotonic=time.monotonic,
                      **sample_options):
    if (action not in MAINTENANCE_CONFIRM or confirm != MAINTENANCE_CONFIRM[action]
            or not SHA.fullmatch(approved) or prepared_at <= 0 or
            (action != "flush" and prepared_at < sampled_at)):
        raise ValueError("maintenance_confirmation_required")
    started = int(clock())
    tick = monotonic()

    def fresh():
        current = int(clock())
        elapsed = monotonic() - tick
        return (0 <= elapsed <= RETRY_PLAN_TTL and abs(current - started - elapsed) <= 2
                and prepared_at <= current <= prepared_at + RETRY_PLAN_TTL
                and (action == "flush" or sampled_at <= prepared_at <= current <= sampled_at + REVIEW_TTL))

    if not fresh():
        return "not_requested", "expired"
    native_id = None
    for _ in range(2):
        result, sample_data, found = maintenance_sample(
            action, scope, nonce, sampled_at, token, int(clock()), **sample_options)
        if result != "candidate":
            return "not_requested", result
        _, evidence = sample_data
        digest = maintenance_digest(action, scope, nonce, sampled_at, token, prepared_at, evidence)
        if not hmac.compare_digest(digest, approved) or (native_id is not None and found != native_id):
            return "not_requested", "plan_changed"
        native_id = found
    if not fresh():
        return "not_requested", "expired"
    directory = SIDECAR_CONFIG if scope == "sidecar" else CONFIG
    try:
        result = executor(action, directory, native_id)
    except Unavailable as error:
        return "not_requested", error.result
    return (("command_completed", "none") if result == "command_completed"
            else ("outcome_unknown", "native_result_unconfirmed"))


def maintenance_lines(action, scope, nonce, sampled_at, token, phase, prepared, plan,
                      outcome, detail, reason):
    values = (("VERSION", 1), ("ACTION", action), ("SCOPE", scope), ("NONCE", nonce),
              ("SAMPLED_AT", sampled_at), ("FINGERPRINT", token), ("PHASE", phase),
              ("PREPARED_AT", prepared), ("PLAN_SHA256", plan), ("OUTCOME", outcome),
              ("DETAIL", detail), ("REASON", reason),
              ("COMMAND_COUNT", "1" if outcome == "command_completed" else
               "unknown" if outcome == "outcome_unknown" else "0"),
              ("EFFECT_VERIFIED", "no"), ("DELIVERY_VERIFIED", "no"), ("ATOMIC", "no"),
              ("CONFIG_CHANGED", "no"), ("SERVICE_CHANGED", "no"),
              ("DELETE_REQUESTED", ("yes" if outcome == "command_completed" else
                "unknown" if outcome == "outcome_unknown" else "no")
                if action == "delete" and phase == "apply" else "no"),
              ("NEW_MESSAGE_SUBMITTED", "no"))
    for key, value in values:
        yield "MAIL_MAINT_" + key + "=" + str(value)


def retry_apply_lines(scope, token, sampled_at, prepared_at, approved, outcome, reason):
    for key, value in (("VERSION", 1), ("SCOPE", scope), ("FINGERPRINT", token),
                       ("SAMPLED_AT", sampled_at), ("PREPARED_AT", prepared_at),
                       ("PLAN_SHA256", approved), ("OUTCOME", outcome), ("REASON", reason),
                       ("REQUEST_COUNT", "1" if outcome == "request_accepted" else
                        "0" if outcome == "not_requested" else "unknown"),
                       ("DELIVERY_VERIFIED", "no"), ("ATOMIC", "no"),
                       ("SERVICE_CHANGED", "no"), ("CONFIG_CHANGED", "no"),
                       ("NEW_MESSAGE_SUBMITTED", "no"), ("DELETE_REQUESTED", "no"),
                       ("FLUSH_REQUESTED", "no")):
        yield "MAIL_RETRY_APPLY_" + key + "=" + str(value)


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
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--retry-plan")
    action.add_argument("--retry-prepare")
    action.add_argument("--retry-apply")
    action.add_argument("--maintenance", choices=tuple(MAINTENANCE_CONFIRM))
    action.add_argument("--exim-action", choices=tuple(EXIM_ACTIONS))
    parser.add_argument("--sendmail-inventory", choices=("mta", "msp"))
    parser.add_argument("--exim-inventory", action="store_true")
    parser.add_argument("--exim-apply", action="store_true")
    parser.add_argument("--maintenance-apply", action="store_true")
    parser.add_argument("--target-fingerprint")
    parser.add_argument("--sampled-at", type=int)
    parser.add_argument("--prepared-at", type=int)
    parser.add_argument("--approve-sha256")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    if os.geteuid() != 0:
        return 2
    if args.sendmail_inventory is not None:
        if (args.scope != "sendmail" or args.messages or args.exim_inventory or
                args.exim_apply or args.maintenance_apply or
                any(value is not None for value in (args.exim_action, args.maintenance,
                    args.retry_plan, args.retry_prepare, args.retry_apply, args.sampled_at,
                    args.target_fingerprint, args.prepared_at, args.approve_sha256, args.confirm)) or
                not SHA.fullmatch(args.selection_nonce or "")):
            parser.error("Sendmail inventory is read-only and requires one normal queue")
        values = sendmail_inventory(args.sendmail_inventory, args.selection_nonce)
        for line in sendmail_inventory_lines(args.sendmail_inventory, args.selection_nonce, *values):
            print(line)
        return 0
    if args.exim_inventory or args.exim_action is not None:
        if (args.scope != "exim" or args.messages or args.maintenance_apply or
                args.maintenance is not None or args.retry_plan is not None or
                args.retry_prepare is not None or args.retry_apply is not None or
                not SHA.fullmatch(args.selection_nonce or "")):
            parser.error("invalid Exim queue context")
        if args.exim_inventory:
            if args.exim_action is not None or args.exim_apply or any(value is not None for value in
                    (args.sampled_at, args.target_fingerprint, args.prepared_at, args.approve_sha256, args.confirm)):
                parser.error("inventory cannot carry Exim write approval")
            result, sampled, total, rows, context = exim_inventory(args.selection_nonce)
            lines = exim_inventory_lines(args.selection_nonce, result, sampled, total, rows, context)
        else:
            if args.exim_action == "flush":
                if args.sampled_at is not None or args.target_fingerprint is not None:
                    parser.error("Exim Flush targets the default queue")
                args.sampled_at = 0
                args.target_fingerprint = "-"
            elif (args.sampled_at is None or not 0 < args.sampled_at <= 9999999999 or
                    not SHA.fullmatch(args.target_fingerprint or "")):
                parser.error("selected Exim message required")
            if args.exim_apply:
                if (args.prepared_at is None or not max(1, args.sampled_at) <= args.prepared_at <= 9999999999 or
                        not SHA.fullmatch(args.approve_sha256 or "") or
                        args.confirm != EXIM_ACTIONS[args.exim_action]):
                    parser.error("explicit Exim action approval required")
                outcome, reason = exim_apply(args.exim_action, args.selection_nonce, args.sampled_at,
                    args.target_fingerprint, args.prepared_at, args.approve_sha256, args.confirm)
                lines = exim_action_lines(args.exim_action, args.selection_nonce, args.sampled_at,
                    args.target_fingerprint, "apply", args.prepared_at, args.approve_sha256, outcome, reason)
            else:
                if any(value is not None for value in (args.prepared_at, args.approve_sha256, args.confirm)):
                    parser.error("approval not permitted in Exim preview")
                result, prepared, plan, detail = exim_prepare_details(args.exim_action, args.selection_nonce,
                    args.sampled_at, args.target_fingerprint)
                lines = exim_action_lines(args.exim_action, args.selection_nonce, args.sampled_at,
                    args.target_fingerprint, "prepare", prepared, plan,
                    "candidate" if result == "candidate" else "not_requested",
                    "none" if result == "candidate" else result, detail)
        for line in lines:
            print(line)
        return 0
    if args.exim_apply:
        parser.error("explicit Exim action required")
    if args.maintenance is not None:
        operation = args.maintenance
        sampled_at = args.sampled_at if args.sampled_at is not None else 0
        target = args.target_fingerprint if args.target_fingerprint is not None else "-"
        if (args.messages or args.scope not in ("postfix", "sidecar") or
                not SHA.fullmatch(args.selection_nonce or "") or
                (operation == "flush" and (sampled_at != 0 or target != "-")) or
                (operation != "flush" and (not 0 < sampled_at <= 9999999999 or
                                           not SHA.fullmatch(target)))):
            parser.error("invalid maintenance selection")
        if args.maintenance_apply:
            if (args.prepared_at is None or not 0 < args.prepared_at <= 9999999999 or
                    not SHA.fullmatch(args.approve_sha256 or "") or
                    args.confirm != MAINTENANCE_CONFIRM[operation]):
                parser.error("maintenance approval required")
            outcome, reason = maintenance_apply(operation, args.scope, args.selection_nonce,
                sampled_at, target, args.prepared_at, args.approve_sha256, args.confirm)
            lines = maintenance_lines(operation, args.scope, args.selection_nonce, sampled_at,
                target, "apply", args.prepared_at, args.approve_sha256, outcome, "-", reason)
        else:
            if any(value is not None for value in (args.prepared_at, args.approve_sha256, args.confirm)):
                parser.error("approval not permitted during maintenance preview")
            status, prepared, plan, detail = maintenance_prepare(
                operation, args.scope, args.selection_nonce, sampled_at, target)
            lines = maintenance_lines(operation, args.scope, args.selection_nonce, sampled_at,
                target, "prepare", prepared, plan, "candidate" if status == "candidate" else "not_requested",
                detail, "none" if status == "candidate" else status)
        for line in lines:
            print(line)
        return 0
    if args.maintenance_apply or args.target_fingerprint is not None:
        parser.error("explicit maintenance action required")
    token = args.retry_plan or args.retry_prepare or args.retry_apply
    apply_fields = (args.prepared_at, args.approve_sha256, args.confirm)
    if token is not None:
        if (args.messages or args.scope not in ("postfix", "sidecar") or
                not SHA.fullmatch(args.selection_nonce or "") or not SHA.fullmatch(token) or
                args.sampled_at is None or not 0 < args.sampled_at <= 9999999999):
            parser.error("invalid selected Retry context")
        if args.retry_apply is not None:
            if (args.prepared_at is None or not args.sampled_at <= args.prepared_at <= 9999999999 or
                    not SHA.fullmatch(args.approve_sha256 or "") or args.confirm != RETRY_CONFIRM):
                parser.error("explicit selected Retry approval required")
            outcome, reason = retry_apply(args.scope, args.selection_nonce, args.sampled_at,
                                          token, args.prepared_at, args.approve_sha256, args.confirm)
            for line in retry_apply_lines(args.scope, token, args.sampled_at, args.prepared_at,
                                          args.approve_sha256, outcome, reason):
                print(line)
            return 0
        if any(value is not None for value in apply_fields):
            parser.error("approval not permitted during Retry preview")
        if args.retry_prepare is not None:
            result, row, prepared_at, plan = retry_prepare(
                args.scope, args.selection_nonce, args.sampled_at, token)
            if plan is not None:
                print("MAIL_RETRY_PREPARED_AT=" + str(prepared_at))
                print("MAIL_RETRY_PLAN_SHA256=" + plan)
        else:
            result, row = retry_review(args.scope, args.selection_nonce, args.sampled_at, token)
        for line in retry_lines(args.scope, token, args.sampled_at, result, row):
            print(line)
        return 0
    if any(value is not None for value in apply_fields):
        parser.error("approval requires explicit Retry Apply")
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
