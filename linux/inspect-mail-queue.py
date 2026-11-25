#!/usr/bin/env python3
"""Privacy-safe, read-only native queue sampling; Python 3.6+.

No message submission, retry/flush, deletion, body reading, or service changes.
No message IDs, addresses, raw delay reasons or command output leave this tool.
The result is a non-atomic sample, NOT an offline-restore preflight.
"""
import argparse
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
                and args[2:] == ["-h", "queue_directory"])
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, choices=("postfix", "sidecar", "exim", "sendmail"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        return 2
    report = sample(args.scope)
    for name, value in sorted(report.items()):
        print("MAIL_QUEUE_" + name.upper() + "=" + str(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
