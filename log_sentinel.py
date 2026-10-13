"""
LogSentinel - SSH Brute-Force & Suspicious Login Detector

A beginner-friendly defensive security tool that reads a Linux SSH
authentication log (like /var/log/auth.log) and detects signs of attack:

  1. Brute-force attacks     - many failed logins from one IP in a short time
  2. Possible compromise     - a successful login from an IP that failed many times
  3. Root login attempts     - someone trying to log in directly as 'root'
  4. Username enumeration    - one IP guessing many different usernames

Usage:
  python log_sentinel.py --file sample_auth.log
  python log_sentinel.py --file /var/log/auth.log --threshold 5 --window 10
  python log_sentinel.py --file /var/log/auth.log.1.gz --json | jq .alerts
  sudo python3 -m log_sentinel --file /var/log/auth.log --output /var/tmp/report
"""

import argparse
import csv
import gzip
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

__version__ = "1.1.0"

# ---------------------------------------------------------------
# 1. PATTERNS: regular expressions that match SSH log lines
# ---------------------------------------------------------------
# Example: "Sep 28 10:15:32 server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
TIMESTAMP = r"^(?P<time>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"

FAILED = re.compile(
    TIMESTAMP + r".*sshd\[\d+\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
ACCEPTED = re.compile(
    TIMESTAMP + r".*sshd\[\d+\]: Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)

# Colours for the terminal output
RED, YELLOW, GREEN, BOLD, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[1m", "\033[0m"
SEVERITY_COLOUR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}

# Rules are kept stable so downstream tooling can key on them.
RULE_BRUTE_FORCE = "Brute-force attack"
RULE_COMPROMISE = "Possible account compromise"
RULE_ROOT = "Direct root login attempt"
RULE_ENUMERATION = "Username enumeration"


def parse_time(text, year=None):
    """Syslog timestamps carry no year, so we stamp them explicitly.

    ``year`` defaults to the current year, but callers analysing stored logs
    can pin it with ``--year`` so December->January spans sort correctly.
    """
    if year is None:
        year = datetime.now().year
    return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")


# ---------------------------------------------------------------
# 2. PARSING: read the log file and pull out the events we care about
# ---------------------------------------------------------------
def open_log(path):
    """Open a log, transparently decompressing ``.gz`` files.

    Logrotate commonly keeps the previous rotation as ``auth.log.1`` *or*
    ``auth.log.1.gz``, so a tool that claims to read ``/var/log`` should
    handle the compressed variant without an extra step.
    """
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")


def parse_log(path, year=None):
    """Return a list of events like {'time', 'type', 'user', 'ip'}."""
    events = []
    with open_log(path) as f:
        for line in f:
            for event_type, pattern in (("failed", FAILED), ("accepted", ACCEPTED)):
                match = pattern.search(line)
                if match:
                    events.append({
                        "time": parse_time(match.group("time"), year=year),
                        "type": event_type,
                        "user": match.group("user"),
                        "ip": match.group("ip"),
                    })
                    break
    return events


# ---------------------------------------------------------------
# 3. DETECTION RULES: each function looks for one kind of attack
# ---------------------------------------------------------------
def detect_brute_force(events, threshold, window_minutes):
    """Flag IPs with >= threshold failures inside a sliding time window."""
    alerts = []
    failures = defaultdict(list)
    for e in events:
        if e["type"] == "failed":
            failures[e["ip"]].append(e["time"])

    window = timedelta(minutes=window_minutes)
    for ip, times in failures.items():
        times.sort()
        start, peak = 0, 0
        for end in range(len(times)):
            # Shrink the window from the left until it fits the time limit
            while times[end] - times[start] > window:
                start += 1
            peak = max(peak, end - start + 1)
        if peak >= threshold:
            alerts.append({
                "severity": "HIGH",
                "rule": RULE_BRUTE_FORCE,
                "ip": ip,
                "details": f"{len(times)} failed logins (peak {peak} within "
                           f"{window_minutes} min, first seen {times[0]:%b %d %H:%M})",
                "mitre": "T1110 - Brute Force",
            })
    return alerts


def detect_success_after_failures(events, threshold):
    """Flag a successful login from an IP that previously failed many times.

    Each IP is reported once: after it is flagged as compromised, further
    successful logins from the same IP no longer raise duplicate CRITICALs.
    """
    alerts = []
    fail_count = defaultdict(int)
    compromised = set()
    for e in sorted(events, key=lambda x: x["time"]):
        if e["type"] == "failed":
            fail_count[e["ip"]] += 1
        elif (
            e["type"] == "accepted"
            and e["ip"] not in compromised
            and fail_count[e["ip"]] >= threshold
        ):
            alerts.append({
                "severity": "CRITICAL",
                "rule": RULE_COMPROMISE,
                "ip": e["ip"],
                "details": f"Logged in as '{e['user']}' at {e['time']:%b %d %H:%M:%S} "
                           f"after {fail_count[e['ip']]} failed attempts",
                "mitre": "T1078 - Valid Accounts",
            })
            compromised.add(e["ip"])
    return alerts


def detect_root_attempts(events):
    """Flag any IP trying to log in directly as root."""
    root_tries = defaultdict(int)
    for e in events:
        if e["type"] == "failed" and e["user"] == "root":
            root_tries[e["ip"]] += 1
    return [{
        "severity": "MEDIUM",
        "rule": RULE_ROOT,
        "ip": ip,
        "details": f"{count} failed login(s) as root",
        "mitre": "T1110.001 - Password Guessing",
    } for ip, count in root_tries.items()]


def detect_user_enumeration(events, min_users=3):
    """Flag IPs that tried many different usernames."""
    users_by_ip = defaultdict(set)
    for e in events:
        if e["type"] == "failed":
            users_by_ip[e["ip"]].add(e["user"])
    return [{
        "severity": "MEDIUM",
        "rule": RULE_ENUMERATION,
        "ip": ip,
        "details": f"Tried {len(users)} usernames: {', '.join(sorted(users)[:6])}"
                   + (" ..." if len(users) > 6 else ""),
        "mitre": "T1110.003 - Password Spraying",
    } for ip, users in users_by_ip.items() if len(users) >= min_users]


# ---------------------------------------------------------------
# 4. REPORTING: print a summary and save JSON / CSV reports
# ---------------------------------------------------------------
def count_events(events):
    failed = sum(1 for e in events if e["type"] == "failed")
    return {
        "events_parsed": len(events),
        "failed": failed,
        "successful": len(events) - failed,
        "unique_ips": len({e["ip"] for e in events}),
    }


def print_report(events, alerts, color=True):
    summary = count_events(events)
    c = _colorizer(color)
    out = sys.stdout
    out.write(f"{c.BOLD}{'=' * 60}\n  LogSentinel - SSH Security Report\n{'=' * 60}{c.RESET}\n")
    out.write(f"  Events parsed     : {summary['events_parsed']}\n")
    out.write(f"  Failed logins     : {summary['failed']}\n")
    out.write(f"  Successful logins : {summary['successful']}\n")
    out.write(f"  Unique source IPs : {summary['unique_ips']}\n")
    out.write(f"  Alerts raised     : {len(alerts)}\n\n")

    if not alerts:
        out.write(f"{c.GREEN}  No suspicious activity detected.{c.RESET}\n\n")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for a in sorted(alerts, key=lambda x: order[x["severity"]]):
        colour = SEVERITY_COLOUR[a["severity"]] if color else ""
        out.write(f"  {colour}{c.BOLD}[{a['severity']}]{c.RESET} {a['rule']}  ->  {a['ip']}\n")
        out.write(f"      {a['details']}\n")
        out.write(f"      MITRE ATT&CK: {a['mitre']}\n\n")

    # Suggest IPs to block (anything HIGH or CRITICAL)
    block = sorted({a["ip"] for a in alerts if a["severity"] in ("HIGH", "CRITICAL")})
    if block:
        out.write(f"{c.BOLD}  Recommended action - review and consider blocking:{c.RESET}\n")
        for ip in block:
            out.write(f"      sudo ufw deny from {ip}\n")
        out.write("\n")


def emit_json(events, alerts):
    """Emit a machine-readable report to stdout (clean pipe for jq/cron)."""
    summary = count_events(events)
    json.dump({"summary": summary, "alerts": alerts}, sys.stdout,
              indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def save_reports(alerts, prefix):
    parent = os.path.dirname(prefix)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(f"{prefix}.json", "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    with open(f"{prefix}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "rule", "ip", "details", "mitre"])
        writer.writeheader()
        writer.writerows(alerts)
    print(f"  Reports saved: {prefix}.json and {prefix}.csv\n")


class _colorizer:
    """Small indirection so colour codes can be switched off for clean piping."""

    __slots__ = ("enabled",)

    def __init__(self, enabled):
        self.enabled = enabled

    def __getattr__(self, name):
        return globals()[name] if self.enabled and name in globals() else ""


# ---------------------------------------------------------------
# 5. MAIN: read command-line options and run everything
# ---------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Detect SSH attacks in Linux auth logs.",
    )
    parser.add_argument("--file", default="sample_auth.log", help="Path to the auth log (.gz supported)")
    parser.add_argument("--threshold", type=int, default=5, help="Failures that count as brute force")
    parser.add_argument("--window", type=int, default=10, help="Time window in minutes")
    parser.add_argument("--output", default="security_report", help="Report file name (no extension)")
    parser.add_argument("--min-users", type=int, default=3, dest="min_users",
                        help="Usernames an IP must try to count as enumeration")
    parser.add_argument("--year", type=int, default=None,
                        help="Stamp un-year'd timestamps with this year (default: current)")
    parser.add_argument("--json", action="store_true",
                        help="Print a machine-readable JSON report to stdout")
    parser.add_argument("--no-color", action="store_true", dest="no_color",
                        help="Disable ANSI colour codes (for logs/CI)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv=None):
    os.system("")  # enables coloured output in Windows Command Prompt
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be >= 1")
    if args.window < 1:
        parser.error("--window must be >= 1")

    try:
        events = parse_log(args.file, year=args.year)
    except FileNotFoundError:
        print(f"Error: log file '{args.file}' not found.")
        raise SystemExit(1)
    except PermissionError:
        print(f"Error: no permission to read '{args.file}'. Try running with sudo.")
        raise SystemExit(1)

    alerts = (
        detect_brute_force(events, args.threshold, args.window)
        + detect_success_after_failures(events, args.threshold)
        + detect_root_attempts(events)
        + detect_user_enumeration(events, args.min_users)
    )

    try:
        if args.json:
            emit_json(events, alerts)
        else:
            print_report(events, alerts, color=not args.no_color)

            if alerts:
                save_reports(alerts, args.output)
        return 0
    except BrokenPipeError:
        # A downstream consumer (`log-sentinel --json | head` / `| jq`) closed
        # the pipe before we finished writing. Keep the exit clean -- no traceback.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())