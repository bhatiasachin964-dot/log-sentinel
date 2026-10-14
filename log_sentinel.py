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
"""

import os
import re
import csv
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

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


def parse_time(text):
    """Syslog timestamps have no year, so we add the current year."""
    return datetime.strptime(f"{datetime.now().year} {text}", "%Y %b %d %H:%M:%S")


# ---------------------------------------------------------------
# 2. PARSING: read the log file and pull out the events we care about
# ---------------------------------------------------------------
def parse_log(path):
    """Return a list of events like {'time', 'type', 'user', 'ip'}."""
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for event_type, pattern in (("failed", FAILED), ("accepted", ACCEPTED)):
                match = pattern.search(line)
                if match:
                    events.append({
                        "time": parse_time(match.group("time")),
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
                "rule": "Brute-force attack",
                "ip": ip,
                "details": f"{len(times)} failed logins (peak {peak} within "
                           f"{window_minutes} min, first seen {times[0]:%b %d %H:%M})",
                "mitre": "T1110 - Brute Force",
            })
    return alerts


def detect_success_after_failures(events, threshold):
    """Flag a successful login from an IP that previously failed many times.

    Each compromised IP is reported once, at its first successful login after
    the failure threshold was reached.
    """
    alerts = []
    fail_count = defaultdict(int)
    reported = set()
    for e in sorted(events, key=lambda x: x["time"]):
        if e["type"] == "failed":
            fail_count[e["ip"]] += 1
        elif (e["type"] == "accepted"
              and fail_count[e["ip"]] >= threshold
              and e["ip"] not in reported):
            reported.add(e["ip"])
            alerts.append({
                "severity": "CRITICAL",
                "rule": "Possible account compromise",
                "ip": e["ip"],
                "details": f"Logged in as '{e['user']}' at {e['time']:%b %d %H:%M:%S} "
                           f"after {fail_count[e['ip']]} failed attempts",
                "mitre": "T1078 - Valid Accounts",
            })
    return alerts


def detect_root_attempts(events):
    """Flag any IP trying to log in directly as root."""
    root_tries = defaultdict(int)
    for e in events:
        if e["type"] == "failed" and e["user"] == "root":
            root_tries[e["ip"]] += 1
    return [{
        "severity": "MEDIUM",
        "rule": "Direct root login attempt",
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
        "rule": "Username enumeration",
        "ip": ip,
        "details": f"Tried {len(users)} usernames: {', '.join(sorted(users)[:6])}"
                   + (" ..." if len(users) > 6 else ""),
        "mitre": "T1110.003 - Password Spraying",
    } for ip, users in users_by_ip.items() if len(users) >= min_users]


# ---------------------------------------------------------------
# 4. REPORTING: print a summary and save JSON / CSV reports
# ---------------------------------------------------------------
def print_report(events, alerts):
    failed = sum(1 for e in events if e["type"] == "failed")
    accepted = len(events) - failed
    unique_ips = len({e["ip"] for e in events})

    print(f"\n{BOLD}{'=' * 60}\n  LogSentinel - SSH Security Report\n{'=' * 60}{RESET}")
    print(f"  Events parsed     : {len(events)}")
    print(f"  Failed logins     : {failed}")
    print(f"  Successful logins : {accepted}")
    print(f"  Unique source IPs : {unique_ips}")
    print(f"  Alerts raised     : {len(alerts)}\n")

    if not alerts:
        print(f"{GREEN}  No suspicious activity detected.{RESET}\n")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for a in sorted(alerts, key=lambda x: order[x["severity"]]):
        colour = SEVERITY_COLOUR[a["severity"]]
        print(f"  {colour}{BOLD}[{a['severity']}]{RESET} {a['rule']}  ->  {a['ip']}")
        print(f"      {a['details']}")
        print(f"      MITRE ATT&CK: {a['mitre']}\n")

    # Suggest IPs to block (anything HIGH or CRITICAL)
    block = sorted({a["ip"] for a in alerts if a["severity"] in ("HIGH", "CRITICAL")})
    if block:
        print(f"{BOLD}  Recommended action - review and consider blocking:{RESET}")
        for ip in block:
            print(f"      sudo ufw deny from {ip}")
        print()


def save_reports(alerts, prefix):
    with open(f"{prefix}.json", "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    with open(f"{prefix}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "rule", "ip", "details", "mitre"])
        writer.writeheader()
        writer.writerows(alerts)
    print(f"  Reports saved: {prefix}.json and {prefix}.csv\n")


# ---------------------------------------------------------------
# 5. MAIN: read command-line options and run everything
# ---------------------------------------------------------------
def main():
    os.system("")  # enables coloured output in Windows Command Prompt
    parser = argparse.ArgumentParser(description="Detect SSH attacks in Linux auth logs.")
    parser.add_argument("--file", default="sample_auth.log", help="Path to the auth log")
    parser.add_argument("--threshold", type=int, default=5, help="Failures that count as brute force")
    parser.add_argument("--window", type=int, default=10, help="Time window in minutes")
    parser.add_argument("--output", default="security_report", help="Report file name (no extension)")
    args = parser.parse_args()

    try:
        events = parse_log(args.file)
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
        + detect_user_enumeration(events)
    )

    print_report(events, alerts)
    if alerts:
        save_reports(alerts, args.output)


if __name__ == "__main__":
    main()
