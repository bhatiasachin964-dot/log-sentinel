import csv
import json

from log_sentinel import (
    detect_brute_force,
    detect_password_spraying,
    detect_root_attempts,
    detect_success_after_failures,
    parse_log,
    save_reports,
)


def failed_line(ts, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    return f"{ts} server sshd[1234]: Failed password for {prefix}{user} from {ip} port 22 ssh2"


def accepted_line(ts, user, ip, method="password"):
    return f"{ts} server sshd[1234]: Accepted {method} for {user} from {ip} port 22 ssh2"


def events_from(tmp_path, lines):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return parse_log(str(log))


# ---------- parsing ----------

def test_parse_log_extracts_failed_and_accepted(tmp_path):
    events = events_from(tmp_path, [
        failed_line("Sep 28 10:15:32", "root", "203.0.113.5"),
        failed_line("Sep 28 10:15:40", "bob", "203.0.113.5", invalid=True),
        accepted_line("Sep 28 10:16:00", "alice", "198.51.100.7", method="publickey"),
    ])
    assert [(e["type"], e["user"], e["ip"]) for e in events] == [
        ("failed", "root", "203.0.113.5"),
        ("failed", "bob", "203.0.113.5"),
        ("accepted", "alice", "198.51.100.7"),
    ]


def test_parse_log_ignores_unrelated_lines(tmp_path):
    events = events_from(tmp_path, [
        "Sep 28 10:00:00 server CRON[99]: pam_unix(cron:session): session opened",
        "Sep 28 10:00:05 server sshd[1234]: Connection closed by 203.0.113.5",
        failed_line("Sep 28 10:00:10", "root", "203.0.113.5"),
    ])
    assert len(events) == 1
    assert events[0]["type"] == "failed"


# ---------- brute force (sliding window) ----------

def test_brute_force_detected_for_fast_burst(tmp_path):
    lines = [failed_line(f"Sep 28 10:00:{s:02d}", "admin", "203.0.113.9") for s in range(0, 12, 2)]
    alerts = detect_brute_force(events_from(tmp_path, lines), threshold=5, window_minutes=10)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.9"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre"].startswith("T1110")


def test_brute_force_ignores_slow_failures(tmp_path):
    # Six failures, but 30 minutes apart: never 5 inside one 10-minute window
    lines = [failed_line(f"Sep 28 {h:02d}:{m:02d}:00", "admin", "203.0.113.9")
             for h, m in [(1, 0), (1, 30), (2, 0), (2, 30), (3, 0), (3, 30)]]
    assert detect_brute_force(events_from(tmp_path, lines), threshold=5, window_minutes=10) == []


def test_brute_force_below_threshold_not_flagged(tmp_path):
    lines = [failed_line(f"Sep 28 10:00:{s:02d}", "admin", "203.0.113.9") for s in range(4)]
    assert detect_brute_force(events_from(tmp_path, lines), threshold=5, window_minutes=10) == []


def test_brute_force_counts_each_ip_separately(tmp_path):
    lines = []
    for s in range(3):
        lines.append(failed_line(f"Sep 28 10:00:{s:02d}", "admin", "203.0.113.1"))
        lines.append(failed_line(f"Sep 28 10:00:{s + 10:02d}", "admin", "203.0.113.2"))
    # 3 failures per IP: below a threshold of 5 even though 6 failures exist in total
    assert detect_brute_force(events_from(tmp_path, lines), threshold=5, window_minutes=10) == []


# ---------- possible compromise ----------

def test_success_after_many_failures_is_critical(tmp_path):
    lines = [failed_line(f"Sep 28 10:00:{s:02d}", "ubuntu", "198.51.100.77") for s in range(5)]
    lines.append(accepted_line("Sep 28 10:01:00", "ubuntu", "198.51.100.77"))
    alerts = detect_success_after_failures(events_from(tmp_path, lines), threshold=5)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["mitre"].startswith("T1078")
    assert "after 5 failed attempts" in alerts[0]["details"]


def test_success_without_prior_failures_not_flagged(tmp_path):
    lines = [accepted_line("Sep 28 10:00:00", "alice", "198.51.100.7")]
    assert detect_success_after_failures(events_from(tmp_path, lines), threshold=5) == []


def test_failures_after_success_do_not_trigger_compromise(tmp_path):
    lines = [accepted_line("Sep 28 10:00:00", "alice", "198.51.100.7")]
    lines += [failed_line(f"Sep 28 10:01:{s:02d}", "alice", "198.51.100.7") for s in range(6)]
    assert detect_success_after_failures(events_from(tmp_path, lines), threshold=5) == []


# ---------- root attempts ----------

def test_root_attempts_flagged_with_count(tmp_path):
    lines = [
        failed_line("Sep 28 10:00:00", "root", "203.0.113.50"),
        failed_line("Sep 28 10:00:05", "root", "203.0.113.50"),
        failed_line("Sep 28 10:00:10", "alice", "203.0.113.51"),
    ]
    alerts = detect_root_attempts(events_from(tmp_path, lines))
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.50"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["details"] == "2 failed login(s) as root"


# ---------- password spraying ----------

def test_password_spraying_flagged_at_three_usernames(tmp_path):
    lines = [failed_line(f"Sep 28 10:00:{i:02d}", name, "203.0.113.77", invalid=True)
             for i, name in enumerate(["admin", "test", "oracle"])]
    alerts = detect_password_spraying(events_from(tmp_path, lines))
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.77"
    assert "Tried 3 usernames" in alerts[0]["details"]


def test_password_spraying_not_flagged_below_minimum(tmp_path):
    lines = [failed_line(f"Sep 28 10:00:{i:02d}", name, "203.0.113.77", invalid=True)
             for i, name in enumerate(["admin", "test"])]
    assert detect_password_spraying(events_from(tmp_path, lines)) == []


# ---------- reports ----------

def test_save_reports_writes_matching_json_and_csv(tmp_path):
    alerts = [{
        "severity": "HIGH",
        "rule": "Brute-force attack",
        "ip": "203.0.113.9",
        "details": "6 failed logins",
        "mitre": "T1110 - Brute Force",
    }]
    prefix = str(tmp_path / "report")
    save_reports(alerts, prefix)

    with open(prefix + ".json", encoding="utf-8") as f:
        assert json.load(f) == alerts

    with open(prefix + ".csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows == alerts


def test_compromised_ip_is_reported_only_once(tmp_path):
    # Regression: later successful logins from an already-flagged IP must not repeat the alert
    lines = [failed_line(f"Sep 28 10:00:{s:02d}", "ubuntu", "198.51.100.77") for s in range(5)]
    lines += [
        accepted_line("Sep 28 10:01:00", "ubuntu", "198.51.100.77"),
        accepted_line("Sep 28 10:02:00", "ubuntu", "198.51.100.77"),
        accepted_line("Sep 28 10:03:00", "ubuntu", "198.51.100.77"),
    ]
    alerts = detect_success_after_failures(events_from(tmp_path, lines), threshold=5)
    assert len(alerts) == 1
    assert "10:01:00" in alerts[0]["details"]


def test_different_compromised_ips_are_each_reported(tmp_path):
    lines = []
    for ip in ("198.51.100.77", "198.51.100.78"):
        lines += [failed_line(f"Sep 28 10:00:{s:02d}", "ubuntu", ip) for s in range(5)]
        lines.append(accepted_line("Sep 28 10:01:00", "ubuntu", ip))
    alerts = detect_success_after_failures(events_from(tmp_path, lines), threshold=5)
    assert sorted(a["ip"] for a in alerts) == ["198.51.100.77", "198.51.100.78"]
