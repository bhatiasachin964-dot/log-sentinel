"""Edge-case, regression and summary tests for LogSentinel. Run with:  pytest -v

Tests marked xfail(strict=True) document KNOWN LIMITATIONS: they describe the
behaviour we want but the code does not have yet. If you fix a limitation the
test will start passing, pytest will report it as a failure (XPASS), and you
then remove the xfail marker.
"""
import csv
import json
import os
import sys
from datetime import datetime

import pytest

import log_sentinel as ls


# ---------- helpers ----------
def fail_line(ts, user, ip, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"{ts} host sshd[100]: Failed password for {who} from {ip} port 22 ssh2"


def ok_line(ts, user, ip, method="password"):
    return f"{ts} host sshd[100]: Accepted {method} for {user} from {ip} port 22 ssh2"


def write_log(tmp_path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def ev(kind, user, ip, ts):
    """Build an event dict directly (bypasses the parser)."""
    return {"time": datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S"),
            "type": kind, "user": user, "ip": ip}


def failures(ip, n, start_minute=0, user="bob", day="Sep 27", hour="10"):
    return [ev("failed", user, ip, f"{day} {hour}:{start_minute + i:02d}:00") for i in range(n)]


# ---------- parsing ----------
class TestParsing:
    def test_failed_password(self, tmp_path):
        events = ls.parse_log(write_log(tmp_path, [fail_line("Sep 27 10:00:00", "bob", "1.2.3.4")]))
        assert len(events) == 1
        assert events[0]["type"] == "failed"
        assert events[0]["user"] == "bob"
        assert events[0]["ip"] == "1.2.3.4"

    def test_invalid_user_extracts_real_username(self, tmp_path):
        events = ls.parse_log(write_log(
            tmp_path, [fail_line("Sep 27 10:00:00", "admin", "1.2.3.4", invalid=True)]))
        assert events[0]["user"] == "admin"

    @pytest.mark.parametrize("method", ["password", "publickey", "keyboard-interactive/pam"])
    def test_accepted_any_method(self, tmp_path, method):
        events = ls.parse_log(write_log(
            tmp_path, [ok_line("Sep 27 10:00:00", "bob", "1.2.3.4", method)]))
        assert len(events) == 1 and events[0]["type"] == "accepted"

    def test_ipv6_address(self, tmp_path):
        events = ls.parse_log(write_log(
            tmp_path, [fail_line("Sep 27 10:00:00", "bob", "2001:db8::1")]))
        assert events[0]["ip"] == "2001:db8::1"

    def test_unrelated_and_malformed_lines_ignored(self, tmp_path):
        lines = [
            "Sep 27 10:00:00 host CRON[1]: pam_unix(cron:session): session opened",
            "this is not a log line at all",
            "",
            "Sep 27 10:00:00 host sshd[100]: Failed password for",   # truncated
        ]
        assert ls.parse_log(write_log(tmp_path, lines)) == []

    def test_impossible_date_does_not_crash(self, tmp_path):
        """Regression: 'Feb 31' is never valid and used to raise ValueError."""
        lines = [fail_line("Feb 31 10:00:00", "bob", "1.2.3.4"),
                 fail_line("Sep 27 10:00:00", "bob", "1.2.3.4")]
        events = ls.parse_log(write_log(tmp_path, lines))
        assert len(events) == 1  # bad line skipped, good line kept

    def test_parse_time_returns_none_for_bad_date(self):
        assert ls.parse_time("Feb 31 10:00:00") is None

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ls.parse_log("does_not_exist.log")


# ---------- brute force ----------
class TestBruteForce:
    def test_below_threshold_no_alert(self):
        assert ls.detect_brute_force(failures("1.1.1.1", 4), threshold=5, window_minutes=10) == []

    def test_at_threshold_alerts(self):
        alerts = ls.detect_brute_force(failures("1.1.1.1", 5), threshold=5, window_minutes=10)
        assert len(alerts) == 1
        assert alerts[0]["ip"] == "1.1.1.1"
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["mitre"].startswith("T1110")

    def test_failures_spread_outside_window_no_alert(self):
        # 5 failures, each 20 minutes apart, with a 10 minute window
        events = [ev("failed", "bob", "1.1.1.1", f"Sep 27 10:{m:02d}:00") for m in (0, 20, 40)] + \
                 [ev("failed", "bob", "1.1.1.1", f"Sep 27 11:{m:02d}:00") for m in (0, 20)]
        assert ls.detect_brute_force(events, threshold=5, window_minutes=10) == []

    def test_window_boundary_is_inclusive(self):
        # 5 failures exactly 10 minutes from first to last: the code counts this as inside
        events = [ev("failed", "bob", "1.1.1.1", f"Sep 27 10:{m:02d}:00") for m in (0, 2, 4, 6, 10)]
        assert len(ls.detect_brute_force(events, 5, 10)) == 1

    def test_one_second_past_window_no_alert(self):
        events = [ev("failed", "bob", "1.1.1.1", f"Sep 27 10:{m:02d}:00") for m in (0, 2, 4, 6)]
        events.append(ev("failed", "bob", "1.1.1.1", "Sep 27 10:10:01"))
        assert ls.detect_brute_force(events, 5, 10) == []

    def test_ips_are_not_combined(self):
        events = failures("1.1.1.1", 3) + failures("2.2.2.2", 3)
        assert ls.detect_brute_force(events, 5, 10) == []

    def test_unsorted_input_is_handled(self):
        events = list(reversed(failures("1.1.1.1", 5)))
        assert len(ls.detect_brute_force(events, 5, 10)) == 1

    def test_accepted_logins_not_counted(self):
        events = failures("1.1.1.1", 4) + [ev("accepted", "bob", "1.1.1.1", "Sep 27 10:05:00")]
        assert ls.detect_brute_force(events, 5, 10) == []

    @pytest.mark.xfail(strict=True, reason="KNOWN LIMITATION: syslog has no year, so "
                       "events across New Year are ordered wrongly (Jan before Dec)")
    def test_attack_across_new_year(self):
        events = [ev("failed", "bob", "9.9.9.9", f"Dec 31 23:5{i}:00") for i in range(5)] + \
                 [ev("failed", "bob", "9.9.9.9", f"Jan 01 00:0{i}:00") for i in range(5)]
        # 10 failures within ~10 minutes should be caught at threshold 10
        assert len(ls.detect_brute_force(events, threshold=10, window_minutes=15)) == 1


# ---------- success after failures ----------
class TestCompromise:
    def test_success_after_threshold_failures_is_critical(self):
        events = failures("3.3.3.3", 5) + [ev("accepted", "ubuntu", "3.3.3.3", "Sep 27 10:30:00")]
        alerts = ls.detect_success_after_failures(events, threshold=5)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "CRITICAL"
        assert "ubuntu" in alerts[0]["details"]
        assert alerts[0]["mitre"].startswith("T1078")

    def test_below_threshold_no_alert(self):
        events = failures("3.3.3.3", 4) + [ev("accepted", "ubuntu", "3.3.3.3", "Sep 27 10:30:00")]
        assert ls.detect_success_after_failures(events, 5) == []

    def test_success_before_failures_no_alert(self):
        events = [ev("accepted", "ubuntu", "3.3.3.3", "Sep 27 09:00:00")] + failures("3.3.3.3", 8)
        assert ls.detect_success_after_failures(events, 5) == []

    def test_reported_once_per_ip(self):
        events = failures("3.3.3.3", 5) + [
            ev("accepted", "ubuntu", "3.3.3.3", "Sep 27 10:30:00"),
            ev("accepted", "ubuntu", "3.3.3.3", "Sep 27 10:35:00"),
        ]
        assert len(ls.detect_success_after_failures(events, 5)) == 1

    def test_different_ip_success_not_flagged(self):
        events = failures("3.3.3.3", 8) + [ev("accepted", "ubuntu", "4.4.4.4", "Sep 27 10:30:00")]
        assert ls.detect_success_after_failures(events, 5) == []

    @pytest.mark.xfail(strict=True, reason="KNOWN LIMITATION: failures are counted forever, "
                       "so 5 typos over 4 weeks cause a false CRITICAL alert")
    def test_old_scattered_failures_should_not_be_critical(self):
        days = (1, 8, 15, 22, 27)
        events = [ev("failed", "bob", "8.8.8.8", f"Sep {d:02d} 10:00:00") for d in days]
        events.append(ev("accepted", "bob", "8.8.8.8", "Sep 27 11:00:00"))
        assert ls.detect_success_after_failures(events, 5) == []


# ---------- root attempts ----------
class TestRoot:
    def test_failed_root_flagged(self):
        events = [ev("failed", "root", "5.5.5.5", "Sep 27 10:00:00")] * 3
        alerts = ls.detect_root_attempts(events)
        assert len(alerts) == 1 and "3 failed" in alerts[0]["details"]

    def test_non_root_not_flagged(self):
        assert ls.detect_root_attempts(failures("5.5.5.5", 5, user="bob")) == []

    @pytest.mark.xfail(strict=True, reason="KNOWN LIMITATION: a SUCCESSFUL root login is not "
                       "flagged at all, which is more serious than a failed one")
    def test_successful_root_login_should_alert(self):
        assert ls.detect_root_attempts([ev("accepted", "root", "6.6.6.6", "Sep 27 10:00:00")])

    @pytest.mark.xfail(strict=True, reason="KNOWN LIMITATION: a single root typo already "
                       "raises a MEDIUM alert (noisy)")
    def test_single_root_typo_should_not_alert(self):
        assert ls.detect_root_attempts([ev("failed", "root", "5.5.5.5", "Sep 27 10:00:00")]) == []


# ---------- username enumeration ----------
class TestEnumeration:
    def test_many_usernames_flagged(self):
        events = [ev("failed", u, "7.7.7.7", f"Sep 27 10:0{i}:00")
                  for i, u in enumerate(["admin", "test", "oracle", "guest"])]
        alerts = ls.detect_user_enumeration(events)
        assert len(alerts) == 1 and "4 usernames" in alerts[0]["details"]

    def test_two_usernames_not_flagged(self):
        events = [ev("failed", u, "7.7.7.7", f"Sep 27 10:0{i}:00")
                  for i, u in enumerate(["a", "b"])]
        assert ls.detect_user_enumeration(events) == []

    def test_repeated_same_username_not_flagged(self):
        assert ls.detect_user_enumeration(failures("7.7.7.7", 10, user="admin")) == []

    @pytest.mark.xfail(strict=True, reason="KNOWN LIMITATION: counts valid usernames too, so "
                       "3 real users behind one NAT look like enumeration")
    def test_three_valid_users_behind_nat_should_not_alert(self):
        events = [ev("failed", u, "5.5.5.5", f"Sep 27 10:0{i}:00")
                  for i, u in enumerate(["alice", "bob", "carol"])]
        assert ls.detect_user_enumeration(events) == []


# ---------- reports ----------
class TestReports:
    ALERT = {"severity": "HIGH", "rule": "Brute-force attack", "ip": "1.1.1.1",
             "details": "5 failed logins", "mitre": "T1110 - Brute Force"}

    def test_json_and_csv_written(self, tmp_path):
        prefix = str(tmp_path / "report")
        ls.save_reports([self.ALERT], prefix)
        assert json.load(open(prefix + ".json", encoding="utf-8")) == [self.ALERT]
        rows = list(csv.DictReader(open(prefix + ".csv", encoding="utf-8")))
        assert rows[0]["ip"] == "1.1.1.1" and rows[0]["severity"] == "HIGH"


# ---------- summary (new feature) ----------
class TestSummary:
    def test_no_alerts(self):
        text = ls.build_summary(failures("1.1.1.1", 2), [])
        assert "No suspicious activity" in text

    def test_overall_severity_is_the_worst(self):
        alerts = [
            {**TestReports.ALERT},
            {"severity": "CRITICAL", "rule": "Possible account compromise", "ip": "2.2.2.2",
             "details": "x", "mitre": "T1078 - Valid Accounts"},
        ]
        text = ls.build_summary(failures("1.1.1.1", 2), alerts)
        assert "Overall severity: CRITICAL" in text
        assert text.index("2.2.2.2") < text.index("1.1.1.1")  # CRITICAL listed first

    def test_contains_recommended_action_per_rule_once(self):
        alerts = [TestReports.ALERT, {**TestReports.ALERT, "ip": "9.9.9.9"}]
        text = ls.build_summary(failures("1.1.1.1", 2), alerts)
        assert text.count("**Brute-force attack:**") == 1

    def test_save_summary_writes_file(self, tmp_path):
        prefix = str(tmp_path / "rep")
        ls.save_summary(failures("1.1.1.1", 2), [TestReports.ALERT], prefix)
        assert os.path.exists(prefix + "_summary.md")


# ---------- end to end ----------
def test_end_to_end_cli(tmp_path, monkeypatch, capsys):
    lines = [fail_line(f"Sep 27 10:0{i}:00", "root", "203.0.113.45") for i in range(6)]
    lines += [ok_line("Sep 27 10:30:00", "ubuntu", "203.0.113.45")]
    log = write_log(tmp_path, lines)
    out = str(tmp_path / "out")
    argv = ["log_sentinel.py", "--file", log, "--output", out, "--summary"]
    monkeypatch.setattr(sys, "argv", argv)
    ls.main()
    printed = capsys.readouterr().out
    assert "CRITICAL" in printed and "203.0.113.45" in printed
    assert os.path.exists(out + ".json") and os.path.exists(out + "_summary.md")
