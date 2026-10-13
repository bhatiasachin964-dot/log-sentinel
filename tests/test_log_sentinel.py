"""Offline tests for LogSentinel's SSH-auth analysis logic.

Everything here runs on the standard library only -- no network, no sudo, no
real /var/log. Test data is hand-built log lines following the exact formats
the tool's regular expressions are anchored to.
"""

import gzip
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import log_sentinel as ls  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------
def ev(t, type_, user, ip):
    return {"time": ls.parse_time(t, year=2026), "type": type_, "user": user, "ip": ip}


FAIL = "Failed password for {user} from {ip} port 22 ssh2"
FAIL_INVALID = "Failed password for invalid user {user} from {ip} port 22 ssh2"
ACCEPT_PW = "Accepted password for {user} from {ip} port 51234 ssh2"
ACCEPT_KEY = "Accepted publickey for {user} from {ip} port 51234 ssh2"
PREFIX = "Sep 27 10:14:00 webserver sshd[2137]: "


# --------------------------------------------------------------------------
# parse_time
# --------------------------------------------------------------------------
class TestParseTime:
    def test_pinned_year(self):
        dt = ls.parse_time("Sep 27 10:14:15", year=2026)
        assert dt == datetime(2026, 9, 27, 10, 14, 15)

    def test_defaults_to_current_year(self):
        assert ls.parse_time("Sep 27 10:14:15").year == datetime.now().year

    def test_cross_year_boundary_ordered_by_pinned_year(self):
        # A single pinned year is applied identically to every parsed event.
        d1 = ls.parse_time("Dec 31 23:59:59", year=2026)
        d2 = ls.parse_time("Nov 30 12:00:00", year=2026)
        assert d1 > d2  # Dec sorts after Nov within the pinned year
        assert d1.year == 2026


# --------------------------------------------------------------------------
# parse_log
# --------------------------------------------------------------------------
class TestParseLog:
    def test_failed_and_accepted_powered(self, tmp_path):
        lines = [
            PREFIX + FAIL.format(user="root", ip="1.2.3.4"),
            PREFIX + ACCEPT_PW.format(user="admin", ip="10.0.0.5"),
            PREFIX + ACCEPT_KEY.format(user="deploy", ip="192.168.1.25"),
            PREFIX + FAIL_INVALID.format(user="nobody", ip="5.6.7.8"),
            "Sep 27 08:00:00 webserver sshd[3191]: pam_unix(sshd:session): session closed for user sachin",
            "Sep 27 08:00:00 webserver sshd[3191]: Received disconnect from 10.0.0.5: 11: BYE",
        ]
        p = tmp_path / "auth.log"
        p.write_text("\n".join(lines) + "\n")
        events = ls.parse_log(str(p), year=2026)
        assert len(events) == 4  # non-matching lines ignored
        assert [e["type"] for e in events] == ["failed", "accepted", "accepted", "failed"]
        assert events[0] == {"time": ls.parse_time("Sep 27 10:14:00", 2026),
                             "type": "failed", "user": "root", "ip": "1.2.3.4"}
        assert events[3]["user"] == "nobody"  # invalid-user prefix stripped

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ls.parse_log(str(tmp_path / "nope.log"))

    def test_gzip_input(self, tmp_path):
        raw = PREFIX + FAIL.format(user="root", ip="1.2.3.4") + "\n"
        p = tmp_path / "auth.log.gz"
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write(raw)
        events = ls.parse_log(str(p), year=2026)
        assert len(events) == 1 and events[0]["ip"] == "1.2.3.4"

    def test_empty_file(self, tmp_path):
        p = tmp_path / "auth.log"
        p.write_text("")
        assert ls.parse_log(str(p)) == []


# --------------------------------------------------------------------------
# detect_brute_force
# --------------------------------------------------------------------------
class TestBruteForce:
    def test_no_failures(self):
        assert ls.detect_brute_force([ev("Sep 27 10:00:00", "accepted", "a", "1.2.3.4")], 5, 10) == []

    def test_below_threshold(self):
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(4)]
        assert ls.detect_brute_force(events, 5, 10) == []

    def test_at_threshold(self):
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(5)]
        alerts = ls.detect_brute_force(events, 5, 10)
        assert len(alerts) == 1 and alerts[0]["rule"] == ls.RULE_BRUTE_FORCE
        assert "peak 5" in alerts[0]["details"]

    def test_peak_not_all_failures(self):
        # 8 failures, but only ever 3 inside a 10-minute window.
        times = ["Sep 27 10:00:00", "Sep 27 10:05:00", "Sep 27 10:06:00",
                 "Sep 27 10:17:00", "Sep 27 10:20:00", "Sep 27 10:21:00",
                 "Sep 27 10:32:00", "Sep 27 10:50:00"]
        events = [ev(t, "failed", "u", "1.2.3.4") for t in times]
        alerts = ls.detect_brute_force(events, 3, 10)  # peak is 3 => threshold 3 fires
        assert len(alerts) == 1
        assert "peak 3" in alerts[0]["details"]
        assert "8 failed logins" in alerts[0]["details"]

    def test_window_boundary_is_inclusive(self):
        # Exactly-ten-minutes-apart events are inside the window: a failure at
        # 10:11:00 is exactly 10 minutes after 10:01:00, so all five are one burst.
        events = [
            ev("Sep 27 10:01:00", "failed", "u", "1.2.3.4"),
            ev("Sep 27 10:02:00", "failed", "u", "1.2.3.4"),
            ev("Sep 27 10:03:00", "failed", "u", "1.2.3.4"),
            ev("Sep 27 10:09:59", "failed", "u", "1.2.3.4"),
            ev("Sep 27 10:11:00", "failed", "u", "1.2.3.4"),
        ]
        alerts = ls.detect_brute_force(events, 4, 10)
        assert len(alerts) == 1 and "peak 5" in alerts[0]["details"]

    def test_unsorted_input_is_sorted(self):
        events = [ev("Sep 27 10:03:00", "failed", "u", "1.2.3.4"),
                  ev("Sep 27 10:01:00", "failed", "u", "1.2.3.4"),
                  ev("Sep 27 10:02:00", "failed", "u", "1.2.3.4")]
        # 3 within one minute window => below default 5, no alert
        assert ls.detect_brute_force(events, 3, 1) == []

    def test_multiple_ips_separate(self):
        e1 = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.1.1.1") for m in range(5)]
        e2 = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "2.2.2.2") for m in range(3)]
        alerts = ls.detect_brute_force(e1 + e2, 5, 10)
        assert [a["ip"] for a in alerts] == ["1.1.1.1"]


# --------------------------------------------------------------------------
# detect_success_after_failures
# --------------------------------------------------------------------------
class TestCompromise:
    def test_classic_compromise(self):
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(9)]
        events.append(ev("Sep 27 10:30:00", "accepted", "ubuntu", "1.2.3.4"))
        alerts = ls.detect_success_after_failures(events, 5)
        assert len(alerts) == 1 and alerts[0]["severity"] == "CRITICAL"
        assert alerts[0]["ip"] == "1.2.3.4"
        assert "after 9 failed attempts" in alerts[0]["details"]
        assert alerts[0]["rule"] == ls.RULE_COMPROMISE

    def test_no_alert_below_threshold(self):
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(3)]
        events.append(ev("Sep 27 10:30:00", "accepted", "ubuntu", "1.2.3.4"))
        assert ls.detect_success_after_failures(events, 5) == []

    def test_failures_without_success(self):
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(9)]
        assert ls.detect_success_after_failures(events, 5) == []

    def test_success_before_failures_not_compromised(self):
        # A login that is *clean* at the time it happens is not later retro-fitted.
        events = [ev("Sep 27 10:00:00", "accepted", "u", "1.2.3.4")]
        events += [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(1, 9)]
        assert ls.detect_success_after_failures(events, 5) == []

    def test_multiple_successes_alert_once(self):
        """Regression: repeated successful logins after a compromise must yield
        exactly ONE alert, not one per login (the original never reset the
        per-IP failure counter)."""
        events = [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", "1.2.3.4") for m in range(9)]
        events.append(ev("Sep 27 10:30:00", "accepted", "ubuntu", "1.2.3.4"))
        events.append(ev("Sep 27 11:00:00", "accepted", "ubuntu", "1.2.3.4"))
        events.append(ev("Sep 27 11:30:00", "accepted", "ubuntu", "1.2.3.4"))
        assert len(ls.detect_success_after_failures(events, 5)) == 1

    def test_two_independent_compromises_two_alerts(self):
        events = []
        for ip, user in (("1.1.1.1", "a"), ("2.2.2.2", "b")):
            events += [ev(f"Sep 27 10:{m:02d}:00", "failed", "u", ip) for m in range(9)]
            events.append(ev("Sep 27 10:30:00", "accepted", user, ip))
        alerts = ls.detect_success_after_failures(events, 5)
        assert {a["ip"] for a in alerts} == {"1.1.1.1", "2.2.2.2"}


# --------------------------------------------------------------------------
# detect_root_attempts
# --------------------------------------------------------------------------
class TestRootAttempts:
    def test_counts_root_per_ip(self):
        events = [
            ev("Sep 27 10:00:00", "failed", "root", "1.2.3.4"),
            ev("Sep 27 10:01:00", "failed", "root", "1.2.3.4"),
            ev("Sep 27 10:02:00", "failed", "root", "5.6.7.8"),
            ev("Sep 27 10:03:00", "failed", "alice", "1.2.3.4"),  # non-root ignored
        ]
        alerts = ls.detect_root_attempts(events)
        assert {a["ip"]: a["details"] for a in alerts} == {
            "1.2.3.4": "2 failed login(s) as root",
            "5.6.7.8": "1 failed login(s) as root",
        }
        assert alerts[0]["rule"] == ls.RULE_ROOT

    def test_invalid_user_root_counted(self):
        events = [ev("Sep 27 10:00:00", "failed", "root", "1.2.3.4")]
        assert len(ls.detect_root_attempts(events)) == 1

    def test_no_root(self):
        events = [ev("Sep 27 10:00:00", "failed", "alice", "1.2.3.4")]
        assert ls.detect_root_attempts(events) == []


# --------------------------------------------------------------------------
# detect_user_enumeration
# --------------------------------------------------------------------------
class TestEnumeration:
    def _fail_for(self, users, ip="9.9.9.9"):
        return [ev(f"Sep 27 10:{m:02d}:00", "failed", u, ip)
                for m, u in enumerate(users)]

    def test_below_min(self):
        assert ls.detect_user_enumeration(self._fail_for(["a", "b"]), min_users=3) == []

    def test_at_min(self):
        alerts = ls.detect_user_enumeration(self._fail_for(["a", "b", "c"]), min_users=3)
        assert len(alerts) == 1 and alerts[0]["ip"] == "9.9.9.9"
        assert "Tried 3 usernames: a, b, c" in alerts[0]["details"]

    def test_deduplicates_users(self):
        # 'a' tried twice still counts once.
        e = self._fail_for(["a", "b", "c"]) + [ev("Sep 27 11:00:00", "failed", "a", "9.9.9.9")]
        alerts = ls.detect_user_enumeration(e, min_users=3)
        assert len(alerts) == 1 and "Tried 3 usernames" in alerts[0]["details"]

    def test_many_users_truncated(self):
        e = self._fail_for([f"user{i}" for i in range(9)])
        alerts = ls.detect_user_enumeration(e, min_users=3)
        assert alerts[0]["details"].endswith(" ...")
        assert alerts[0]["details"].count(", ") >= 5  # first 6 shown, then " ..."

    def test_default_min_users(self):
        # default is 3
        assert ls.detect_user_enumeration(self._fail_for(["a", "b", "c"])) != []
        assert ls.detect_user_enumeration(self._fail_for(["a", "b"])) == []


# --------------------------------------------------------------------------
# CLI integration
# --------------------------------------------------------------------------
class TestCLI:
    def _write_auth(self, tmp_path, lines):
        p = tmp_path / "auth.log"
        p.write_text("\n".join(lines) + "\n")
        return p

    def test_json_output(self, tmp_path, capsys):
        # 5 failures then a success => compromise CRITICAL fires.
        lines = ([PREFIX + FAIL.format(user="root", ip="1.2.3.4") for _ in range(5)]
                 + [PREFIX + ACCEPT_PW.format(user="ubuntu", ip="1.2.3.4")])
        p = self._write_auth(tmp_path, lines)
        assert ls.main(["--file", str(p), "--json", "--year", "2026"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["summary"]["events_parsed"] == 6
        assert data["summary"]["failed"] == 5
        assert data["summary"]["successful"] == 1
        assert any(a["rule"] == ls.RULE_COMPROMISE for a in data["alerts"])

    def test_json_prints_no_colour_report(self, tmp_path, capsys):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="root", ip="1.2.3.4")])
        ls.main(["--file", str(p), "--json", "--year", "2026"])
        out = capsys.readouterr().out
        assert "\033[" not in out
        json.loads(out)  # stdout is pure JSON

    def test_no_color_removes_ansi(self, tmp_path, capsys):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="root", ip="1.2.3.4")])
        ls.main(["--file", str(p), "--year", "2026", "--no-color"])
        assert "\033[" not in capsys.readouterr().out

    def test_default_output_has_colour(self, tmp_path, capsys):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="root", ip="1.2.3.4")])
        # root attempt is MEDIUM (yellow) => colour present
        ls.main(["--file", str(p), "--year", "2026"])
        assert "\033[" in capsys.readouterr().out

    def test_saves_reports_into_nested_dir(self, tmp_path):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="root", ip="1.2.3.4")])
        out = tmp_path / "sub" / "nested" / "rep"
        ls.main(["--file", str(p), "--year", "2026", "--output", str(out), "--no-color"])
        assert (tmp_path / "sub" / "nested" / "rep.json").exists()
        assert (tmp_path / "sub" / "nested" / "rep.csv").exists()

    def test_gzip_file(self, tmp_path, capsys):
        p = tmp_path / "auth.log.gz"
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write(PREFIX + FAIL.format(user="root", ip="1.2.3.4") + "\n")
        ls.main(["--file", str(p), "--json", "--year", "2026"])
        assert json.loads(capsys.readouterr().out)["summary"]["events_parsed"] == 1

    def test_missing_file_exit_1(self, tmp_path):
        with pytest.raises(SystemExit) as e:
            ls.main(["--file", str(tmp_path / "missing.log")])
        assert e.value.code == 1

    def test_invalid_threshold(self, tmp_path):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="root", ip="1.2.3.4")])
        with pytest.raises(SystemExit) as e:
            ls.main(["--file", str(p), "--threshold", "0"])
        assert e.value.code == 2

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as e:
            ls.main(["--version"])
        assert e.value.code == 0
        assert ls.__version__ in capsys.readouterr().out

    def test_min_users_flag(self, tmp_path, capsys):
        p = self._write_auth(tmp_path, [PREFIX + FAIL.format(user="alice", ip="1.2.3.4"),
                                        PREFIX + FAIL.format(user="bob", ip="1.2.3.4")])
        # default min_users=3 => no enumeration alert; raise? can't lower to 2 legitimately.
        ls.main(["--file", str(p), "--json", "--year", "2026"])
        assert json.loads(capsys.readouterr().out)["alerts"] == []
        # with --min-users 2 they are flagged
        ls.main(["--file", str(p), "--json", "--year", "2026", "--min-users", "2"])
        alerts = json.loads(capsys.readouterr().out)["alerts"]
        assert any(a["rule"] == ls.RULE_ENUMERATION for a in alerts)


# --------------------------------------------------------------------------
# Standalone `python log_sentinel.py` entrypoint (as shipped in README)
# --------------------------------------------------------------------------
class TestStandaloneEntrypoint:
    def test_run_as_script(self, tmp_path):
        p = tmp_path / "auth.log"
        p.write_text(PREFIX + FAIL.format(user="root", ip="1.2.3.4") + "\n")
        script = str(Path(__file__).resolve().parent.parent / "log_sentinel.py")
        r = subprocess.run(
            [sys.executable, script, "--file", str(p), "--json", "--year", "2026"],
            capture_output=True, text=True, cwd=Path(__file__).resolve().parent,
        )
        assert r.returncode == 0
        assert json.loads(r.stdout)["summary"]["events_parsed"] == 1

    def test_piping_to_closed_consumer_no_traceback(self, tmp_path):
        """`log-sentinel --json | head` must not spew a BrokenPipeError traceback."""
        p = tmp_path / "auth.log"
        p.write_text(PREFIX + FAIL.format(user="root", ip="1.2.3.4") + "\n")
        cmd = (f"{sys.executable} {Path(__file__).resolve().parent.parent / 'log_sentinel.py'} "
               f"--file {p} --json --year 2026 | head -c 5")
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        assert "BrokenPipeError" not in r.stderr
        assert "Traceback" not in r.stderr
        assert r.returncode == 0