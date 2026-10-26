"""Command-line tests: exit codes, error messages and option handling."""
import sys

import pytest

import log_sentinel as ls


def failed_line(ts, user, ip):
    return f"{ts} server sshd[1234]: Failed password for {user} from {ip} port 22 ssh2"


def accepted_line(ts, user, ip):
    return f"{ts} server sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2"


def write_log(tmp_path, lines):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["log_sentinel.py", *args])
    ls.main()


def test_clean_log_reports_no_suspicious_activity(tmp_path, monkeypatch, capsys):
    log = write_log(tmp_path, [accepted_line("Sep 27 10:00:00", "alice", "198.51.100.7")])
    out = tmp_path / "out"
    run_cli(monkeypatch, "--file", log, "--output", str(out))
    assert "No suspicious activity detected" in capsys.readouterr().out
    # No alerts means no report files should be written
    assert not (tmp_path / "out.json").exists()
    assert not (tmp_path / "out.csv").exists()


def test_missing_file_exits_with_code_1_and_clear_message(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "--file", str(tmp_path / "missing.log"))
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().out


def test_unreadable_file_exits_with_code_1_and_suggests_sudo(monkeypatch, capsys):
    def deny(path):
        raise PermissionError(path)

    monkeypatch.setattr(ls, "parse_log", deny)
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "--file", "auth.log")
    assert exc.value.code == 1
    printed = capsys.readouterr().out
    assert "no permission" in printed
    assert "sudo" in printed


def test_threshold_option_controls_brute_force_detection(tmp_path, monkeypatch, capsys):
    # Four quick failures from one IP: below the default threshold of 5
    lines = [failed_line(f"Sep 27 10:00:{s:02d}", "admin", "203.0.113.9") for s in range(0, 40, 10)]
    log = write_log(tmp_path, lines)
    out = str(tmp_path / "out")

    run_cli(monkeypatch, "--file", log, "--output", out)
    assert "Brute-force attack" not in capsys.readouterr().out

    run_cli(monkeypatch, "--file", log, "--output", out, "--threshold", "3")
    assert "Brute-force attack" in capsys.readouterr().out


def test_window_option_controls_brute_force_detection(tmp_path, monkeypatch, capsys):
    # Five failures, three minutes apart: 12 minutes from first to last
    lines = [failed_line(f"Sep 27 10:{m:02d}:00", "admin", "203.0.113.9") for m in range(0, 15, 3)]
    log = write_log(tmp_path, lines)
    out = str(tmp_path / "out")

    run_cli(monkeypatch, "--file", log, "--output", out)  # default window: 10 minutes
    assert "Brute-force attack" not in capsys.readouterr().out

    run_cli(monkeypatch, "--file", log, "--output", out, "--window", "15")
    assert "Brute-force attack" in capsys.readouterr().out


def test_summary_is_only_written_when_requested(tmp_path, monkeypatch):
    lines = [failed_line(f"Sep 27 10:00:{s:02d}", "admin", "203.0.113.9") for s in range(6)]
    log = write_log(tmp_path, lines)
    out = str(tmp_path / "out")

    run_cli(monkeypatch, "--file", log, "--output", out)
    assert not (tmp_path / "out_summary.md").exists()

    run_cli(monkeypatch, "--file", log, "--output", out, "--summary")
    assert (tmp_path / "out_summary.md").exists()
