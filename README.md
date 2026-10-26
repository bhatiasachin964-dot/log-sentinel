# LogSentinel 🛡️

[![Tests](https://github.com/bhatiasachin964-dot/log-sentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/bhatiasachin964-dot/log-sentinel/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A Python tool that analyses Linux SSH authentication logs (`/var/log/auth.log`) and detects signs of attack, mapped to the MITRE ATT&CK framework. Think of it as a tiny version of what a SIEM (like Splunk) does in a Security Operations Centre.

Built by a Technical Support Engineer who spends his days reading production logs, so the rules are based on what actually shows up in incident tickets.

## What It Detects

| Severity | Rule | What it means | MITRE ATT&CK |
|---|---|---|---|
| CRITICAL | Possible account compromise | An IP failed many times, then logged in successfully | T1078 |
| HIGH | Brute-force attack | Many failed logins from one IP within a short time window | T1110 |
| MEDIUM | Direct root login attempt | Someone tried to log in as `root` | T1110.001 |
| MEDIUM | Possible password spraying | One IP failed logins across many different usernames | T1110.003 |

The spraying rule flags the pattern MITRE ATT&CK's detection strategy for T1110.003 describes: authentication failures across many accounts. SSH logs don't record which password was tried, so it can't be told apart from credential stuffing (T1110.004), which is why the alert says "possible".

## Features
- Parses real Linux SSH logs using regular expressions
- Sliding time-window detection for brute-force attacks
- Colour-coded severity report in the terminal
- Exports alerts to **JSON** and **CSV** for further analysis
- Suggests firewall (`ufw`) block commands for high-risk IPs
- `--summary` writes a plain-English Markdown incident summary (rule-based, generated only from the data)
- No external libraries, only the Python standard library

## How to Run
Requires Python 3.8+.

```
python log_sentinel.py --file sample_auth.log
```

Options:
```
--file       Path to the log file (default: sample_auth.log)
--threshold  Failed logins that count as brute force (default: 5)
--window     Time window in minutes (default: 10)
--output     Report file name without extension (default: security_report)
--summary    Also write <output>_summary.md, a plain-English incident summary
```

To analyse a real Linux server's log:
```
sudo python3 log_sentinel.py --file /var/log/auth.log
```

## Sample Output
```
[CRITICAL] Possible account compromise  ->  198.51.100.77
    Logged in as 'ubuntu' at Sep 27 13:05:12 after 9 failed attempts
    MITRE ATT&CK: T1078 - Valid Accounts

[HIGH] Brute-force attack  ->  203.0.113.45
    18 failed logins (peak 18 within 10 min, first seen Sep 27 10:14)
    MITRE ATT&CK: T1110 - Brute Force
```

## About the Sample Log
`sample_auth.log` is a synthetic log containing normal user activity plus three simulated attackers. The attacker IPs use reserved documentation ranges (RFC 5737), so they are not real addresses.

## Testing
```
pip install -r requirements-dev.txt
pytest -v
```
50 tests cover parsing, each detection rule (including threshold and time-window boundaries), report export, the `--summary` output and an end-to-end CLI run. GitHub Actions runs them on Python 3.9 and 3.12, plus a smoke test on the sample log and a `ruff` lint check, on every push.

A further 5 tests in `tests/test_edge_cases.py` are marked `xfail(strict=True)`: they describe the *desired* behaviour for the known limitations below, so they will start failing the moment a limitation is fixed and remind me to remove the marker.

## Known Limitations
Each of these is demonstrated by an `xfail` test in `tests/`.
- **No year in syslog timestamps.** The current year is assumed, so an attack spanning New Year is ordered wrongly and can be missed.
- **Compromise rule has no time window.** Failures are counted forever, so a few typos over several weeks followed by a login raises a false CRITICAL alert.
- **Successful root logins are not flagged.** Only failed root attempts are, and a single typo already raises MEDIUM, which is noisy.
- **The password-spraying rule counts valid usernames too.** Several real users behind one NAT can look like spraying.
- Rotated or compressed logs (`auth.log.1`, `.gz`) are not read automatically.

## How I Built This with AI
I used Claude (free tier) as a reviewer and pair programmer, not as an author I trusted blindly. Every suggestion was run, tested or checked against the raw log or the MITRE ATT&CK site before it went into the code.

See [AI_NOTES.md](AI_NOTES.md) for what I asked, where the AI was right, where it was wrong, and how I caught it.

## What I Learned
- How SSH authentication logs are structured on Linux
- Writing detection rules and tuning thresholds to reduce false positives
- Mapping detections to MITRE ATT&CK techniques
- Incident response basics: detect, triage by severity, recommend containment
- Verifying AI-generated code and claims instead of trusting them
