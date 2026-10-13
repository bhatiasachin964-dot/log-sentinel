# LogSentinel 🛡️

A Python tool that analyses Linux SSH authentication logs (`/var/log/auth.log`) and detects signs of attack, mapped to the MITRE ATT&CK framework. Think of it as a tiny version of what a SIEM (like Splunk) does in a Security Operations Centre.

## What It Detects

| Severity | Rule | What it means | MITRE ATT&CK |
|---|---|---|---|
| CRITICAL | Possible account compromise | An IP failed many times, then logged in successfully | T1078 |
| HIGH | Brute-force attack | Many failed logins from one IP within a short time window | T1110 |
| MEDIUM | Direct root login attempt | Someone tried to log in as `root` | T1110.001 |
| MEDIUM | Username enumeration | One IP guessed many different usernames | T1110.003 |

## Features
- Parses real Linux SSH logs using regular expressions
- Sliding time-window detection for brute-force attacks
- Colour-coded severity report in the terminal (`--no-color` for logs/CI)
- Reads **gzip'ed** logs (`auth.log.1.gz`) transparently — no extra step for logrotate output
- Machine-readable **JSON** output that pipes cleanly into `jq` or cron
- Exports alerts to **JSON** and **CSV** for further analysis
- Suggests firewall (`ufw`) block commands for high-risk IPs
- Pins the log's year with `--year` so stored logs analyse deterministically
- No external libraries, only the Python standard library

## How to Run
Requires Python 3.8+.

```
python log_sentinel.py --file sample_auth.log
sudo python3 -m log_sentinel --file /var/log/auth.log --output /var/tmp/ssh-report
```

Install as a command (optional): `pip install .`, then use `log-sentinel ...` with the same flags.

### Options

| Flag | Default | Description |
|---|---|---|
| `--file` | `sample_auth.log` | Path to the auth log (`.gz` auto-detected) |
| `--threshold` | `5` | Failed logins that count as brute force (and as pre-compromise) |
| `--window` | `10` | Time window in minutes for the brute-force burst |
| `--min-users` | `3` | Usernames an IP must try to count as enumeration |
| `--output` | `security_report` | Report file name (no extension); parent dirs are created |
| `--year` | *(current)* | Stamp the un-dated syslog timestamps with this year |
| `--json` | off | Print one machine-readable JSON report to stdout (no colour report) |
| `--no-color` | off | Disable ANSI colour codes (clean for files/CI) |
| `--version` | — | Print the version and exit |

### Examples

Analyse a single file, then pipe just the alerts through `jq`:

```bash
python log_sentinel.py --file /var/log/auth.log --json | jq .alerts
```

Handle a compressed rotation and write reports to a nested directory:

```bash
sudo python log_sentinel.py --file /var/log/auth.log.1.gz --output /var/tmp/ssh/report
```

Script it (drop-in for cron):

```python
from log_sentinel import parse_log, detect_brute_force

events = parse_log("/var/log/auth.log")
alerts = detect_brute_force(events, threshold=5, window_minutes=10)
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

## Development / Testing

The detection logic is pure and fully offline — no network, sudo, or real logs
needed to test it.

```bash
python -m pytest tests/ -v
ruff check log_sentinel.py tests/
```

## About the Sample Log

`sample_auth.log` is a synthetic log containing normal user activity plus three simulated attackers. The attacker IPs use reserved documentation ranges (RFC 5737), so they are not real addresses.

## What I Learned
- How SSH authentication logs are structured on Linux
- Writing detection rules and tuning thresholds to reduce false positives
- Mapping detections to MITRE ATT&CK techniques
- Incident response basics: detect, triage by severity, recommend containment