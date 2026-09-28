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
- Colour-coded severity report in the terminal
- Exports alerts to **JSON** and **CSV** for further analysis
- Suggests firewall (`ufw`) block commands for high-risk IPs
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

## What I Learned
- How SSH authentication logs are structured on Linux
- Writing detection rules and tuning thresholds to reduce false positives
- Mapping detections to MITRE ATT&CK techniques
- Incident response basics: detect, triage by severity, recommend containment
