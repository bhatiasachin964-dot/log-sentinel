# SSH Security Incident Summary

Analysed 47 SSH events (34 failed logins, 13 successful logins) from 6 source IPs.

**Overall severity: CRITICAL.** Alerts raised: 6 (1 CRITICAL, 2 HIGH, 3 MEDIUM).

## Alerts

| Severity | Rule | Source IP | Details | MITRE ATT&CK |
|---|---|---|---|---|
| CRITICAL | Possible account compromise | 198.51.100.77 | Logged in as 'ubuntu' at Sep 27 13:05:12 after 9 failed attempts | T1078 - Valid Accounts |
| HIGH | Brute-force attack | 203.0.113.45 | 18 failed logins (peak 18 within 10 min, first seen Sep 27 10:14) | T1110 - Brute Force |
| HIGH | Brute-force attack | 198.51.100.77 | 9 failed logins (peak 9 within 10 min, first seen Sep 27 13:03) | T1110 - Brute Force |
| MEDIUM | Direct root login attempt | 192.0.2.200 | 3 failed login(s) as root | T1110.001 - Password Guessing |
| MEDIUM | Direct root login attempt | 203.0.113.45 | 18 failed login(s) as root | T1110.001 - Password Guessing |
| MEDIUM | Possible password spraying | 198.51.100.77 | Tried 6 usernames: admin, ftpuser, guest, oracle, test, ubuntu | T1110.003 - Password Spraying |

## Recommended actions

- **Possible account compromise:** Treat as an incident: check the account's activity, rotate its credentials and review the source IP.
- **Brute-force attack:** Review and consider blocking the source IP; enable key-only login or fail2ban.
- **Direct root login attempt:** Disable direct root login over SSH (PermitRootLogin no).
- **Possible password spraying:** Check whether any targeted usernames are real accounts and enforce key-only SSH login; review the source IP.

_Automated rule-based summary. Verify against the raw log before taking action._
