# AI Notes: How I Used Claude on LogSentinel

**Tool:** Claude (free tier)  
**Date:** 23 October 2026

## 1. What I asked

| # | What I asked | Why |
|---|---|---|
| 1 | Review my code and README, fix the bugs and add tests | Find weaknesses I couldn't see myself |
| 2 | Add a `--summary` flag that writes a plain-English incident report | Practise RCA-style output built from detection data |
| 3 | Push the changes to this repo without breaking my existing tests or CI | Keep the project green |
| 4 | Check the "Username enumeration" rule's MITRE ATT&CK mapping on attack.mitre.org | Validate the security claims |

## 2. Where Claude was right

- **Crash on impossible dates.** A log line dated `Feb 31` (or `Feb 29` in a non-leap year) made `parse_time` raise `ValueError` and stopped the whole run. A regression test now proves it: it fails on the old code and passes on the new.
- **Missed logins.** `Accepted keyboard-interactive/pam` lines were ignored because the regex only matched `password` and `publickey`, so a compromise on a PAM-based server would have gone unreported. A test now covers all three methods.
- **Wrong name for the MITRE technique.** The rule was called "Username enumeration" but mapped to T1110.003, which [MITRE defines](https://attack.mitre.org/techniques/T1110/003/) as password spraying: a few common passwords tried against many accounts. Its detection strategy (DET0487) looks for authentication failures across multiple accounts, which is exactly what the rule detects. So the technique was right and the name was wrong. The rule is now "Possible password spraying". It says "possible" because SSH logs don't record the password tried, so it could also be credential stuffing (T1110.004).
- **Design limitations I haven't fixed yet:** no year in syslog timestamps, failures counted forever by the compromise rule, successful root logins not flagged, and real users behind one NAT looking like spraying. Each one now has a strict `xfail` test that will fail loudly once it's fixed.

## 3. Where Claude was wrong, and how it was caught

- **It said my biggest gap was missing tests.**  
  *How it was caught:* when it inspected the actual repo before pushing, it found 15 existing tests, a GitHub Actions pipeline and a ruff config. It had only seen my README, which didn't mention them.  
  *What we did:* the README now describes the tests and CI.

- **It planned to overwrite `tests/test_log_sentinel.py`.**  
  *How it was caught:* the same repo check showed that file already held my 15 tests, including regression tests for repeated alerts.  
  *What we did:* kept my file and added the new tests separately as `tests/test_edge_cases.py`.

- **Its first test file would have failed my CI.**  
  *How it was caught:* running my CI's `ruff check` locally before pushing flagged 3 lines over my 100-character limit.  
  *What we did:* wrapped the lines. Ruff, the tests and the smoke test all passed before anything was pushed, and GitHub Actions went green.

- **One generated test proves less than it looks.**  
  `test_window_boundary_is_inclusive` only locks in what the code already does (failures exactly 10 minutes apart count as inside the window). It doesn't prove that's the right behaviour. That's a design decision I still have to make.

## 4. What changed because of this

- `parse_time` returns `None` for impossible dates, and `parse_log` skips those lines
- Accepted logins via any SSH authentication method are parsed
- New `--summary` flag writes a Markdown incident summary built only from the data
- "Username enumeration" renamed to "Possible password spraying", keeping T1110.003
- 35 new passing tests plus 5 strict `xfail` tests for known limitations. Run against the original code, the regression tests for both bugs fail, which shows they really catch them.

## 5. What I'd do differently

- Give the AI the whole repository from the start, not just the README. Most of its mistakes came from missing context.
- Decide the intended behaviour first and then ask for boundary tests, so the tests check the spec rather than copy the code.
- Keep running AI-written tests against the old code to confirm they can fail.
