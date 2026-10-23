# AI Notes: How I Used Claude on LogSentinel

<!-- Fill every [BRACKET] with something that really happened. Delete this comment before publishing. -->

**Tool:** Claude (free tier)  
**Date:** [date]

## 1. What I asked

| # | Prompt (short) | Why |
|---|---|---|
| 1 | Review the code as a senior engineer: bugs, edge cases, false-positive risks | Find weaknesses I couldn't see |
| 2 | Write pytest tests for the window logic, threshold boundary, compromise rule, malformed lines | Get a test suite fast |
| 3 | Check my MITRE ATT&CK mappings and say what it's unsure about | Validate the security claims |
| 4 | Write a manager-friendly incident summary from the JSON report | Test AI for RCA-style writing |

## 2. Where Claude was right

- [Example: it spotted that timestamps have no year, which breaks ordering across New Year. I confirmed it by running a log that crosses 31 Dec.]
- [Example: ...]

## 3. Where Claude was wrong, and how I caught it

- **[What it claimed or produced]**  
  *How I caught it:* [ran the test / checked attack.mitre.org / compared with the raw log]  
  *What I did:* [fixed X / rejected it]

- **[Second example]**  
  *How I caught it:* [...]  
  *What I did:* [...]

## 4. What I changed because of this

- [Code change 1]
- [Code change 2]
- [New test added]

## 5. What I'd do differently

[One or two sentences. For example: always run generated tests against deliberately broken code to confirm they can fail.]
