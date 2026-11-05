# Report format

The agent can write the report directly. For deterministic output, prepare sanitized JSON and run the bundled `scripts/render_report.py INPUT --output-dir NEW_DIRECTORY` with Python 3.10+. It needs no packages or network. Run it from outside any untrusted repository. Use an existing private, unsynced parent directory; the output directory must be new. If disk writes fail, a partial output directory may remain; inspect it and choose a fresh destination on retry. Never overwrite an existing report.

The renderer is not a scanner or a redaction tool. **Sanitize before input.** Do not give it raw provider exports, config files, messages, secrets, personal addresses, internal hostnames or private paths. It rejects unknown fields and some recognizable secrets but cannot identify arbitrary passwords. Review its final output before sharing. CSV is formula-neutralized, but importing/re-exporting it through other tools may change escaping.

Version 1 input contains exactly these fields:

| Field | Value |
| --- | --- |
| schema_version | integer `1` |
| as_of | ISO date `YYYY-MM-DD` |
| scope | Named sources and boundaries, using aliases |
| summary | Substantive main finding and key uncertainty, not just counts |
| next_step | Most useful next verification or owner decision |
| coverage | Exactly one row for each category below |
| findings | Zero to 1000 rows, using the finding fields below |
| limitations | 1–100 nonempty strings |

Categories: `accounts`, `permissions`, `keys`, `ai-connectors`, `dependencies`, `app-launch`.

Each coverage row has exactly `category`, `status`, `detail`. Status: `checked`, `partial`, `blocked`, `not-requested`, `not-applicable`. Detail must describe source/date range, sampling, pagination or why absent. `checked` means the stated evidence was reviewed, not that a category is universally safe. Findings require `checked` or `partial` coverage; use `partial` when some evidence exists but key verification is blocked.

Each finding has exactly these string fields:

| Field | Meaning |
| --- | --- |
| id | Unique stable `F-001` style ID |
| category | One category above |
| item | Non-sensitive local alias |
| evidence | Aliased source pointer, observed fact, and inference distinction |
| observed_at | ISO observation date, no later than as_of |
| state | `confirmed`, `candidate`, `unknown` |
| confidence | `high`, `medium`, `low` |
| severity | `critical`, `high`, `medium`, `low`, `informational`, `unknown` |
| priority | `now`, `this-week`, `later`, `investigate` |
| impact | Practical consequence and reason for priority |
| action | Specific review/verification or proposed change, not an executed command |
| action_readiness | `review-now` for decisions supported by present evidence; `needs-evidence` for verification tasks requiring additional evidence |
| decision | `pending`, `keep`, `review-change`, `accepted-risk`, `resolved` |
| retest | Evidence that would verify resolution; do not mark resolved without it |

All text is limited to 2000 characters per field. No extra properties, duplicate JSON keys, query-bearing URLs, credential-bearing URLs or raw headers. Keep evidence aliases resolvable by the owner in their private source, without exporting an alias map containing personal data. Findings CSV contains the rows only; always deliver it with report.md, which retains scope, coverage and limitations.

For subsequent audits, retain finding IDs when identity is established. Resolve only with dated new evidence; missing evidence is not resolution. Do not merge tenants just because names match.
