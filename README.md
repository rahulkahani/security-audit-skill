# Security Audit

A read-only agent skill for finding forgotten accounts, reviewing connected permissions and key metadata, and checking repository or app-launch exposure. Inspired by Claire Vo’s personal security audit prompt; independently redesigned for bounded collection and evidence-based reporting.

## Use

Copy the `security-audit/` folder into your agent’s skills directory, then invoke `$security-audit`. No dependencies, access tokens, or configuration are bundled. Review the instructions before enabling it. Copying this repo into a chat does not automatically install a skill or connect your accounts.

For Codex on macOS/Linux:

```sh
git clone https://github.com/rahulkahani/security-audit-skill.git
cd security-audit-skill
mkdir -p "$HOME/.codex/skills"
test ! -e "$HOME/.codex/skills/security-audit" && cp -R security-audit "$HOME/.codex/skills/security-audit"
```

The last command copies only if no skill already occupies that path. If it exists, compare it before replacing anything. Start a new agent session to discover the installed skill. For Claude Code, use the same `security-audit/` folder in `~/.claude/skills/` instead; this package does not configure connectors or permissions in either application.

Example:

> Use $security-audit to review the sanitized app-grant export I supplied. Limit the audit to this file. Produce a private report and checklist; don’t change permissions or inspect credentials.

For a repository:

> Use $security-audit in repo-intake mode on this named checkout. Inspect static files only. Include development and build dependencies, explain evidence and blind spots, and don’t install or run the project.

## What improved

- Bounded sources replace the original draft’s “all available” sweep.
- Credential values, key fragments, environment files and shell history are excluded from routine collection.
- Email activity is a discovery signal, never proof of an active account or last use.
- Evidence state and confidence are separate from severity and priority.
- Every source has a coverage result, including blocked, partial and unrequested areas.
- Private Markdown and spreadsheet-safe CSV replace automatic cloud sharing.
- Dependency analysis includes development, build and transitive dependencies; advisory checks are optional and disclose their network destination.
- Audit and remediation are separate. Report generation does not authorize rotation, revocation, deletion or uploads.

The skill is guidance, not a sandbox or a malware scanner. It cannot prove an account is unused, a key is valid, a vulnerability is exploitable, or a machine is clean. The helper below formats reviewed metadata; it is not an automated account scanner or a comprehensive secret detector.

## Try the synthetic example

Requires Python 3.10+; uses only the standard library and no network.

```sh
python3 security-audit/scripts/render_report.py examples/synthetic-audit.json --output-dir /tmp/security-audit-demo
python3 -m unittest discover -s tests -v
```

The output directory must not exist. It is created with owner-only permissions, and files are owner-readable/writable. Review reports before moving them into synced folders or sharing them. The helper rejects unknown fields and some recognizable secret patterns, but **input must already be sanitized**.

Then test the agent behavior in a fresh conversation:

> Use $security-audit with only examples/synthetic-audit.json from this repository. Treat it as invented evidence. Produce a report, explain the coverage gaps, and do not access my email, accounts, credentials or other repositories.

Expected: three findings (a broad grant, a dependency-version gap, a possible old account), blocked key coverage, and no account changes or network calls. The helper test proves formatting and validation behavior; the agent test checks interpretation. Neither performs an audit of your actual security.

See [the skill](security-audit/SKILL.md), [input format](security-audit/references/report-format.md), [design and attribution](docs/design.md), and [behavioral evaluation cases](tests/behavioral-cases.md).
