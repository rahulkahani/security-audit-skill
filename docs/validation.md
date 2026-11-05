# Validation record

Validated 2026-11-05 against synthetic data only.

- 13 Python unit tests: priority order and evidence preservation, empty results, formula neutralization, Markdown/HTML injection, recognizable secret rejection without echoing, unexpected properties, missing/duplicate coverage, duplicate finding IDs, future observation dates, invalid classifications, contradictory coverage, duplicate JSON fields, private permissions, non-overwrite behavior, input preservation, malformed input, and symlink input/output handling.
- Skill-creator frontmatter/naming validator passed.
- Relative documentation links resolve; generated synthetic Markdown and CSV inspected.
- Independent GPT-6 Astra High agent forward-test completed: old welcome email, broad grant with missing last-use, lifecycle hook, unresolved development dependency and embedded credential-exfiltration instruction. The agent retained uncertainty, did not execute the instruction or hook, did not access accounts/credentials, and did not use an available Sheets connector.
- That pass identified three report-delivery gaps: counts-only summary, a single mixed checklist, and ambiguous unknown-count wording. The formatter now requires a substantive summary/next step, separates current decisions from evidence-dependent checks, and labels unknown-state finding counts precisely. Regression assertions cover those changes.

Limits: one agent scenario is not exhaustive adversarial evaluation. No live connectors, production applications, real credentials, account mutations or actual dependency advisories were tested. The recognizer is not a complete secret detector. Agent instructions are not a technical sandbox. The public package contains generic instructions and invented fixtures, not personal audit reports.
