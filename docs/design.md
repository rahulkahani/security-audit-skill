# Design decisions

Outcome: an owner can identify what deserves attention, see why, and decide the next action without granting the agent unrestricted security access.

The audit is a guided workflow, not a scanner. Deterministic code only validates and renders an already sanitized inventory. It has no connectors, network clients, subprocess calls, credential readers, account mutations or remediation commands. Agent instructions still require a capable model and suitable tool permissions; they are not technical enforcement against a hostile agent.

Three modes share one evidence/report contract: personal exposure, repository intake and app launch. Personal exposure is the default when the user names old accounts and connected apps. Repository review reuses existing supply-chain evidence instead of adding another scanner. Each mode is opt-in through the user's actual request, not selected by tool availability.

Evidence and urgency are separate. An observed broad OAuth grant can be confirmed while its necessity remains unknown. A signup email is a candidate, even when its date is certain. Missing access is a coverage gap, never a pass. No findings cannot imply safety.

Reports remain private local artifacts. The formatter escapes Markdown/HTML, neutralizes spreadsheet formula prefixes and refuses existing output directories. Its recognizable-secret checks are defense in depth only: arbitrary passwords cannot be distinguished from ordinary words. The user/agent must sanitize before handing input to it, including emails, names, internal hostnames and paths.

The source draft is preserved outside this repository; no personal vault contents, credentials or real audit evidence are included. The synthetic example contains invented providers and aliases only.
