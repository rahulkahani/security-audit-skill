# Personal exposure

Use only named accounts, tenants, projects and date ranges. If no sources are available, produce a manual checklist; do not request passwords or blanket access. A connector's existence does not authorize using it.

## Discover accounts

For an authorized mailbox/date window, prefer sender domain, dates and minimal subject metadata. Search bounded signup, welcome, verification, subscription and receipt categories; paginate within the agreed limit and record truncation. Avoid password-reset bodies, magic links and codes. Never click email links to verify an account. Normalize provider names carefully; distinguish marketing lists from signups and separate tenants/accounts with aliases.

Mail proves a message was received, not that the account still exists, is paid, is unused, or belongs to the user. “Last seen in mail” is not “last login.” A receipt is historical payment evidence, not proof of an active subscription. Label these discovery candidates and ask the owner to verify through the provider's independently opened account page. Do not infer “first signup” from a limited search window.

## Permissions and projects

From a provider's metadata-only connected-app view, record publisher, grant type, scopes, project/account alias, last-use date if explicitly provided, and observation date. Distinguish OAuth apps, GitHub Apps, tokens, service accounts and memberships: their scopes and revocation effects differ. Note whether access is read, write or administrative and what data/resources are reachable. Broad scope is a review signal whose significance depends on actual need.

A configurable 90-day inactivity threshold is a triage heuristic only. Missing last-use means unknown, not unused. Confirm project ownership, current dependencies, billing and data-retention obligations before recommending retirement. Never visit a delete/revoke/rotate flow or change access during the audit.

## Key inventory without key material

Use provider key-list metadata only when values are not returned. Alias identifiers as `key-01`, etc.; do not include raw key IDs if unnecessary. Record provider, owner/project alias, role/scopes, created, expires, last used and status. If only a `.env` file, shell history or credentials file is available, do not open it: report metadata inventory unavailable. Existing sanitized secret-scanner alerts can establish a reported exposure location; do not rerun a scanner or inspect patches without a separately scoped, secret-safe workflow. A code reference cannot prove a key is valid or unused. Deleting a key from a file is not revocation.

## AI integrations and local exposure

Use metadata-only integration/permission screens or owner-prepared sanitized inventories for MCP, ChatGPT, Claude, Cursor and browser/editor extensions. Record data domains, capabilities, publisher, version, auto-run/approval settings and scope. Do not cat configuration files that may embed tokens, headers or environment variables. Unknown transport or last use is a gap. Avoid blanket “AI sees everything” claims: distinguish configured, enabled, authorized and observed use. Review uploaded-data retention only against current official provider policy and visible settings; don't infer provider deletion from disconnecting a connector.

Machine checks are limited to named metadata sources. No home-directory sweep, process-env dump, keychain access, network probing, persistence removal or forensic claims.

## Manual checklist when access is missing

- [ ] Independently open each named provider's account/integrations page.
- [ ] Record app publisher, granted capabilities and last use without copying secrets.
- [ ] Verify whether each discovered account/project is still needed.
- [ ] List key scopes, age and expiry from metadata-only views.
- [ ] Identify what would break before narrowing or retiring access.
- [ ] Review the sanitized report; authorize any later changes individually.
