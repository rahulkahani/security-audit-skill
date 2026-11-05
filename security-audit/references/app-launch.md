# App launch review

Limit the review to the named application, revision and deployment. This is a static/configuration review unless the user separately authorizes a specific dynamic check. Do not probe live endpoints, create users, submit uploads, send mail, spend API credits or mutate databases.

Review evidence for:

- Client/server boundaries: public environment-variable names and bundling paths, hardcoded credential indicators from already sanitized alerts, debug/config artifacts and source maps. Do not open secret files or print credential values.
- Authentication and authorization where applicable: server-side checks, tenant ownership, administrative paths, anonymous access and documented public data.
- Storage/database policy: intended public read scope, write policy, tenant separation and service-role usage. Treat absence of deployed policy evidence as unknown.
- Input and output handling: validation, escaping, file upload boundaries, URL-fetch restrictions and safe error handling.
- Abuse/cost controls: rate limits, unauthenticated expensive calls, upload/body limits, queue/retry limits and billing exposure.
- Runtime and dependencies: exact deployed runtime where visible, lockfile coverage including build/dev paths, official current advisories and applicability.
- Deployment/update chain: source-to-build revision, updater authorization, write routes, action permissions, untrusted build inputs, logs and rollback evidence.

Use `not-applicable` only with a reason (for example, no account system). Local code cannot establish deployed behavior. Distinguish “code contains a control,” “deployment configuration observed,” and “behavior tested.” State which are unverified. Finish with specific launch blockers supported by evidence and a separate verification checklist; never certify the site safe.
