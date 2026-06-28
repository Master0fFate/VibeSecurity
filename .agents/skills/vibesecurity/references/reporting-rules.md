# Reporting Rules

Put confirmed findings first. Separate needs-review candidates from findings. Avoid alarming language for unconfirmed candidates.

For every finding, include:

- ID, title, severity, confidence, category, and status.
- Affected file paths plus tight line or symbol evidence.
- Reachable attack scenario.
- Concrete impact.
- Recommended fix.
- Verification steps.
- Standards mapping when useful.

When there are no confirmed findings, say what was reviewed, which references were used, which files or risk classes were skipped, and what residual risk remains.

Redact likely secrets in all snippets, including tokens, private keys, cloud keys, database URLs, signing secrets, OAuth secrets, and session secrets.
