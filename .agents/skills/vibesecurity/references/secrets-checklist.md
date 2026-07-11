# Secrets Checklist

Review `.env`, config, fixtures, tests, docs, logs, examples, generated output, CI variables, prompts, traces, telemetry, and vector stores.

Look for:

- API keys, cloud credentials, OAuth secrets, signing keys, JWT secrets, private keys, database URLs, webhook secrets, session secrets, and service tokens.
- Secrets serialized into client bundles or `NEXT_PUBLIC_*`-style public variables.
- Secrets printed into logs, reports, traces, exception messages, prompts, or tool outputs.
- Authorization headers, session cookies, credential-bearing URLs, and signed query strings captured in diagnostics or fixtures.
- Test fixtures that use real-looking production tokens.
- Long-lived credentials where short-lived or scoped tokens should exist.

Always redact values. Report the file, line, secret class, exposure path, and rotation recommendation without reproducing the secret.
