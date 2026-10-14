# Secrets Checklist

Review `.env`, config, fixtures, tests, docs, logs, examples, generated output, CI variables, prompts, traces, telemetry, vector stores, and client bundles.

Look for:

- API keys, cloud credentials, OAuth secrets, signing keys, JWT secrets, private keys, database URLs, webhook secrets, session secrets, and service tokens. The helper's format library (`formats/secrets.yaml`) covers 92 documented token shapes, each tagged with its source (vendor documentation, Gitleaks default config, or observed), and an entropy layer gated on secret-named context.
- Secrets serialized into client bundles or behind public build prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`). A Supabase `service_role` or `sb_secret_` key, or an LLM provider key with `dangerouslyAllowBrowser`, in browser code is critical.
- Secrets printed into logs, reports, traces, exception messages, prompts, or tool outputs.
- Authorization headers, session cookies, credential-bearing URLs, and signed query strings captured in diagnostics or fixtures.
- Test fixtures that use real-looking production tokens.
- Long-lived credentials where short-lived or scoped tokens should exist.
- Secrets that exist only in git history (`history` command); deleting the file is not rotation.

Always redact values. Report the file, line, secret class (format id), exposure path, and rotation recommendation without reproducing the secret. The helper never emits the value; only the format id and column.

When writing fixtures or examples yourself, never commit a complete token shape: use the `{alnum:N}`/`{hex:N}` template placeholders expanded by `expand_sample()` so secret scanners and push protection stay quiet.
