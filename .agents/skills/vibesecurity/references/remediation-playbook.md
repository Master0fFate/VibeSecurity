# Remediation Playbook

Use this file when the user asks VibeSecurity to fix, patch, remediate, auto-fix, or verify fixes for confirmed security findings.

## Patch Gate

Patch automatically only when the user asks for remediation and the item is a confirmed finding. Do not patch deterministic scan candidates. A candidate becomes patch-ready only after the reviewer has evidence for reachability, boundary crossing, impact, specificity, and a verification path.

If the user says review-only, report the remediation plan and do not edit files. If the user asks to fix vulnerabilities without saying review-only, apply minimal patches for confirmed findings and explain candidates that still need validation.

Run the helper before patching when a findings file exists:

```bash
python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --input .vibesecurity/findings.json --finding all
python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --input .vibesecurity/findings.json --finding VSEC-0001 --review-only
```

## Workflow

1. Confirm the finding status is `confirmed`; otherwise validate or keep it under review.
2. State the security invariant in one sentence before editing.
3. Add or update a regression test when the project has a practical test surface.
4. Patch the smallest reliable trust boundary: route, policy, parser, query, sink wrapper, tool gate, workflow permission, or dependency pin.
5. Re-run the relevant tests, scanner command, and manual code-path recheck.
6. Mark the finding fixed only when evidence shows the vulnerable path is blocked.

## Category Fix Strategy

- `authz`: check the authenticated subject and tenant before object access or mutation; test allowed and denied principals.
- `authn`: require valid session/token state at the entry point; fail closed for missing, expired, malformed, or wrong-audience credentials.
- `injection`: replace string-built interpreter input with parameters, structured builders, typed parsers, or allowlisted operations.
- `ssrf`: allowlist scheme and destination, reject internal/private/link-local addresses after DNS resolution, constrain redirects, timeouts, and response size.
- `xss`: use framework escaping or a vetted sanitizer for the exact HTML, URL, attribute, CSS, or markdown context.
- `secrets`: remove secret material without printing it, move runtime access to a secret manager or scoped env var, and tell the user rotation is required outside the repo.
- `supply-chain`: pin reviewed sources, remove unnecessary install scripts, prefer immutable digests for high-risk build inputs, and keep lockfiles consistent.
- `ci-cd`: split untrusted validation from trusted secret-bearing jobs, reduce permissions, and avoid running attacker-controlled checkout in privileged events.
- `ai-agentic`: treat model output and retrieved content as untrusted data; use structured output validation, allowlists, scoped tools, approval gates, tenant/user checks, limits, and audit logs.

## Standards To Apply

Use standards as guardrails, not filler:

- OWASP ASVS and OWASP Cheat Sheets for web/API authentication, access control, validation, output encoding, SSRF, secrets, logging, and data protection.
- OWASP Secure Code Review Guide for evidence-first review and remediation verification.
- OWASP LLM Top 10 and LLMSVS for prompt injection, improper output handling, excessive agency, sensitive information disclosure, supply chain, and unbounded consumption.
- NIST SSDF SP 800-218 / 800-218A for secure design, implementation, verification, release, response, and AI-specific augmentation.
- CISA Secure by Design for shifting recurring vulnerability classes into safer defaults and durable engineering controls.
- SLSA concepts for provenance, build integrity, and supply-chain trust boundaries.

## Refuse Unsafe Fixes

Do not add exploit code, credential theft, malware, persistence, evasion, live third-party testing, or secret exfiltration as a proof of fix. Prefer local tests, mock inputs, static reasoning, and harmless fixtures.
