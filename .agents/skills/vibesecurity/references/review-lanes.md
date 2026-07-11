# Review Lanes

Use this compact map to prevent matcher-driven tunnel vision. Apply every lane briefly to the active scope, then deepen only where the system exposes that boundary. Mark absent, reviewed, needs-review, profile-only, unsupported, or out-of-scope; never assume silence means safe.

## Security Model

Before findings, identify:

- **Assets:** credentials, personal or tenant data, money, privileged actions, source/build integrity, models, memory, availability, and reputation.
- **Actors:** anonymous, authenticated, lower-privileged, cross-tenant, maintainer, CI job, service, dependency, model, agent, and compromised third party.
- **Entry points:** routes, events, queues, webhooks, files, imports, prompts, retrieved content, tools, scheduled jobs, admin paths, and deployment inputs.
- **Trust boundaries:** browser/server, user/tenant, service/service, model/tool, agent/agent, repo/CI, build/deploy, network zone, host/container, and secret store/runtime.
- **Sensitive flows:** where untrusted data enters, is transformed or authorized, crosses a boundary, reaches a sink, persists, or leaves the system.
- **High-impact operations:** identity changes, payment, deletion, export, messaging, deployment, code execution, credential access, and policy changes.
- **Unknowns:** generated code, external configuration, runtime-only controls, infrastructure outside the repo, unavailable dependencies, and skipped or truncated files.

## Lanes

1. **Authentication and sessions** — credential verification, account recovery, MFA, token issuer/audience/signature/time claims, cookie flags, fixation, revocation, alternate login paths, and fail-closed errors.
2. **Authorization and tenancy** — route and service policies, object ownership, tenant filters, role changes, bulk operations, background jobs, cache keys, exports, and confused-deputy paths.
3. **Validation and interpreter sinks** — schemas, canonicalization, query construction, shell/process APIs, templates, expression engines, deserialization, regular expressions, and second-order injection.
4. **Browser and client trust** — XSS by output context, DOM sinks, CSRF, CORS, redirects, postMessage, client-side secrets, cache/revalidation leaks, clickjacking, and browser automation.
5. **Files and parsers** — upload type and size, path containment, symlinks, archive extraction, decompression bombs, parser modes, temporary files, download authorization, and cleanup.
6. **Network and egress** — SSRF, DNS rebinding, redirect policy, scheme and destination allowlists, internal/link-local ranges, proxies, webhooks, TLS verification, timeouts, and response bounds.
7. **Secrets and cryptography** — committed or logged credentials, public bundles, key storage and rotation, vetted primitives, secure randomness, nonces, authenticated encryption, password hashing, and certificate validation.
8. **Data protection and privacy** — collection minimization, purpose and consent, tenant isolation, field-level access, logs/traces/analytics/prompts, retention, deletion, backup, export, and third-party disclosure.
9. **Business logic and concurrency** — state transitions, replay and idempotency, race conditions, TOCTOU, duplicate payment, quota bypass, inventory or balance invariants, approval separation, and workflow ordering.
10. **Availability and abuse economics** — input/output limits, rate and concurrency limits, retries, fan-out, pagination, queue pressure, cancellation, timeouts, decompression, algorithmic complexity, AI spend, and noisy-neighbor isolation.
11. **Dependencies and build integrity** — manifest/lock consistency, provenance, typosquatting, install hooks, generated code, mutable refs, remote downloads, container bases, artifact handoff, and reproducibility.
12. **CI/CD, infrastructure, and operations** — untrusted events, token permissions, secret-bearing jobs, action pinning, script interpolation, caches/artifacts, deployment approvals, IAM/network exposure, debug modes, error leakage, audit logs, rollback, and incident response.
13. **AI and agentic systems** — direct/indirect prompt injection, goal hijack, tool misuse, identity delegation, dynamic MCP/A2A supply chain, output-to-sink validation, memory poisoning, inter-agent trust, cascading failures, human over-trust, rogue behavior, and model/data/resource boundaries.

## Evidence Strategy

- Start at externally reachable or lower-trust inputs and trace forward to high-impact sinks.
- Start at privileged sinks and trace backward to their callers, authorization, validation, and deployment reachability.
- Check negative paths: missing, malformed, expired, cross-tenant, replayed, concurrent, oversized, timed out, dependency unavailable, and partial failure.
- Search for counterevidence before confirming: middleware, policy composition, framework escaping, parameterization, allowlists, environment gates, tests, and dead/unreachable code.
- Prefer one decisive regression test over speculative exploit code. For configuration and workflows, verify the rendered/effective policy when practical.

## Assurance Statement

Every review ends with: reviewed scope; detected stack and boundaries; confirmed, closed, and needs-review items; files and surfaces skipped; selection or candidate truncation; matcher diagnostics; optional tools actually run; manual checks performed; and residual risk. “No confirmed findings” is acceptable. “Secure” or “gapless” is not.
