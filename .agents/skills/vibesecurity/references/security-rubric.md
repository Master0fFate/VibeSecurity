# Security Rubric

A finding must satisfy all five conditions:

1. Reachable: attacker-controlled, user-controlled, lower-privileged, or untrusted input reaches the behavior.
2. Boundary-crossing: the behavior crosses an auth, tenant, trust, filesystem, network, command, model/tool, secret, privacy, or resource boundary.
3. Impactful: realistic confidentiality, integrity, availability, authorization, financial, privacy, or supply-chain harm exists.
4. Specific: the affected file, function, line, route, workflow, or tool is named.
5. Fixable: a concrete mitigation and verification step can be stated.

Before confirming, actively check counterevidence: guards, middleware, policy composition, safe framework defaults, sanitizers, environment gates, tests, and dead or unreachable code. Do not report style issues, generic warnings, tool hits without manual confirmation, or missing-context claims unless confidence is clearly low. Never print secret values.

Calibrate severity from impact, exploitability, privileges, interaction, blast radius, and recovery. Calibrate confidence separately from evidence quality and missing runtime context. Matcher severity and confidence are triage hints only.

## Severity

| Severity | Use when |
|---|---|
| Critical | Remote unauthenticated compromise, cross-tenant data compromise, arbitrary command execution, credential exfiltration, or supply-chain takeover. |
| High | Auth bypass, privilege escalation, sensitive data exposure, SSRF to internal resources, destructive tool execution, or CI secret exposure. |
| Medium | Exploitable with auth or constraints, scoped data exposure, XSS in sensitive context, or weak object-level authorization. |
| Low | Defense-in-depth gap, limited information leak, or weak validation with low impact. |
| Info | Coverage note, hardening suggestion, or documentation gap. |

Use impact, reachability, exploitability, boundary crossed, and blast radius to choose severity.

## Review Outcome

- `confirmed`: all five conditions pass with direct code or effective-configuration evidence.
- `needs-review`: signal is meaningful, but a required condition or counterevidence check is unresolved.
- `fixed`: the vulnerable path was re-read and a decisive regression check passed.
- `false-positive` or `wont-fix`: record the evidence or accepted risk; do not silently drop it.

When no finding is confirmed, report reviewed lanes, proof performed, skipped/truncated surfaces, matcher diagnostics, and residual risk. Do not convert absence of evidence into assurance.
