---
name: vibesecurity
description: Defensive, local security review for code the user owns or is authorized to assess. Use for explicit $vibesecurity commands, security review of diffs, web/API routes, AI agents, dependencies, secrets, CI/CD, auth bypass, SSRF, injection, RCE, prompt injection, excessive agency, and evidence-backed remediation. Do not use for ordinary refactors, style review, performance tuning, or unauthorized/offensive testing.
---

# VibeSecurity

Review owned or authorized code defensively. Do not exploit third-party systems, steal credentials, create malware, add persistence or evasion, run unauthorized network tests, or print secret values.

## Operating Principles

1. Start cheap: inspect diffs, inventory, deterministic candidates, and small support context.
2. Escalate only on evidence: inspect reachable code paths before making a finding.
3. State exact evidence: file, line or symbol, reachable scenario, impact, remediation, and verification.
4. Keep context small: load only the references needed for the active command.
5. Patch confirmed findings when the user asks for fixing, patching, remediation, or auto-fix; use review-only mode when the user asks only for a review.
6. Treat secrets as toxic: redact likely secret values in output.
7. Never report a vulnerability from a matcher alone; confirm data flow and boundary crossing.

## Commands

- `$vibesecurity brief` - create or update a concise project security profile.
- `$vibesecurity diff` - review changed files and minimal supporting code.
- `$vibesecurity scan` - run the local deterministic helper and manually validate ranked candidates.
- `$vibesecurity deep <scope>` - perform targeted deep review of a path, feature, or risk class.
- `$vibesecurity recheck` - verify fixes or existing findings.
- `$vibesecurity fix <finding-id|all> [--review-only]` - apply guarded remediation for confirmed findings, or render a non-writing remediation plan.
- `$vibesecurity teach` - convert confirmed true positives into local matchers.
- `$vibesecurity ai [scope]` - review AI/LLM/agentic security risks.

## Workflow

1. Load `references/security-rubric.md` and `references/finding-schema.md` before emitting findings.
2. For `$vibesecurity scan`, run `python .agents/skills/vibesecurity/scripts/vibesecurity.py scan` when local execution is appropriate.
3. Read only the smallest category reference that matches the code under review.
4. Inspect helper `project`, `scope.coverage`, `rule_packs`, `files_skipped`, `truncated`, and `unsupported_or_profile_only` before judging coverage.
5. Inspect candidate code plus direct auth, schema, route, model, tool, or workflow support context.
6. Report confirmed findings first. Put unconfirmed matcher hits under coverage or candidate notes.
7. If fixing, load `references/remediation-playbook.md`, run `fix-plan` when a findings file exists, explain the security invariant, patch minimally, add or update tests when possible, then recheck.

## Reference Loading

Always load:

- `references/security-rubric.md`
- `references/finding-schema.md`

Load only when relevant:

- Command behavior: `references/command-map.md`
- Reporting: `references/reporting-rules.md`, `assets/templates/report.md`, `assets/templates/finding.json`
- Remediation: `references/remediation-playbook.md`, `assets/templates/remediation-plan.json`
- Web/API: `references/web-api-checklist.md`
- AI/agentic: `references/ai-agentic-checklist.md`
- Supply chain: `references/supply-chain-checklist.md`
- CI/CD: `references/ci-cd-checklist.md`
- Secrets: `references/secrets-checklist.md`
- Coverage truth: `references/coverage-matrix.md`
- Standards mapping: `references/standards-map.md`
- Framework specifics: one matching file under `references/framework-notes/`
- Examples: one matching file under `references/examples/`
- Matcher learning: `assets/templates/matcher.yaml` and `references/matchers/local-project.yaml`

Do not load all framework notes, examples, or matchers at once.

## Output Requirements

For each finding include ID, title, severity, confidence, status, category, affected files, evidence, attack scenario, impact, recommendation, verification, and useful standards mapping. If no finding is confirmed, state what was reviewed, what was skipped, which rule packs ran, and any unsupported/profile-only surfaces.

## Safety Boundaries

Refuse or redirect requests for live exploitation of third-party targets, credential theft, stealth, persistence, malware, unauthorized scanning, or secret exfiltration. For exploitability proof, prefer safe reasoning, local unit tests, and mock inputs.
