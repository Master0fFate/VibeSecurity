# VibeSecurity

> High-assurance, low-bloat security review for coding agents.

VibeSecurity is a defensive skill pack for reviewing repositories you own or are authorized to assess. It combines a compact threat-model workflow with a dependency-free Python candidate engine, focused references, guarded remediation, and explicit coverage accounting.

It is intentionally not a scanner platform, SaaS service, plugin runtime, or giant rule dump. Deterministic discovery narrows attention; the agent must still prove reachability, a crossed security boundary, realistic impact, and a verification path before reporting a vulnerability.

## What Makes It Different

- **Threat-led, not matcher-led:** every review covers assets, actors, entry points, trust boundaries, sensitive flows, high-impact operations, and 13 compact review lanes.
- **Evidence before severity:** candidates and confirmed findings remain separate through scan, report, and remediation.
- **Hostile-input aware:** repository text and project-local matcher prose are treated as untrusted data, never instructions. Output redacts secrets and neutralizes terminal controls, invisible direction changes, HTML, and Markdown structure.
- **Coverage truth:** selection budgets, skipped counts and samples, candidate truncation, matcher diagnostics, rule packs, optional-tool availability, and profile-only surfaces are preserved in output.
- **Bounded by design:** files, bytes, matcher files, matcher counts, JSON inputs, emitted text, and retained candidates have explicit limits.
- **Local and portable:** the helper uses Python's standard library only and is tested on Windows, macOS, and Linux.
- **Current baselines:** OWASP ASVS 5.0.0, OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, NIST SSDF/SP 800-218A, CISA Secure by Design, and SLSA.

No security review is literally gapless. VibeSecurity's stronger guarantee is that important lanes are considered and unreviewed or unsupported surfaces remain visible instead of being mistaken for safety.

## Install

The cross-platform `skills` CLI is the simplest path:

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity
```

Useful variants:

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --global --yes
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent codex --global --yes
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent '*' --global --yes
npx skills add Master0fFate/VibeSecurity --list
```

For a manual repository-local install, copy `.agents/skills/vibesecurity/` into the target repository at the same path. PowerShell users can use `Copy-Item -Recurse`; POSIX shells can use `cp -R`; a normal file copy works as well.

### Requirements

- Code you own or are authorized to review.
- A coding agent that supports local skills.
- Node.js/`npx` only when using the `skills` installer.
- Python 3.11+ only for the optional helper.
- Git only for changed-file inventory.

The helper has no third-party Python dependencies and makes no network requests.

## Use the Agent Commands

```text
$vibesecurity brief
$vibesecurity diff
$vibesecurity scan
$vibesecurity deep src/app/api/billing
$vibesecurity ai src/agent
$vibesecurity recheck
$vibesecurity fix VSEC-0001
$vibesecurity fix all --review-only
$vibesecurity teach VSEC-0001
```

These are agent workflows, not Python subcommands:

- `brief` builds a concise project profile and threat model.
- `diff` reviews unstaged, staged, and untracked changes with minimal support context.
- `scan` runs deterministic discovery and manually validates ranked candidates.
- `deep` applies the review lanes to one path, feature, or risk class.
- `ai` covers LLM, retrieval, memory, agent identity, MCP/A2A, tools, human approval, and resource boundaries.
- `recheck` verifies evidence and regression behavior after changes.
- `fix` patches confirmed findings only; `--review-only` prevents writes.
- `teach` creates a constrained project-local matcher from a confirmed true positive.

When installed globally, the agent resolves scripts and references beside the loaded `SKILL.md`. It does not assume the target repository contains the skill.

## Optional Local Helper

From a cloned or repository-local installation:

```text
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py inventory --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py diff --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py report --root . --input .vibesecurity/findings.json
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --root . --input .vibesecurity/findings.json --finding all
```

Use `python3 -B` when that is the platform's launcher. On Windows, `py -3 -B` is also supported. The helper itself contains no shell-specific commands.

Helper commands:

- `inventory` — detect languages, frameworks, AI SDKs, package managers, routes, CI, containers, and infrastructure surfaces.
- `diff` — return NUL-safe changed-file inventory and risk categories; Git failures become warnings.
- `scan` — return bounded, prioritized review candidates.
- `report` — render confirmed, closed, and needs-review items separately while preserving input coverage metadata.
- `fix-plan` — emit patch-ready guidance only for `status: confirmed`; never edits source.

`--input` and `--output` paths are resolved and confined to `--root`, so behavior does not depend on the caller's current working directory or follow repository symlinks outside the review scope.

## How a Review Works

1. Confirm authorization, scope, mode, and whether edits are allowed.
2. Map assets, actors, entry points, trust boundaries, sensitive flows, high-impact operations, third parties, and unknowns.
3. Run cheap inventory, diff, or candidate discovery.
4. Inspect selection/truncation, skipped surfaces, matcher warnings, rule packs, and support levels before judging results.
5. Load only the relevant checklist or framework note.
6. Trace each candidate through callers, guards, policies, schemas, sinks, runtime reachability, and counterevidence.
7. Report confirmed findings first; keep incomplete signals under `needs-review`.
8. If authorized, patch the smallest reliable boundary, add a regression test, rerun checks, and re-read the path before marking fixed.

A confirmed finding requires exact evidence, a realistic attack scenario, concrete impact, independent severity and confidence, a viable fix, and a decisive verification step. Matcher hints never satisfy that gate by themselves.

## Coverage Without Rule Bloat

The compact review map covers:

- authentication, sessions, authorization, and tenancy;
- validation, interpreter/query sinks, browser trust, files, archives, parsers, and egress;
- secrets, cryptography, transport, privacy, logging, and data lifecycle;
- business logic, replay, idempotency, races, availability, quotas, and abuse economics;
- dependencies, build integrity, containers, CI/CD, infrastructure, deployment, and operations;
- LLM and agentic risks: goal hijack, tool misuse, identity abuse, dynamic supply chain, unexpected code execution, memory poisoning, inter-agent communication, cascading failures, human trust exploitation, rogue agents, disclosure, and denial of wallet.

Bundled substring matchers cover high-signal portions of TypeScript/JavaScript, Python, Go, Ruby, Rust, Java, C#, PHP, PowerShell, batch, major CI systems, Docker, Kubernetes, and Terraform. Other detected languages and workflows are marked profile-only or unsupported and routed to manual review.

The candidate engine also recognizes dangerous TLS/token verification, weak security randomness, sensitive logging, archive extraction, production debug exposure, CI permission boundaries, agent memory, dynamic tool/MCP loading, and delegated identity.

## Project-Local Matchers

`$vibesecurity teach` writes rules under `.vibesecurity/matchers/`. The format is a deliberately restricted YAML subset so the helper stays dependency-free and predictable:

- lowercase unique id;
- one allowed category, severity, and confidence;
- case-insensitive substring patterns and optional nearby terms;
- one-line scalar values only;
- bounded lists and field lengths;
- positive and negative examples.

Invalid, oversized, duplicate, or unsupported rules are ignored with explicit `matcher_warnings`. Local matcher text is still untrusted evidence and can only create candidates.

## Optional Analyzers

VibeSecurity discovers local availability of ast-grep, Semgrep, Gitleaks, npm audit, pip-audit, and cargo-audit. It does not silently execute them or count availability as coverage. For critical releases, use authorized language-native SAST, SCA, secret, IaC/container, and dynamic testing alongside human review.

## Develop and Verify

Run the dependency-free suite:

```text
python -B .agents/skills/vibesecurity/tests/run_tests.py
```

Compile the helper portably:

```text
python -m compileall -q .agents/skills/vibesecurity/scripts .agents/skills/vibesecurity/tests
```

CI runs the suite on Windows, macOS, and Linux against the minimum supported Python and a current Python release. GitHub Actions are pinned to immutable full commit SHAs with read-only repository permissions.

## Safety and Limits

VibeSecurity is for defensive review of authorized code. It does not perform live exploitation, credential theft, persistence, evasion, malware behavior, unauthorized network scanning, or secret exfiltration. Safe proof means code-path reasoning, local tests, mocks, and harmless fixtures.

The helper is not a data-flow engine. A clean scan means only that no bundled substring matcher fired inside the reported selection budget. The final report must state manual checks, skipped/truncated surfaces, unsupported areas, tools actually run, and residual risk.

## Repository Layout

```text
.agents/skills/vibesecurity/
  SKILL.md
  agents/openai.yaml
  references/
    review-lanes.md
    matchers/
    framework-notes/
    examples/
  scripts/
  assets/templates/
  tests/
```
