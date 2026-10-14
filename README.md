# VibeSecurity

> Evidence-first security review for AI-assisted code. Every detector cites a CWE, an OWASP 2025 category, and an ASVS 5.0.0 requirement; every advisory carries a CVSS score, an EPSS probability, and its KEV status.

VibeSecurity is a defensive skill pack for reviewing repositories you own or are authorized to assess. It combines a compact threat-model workflow with a dependency-free Python helper that finds candidates, matches lockfiles against live advisory data, checks that your dependencies actually exist, and hands the agent standards-backed context for manual validation.

It is intentionally not a scanner platform, SaaS service, plugin runtime, or giant rule dump. Deterministic discovery narrows attention; the agent must still prove reachability, a crossed security boundary, realistic impact, and a verification path before reporting a vulnerability.

## Why this exists, in numbers

| Measured fact | Source |
|---|---|
| LLMs chose the insecure implementation in 45% of curated tasks; Java over 70% | Veracode, 2025 GenAI Code Security Report |
| About 40% of Copilot-completed programs across CWE Top 25 scenarios contained the weakness | Pearce et al., IEEE S&P 2022 |
| 5.2% (commercial) to 21.7% (open-source) of generated package references do not exist; 205,474 unique hallucinated names | Spracklen et al., USENIX Security 2025 |
| 23.8 million new secrets on public GitHub in 2024, up 25%; 70% of 2022 leaks still valid | GitGuardian, State of Secrets Sprawl 2025 |
| 170 of 1,645 Lovable apps exposed Supabase tables to anyone holding the public key (CVE-2025-48757, CVSS 9.3) | NVD, May 2025 |
| 400+ exposed secrets and 2,000+ vulnerabilities across 5,600 vibe-coded apps | Escape.tech, October 2025 |

Sources, caveats, and the incident table (Tea, Moltbook) live in `.agents/skills/vibesecurity/references/evidence-base.md`. The `vibecoder` matcher pack targets exactly those failure modes: Supabase Row Level Security off, service keys in client bundles, `NEXT_PUBLIC_` secrets, open Firebase rules, browser-side LLM SDKs, unverified webhooks.

## What Makes It Different

- **Standards are data, not vibes:** `references/standards/` holds MITRE CWE names, the CWE Top 25 2025 with scores, OWASP Top 10:2025 and LLM/Agentic categories, and 76 verbatim ASVS 5.0.0 requirements, each with source URL and retrieval date. Every candidate resolves to them; SARIF output carries CWE tags.
- **Severity has a basis:** advisory severity comes from the GHSA review band, or a CVSS v3.1 base score computed from the vector with the FIRST formula, or an explicit medium default. KEV listing escalates to critical. EPSS probability rides along for prioritisation.
- **Slopsquatting defence:** `feed refresh` records whether each npm and PyPI dependency exists on the public registry and when it was first published; `scan` flags names that resolve nowhere and package.json entries absent from the lockfile.
- **Secret coverage that stays quiet in git:** 92 token formats (Anthropic, OpenAI, Supabase, Stripe, Clerk, Slack, AWS, and more), each tagged `vendor-doc`, `gitleaks-default-config`, or `observed`; specific formats win over generic ones on the same span; fixtures store shape templates, never token-shaped strings.
- **Threat-led, not matcher-led:** every review covers assets, actors, entry points, trust boundaries, sensitive flows, high-impact operations, and 13 compact review lanes.
- **Evidence before severity:** candidates and confirmed findings stay separate through scan, report, and remediation; confirmed findings require source citations.
- **Hostile-input aware:** repository text and project-local matcher prose are untrusted data, never instructions. Output redacts secrets and neutralizes terminal controls, invisible direction changes, HTML, and Markdown structure.
- **Coverage truth:** selection budgets, skipped counts, candidate truncation, matcher diagnostics, advisory provenance, dependency hygiene, and profile-only surfaces are preserved in output.
- **Bounded and local:** standard library only; tested on Windows, macOS, and Linux; every command except `feed refresh` runs offline.

No security review is literally gapless. VibeSecurity's stronger guarantee is that important lanes are considered and unreviewed or unsupported surfaces remain visible instead of being mistaken for safety.

## Install

VibeSecurity follows the open [Agent Skills specification](https://agentskills.io/specification). Install it only for the agents you use.

### Codex

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent codex --global --yes
```

### Claude Code

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent claude-code --global --yes
```

Claude Code exposes the installed skill as `/vibesecurity` from `~/.claude/skills/vibesecurity/`, following [Claude Code's native skills model](https://code.claude.com/docs/en/slash-commands).

### Codex and Claude Code

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent codex --agent claude-code --global --yes
```

Repeating `--agent` is the [`skills` CLI's documented multi-agent form](https://github.com/vercel-labs/skills#options). It keeps one canonical skill and links agent-specific locations when the platform supports links.

For interactive agent selection or repository inspection:

```text
npx skills add Master0fFate/VibeSecurity --skill vibesecurity
npx skills add Master0fFate/VibeSecurity --list
```

For a manual project install, copy the canonical `.agents/skills/vibesecurity/` folder to `.agents/skills/vibesecurity/` for Codex or `.claude/skills/vibesecurity/` for Claude Code. Prefer the CLI when installing for both so the copies cannot drift.

### Requirements

- Code you own or are authorized to review.
- A coding agent that supports local skills.
- Node.js/`npx` only when using the `skills` installer.
- Python 3.11+ only for the optional helper.
- Git only for changed-file inventory and history scans.

The helper has no third-party Python dependencies. Only `feed refresh` uses the network (api.osv.dev, cisa.gov, api.first.org, registry.npmjs.org, pypi.org).

## Quick Start for a Vibe-Coded App

```text
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . --fail-on confirmed-high
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py history --root .
```

Then ask the agent: `/vibesecurity scan` (Claude Code) or `$vibesecurity scan` (Codex). It validates the ranked candidates, reads the Supabase, Firebase, or Next.js framework note that matches `project.platforms`, and reports confirmed findings with their CWE, OWASP, and ASVS references.

## Use the Agent Commands

| Workflow | Codex | Claude Code |
| --- | --- | --- |
| Project brief | `$vibesecurity brief` | `/vibesecurity brief` |
| Changed files | `$vibesecurity diff` | `/vibesecurity diff` |
| Repository scan | `$vibesecurity scan` | `/vibesecurity scan` |
| Focused review | `$vibesecurity deep src/app/api/billing` | `/vibesecurity deep src/app/api/billing` |
| AI/agent review | `$vibesecurity ai src/agent` | `/vibesecurity ai src/agent` |
| Advisory cache | `$vibesecurity feed refresh` | `/vibesecurity feed refresh` |
| Recheck | `$vibesecurity recheck` | `/vibesecurity recheck` |
| Fix one finding | `$vibesecurity fix VSEC-0001` | `/vibesecurity fix VSEC-0001` |
| Review-only plan | `$vibesecurity fix all --review-only` | `/vibesecurity fix all --review-only` |
| Teach matcher | `$vibesecurity teach VSEC-0001` | `/vibesecurity teach VSEC-0001` |

These are agent workflows, not Python subcommands:

- `brief` builds a concise project profile and threat model.
- `diff` reviews unstaged, staged, and untracked changes with minimal support context.
- `scan` runs deterministic discovery and manually validates ranked candidates.
- `deep` applies the review lanes to one path, feature, or risk class.
- `ai` covers LLM, retrieval, memory, agent identity, MCP/A2A, tools, human approval, and resource boundaries.
- `feed` refreshes or inspects the advisory, EPSS, KEV, and registry cache.
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
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py deps --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py history --root .
python -B .agents/skills/vibesecurity/scripts/vibesecurity.py verify --root . --input .vibesecurity/findings.json --finding all
```

Use `python3 -B` when that is the platform's launcher. On Windows, `py -3 -B` is also supported. The helper itself contains no shell-specific commands.

Helper commands:

- `inventory` — detect languages, frameworks, platforms (Supabase, Firebase, Clerk, Convex, Prisma, Stripe, and more), AI SDKs, package managers, env files, routes, CI, containers, and infrastructure surfaces.
- `diff` — return NUL-safe changed-file inventory and risk categories; Git failures become warnings.
- `scan` — bounded, prioritized review candidates from matchers and the secret engine; with a cache present, offline SCA with CVSS/EPSS/KEV data, registry existence checks, and manifest-versus-lockfile drift; with `--run-analyzers`, execute opted-in local analyzers.
- `report` — render confirmed, closed, and needs-review items separately with CWE/OWASP/ASVS lines and exploit-intelligence fields, preserving input coverage metadata.
- `fix-plan` — patch-ready guidance only for `status: confirmed` items with validated `sources`; never edits source.
- `deps` — lockfile/manifest dependency inventory with explicit `unsupported` records for Maven, Gradle, yarn berry, Hex, NuGet, and Swift.
- `feed refresh|status|export|import` — refresh or inspect the cache (OSV/GHSA advisories, CISA KEV, FIRST EPSS, npm and PyPI registry metadata); export or verify air-gap bundles.
- `history` — bounded git-history secret scan; reports `only_in_history` items; never prints values.
- `verify` — rerun scan surfaces and a test command, then report `verified | still-present | test-failed | inconclusive` per finding.
- `baseline` — show baseline state, including expired suppressions that re-fire.

`--input` and `--output` paths are resolved and confined to `--root`, so behavior does not depend on the caller's current working directory or follow repository symlinks outside the review scope.

### What a candidate looks like

```json
{
  "matcher_id": "supabase-rls-disabled",
  "path": "supabase/migrations/0003_orders.sql",
  "line": 12,
  "severity_hint": "critical",
  "confidence_hint": "high",
  "status": "needs-review",
  "cwe": "CWE-862, CWE-285",
  "owasp": "A01:2025",
  "asvs": "V8.2.2, V8.3.1",
  "standards": {
    "cwe": [{"id": "CWE-862", "name": "Missing Authorization", "top25_2025_rank": 4}],
    "owasp": [{"id": "A01:2025", "name": "Broken Access Control"}],
    "asvs": [{"id": "V8.2.2", "level": "1", "text": "Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items ..."}]
  },
  "priority_score": 118,
  "priority_reasons": ["severity:critical", "category:authz", "high-signal-matcher", "cwe-top25-2025-rank-4"]
}
```

Advisory candidates add `advisory_ids`, `sources`, `advisory_fix`, `severity_basis`, `cvss`, `epss`, and `kev`.

### Exit codes and CI gating

| Code | Meaning |
| --- | --- |
| 0 | Clean: no findings at or above the `--fail-on` threshold |
| 1 | Findings at or above the threshold (confirmed findings only; candidates never fail a build) |
| 2 | Tool error or incomplete scan — never silently clean |
| 3 | Usage error |

`--fail-on` accepts `none` (default), `confirmed`, `confirmed-high`, or `critical`. `--format sarif` emits SARIF 2.1.0 with partial fingerprints and CWE tags for GitHub code scanning. Recipes for GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and pre-commit live in `docs/integrations/`.

### Policy configuration

`.vibesecurity/config.json` (schema 1), all optional: `network_enabled` (default true), `registry_lookups` (true), `fail_on` (none), `max_cache_age_hours` (72), `history_window_months` (12), `baseline_max_age_days` (180), `allowed_analyzers`. Precedence: CLI > config > defaults; unknown keys produce warnings. Baselines live in `.vibesecurity/baseline.json` with mandatory `expires_on`; expired suppressions re-fire visibly and corrupted baselines never silence findings.

## How a Review Works

1. Confirm authorization, scope, mode, and whether edits are allowed.
2. Map assets, actors, entry points, trust boundaries, sensitive flows, high-impact operations, third parties, and unknowns.
3. Run cheap inventory, diff, or candidate discovery.
4. Inspect selection/truncation, skipped surfaces, matcher warnings, rule packs, advisory provenance, and support levels before judging results.
5. Load only the relevant checklist or framework note.
6. Trace each candidate through callers, guards, policies, schemas, sinks, runtime reachability, and counterevidence.
7. Report confirmed findings first with their resolved standards; keep incomplete signals under `needs-review`.
8. If authorized, patch the smallest reliable boundary, add a regression test, rerun checks, and re-read the path before marking fixed.

A confirmed finding requires exact evidence, a realistic attack scenario, concrete impact, independent severity and confidence, a viable fix, and a decisive verification step. Matcher hints never satisfy that gate by themselves.

## Coverage Without Rule Bloat

The compact review map covers:

- authentication, sessions, authorization, and tenancy;
- validation, interpreter/query sinks, browser trust, files, archives, parsers, and egress;
- secrets, cryptography, transport, privacy, logging, and data lifecycle;
- business logic, replay, idempotency, races, availability, quotas, and abuse economics;
- dependencies, build integrity, containers, CI/CD, infrastructure, deployment, and operations;
- data-access platforms used by generated apps: Supabase RLS and keys, Firebase rules, Next.js env prefixes, auth middleware, Convex, tRPC, webhooks;
- LLM and agentic risks: goal hijack, tool misuse, identity abuse, dynamic supply chain, unexpected code execution, memory poisoning, inter-agent communication, cascading failures, human trust exploitation, rogue agents, disclosure, and denial of wallet.

Bundled matchers cover high-signal portions of TypeScript/JavaScript, Python, Go, Ruby, Rust, Java, C#, PHP, PowerShell, batch, SQL migrations, Firebase rules, major CI systems, Docker, Kubernetes, and Terraform. Other detected languages and workflows are marked profile-only or unsupported and routed to manual review.

## Project-Local Matchers

`$vibesecurity teach` writes rules under `.vibesecurity/matchers/`. The format is a deliberately restricted YAML subset so the helper stays dependency-free and predictable:

- lowercase unique id;
- one allowed category, severity, and confidence; optional `cwe`, `owasp`, `asvs` ids (validated);
- case-insensitive substring `patterns`, bounded `regex_patterns` (no backreferences or nested unbounded quantifiers), `exclude_patterns`, `same_line_terms`, `nearby_terms`, and `nearby_excludes`;
- one-line scalar values only;
- bounded lists and field lengths;
- positive and negative examples, run through the engine in CI.

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

CI runs the suite on Windows, macOS, and Linux against the minimum supported Python and a current Python release. GitHub Actions are pinned to immutable full commit SHAs with read-only repository permissions. The suite validates every bundled matcher example through the engine, measures secret-format recall and precision on a templated corpus, and checks the CVSS calculator against known-answer vectors.

## Safety and Limits

VibeSecurity is for defensive review of authorized code. It does not perform live exploitation, credential theft, persistence, evasion, malware behavior, unauthorized network scanning, or secret exfiltration. Safe proof means code-path reasoning, local tests, mocks, and harmless fixtures.

The helper is not a data-flow engine. A clean scan means only that no bundled matcher, secret-format rule, cached advisory, or registry check fired inside the reported selection budget. SCA matches say a pinned version is inside an advisory range; exploitability in your code still needs review, and EPSS is a population-level probability, not a verdict about your deployment. Version comparison supports the semver and PEP 440 subset documented in the tests; unparseable versions are reported, never guessed. CVSS v4.0 vectors are reported but not scored. Registry checks cover npm and PyPI only. `feed refresh` is the only networked command. The final report must state manual checks, skipped/truncated surfaces, unsupported areas, tools actually run, and residual risk.

## Repository Layout

```text
.agents/skills/vibesecurity/
  SKILL.md
  agents/openai.yaml
  references/
    evidence-base.md
    review-lanes.md
    standards/          CWE, CWE Top 25 2025, ASVS 5.0.0, OWASP 2025 data
    matchers/           high-signal, vibecoder, trust-boundaries, supply-chain, leaks, ai-agentic
    formats/            secrets.yaml (92 token formats)
    framework-notes/    supabase, firebase, nextjs, express, fastapi, django, ...
    examples/
  scripts/
  assets/templates/
  tests/
docs/
```
