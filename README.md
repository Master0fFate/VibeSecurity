# VibeSecurity

> A defensive security review skill pack for arbitrary repositories and worktrees.

VibeSecurity gives your coding agent a focused security-review brain without turning your project into a scanner platform or plugin runtime. Drop the skill into `.agents/skills/`, invoke `$vibesecurity`, and review diffs, routes, AI agents, dependencies, secrets, infrastructure, and CI/CD workflows with evidence-first discipline.

## Why Use It?

AI-assisted code moves fast. That is useful right up until a generated route skips authorization, an agent pipes model output into a shell, or a GitHub Actions workflow runs forked code with trusted permissions. VibeSecurity exists for that messy middle: the moment before you merge, when you want a cheap, local, security-focused second pass.

Use it when you want:

- **Defensive review without ceremony**: no npm package, SaaS account, gateway key, worker service, or cloud sandbox.
- **Lower token burn**: deterministic candidate discovery first, then targeted agent review only where risk appears.
- **AI-agent security coverage**: prompt injection, excessive agency, unsafe tool calls, retrieval authorization, secrets in prompts, and cost abuse.
- **Generic repository coverage**: language/workflow profiling, web/API auth, object-level authorization, SSRF, injection, XSS, file paths, secrets, supply chain, AI-agentic, infrastructure, and CI/CD risks.
- **Evidence-backed findings**: matchers create review candidates; the agent must confirm reachability, boundary crossing, impact, and remediation before calling something a vulnerability.

## Install With `skills`

The easiest install path is the open `skills` CLI:

```bash
npx skills add Master0fFate/VibeSecurity --skill vibesecurity
```

Useful variants:

```bash
# Install globally for detected compatible agents
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --global --yes

# Install to a specific agent
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent codex --global --yes

# Install to every supported agent target without prompts
npx skills add Master0fFate/VibeSecurity --skill vibesecurity --agent '*' --global --yes

# Inspect what the package exposes before installing
npx skills add Master0fFate/VibeSecurity --list
```

`skills` discovers VibeSecurity from `.agents/skills/vibesecurity/SKILL.md`, so the GitHub repository itself is the installable skill package. No npm package, SaaS account, API key, or build step is required.

## Requirements

Hard requirements:

- Code you own or are authorized to review.
- A coding agent that supports local skills installed from `.agents/skills/`.
- Node.js with `npx` for the `skills` CLI install path, or a manual copy of the skill folder.
- Python 3.11+ to run the optional local helper commands.
- Git for `$vibesecurity diff` risk classification.

Optional coverage enhancers:

- `sg` / ast-grep for AST-aware local checks.
- Semgrep for external rule packs.
- Gitleaks for dedicated secret scanning.
- `npm audit`, pip-audit, and cargo-audit for ecosystem dependency checks.

Missing optional tools do not break installation or scanning. VibeSecurity reports unavailable analyzers as coverage caveats and falls back to bundled rule packs plus manual agent validation.

## Manual Install

Copy the skill folder into any repository:

```bash
mkdir -p .agents/skills
cp -R path/to/VibeSecurity/.agents/skills/vibesecurity .agents/skills/
```

Then invoke it from your agent:

```text
$vibesecurity diff
```

## Agent Commands

These commands are handled by your coding agent after it loads the `vibesecurity` skill. They are not Python CLI subcommands.

```text
$vibesecurity brief
$vibesecurity diff
$vibesecurity scan
$vibesecurity deep src/app/api/billing
$vibesecurity ai src/agent
$vibesecurity recheck
$vibesecurity fix VSEC-0001
$vibesecurity fix all --review-only
$vibesecurity teach
```

Agent-to-helper mapping:

- `$vibesecurity diff` may call `python .agents/skills/vibesecurity/scripts/vibesecurity.py diff`.
- `$vibesecurity scan` may call `python .agents/skills/vibesecurity/scripts/vibesecurity.py scan`.
- `$vibesecurity recheck` may call `scan` and `report`, then manually validate status.
- `$vibesecurity fix` may call `python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan` before the agent applies patches to confirmed findings.
- `$vibesecurity brief`, `deep`, `ai`, and `teach` are agent workflows guided by the references.

`fix` is the remediation lane: it patches confirmed findings when you ask for a fix, patch, remediation, or auto-fix. It does not patch raw scan candidates. Use `--review-only` when you want the remediation plan without file edits.

## Optional Local Helper

The helper is read-only by default, has no third-party dependencies, and uses only the Python standard library.

Supported local helper commands are:

```text
inventory
diff
scan
report
fix-plan
```

```bash
python .agents/skills/vibesecurity/scripts/vibesecurity.py inventory
python .agents/skills/vibesecurity/scripts/vibesecurity.py diff
python .agents/skills/vibesecurity/scripts/vibesecurity.py scan
python .agents/skills/vibesecurity/scripts/vibesecurity.py report --input .vibesecurity/findings.json
python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --input .vibesecurity/findings.json --finding all
python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --input .vibesecurity/findings.json --finding VSEC-0001 --review-only
```

`scan` returns candidates, not final findings. The payload includes `project` profiling, `scope.coverage`, `rule_packs`, `matchers_loaded`, `truncated`, `candidate_limit`, `candidates_total`, `candidates_returned`, skipped-file coverage, optional analyzer availability, and candidate priority metadata. Your agent still has to validate code paths before reporting a vulnerability.

`fix-plan` returns patch-ready guidance only for `status: confirmed` findings. It blocks `needs-review` candidates so automated remediation cannot silently turn a matcher hit into a source edit.

## Smoke Tests

Run the bundled fixtures:

```bash
PYTHONDONTWRITEBYTECODE=1 python .agents/skills/vibesecurity/scripts/vibesecurity.py inventory --root .agents/skills/vibesecurity/tests/fixtures
PYTHONDONTWRITEBYTECODE=1 python .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root .agents/skills/vibesecurity/tests/fixtures
PYTHONDONTWRITEBYTECODE=1 python .agents/skills/vibesecurity/scripts/vibesecurity.py report --input .agents/skills/vibesecurity/tests/expected/findings.json
PYTHONDONTWRITEBYTECODE=1 python .agents/skills/vibesecurity/tests/run_tests.py
```

Expected candidate classes include:

- `missing-auth-route-candidate`
- `ai-output-to-shell`
- `github-actions-pr-target`
- `unpinned-github-action`

## What Is Included?

- `SKILL.md` with command routing, safety boundaries, and reference-loading rules.
- Focused references for web/API, AI-agentic, supply-chain, secrets, CI/CD, and coverage-truth review.
- Framework notes for Next.js, React, Express, Fastify, Hono, NestJS, FastAPI, Django, Flask, Rails, Go HTTP, and adjacent generic surfaces discovered by inventory.
- Small examples for missing auth, object-level auth, SSRF, LLM-output-to-shell, RAG prompt injection, and privileged PR workflows.
- Matcher catalogs that find high-signal candidates across TypeScript, JavaScript, Python, Go, Ruby, Rust, Java, C#, PHP, GitHub Actions, GitLab CI, Jenkins, Docker, Kubernetes, and Terraform without claiming scanner certainty.
- Templates for findings, matchers, project profiles, and reports.
- Fixtures that prove the helper catches useful signals without full-repo AI review.

## Skill-Pack Architecture

VibeSecurity remains an installable skill set:

```text
.agents/skills/vibesecurity/
  SKILL.md
  references/
  references/matchers/
  scripts/
  assets/templates/
  tests/
```

The helper is a progressively enhanced local candidate engine. It uses bundled YAML matcher packs and Python standard-library code by default. If local analyzers such as `sg`, Semgrep, Gitleaks, npm audit, pip-audit, or cargo-audit are installed, the helper reports their availability as coverage metadata; missing tools do not break installation or scanning.

Coverage is explicit. Inventory and scan payloads classify detected languages and workflows as `candidate-detector`, `profile-only`, or `unsupported`. Reports preserve those caveats so VibeSecurity does not imply broad coverage when only a narrow detector path ran.

## Safety Boundaries

VibeSecurity is for code you own or are authorized to assess. It does not perform live exploitation, credential theft, malware behavior, persistence, evasion, unauthorized network scanning, or secret exfiltration. It redacts likely secrets and prefers local reasoning, tests, and mock inputs over live exploit proof.

## Design Philosophy

VibeSecurity is a skill pack, not a scanner product.

It starts cheap, stays local, and loads detail only when needed. The skill tells the agent how to think like a defensive reviewer, while the helper narrows attention to risky files and lines. That combination gives you the pressure point you want in a fast-moving codebase without dragging in a backend, package tree, or model-gateway dependency.
