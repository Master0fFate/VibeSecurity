# VibeSecurity

> A lightweight defensive security review skill for vibe-coded repositories.

VibeSecurity gives your coding agent a focused security-review brain without turning your project into a scanner platform. Drop the skill into `.agents/skills/`, invoke `$vibesecurity`, and review diffs, routes, AI agents, dependencies, secrets, and CI/CD workflows with evidence-first discipline.

## Why Use It?

AI-assisted code moves fast. That is useful right up until a generated route skips authorization, an agent pipes model output into a shell, or a GitHub Actions workflow runs forked code with trusted permissions. VibeSecurity exists for that messy middle: the moment before you merge, when you want a cheap, local, security-focused second pass.

Use it when you want:

- **Defensive review without ceremony**: no npm package, SaaS account, gateway key, worker service, or cloud sandbox.
- **Lower token burn**: deterministic candidate discovery first, then targeted agent review only where risk appears.
- **AI-agent security coverage**: prompt injection, excessive agency, unsafe tool calls, retrieval authorization, secrets in prompts, and cost abuse.
- **Web/API coverage**: auth, object-level authorization, SSRF, injection, XSS, file paths, secrets, supply chain, and CI/CD risks.
- **Evidence-backed findings**: matchers create review candidates; the agent must confirm reachability, boundary crossing, impact, and remediation before calling something a vulnerability.

## Install

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
$vibesecurity teach
```

Agent-to-helper mapping:

- `$vibesecurity diff` may call `python .agents/skills/vibesecurity/scripts/vibesecurity.py diff`.
- `$vibesecurity scan` may call `python .agents/skills/vibesecurity/scripts/vibesecurity.py scan`.
- `$vibesecurity recheck` may call `scan` and `report`, then manually validate status.
- `$vibesecurity brief`, `deep`, `ai`, `fix`, and `teach` are agent workflows guided by the references.

## Optional Local Helper

The helper is read-only by default, has no third-party dependencies, and uses only the Python standard library.

Supported local helper commands are:

```text
inventory
diff
scan
report
```

```bash
python .agents/skills/vibesecurity/scripts/vibesecurity.py inventory
python .agents/skills/vibesecurity/scripts/vibesecurity.py diff
python .agents/skills/vibesecurity/scripts/vibesecurity.py scan
python .agents/skills/vibesecurity/scripts/vibesecurity.py report --input .vibesecurity/findings.json
```

`scan` returns candidates, not final findings. The payload includes `truncated`, `candidate_limit`, `candidates_returned`, skipped-file coverage, and git warnings when applicable. Your agent still has to validate code paths before reporting a vulnerability.

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
- Focused references for web/API, AI-agentic, supply-chain, secrets, and CI/CD review.
- Framework notes for Next.js, React, Express, Fastify, Hono, NestJS, FastAPI, Django, Flask, Rails, and Go HTTP.
- Small examples for missing auth, object-level auth, SSRF, LLM-output-to-shell, RAG prompt injection, and privileged PR workflows.
- Matcher catalogs that find high-signal candidates without claiming scanner certainty.
- Templates for findings, matchers, project profiles, and reports.
- Fixtures that prove the helper catches useful signals without full-repo AI review.

## Safety Boundaries

VibeSecurity is for code you own or are authorized to assess. It does not perform live exploitation, credential theft, malware behavior, persistence, evasion, unauthorized network scanning, or secret exfiltration. It redacts likely secrets and prefers local reasoning, tests, and mock inputs over live exploit proof.

## Design Philosophy

VibeSecurity is a skill pack, not a scanner product.

It starts cheap, stays local, and loads detail only when needed. The skill tells the agent how to think like a defensive reviewer, while the helper narrows attention to risky files and lines. That combination gives you the pressure point you want in a fast-moving codebase without dragging in a backend, package tree, or model-gateway dependency.
