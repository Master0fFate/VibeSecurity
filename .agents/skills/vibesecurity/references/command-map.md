# Command Map

## `$vibesecurity brief`

Create or update `.vibesecurity/PROJECT_SECURITY_PROFILE.md` from package files, routes, auth modules, CI files, AI surfaces, and deployment hints. Keep it concise and treat it as reviewer aid, not ground truth.

## `$vibesecurity diff`

Use `git diff --name-only`, staged changes, and untracked files. Classify changed files by risk, read minimal support context, then report confirmed findings or coverage caveats.

## `$vibesecurity scan`

Run `python .agents/skills/vibesecurity/scripts/vibesecurity.py scan` when local execution is appropriate. Treat output as candidates. Read `project`, `scope.coverage`, `rule_packs`, `files_skipped`, `truncated`, and `unsupported_or_profile_only` before judging coverage. Manually validate reachable data flow, security boundary crossing, and impact before reporting a finding.

## `$vibesecurity deep <scope>`

Require a path, feature, or risk class. Cap context to the scoped files plus direct auth/schema/tool/route support. Prefer multiple small passes over a full-repo review.

## `$vibesecurity recheck`

Re-read affected files and tests. Mark each finding fixed, unresolved, false-positive, or uncertain. Do not claim a fix without code evidence.

## `$vibesecurity fix <finding-id|all> [--review-only]`

Apply guarded remediation for a confirmed finding, or render a remediation plan when the user requests review-only.

Rules:

- Load `references/remediation-playbook.md`.
- If a findings file exists, run `python .agents/skills/vibesecurity/scripts/vibesecurity.py fix-plan --input .vibesecurity/findings.json --finding <finding-id|all>`.
- Patch only `status: confirmed` findings. Keep matcher hits and `needs-review` items blocked until reachability, boundary crossing, impact, and verification are validated.
- If the user says review-only, run `fix-plan --review-only`, report the plan, and do not edit files.
- Explain the security invariant before patching, patch minimally, add or update tests when possible, then recheck.
- Never claim a finding is fixed without re-reading changed code and verification output.

## `$vibesecurity patch <finding-id>`

Alias the workflow to `$vibesecurity fix <finding-id>` when the user says patch, remediate, auto-fix, or fix vulnerabilities.

## `$vibesecurity teach`

Convert confirmed true positives into local matcher entries with one positive and one negative example. Matchers generate candidates only.

## `$vibesecurity ai [scope]`

Review prompt injection, unsafe tools, model output handling, retrieval authorization, secret leakage, excessive agency, and cost/resource controls.
