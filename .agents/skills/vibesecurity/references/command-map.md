# Command Map

## `$vibesecurity brief`

Create or update `.vibesecurity/PROJECT_SECURITY_PROFILE.md` from package files, routes, auth modules, CI files, AI surfaces, and deployment hints. Keep it concise and treat it as reviewer aid, not ground truth.

## `$vibesecurity diff`

Use `git diff --name-only`, staged changes, and untracked files. Classify changed files by risk, read minimal support context, then report confirmed findings or coverage caveats.

## `$vibesecurity scan`

Run `python .agents/skills/vibesecurity/scripts/vibesecurity.py scan` when local execution is appropriate. Treat output as candidates. Manually validate reachable data flow, security boundary crossing, and impact before reporting a finding.

## `$vibesecurity deep <scope>`

Require a path, feature, or risk class. Cap context to the scoped files plus direct auth/schema/tool/route support. Prefer multiple small passes over a full-repo review.

## `$vibesecurity recheck`

Re-read affected files and tests. Mark each finding fixed, unresolved, false-positive, or uncertain. Do not claim a fix without code evidence.

## `$vibesecurity fix <finding-id>`

Explain the security invariant, patch minimally only when the user wants edits, add or update tests where possible, then recheck.

## `$vibesecurity teach`

Convert confirmed true positives into local matcher entries with one positive and one negative example. Matchers generate candidates only.

## `$vibesecurity ai [scope]`

Review prompt injection, unsafe tools, model output handling, retrieval authorization, secret leakage, excessive agency, and cost/resource controls.
