# VibeSecurity Enterprise Upgrade Program

Status: approved plan · Not yet implemented · Owner: VibeSecurity maintainers
Baseline audited: repository `main`, skill version 2.1.0
Program goal: close the "newest vulnerabilities and leaks" gap and raise VibeSecurity to daily-enterprise-use quality, without breaking its local-first, candidate-first design.

Notation used in this document:

- `[pending product decision: X]` — a choice the maintainers must make before implementation.
- `[to be decided: X]` — an engineering detail left open on purpose.
- `[source needed: X]` — a claim that is not yet verified against a primary source. Do not act on it until verified.
- Effort unit: one engineer-week (EW). Team assumption: 2–3 engineers.
- TTD = time-to-detect: hours between public advisory publication and VibeSecurity flagging a repository that uses an affected version.

---

## 1. Current-State Assessment

### 1.1 What VibeSecurity is

VibeSecurity is a security-review skill pack for coding agents (Codex, Claude Code) plus a local Python helper. It is distributed through the open Agent Skills specification (`npx skills add`). The helper is a CLI-style command set: `inventory`, `diff`, `scan`, `report`, `fix-plan`. The agent commands (`brief`, `deep`, `ai`, `recheck`, `fix`, `teach`) are agent workflows, not Python subcommands.

Technology and deployment model (all verified in the repository):

| Property | Current value | Evidence |
| --- | --- | --- |
| Runtime | Python 3.11+, standard library only | `scripts/*.py`, no imports outside stdlib |
| Network calls | None, by design | README "the helper ... makes no network requests" |
| Detection engine | Bounded substring matchers with glob filters and nearby-term windows | `scripts/vibesecurity_matchers.py` |
| Bundled rules | 33 matchers in 4 packs: `high-signal` (9), `supply-chain` (10), `trust-boundaries` (6), `ai-agentic` (8); plus 3 built-in fallback rules | `references/matchers/*.yaml`, `fallback_matchers()` |
| Local rules | Project matchers under `.vibesecurity/matchers/`, restricted YAML subset | `matcher_paths()`, `assets/templates/matcher.yaml` |
| Fix path | `fix-plan` emits category-level remediation steps for `status: confirmed` items only; never edits source | `scripts/vibesecurity_remediation.py` |
| Report | JSON and Markdown; confirmed / closed / needs-review kept separate; redaction of secrets and terminal controls | `scripts/vibesecurity_report.py`, `vibesecurity_common.py: redact(), visible_text()` |
| Bounds | 200 candidates, 25,000 files, 1 MB/file, 250 MB total, 512 matchers; truncation and skip counts reported | `vibesecurity_common.py` `MAX_*` constants |
| CI | GitHub Actions matrix (Windows/macOS/Linux × Python 3.11/3.14), actions pinned by commit SHA, read-only permissions | `.github/workflows/ci.yml` |
| Tests | Dependency-free suite: scan, report, remediation, hardening behaviors + adversarial fixtures | `tests/run_tests.py` |
| Standards baseline | OWASP ASVS 5.0.0, OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026 [pending product decision: confirm 2026 list is published; the repo already cites it], NIST SP 800-218A (SSDF), CISA Secure by Design, SLSA | `references/standards-map.md`, README |

### 1.2 Detection inventory (what it finds today)

Verified by reading the matcher catalog and scan code:

- **Secrets:** substring markers (`api_key`, `client_secret`, `BEGIN PRIVATE KEY`, ...) with `=`/`:` nearby terms. No entropy analysis. No provider token formats. No git-history scan.
- **Authorization/authentication:** sensitive-looking route handlers (Next.js, Express, FastAPI, Flask-style decorators, Rails, Spring, .NET, PHP) flagged for manual auth review.
- **Injection/sinks:** `eval`, `exec`, `os.system`, `child_process`, SQL string building, path joins with variables (per `high-signal.yaml`, `trust-boundaries.yaml`).
- **SSRF:** request sinks with user-influenced URLs.
- **CI/CD and supply chain:** `pull_request_target` workflows, unpinned GitHub Actions, install scripts in manifests, unpinned base images, curl-pipe-shell patterns.
- **AI/agentic:** model output into command execution, dynamic tool loading, agent memory writes, MCP patterns, delegated identity.
- **Crypto/TLS:** disabled certificate verification, weak randomness, hardcoded JWT secrets.

All results are candidates with `status: needs-review`. The skill gate requires the agent to prove reachability, boundary crossing, impact, and verification before a finding becomes `confirmed`.

### 1.3 What it does NOT do today (the honest list)

These are the facts that drive the gap analysis:

1. **No vulnerability data ingestion.** There is no feed, database, or cache of published advisories. The rule packs are frozen at repository release time. A CVE published yesterday is invisible unless a bundled substring rule happens to match its pattern.
2. **No dependency analysis (no SCA).** The helper reads no lockfiles. It never maps installed package versions to known-affected ranges. Optional analyzers (`npm audit`, `pip-audit`, `cargo-audit`, Semgrep, Gitleaks, ast-grep) are discovered but never executed.
3. **No secret verification or secret classes beyond substrings.** No entropy scoring. No recognition of token formats (cloud access keys, package-registry tokens, signed URLs). No scan of git history. Secrets stay in history after deletion; today VibeSecurity only reads the working tree.
4. **Fix guidance is generic.** `remediation_item()` output has `remediation_steps`, `verification`, and `standards` fields. There is no `sources` field. Nothing forces a fix plan to cite a CVE, GHSA, OSV, or vendor advisory.
5. **No CI gating contract.** No documented exit-code matrix, no `--fail-on` policy, no SARIF output, no baseline/suppression file, no stable finding IDs across runs.
6. **No advisory freshness accounting.** Because no data is ingested, no output can state how current the vulnerability knowledge is.

### 1.4 Strengths the program must keep

- Local-first, offline-clean, stdlib-only helper. Fast, auditable, no supply-chain surface of its own.
- Candidate-vs-confirmed separation. This is the anti-false-positive core.
- Explicit coverage accounting: skipped files, truncation, matcher warnings, profile-only surfaces.
- Hostile-input handling: repository text is untrusted data; secrets are redacted in every output path.
- Tests run in CI on three operating systems.

Design rule for this program: every new capability is added as an opt-in layer. The offline default behavior must not change without a major-version decision.

---

## 2. Gap Analysis

Each gap states: the class missed, the attack scenario it leaves open, and why the current tool misses it. Every gap maps to at least one improvement in Section 3 (mapping shown in the ID column).

### G1. New CVEs and advisories (detection currency) → A1, A3

- **What is missed:** any vulnerability whose detection depends on published advisory data — dependency CVEs, patched library versions, newly disclosed exploit techniques.
- **Attack scenario:** a company updates a dependency on Monday; the advisory lands Tuesday; VibeSecurity (frozen rules) reports nothing on Wednesday. The attacker who reads the advisory exploits the window.
- **Why missed:** no ingestion path exists. Matchers are static text rules, version-blind by construction.
- **Reference class (real, named for context; verify details in the cited databases before reuse):** CVE-2021-44228 (Log4Shell) showed that a single library advisory can expose thousands of downstream projects within hours of disclosure. Logfile-pattern rules could not have caught it; version-range matching against advisories could.

### G2. Dependency/lockfile blindness (SCA) → A2, A3, A5

- **What is missed:** known-vulnerable package versions pinned in `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `requirements.txt`, `Pipfile.lock`, `go.mod`/`go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, Gradle/pom dependency trees.
- **Attack scenario:** an app pins a compromised or vulnerable transitive dependency. An attacker uses a published exploit against it. VibeSecurity sees the manifest text, flags install scripts at most, and stays silent about the version.
- **Why missed:** no lockfile parsers, no advisory matching, no version-range logic. The inventory step detects package managers (`vibesecurity_inventory.py`) but never resolves versions.

### G3. Actively exploited vulnerabilities (KEV) → A4

- **What is missed:** escalation context. CISA publishes a Known Exploited Vulnerabilities (KEV) catalog. Presence on that list changes response priority from "schedule" to "now".
- **Attack scenario:** two medium-severity CVEs; one is exploited in the wild per KEV, one is not. Current tooling treats them identically. The exploited one waits in a backlog while an attacker uses it.
- **Why missed:** no KEV ingestion, no severity escalation data path.

### G4. Live secret leaks in the working tree → B1, B2

- **What is missed:** real provider tokens whose key names do not match the six bundled substrings — for example a random-looking token assigned to an innocent variable name, or a credential format that carries its own structure (cloud access-key prefixes, JWTs, private key blocks in unusual filenames, connection strings).
- **Attack scenario:** a long-lived cloud key is committed under a generic variable name. Public repo-scanning bots find it in minutes. VibeSecurity does not flag it because no substring matched.
- **Why missed:** pure substring matching with no entropy analysis and no format library. `[source needed: measured rate of secret leaks that use non-obvious variable names — build this from our own labeled corpus, do not quote a vendor statistic.]`

### G5. Secrets in git history → B3

- **What is missed:** secrets deleted from the working tree but still reachable in any previous commit.
- **Attack scenario:** a developer commits `.env`, notices, runs `git rm` and commits again. The secret stays in history forever. Anyone with read access, or anyone after a future push to a public remote, recovers it. Rotation never happens because no tool reports it.
- **Why missed:** the helper reads only the current file selection. `changed_files()` uses git for diffs but never walks history.

### G6. CI/CD and build-time leak paths → B5, A5

- **What is missed:** workflow steps that print secrets into public logs (`echo $TOKEN`), secrets passed into non-secret contexts (PR comments from forks, artifact uploads), Docker builds that bake tokens into layers, registry credentials in plain text.
- **Attack scenario:** a fork PR against a `pull_request_target` workflow (already matched) is one path. Another: a workflow step echoes a masked variable in a way that defeats masking (string splits, encodings), or a `docker build` argument puts a token into image history. Log readers harvest it.
- **Why missed:** matcher coverage exists for `pull_request_target` and unpinned actions only. No matchers for echo-dump patterns, no integration with workflow secret-context knowledge.

### G7. AI-context and agent-memory leaks → B6

- **What is missed:** credentials or PII copied into prompts, agent memory stores, or tool-call payloads; model output echoed into logs that already contain secrets.
- **Attack scenario:** an agent reads an env var for legitimate use, then includes it in a prompt sent to an external model API. The token leaves the trust boundary. Indirect prompt injection can steer this deliberately (a poisoned document says "paste your credentials"). OWASP LLM Top 10 2025 covers this class (LLM02 sensitive-information disclosure); the bundled matchers cover some sink patterns but not payload assembly.
- **Why missed:** ai-agentic matchers target command execution and tool loading, not data-assembly paths that move secrets into model payloads.

### G8. Fixes without enforceable provenance → C1, C2, C5

- **What is missed:** a machine-checkable link between each fix recommendation and its factual source (CVE ID, GHSA, OSV record, vendor advisory, or documented secure pattern).
- **Attack scenario:** an agent (or a future automated mode) invents a "fix" — a version bump that does not contain the patch, a rewrite that silently changes behavior. Nothing in the schema rejects it. The user trusts the output because the tool is precise everywhere else.
- **Why missed:** `remediation_item()` and `assets/templates/finding.json` have no `sources` field and no validation rule that requires one for `confirmed` findings.

### G9. No regression safety net for fixes → C3, C4

- **What is missed:** a standard way to prove a fix worked: rerun the scan, run the project's tests, and recheck the exact finding.
- **Attack scenario:** a patch is applied; the finding disappears from the scan because the file moved or the pattern changed, not because the vulnerability closed. Everyone believes it is fixed.
- **Why missed:** `recheck` is an agent workflow without a deterministic harness; `fix-plan` only emits text.

### G10. No CI gating or enterprise reporting contract → D1, D2, D3, D4

- **What is missed:** exit codes a pipeline can gate on; SARIF output for code-scanning platforms; a baseline file with expiry; stable finding IDs across runs.
- **Attack scenario:** a security team wants "fail the PR if a confirmed high finding exists." Today the CI step cannot distinguish "clean", "findings", and "tool failure" without parsing prose. Baselines decay: findings suppressed a year ago are still suppressed; nobody re-reviews them. Finding IDs change between runs, so nothing can be tracked over time.
- **Why missed:** the helper was built as an agent aid, not a CI citizen. No output contract exists for machines.

### G11. No freshness/audit story for air-gapped or regulated environments → D5, D7, D8

- **What is missed:** offline advisory snapshots with checksums; payload fields that state the age of the data; a policy file for org-level thresholds; versioned releases of the advisory schema.
- **Attack scenario:** a regulated enterprise pins an old snapshot without knowing it. Audit asks "what vulnerability data did you use on 2026-05-01?" Nothing in the tool can answer.
- **Why missed:** no data layer exists yet at all.

### Coverage boundary stated for honesty

Some recent vulnerability classes are out of scope for a repository-scanning tool by nature: vulnerabilities in installed runtimes and binaries (example class: CVE-2024-6387, the OpenSSH "regreSSHion" race condition, lives in the sshd binary, not in project source or lockfiles). The program adds no host-scanning capability. The report must keep stating these limits. Likewise, supply-chain compromises that ship only in release tarballs and not in source control (example: CVE-2024-3094, the xz-utils backdoor, affected upstream release tarballs, not the git repository content) require build-provenance controls outside this tool's reach; VibeSecurity can only contribute markers (checksum pinning rules) — the real answer lives in build pipelines (SLSA provenance). [source needed: confirm exact affected-version ranges for CVE-2024-3094 and CVE-2024-6387 against NVD/OSV before citing them in user-facing output.]

---

## 3. Improvement Proposals

Four tracks. Every item carries the five required fields plus an ID used by the backlog and roadmap.

### Track A — Detection currency

#### A1. Advisory feed ingestion and local cache (`feed` subcommand)

- **Problem it solves:** G1. VibeSecurity has no path from "advisory published" to "candidate produced". Target TTD: `[pending product decision: 24h vs 48h]` after publication.
- **Proposed solution:** new opt-in `feed` subcommand that pulls three named sources into `.vibesecurity/cache/` (already gitignored): (1) OSV.dev — full ecosystem dumps and/or API queries per package; (2) CISA KEV catalog JSON; (3) GitHub Advisory Database (GHSA). The core scan stays offline-clean: `scan` only reads the cache. Cache carries `fetched_at`, source, and a sha256 per file. Every payload that uses cache data emits `advisory_db: {source, fetched_at, age_hours, sha256}`. If age exceeds `[pending product decision: max age, suggest 72h]`, scan emits a visible staleness warning and downgrades advisory-based results to `needs-review`.
- **Affected modules/files:** new `scripts/vibesecurity_feed.py`; `vibesecurity.py` (subcommand); `vibesecurity_common.py` (cache bounds); `vibesecurity_scan.py` (staleness fields); `.gitignore` (document cache path).
- **Dependencies:** urllib (stdlib) for HTTPS; `[to be decided: exact OSV dump endpoints and retry/backoff policy]`; no third-party packages.
- **How the effect is measured:** TTD replay harness (test): freeze dated advisory snapshots and a fixture repo using an affected version; assert the fixture is flagged within the harness when the snapshot is present, and that `advisory_db.age_hours` is reported. Metric: median TTD across the replay corpus ≤ target; 100% of cache-consuming payloads include the provenance block.

#### A2. Lockfile and manifest inventory (`deps` subcommand)

- **Problem it solves:** G2. The helper cannot see package versions.
- **Proposed solution:** stdlib parsers produce a normalized dependency inventory: `{ecosystem, name, version, source_file, line}`. Initial set: `package-lock.json` (v2/v3), `yarn.lock` (v1; berry `[to be decided]`), `pnpm-lock.yaml` (subset fields only), `poetry.lock`, pinned `requirements*.txt`, `Pipfile.lock`, `go.mod`+`go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`. Gradle and Maven are `[to be decided: parse lockfiles only, not build graphs]`. Unknown formats are reported as `unsupported`, never silently skipped.
- **Affected modules/files:** new `scripts/vibesecurity_deps.py`; `vibesecurity_inventory.py` (reuse manifest detection); `vibesecurity_common.py` (size bounds).
- **Dependencies:** none beyond stdlib; yaml subsets parsed with the same restricted-subset discipline used by matcher files.
- **How the effect is measured:** parse success rate on a fixture corpus of real-format lockfiles: ≥ 98% of entries extracted with correct name/version; unit tests pin behavior per format; unsupported formats always produce an explicit `unsupported` record.

#### A3. Advisory matching engine (offline SCA match)

- **Problem it solves:** G1+G2 end-to-end: map dependency inventory to cached advisories.
- **Proposed solution:** match `name+version` against OSV `affected` ranges (ecosystem/SEMVER and ECOSYSTEM types; GIT ranges marked unsupported with warning). Output candidate findings with `advisory_ids[]` (CVE + GHSA + OSV aliases), `affected_range`, `fixed_version` — all copied verbatim from advisory data, never computed by guesswork. Empty `fixed_version` in the advisory is surfaced as "no fix published", not as a guessed version.
- **Affected modules/files:** new `scripts/vibesecurity_sca.py`; `vibesecurity_scan.py` (merge into candidates with `source: "advisory"`); `vibesecurity_prioritize.py` (advisory ranking).
- **Dependencies:** A1 (cache), A2 (inventory), stdlib semver-subset comparison `[to be decided: full PEP 440/semver handling scope — start with exact + caret ranges]`.
- **How the effect is measured:** replay corpus test: for each dated snapshot, recall of known-affected fixture pairs = 100% (no false negatives in corpus), and 100% of emitted advisories carry verifiable IDs and copied range data. Zero fabricated versions is asserted mechanically (every `fixed_version` must exist in the advisory record).

#### A4. KEV enrichment and severity escalation

- **Problem it solves:** G3.
- **Proposed solution:** when an advisory ID (CVE) appears in the cached KEV catalog, the candidate gets `kev: true`, `known_exploited: true`, and severity escalated one band (max: critical) with a visible reason string.
- **Affected modules/files:** `vibesecurity_sca.py`; `vibesecurity_prioritize.py`; report templates.
- **Dependencies:** A1, A3.
- **How the effect is measured:** dated KEV snapshot test: 100% of KEV-listed advisories in the corpus are flagged; no non-KEV advisory is escalated; escalation reason always present.

#### A5. Optional-analyzer execution bridge

- **Problem it solves:** G2/G6 depth where a native tool already exists on the machine (npm audit, pip-audit, cargo-audit, govulncheck, Semgrep, Gitleaks).
- **Proposed solution:** explicit opt-in flag `--run-analyzers <list>` (config-gated, see D7) executes discovered analyzers with JSON output where supported, normalizes results into the candidate stream with `tool`, `tool_version`, `exit_code`, and rule IDs preserved. Failures become warnings, never silent skips. Default stays discovery-only.
- **Affected modules/files:** `vibesecurity_coverage.py` (analyzer discovery already exists); new `scripts/vibesecurity_bridge.py`; `vibesecurity_scan.py`.
- **Dependencies:** D7 (policy), subprocess handling with timeouts `[to be decided: per-analyzer timeout table]`.
- **How the effect is measured:** bridge fixture test per supported analyzer: normalized output parses, provenance fields present, nonzero exits produce warnings; measured added wall-clock ≤ `[to be decided: budget per analyzer]`.

### Track B — Leak coverage

#### B1. Provider token-format secret engine

- **Problem it solves:** G4 for structured credentials.
- **Proposed solution:** a data-driven format library (regex + optional checksum validators, kept in versioned YAML like matchers) for credential families: cloud access keys, JWTs, private key blocks, package-registry tokens, database/connection URLs with embedded passwords, signing keys, webhook URLs with tokens. Format definitions carry provider class only — no real secrets, ever. Each detection reports file, line, key name (when present), format id, and a fully redacted preview. Values are never emitted; the redaction path in `vibesecurity_common.py` stays the only renderer.
- **Affected modules/files:** new `references/formats/secrets.yaml`; new `scripts/vibesecurity_secrets.py`; `vibesecurity_common.py` (redaction remains single-source).
- **Dependencies:** none external. Fixture corpus generated locally (fake tokens in documented formats); no real credentials in tests.
- **How the effect is measured:** labeled corpus (initial target: ≥ 200 positive samples across families, ≥ 500 negatives): recall ≥ `[pending product decision: suggest 90%]`, precision ≥ `[pending product decision: suggest 90%]`, measured by the test suite on every run; corpus and scores committed with the code.

#### B2. Entropy-based secret candidates

- **Problem it solves:** G4 for unstructured high-entropy strings.
- **Proposed solution:** Shannon entropy scoring over string literals and env-style values above a length floor, gated to files with secret-adjacent context (existing nearby terms), emitted only as low-confidence `needs-review` candidates. Thresholds versioned in config; `[to be decided: default threshold — calibrate on corpus before setting]`.
- **Affected modules/files:** `vibesecurity_secrets.py` (shared with B1); minimal stdlib tokenizer `[to be decided: per-language tokenization scope]`.
- **Dependencies:** B1 corpus for calibration.
- **How the effect is measured:** corpus-graded false-positive rate per 1,000 lines on clean fixture repos; target `[pending calibration]`; suite fails if the rate regresses beyond tolerance.

#### B3. Git history secret scan (`history` subcommand)

- **Problem it solves:** G5.
- **Proposed solution:** bounded `git log -p` walk (default window `[pending product decision: suggest 12 months]`, `--all-refs` optional) streamed through the B1/B2 detectors; output reports commit hash (short), file, line, format id — never the value. Bounds: max bytes per commit diff, max commits, hard timeout; breaches become explicit warnings. Deleted-file secrets that only exist in history are reported with `only_in_history: true`.
- **Affected modules/files:** new `scripts/vibesecurity_history.py`; reuses `run_git` from `vibesecurity_scan.py`.
- **Dependencies:** B1, B2; git present (already required for `diff`).
- **How the effect is measured:** synthetic-repo fixture with planted secrets at known commits: 100% detected; bounded runtime verified on a large synthetic history `[to be decided: size target]`; no secret values appear in any output (automated leak assertion).

#### B4. Redaction hardening and secret-handling policy

- **Problem it solves:** defense-in-depth for every output path, including `.env`-style files named in the internal review.
- **Proposed solution:** extend `redact()` rules; for `.env`, `.env.*`, and secret-named files, emit path+line+key name and a placeholder only — no raw snippet even if it "looks harmless"; add leak assertions to the test suite that scan all report fixtures for known fake-secret markers.
- **Affected modules/files:** `vibesecurity_common.py` (`redact`, `redacted_snippet`); `vibesecurity_report.py`; tests.
- **Dependencies:** none.
- **How the effect is measured:** automated assertion: zero occurrences of planted fake secrets in every rendered output fixture; unit tests per redaction rule; suite fails on any leak.

#### B5. CI/CD leak-pattern matchers

- **Problem it solves:** G6.
- **Proposed solution:** new matcher pack `references/matchers/leaks.yaml`: secrets echoed into logs (`echo`/`print` of secret-named vars), secrets in workflow `env:` blocks exposed to fork-triggerable jobs, `docker build` argument passthrough of token-named variables, artifact upload of secret-named files. Patterns are structure-based (names + contexts), not provider-specific.
- **Affected modules/files:** `references/matchers/leaks.yaml`; fixture tests.
- **Dependencies:** none (pure matcher addition).
- **How the effect is measured:** fixture corpus of positive and negative workflow samples; each matcher ships both; suite asserts hits and non-hits.

#### B6. AI-context leak matchers

- **Problem it solves:** G7.
- **Proposed solution:** matcher pack additions targeting secret-bearing data flowing into model payloads, prompt assembly, agent memory writes, and tool-call arguments; review prompts direct the agent to trace the data path (consistent with the existing OWASP LLM mapping in `standards-map.md`).
- **Affected modules/files:** `references/matchers/ai-agentic.yaml` (extend); `references/ai-agentic-checklist.md`.
- **Dependencies:** none.
- **How the effect is measured:** fixture tests (positive + negative); candidate count on an AI-app fixture corpus increases only for intended patterns (precision check in suite).

### Track C — Fix quality

#### C1. Mandatory source citations in the finding/fix schema

- **Problem it solves:** G8.
- **Proposed solution:** add `sources[]` to `assets/templates/finding.json`, the report renderer, and `remediation_item()`. Rules: `confirmed` findings require ≥ 1 source of type `CVE | GHSA | OSV | KEV | vendor-advisory | standard | documented-pattern`, each with a stable identifier and (when applicable) a URL; `needs-review` items may omit sources; `fix-plan` refuses to emit patch guidance for `confirmed` items with zero sources and reports them under a `blocked: missing-source` section instead.
- **Affected modules/files:** `assets/templates/finding.json`, `vibesecurity_remediation.py`, `vibesecurity_report.py`, `references/finding-schema.md`, tests.
- **Dependencies:** none. This is the enforcement backbone for the no-made-up-patches rule.
- **How the effect is measured:** schema validation test: 100% of confirmed items in the corpus carry ≥ 1 source; the blocked path is exercised; zero advisory-style claims without a resolvable identifier.

#### C2. Advisory-driven dependency fix data

- **Problem it solves:** the version-bump half of G8.
- **Proposed solution:** for advisory findings (A3), the fix plan's recommended version is computed only from the advisory's own `fixed` range data (select smallest known-good version satisfying the range, as published). If the advisory has no fix range, the plan states "no fixed version published; mitigation options: [from advisory text or vendor bulletin, quoted with source]" and never invents a version. Upgrade recommendations for non-advisory findings remain boundary-level guidance, clearly labeled.
- **Affected modules/files:** `vibesecurity_sca.py` → `vibesecurity_remediation.py` handoff; `references/remediation-playbook.md`.
- **Dependencies:** A1, A3, C1.
- **How the effect is measured:** property test: for every emitted version recommendation there exists a matching `fixed` entry in the advisory record (mechanical assertion); corpus of advisories without fixes produce zero invented versions.

#### C3. Fix verification harness (`fix --verify` semantics for the helper)

- **Problem it solves:** G9.
- **Proposed solution:** helper subcommand `verify` (agent maps it into `fix`/`recheck`): given a findings file and finding ids, it (1) reruns `scan` (and `deps`/SCA when applicable) on the patched tree, (2) asserts each target finding no longer fires, (3) optionally runs a user-supplied test command with a timeout, (4) emits a per-finding verdict: `verified | still-present | test-failed | inconclusive`. It never claims more than it measured.
- **Affected modules/files:** new `scripts/vibesecurity_verify.py`; `vibesecurity.py` (subcommand); `SKILL.md` helper mapping.
- **Dependencies:** D4 (stable IDs to match findings across runs); scan determinism.
- **How the effect is measured:** end-to-end fixture test: plant a known vulnerable pin (from a dated advisory snapshot), confirm, patch to fixed version, run `verify` → expect `verified`; tamper the patch → expect `still-present`; break tests → expect `test-failed`.

#### C4. Regression-test skeletons in fix plans

- **Problem it solves:** the "prove it stays fixed" half of G9.
- **Proposed solution:** `fix-plan` output gains `regression_test` guidance per category (skeleton text, never auto-applied): the smallest test that fails before the fix and passes after, plus where to put it. Sourced from the remediation playbook; playbook entries each gain a testable invariant statement.
- **Affected modules/files:** `vibesecurity_remediation.py`, `references/remediation-playbook.md`.
- **Dependencies:** C1.
- **How the effect is measured:** 100% of confirmed findings' fix plans include a regression_test block; suite asserts presence and non-emptiness.

#### C5. Anti-hardcoding rules and matcher review gate

- **Problem it solves:** keeps the tool project-agnostic (constraint) and blocks project-specific drift in `teach`-generated and bundled rules.
- **Proposed solution:** (1) loader rejects matcher rules containing absolute paths, home-dir expansions, or user names; (2) `teach`-generated matchers must pass their own positive and negative examples through the real engine before being written; (3) CI runs the full fixture corpus against every bundled matcher — a matcher that only fires on one specific project's files fails review; (4) documented review checklist for new rules (patterns must describe a class, not a project).
- **Affected modules/files:** `vibesecurity_matchers.py` (validation), `assets/templates/matcher.yaml`, new `tests/test_matcher_gate.py`, `.github/workflows/ci.yml` (unchanged runner, new suite member).
- **Dependencies:** none.
- **How the effect is measured:** gate tests: invalid rules rejected with explicit warnings; a deliberately project-specific matcher fixture causes suite failure; bundled matcher corpus pass rate = 100% in CI.

### Track D — Enterprise workflow readiness

#### D1. Exit codes and CI gating policy

- **Problem it solves:** G10 (machine-consumable verdict).
- **Proposed solution:** documented exit-code matrix: `0` clean; `1` findings at/above threshold; `2` tool error/incomplete scan (never silently clean); `3` usage error. Add `--fail-on <confirmed|confirmed-high|critical|none>` (default `none` to preserve current behavior; `[pending product decision: change default in 3.0]`). Thresholds act on confirmed findings only; candidates never fail a build.
- **Affected modules/files:** `vibesecurity.py` (entry), `vibesecurity_common.py`; README matrix.
- **Dependencies:** none.
- **How the effect is measured:** unit tests pin each exit path; documented matrix matches tests; no path returns `0` on tool failure.

#### D2. SARIF 2.1.0 output

- **Problem it solves:** G10 (platform ingestion: GitHub code scanning and other SARIF consumers).
- **Proposed solution:** `--format sarif` on `report` and `scan`: map candidates/findings to SARIF runs; rule ids = matcher/advisory ids; `partialFingerprints` from content hash; `properties` carry VibeSecurity provenance (advisory db block, coverage fields). Validate against the official SARIF 2.1.0 JSON schema in CI (schema vendored with checksum; stdlib jsonschema-free structural validation `[to be decided: minimal validator scope vs vendored schema]`).
- **Affected modules/files:** new `scripts/vibesecurity_sarif.py`; `vibesecurity_report.py`; CI step.
- **Dependencies:** D4 (fingerprints), OASIS SARIF 2.1.0 specification (OASIS Standard).
- **How the effect is measured:** CI validates all SARIF fixture outputs against the vendored schema; a manual acceptance step loads a sample into GitHub code scanning `[to be decided: smoke-test repository]`.

#### D3. Baseline and suppression with expiry

- **Problem it solves:** G10 (accepted-risk tracking without eternal suppression).
- **Proposed solution:** `.vibesecurity/baseline.json` (project-local, committed by the user's choice): entries `{finding_id_fingerprint, reason, approved_by, expires_on}`; loader applies suppressions only when unexpired; expired or unknown entries are reported visibly; max entry age `[pending product decision: suggest 180 days]`.
- **Affected modules/files:** new `scripts/vibesecurity_baseline.py`; `vibesecurity_report.py`, `vibesecurity_scan.py`.
- **Dependencies:** D4.
- **How the effect is measured:** tests: expired suppression re-fires the finding; tampered/unparseable baseline produces warning + full reporting (fail-open to visibility, never to silence).

#### D4. Stable finding IDs

- **Problem it solves:** G10 (tracking, baselines, verify harness).
- **Proposed solution:** deterministic fingerprint per candidate/finding: `sha256(kind + locator + evidence-normalized + advisory-id)` truncated, plus a stable ordinal for display (`VSEC-####` mapped via findings file). Same tree + same db snapshot → same IDs. Content change (file moved, line shift only) handled by a documented canonicalization (path-normalized locator).
- **Affected modules/files:** `vibesecurity_common.py`; `vibesecurity_report.py`; `vibesecurity_verify.py` (C3).
- **Dependencies:** none.
- **How the effect is measured:** determinism test: two runs on identical tree → identical IDs; line-only shift → same locator hash (documented behavior); patch → ID changes.

#### D5. Offline/air-gap mode with pinned snapshots

- **Problem it solves:** G11.
- **Proposed solution:** `feed export` writes a versioned, checksummed snapshot bundle (advisories + KEV + formats); `scan --advisory-db <bundle>` uses it with zero network. Each payload embeds bundle hash + created date. Optional integrity signing with sigstore/cosign `[pending product decision: adopt or document checksums only]`.
- **Affected modules/files:** `vibesecurity_feed.py`; docs; `[to be decided: bundle layout and rotation policy]`.
- **Dependencies:** A1, A3.
- **How the effect is measured:** air-gap test: network disabled environment flag; scan completes with pinned bundle; payload carries provenance; bundle sha mismatch → hard error.

#### D6. CI/CD integration recipes

- **Problem it solves:** G10/G11 adoption.
- **Proposed solution:** documented, minimal integrations: GitHub Actions (job template + SARIF upload), GitLab CI (job template), Jenkins (pipeline step), Azure DevOps (task script), plus pre-commit hook wiring for the agent-side commands. Each recipe states required permissions and the exit-code contract (D1).
- **Affected modules/files:** new `docs/integrations/*.md`; optional example workflow under `.github/` (non-triggering path).
- **Dependencies:** D1, D2.
- **How the effect is measured:** each recipe includes a copy-paste example validated once in a live pipeline by a maintainer; doc lint (links, command names) in CI.

#### D7. Policy configuration

- **Problem it solves:** G11 (org-level control).
- **Proposed solution:** `.vibesecurity/config.json` (schema-versioned): network on/off, allowed analyzers (A5), fail-on threshold overrides, history window, staleness limit, baseline max age. Precedence: CLI > config > built-in default. Unknown keys are warnings, not errors.
- **Affected modules/files:** new `scripts/vibesecurity_config.py`; all subcommands read it; docs.
- **Dependencies:** interacts with A1, A5, B3, D1, D3.
- **How the effect is measured:** config matrix tests: each option proven to change behavior; precedence test; unknown-key warning test.

#### D8. Versioning, releases, and support policy

- **Problem it solves:** G11 (enterprise trust in the artifact itself).
- **Proposed solution:** semantic versioning for the helper CLI and the matcher/format schemas separately (schemas carry their own `schema_version`); tagged releases with changelog; advisory-schema changes are additive-minor; release checklist (tests, corpus scores, snapshot regeneration); documented support: latest minor gets fixes `[pending product decision: support window length]`.
- **Affected modules/files:** README (versioning section), `CHANGELOG.md` (new), release workflow `[to be decided: GitHub Releases automation]`.
- **Dependencies:** none.
- **How the effect is measured:** release checklist doc exists and the first tagged release under this policy passes it (CI green, changelog present, corpus scores recorded).

---

## 4. Prioritized Backlog

Impact = security value for enterprise daily use. Effort = engineer-weeks (EW) for 1 engineer; parallelize across the team where noted.

| ID | Item | Track | Impact | Effort | Priority |
| --- | --- | --- | --- | --- | --- |
| A1 | Advisory feed + cache (`feed`) | Detection currency | Critical — enables all SCA freshness | 3 EW | P0 |
| A2 | Lockfile/manifest inventory (`deps`) | Detection currency | Critical — version visibility | 4 EW | P0 |
| A3 | Offline advisory matching (SCA) | Detection currency | Critical — newest-CVE detection | 3 EW | P0 |
| B1 | Token-format secret engine | Leak coverage | Critical — live credential leaks | 3 EW | P0 |
| C1 | Mandatory source citations schema | Fix quality | Critical — blocks invented fixes | 1.5 EW | P0 |
| D1 | Exit codes + `--fail-on` | Enterprise | High — CI gating contract | 1 EW | P0 |
| A4 | KEV enrichment | Detection currency | High — exploit-priority ordering | 1 EW | P1 |
| B2 | Entropy candidates | Leak coverage | High — non-obvious secrets | 2 EW | P1 |
| B3 | Git history scan (`history`) | Leak coverage | High — historical leaks | 2.5 EW | P1 |
| B4 | Redaction hardening | Leak coverage | Medium — output safety | 1 EW | P1 |
| C2 | Advisory-driven fix versions | Fix quality | High — factual version bumps | 1.5 EW | P1 |
| C3 | `verify` harness | Fix quality | High — proves fixes | 2 EW | P1 |
| C5 | Anti-hardcoding matcher gate | Fix quality | High — keeps tool project-agnostic | 1 EW | P1 |
| D3 | Baseline with expiry | Enterprise | High — accepted-risk hygiene | 1.5 EW | P1 |
| D4 | Stable finding IDs | Enterprise | High — enables D3/C3/SARIF | 1.5 EW | P1 |
| D7 | Policy configuration | Enterprise | Medium-High — org control | 2 EW | P1 |
| A5 | Analyzer execution bridge | Detection currency | Medium — depth via local tools | 2.5 EW | P1 |
| B5 | CI/CD leak matchers | Leak coverage | Medium — build-time leaks | 1 EW | P2 |
| B6 | AI-context leak matchers | Leak coverage | Medium — agent payload leaks | 1 EW | P2 |
| C4 | Regression-test skeletons | Fix quality | Medium — fix durability | 1 EW | P2 |
| D2 | SARIF 2.1.0 output | Enterprise | Medium-High — platform ingestion | 2 EW | P1 |
| D5 | Air-gap pinned snapshots | Enterprise | Medium — regulated environments | 1.5 EW | P2 |
| D6 | CI integration recipes | Enterprise | Medium — adoption | 1.5 EW | P2 |
| D8 | Versioning + support policy | Enterprise | Medium — trust and lifecycle | 1 EW | P2 |

Priority rationale: P0 = the program's stated goal is unreachable without it (newest-vulnerability detection, live-secret leaks, factual-fix enforcement, CI verdict). P1 = closes remaining gap classes and unlocks P0 value in pipelines. P2 = polish, breadth, and lifecycle items.

---

## 5. Phased Roadmap

Team: 2–3 engineers. Durations assume that team size. Every phase ends with acceptance tests a developer can run. No phase claims success without its tests passing.

### Phase 0 — Truth and trust foundations (Weeks 1–2)

Deliverables: C1 (source-citation schema + blocked path), D1 (exit codes + `--fail-on`), D4 (stable IDs), B4 (redaction hardening + leak assertions). Update `references/finding-schema.md`, README contract section.

Acceptance tests:

1. `python -B .agents/skills/vibesecurity/tests/run_tests.py` — all pass, including new schema/gate tests.
2. Feed a findings file with a `confirmed` item lacking `sources` → `fix-plan` places it under `blocked: missing-source` (JSON assertion in test).
3. Run `scan` twice on the fixture tree → identical finding fingerprints (determinism test).
4. Corrupt an output with a planted fake secret → leak assertion fails the suite (negative test proves the assertion works).
5. Exit-code matrix: `scan` on clean tree → 0; with confirmed high + `--fail-on confirmed-high` → 1; missing git in diff mode → 2 (unit tests pin each).

### Phase 1 — Leak coverage (Weeks 3–6)

Deliverables: B1 (format engine + labeled corpus + scores), B2 (entropy layer), B3 (`history` subcommand), B5 and B6 (matcher packs with fixtures).

Acceptance tests:

1. Corpus run reports recall/precision ≥ agreed targets; scores printed by the suite and stored under `tests/corpus-scores/` (committed).
2. Synthetic history repo: `python -B .agents/skills/vibesecurity/scripts/vibesecurity.py history --root tests/fixtures/leaky-history` reports every planted secret with commit hash and `only_in_history: true`, and no secret values appear in output (automated assertion).
3. `.env` fixture scan: output contains key names only, no values.
4. CI-leak matcher fixtures: each positive workflow sample fires; each negative stays silent.
5. AI-context fixtures: secret-into-prompt assembly candidates appear as `needs-review` with the expected review prompt.

### Phase 2 — Detection currency (Weeks 7–12)

Deliverables: A1 (`feed` + cache + provenance block), A2 (`deps` inventory), A3 (SCA matching), A4 (KEV escalation), A5 (analyzer bridge behind D7 config gate added in parallel).

Acceptance tests:

1. `feed refresh --root .` (network available) populates `.vibesecurity/cache/`; a second run is idempotent (hash-identical unless upstream changed).
2. `deps --root tests/fixtures/deps-sample` extracts ≥ 98% of corpus entries correctly (per-format unit tests).
3. TTD replay harness: with a dated OSV/KEV snapshot and a fixture repo pinning an affected version, `scan` produces an advisory candidate with correct IDs, copied `fixed_version`, and `advisory_db` provenance; harness reports median TTD for the replay corpus; target = agreed `[pending product decision: 24h/48h]`.
4. KEV-listed CVE in corpus → `known_exploited: true` + escalated severity + reason; non-KEV CVE → no escalation.
5. Staleness: backdate the cache snapshot beyond the limit → warning present and advisory results downgraded to `needs-review`.
6. `--run-analyzers npm-audit` (analyzer installed): normalized candidates carry `tool` + `tool_version` + `exit_code`; with the analyzer missing → explicit warning, exit unaffected.

### Phase 3 — Fix quality (Weeks 13–15)

Deliverables: C2 (advisory-driven versions), C3 (`verify` harness), C4 (regression skeletons), C5 (matcher gate + CI corpus).

Acceptance tests:

1. Property test: every version recommendation in the corpus maps to an advisory `fixed` entry (mechanical check, no exceptions).
2. Advisory without a fix range → plan states "no fixed version published" and cites the advisory; no version is suggested.
3. E2E fixture: vulnerable pin → confirm → upgrade → `verify` returns `verified`; revert the patch → `still-present`; break the test command → `test-failed`.
4. 100% of confirmed findings' fix plans include a non-empty `regression_test` block (suite assertion).
5. Matcher gate: commit a deliberately project-specific matcher → CI fails with the gate's message; remove it → CI green.

### Phase 4 — Enterprise rollout (Weeks 16–20)

Deliverables: D2 (SARIF), D3 (baseline with expiry), D5 (air-gap snapshots), D6 (integration recipes), D7 (policy config), D8 (versioning/support policy + first tagged release).

Acceptance tests:

1. SARIF outputs for all fixture findings validate against the vendored SARIF 2.1.0 schema in CI; one sample loads in GitHub code scanning (manual step, recorded in the release checklist).
2. Baseline: suppress a finding with `expires_on` in the future → suppressed; set it in the past → finding re-fires with a visible expired-suppression notice (test).
3. Air-gap: `feed export` → bundle; run `scan --advisory-db bundle` with networking disabled (CI job marks network off) → completes; tamper bundle → hard error.
4. Each integration recipe (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, pre-commit) executed once by a maintainer; PR references recorded.
5. Config matrix: every policy option changes the documented behavior (tests); precedence CLI > config > default proven.
6. First tagged release under D8 passes the release checklist: tests green on all three OSes, changelog present, corpus scores attached, snapshot regenerated and checksummed.

### Post-program metric (the program's own success gate)

- Median TTD on the replay corpus ≤ target for 4 consecutive weeks.
- Corpus recall/precision for secrets ≥ agreed thresholds for 4 consecutive weeks.
- Zero `confirmed` findings without sources across all test corpora (enforced mechanically).
- A daily CI run of VibeSecurity on a sample enterprise-shaped repo passes for 4 consecutive weeks with no false failure (exit 2) events.

---

## 6. Verification & Sources

### 6.1 Citation discipline (how every fix stays factual)

1. **Confirmed findings must cite.** From C1 onward, `confirmed` requires ≥ 1 resolvable source identifier: CVE ID, GHSA ID, OSV ID, KEV entry, vendor advisory URL, a published standard section, or a documented secure-pattern reference (for design findings that have no CVE). Unverifiable claims stay `needs-review`.
2. **Version data is copied, never computed.** Recommended fixed versions come verbatim from advisory `fixed` ranges (C2). A missing range yields "no fixed version published", never a guess.
3. **Advisory content is quoted, not paraphrased into facts.** Impact statements in output are taken from the advisory text with attribution, or written as review prose clearly marked as reviewer judgment.
4. **No real secrets anywhere.** Test corpora use locally generated fake tokens in documented formats. Redaction assertions (B4) run on every output fixture.
5. **Freshness is part of truth.** Every advisory-driven output carries the `advisory_db` provenance block; stale data downgrades results (A1).

### 6.2 Anti-regression and anti-hardcoding rules

1. **Determinism:** two scans of the same tree and same snapshot must produce identical fingerprints (D4 test). 
2. **Regression tests:** every confirmed fix ships with a regression-test skeleton (C4); the `verify` harness (C3) is the mechanical proof.
3. **Project-agnostic gate:** matchers may not contain absolute paths or single-project identifiers; every bundled matcher carries positive and negative examples; CI runs the full corpus (C5). Fixes target vulnerability classes and boundaries, never project-specific strings.
4. **No silent failures:** git errors, missing analyzers, stale caches, unparseable baselines, and unsupported formats all produce visible warnings (existing design rule; extended by A2/A5/D3).
5. **Exit-code honesty:** tool failure never returns "clean" (D1).
6. **Suite must fail closed:** every assertion above lives in the test suite; CI on three OSes is the enforcement floor.

### 6.3 Source register (primary sources used or planned by this program)

All items below are real, publicly documented sources; identifiers cited in shipped output must resolve against them. No statistic in this document comes from a vendor marketing source.

- **OSV.dev** — open vulnerability database, API, and schema (Google; osv.dev). Program use: A1/A3 advisory ingestion and matching.
- **CISA Known Exploited Vulnerabilities (KEV) catalog** — JSON feed on cisa.gov. Program use: A4.
- **GitHub Advisory Database** (GHSA IDs; github.com/advisories, CC-BY-4.0 licensed data). Program use: A1/A3.
- **CVE Program** (cve.org) and **NVD** (nvd.nist.gov) — CVE record resolution.
- **OASIS SARIF 2.1.0** — Static Analysis Results Interchange Format standard. Program use: D2.
- **NIST SP 800-218** (SSDF), **OWASP ASVS 5.0.0**, **OWASP LLM Top 10 2025**, **OWASP Agentic Top 10** `[source needed: confirm published status and exact title/year of the Agentic list the repo already cites]`, **SLSA** — standards mapping (already bundled in `references/standards-map.md`).
- **Reference vulnerability events** used only as motivating examples, each verifiable in the databases above: CVE-2021-44228 (Apache Log4j 2 JNDI RCE), CVE-2024-3094 (xz-utils backdoor in release tarballs), CVE-2024-6387 (OpenSSH regreSSHion). `[source needed: re-verify exact affected versions and publication dates against NVD/OSV before these appear in any user-facing artifact.]`
- **Named external tools referenced for integration/bridge design** (existence and public documentation verified; capability claims limited to their public docs): osv-scanner, cve-bin-tool, npm audit, pip-audit, cargo-audit, govulncheck, Semgrep, Gitleaks, TruffleHog, detect-secrets, ast-grep, pre-commit, Dependabot, Renovate, cosign/sigstore.

### 6.4 Anti-fabrication checklist (applies to this document and all future artifacts)

- Every CVE/advisory ID cited must exist in the source register's databases.
- Every capability claimed must be either present in the repository or listed in this program as not yet implemented. This document claims no future capability as current.
- Every metric target marked `[pending product decision]` or `[to be decided]` stays a placeholder until a dated decision record sets it. No placeholder is silently resolved.
- Every `[source needed]` item blocks publication of that claim in user-facing output until a primary source is attached.

### 6.5 Decisions required before Phase 2 starts

| Decision | Owner | Needed by | Default if unresolved |
| --- | --- | --- | --- |
| TTD target (24h vs 48h) | Product + security lead | End of Phase 1 | 48h (conservative) |
| Staleness limit for advisory cache | Security lead | End of Phase 1 | 72h |
| Secret corpus recall/precision targets | Security lead | Phase 1 kickoff | 90% / 90% |
| Default history scan window | Security lead | Phase 1 kickoff | 12 months |
| Baseline max age | Product | Phase 4 kickoff | 180 days |
| Snapshot signing (cosign vs checksums) | Security lead | Phase 4 kickoff | sha256 checksums only |
| `--fail-on` default change (3.0) | Maintainers | Phase 4 | Keep `none` |
| Support window length | Maintainers | Phase 4 | Latest minor only |

---

End of program. Implementation status of every item in this document: **not started**. The `main` branch remains the source of truth for current capability; README links here for the roadmap only.
