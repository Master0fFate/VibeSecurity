# Changelog

All notable changes to VibeSecurity are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning for the helper CLI and the matcher/format schemas together.

## [3.0.0] - 2026-08-17

Enterprise upgrade program implemented. Breaking: confirmed findings now require source citations,
and helper exit codes are a documented contract.

### Added — detection currency (track A)

- `feed` subcommand: `refresh`, `status`, `export`, `import`. Pulls OSV
  (which aggregates GitHub GHSA advisories) per installed package and the CISA
  KEV catalog into a checksummed local cache under `.vibesecurity/cache/`.
  Refuses network use when policy disables it.
- `deps` subcommand: stdlib lockfile parsers for package-lock.json (v2/v3),
  yarn.lock v1, pnpm-lock.yaml (packages subset), poetry.lock, pinned
  requirements*.txt, Pipfile.lock, go.mod, Cargo.lock, Gemfile.lock (GEM
  section), and composer.lock. Unsupported ecosystems (Maven, Gradle, yarn
  berry, Hex, NuGet, Swift) are reported explicitly, never silently skipped.
- Offline SCA: `scan`/`sca` match pinned versions against cached advisory
  ranges. Fresh matches are `confirmed` with CVE/GHSA/OSV citations; stale
  cache (default limit 72h) downgrades them to `needs-review` with a visible
  warning. KEV-listed CVEs escalate to critical with a stated reason.
- `--run-analyzers`: opt-in execution bridge for npm-audit, pip-audit,
  semgrep, gitleaks (normalized) and cargo-audit, govulncheck (summary-only),
  each with timeouts, exit-code capture, and provenance fields.
- `--advisory-db`: load advisories offline from a cache directory or an
  exported bundle whose section checksums are verified; tampering is a hard
  error.

### Added — leak coverage (track B)

- Secret token-format engine (`references/formats/secrets.yaml`): 17
  vendor-documented credential formats detected with values never emitted.
- Entropy layer: high-entropy literals gated on secret-named context,
  reported as low-confidence candidates.
- `history` subcommand: bounded git-history secret scan (default 12 months)
  reporting commit, path, format id, and `only_in_history` — values withheld.
- New `leaks` matcher pack: workflow secret echo, docker build-arg secrets,
  secret-file artifact uploads, fork-triggered secret access.
- AI-context leak matchers: secrets assembled into model payloads, agent
  memory writes, and tool-call arguments.
- Redaction hardened: npm/PyPI/Anthropic tokens, URL password parameters.

### Added — fix quality (track C)

- `sources` is mandatory for confirmed findings; `fix-plan` blocks confirmed
  items without citations under `blocked: missing-source`.
- `advisory_fix`: recommended versions are copied verbatim from advisory
  fixed events; advisories without fixes state "no fixed version published".
- Every remediation plan now carries a `regression_test` skeleton.
- `verify` subcommand: reruns scan surfaces, compares stable fingerprints,
  optionally runs a test command, and reports `verified`, `still-present`,
  `test-failed`, or `inconclusive`.
- Anti-hardcoding matcher gate: absolute paths, home expansions, and
  machine-specific values are rejected; bundled matcher examples must pass
  through the engine (CI-enforced).

### Added — enterprise readiness (track D)

- Exit-code contract: 0 clean, 1 findings at/above `--fail-on`, 2 tool error,
  3 usage error. Candidates never fail a build.
- `--format sarif`: SARIF 2.1.0 output with partial fingerprints and
  VibeSecurity properties, structurally validated before emission.
- Stable finding fingerprints: survive line shifts, change with code or
  evidence changes; tracked by baselines and `verify`.
- `.vibesecurity/baseline.json`: suppressions with mandatory `expires_on`
  (default max age 180 days); expired entries re-fire visibly; baseline
  corruption never silences findings.
- `.vibesecurity/config.json` (schema 1): `network_enabled`, `fail_on`,
  `max_cache_age_hours`, `history_window_months`, `baseline_max_age_days`,
  `allowed_analyzers`. Precedence: CLI > config > defaults; unknown keys warn.
- Integration recipes: GitHub Actions, GitLab CI, Jenkins, Azure DevOps,
  pre-commit (`docs/integrations/`).
- Version and support policy: semantic versioning, latest-minor support,
  release checklist maintained by maintainers.

### Changed

- Skill and helper version 2.1.0 → 3.0.0.
- `scan` output gains `gate`, `baseline`, `suppressed`, `advisory_db`,
  fingerprints, and secret-engine candidates.
- `fix-plan` blocks source-less confirmed findings (breaking for pipelines
  that treated confirmed-without-sources as patchable).

## [2.1.0]

- Bounded candidate engine, coverage accounting, redaction, CI on three
  operating systems, skills-CLI installation support.

## [2.0.0]

- Candidate-vs-confirmed review model, restricted matcher format, defensive
  boundaries, hostile-input handling.
