# Changelog

All notable changes to VibeSecurity are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning for the helper CLI and the matcher/format schemas together.

## [4.0.0] - 2026-10-14

Evidence release. Every detector now cites measured data: MITRE CWE ids and the
CWE Top 25 2025 ranks, OWASP Top 10:2025 and LLM/Agentic categories, verbatim
ASVS 5.0.0 requirements, FIRST CVSS v3.1 base scores, FIRST EPSS exploitation
probabilities, CISA KEV, and public-registry facts. Breaking: candidate and
advisory payloads gain fields; advisory severity no longer defaults to high.

### Added — standards data

- `references/standards/`: `cwe-catalog.json` (65 CWE names copied from MITRE
  4.20), `cwe-top25-2025.json` (rank, score, KEV count, change vs 2024),
  `asvs-5.0.0.json` (76 requirements, verbatim text, from the official OWASP
  export), `owasp-top10-2025.json` (Top 10:2025, LLM Top 10 2025, Agentic Top 10
  2026). Each file records its source URL and retrieval date.
- `scripts/vibesecurity_standards.py`: validates `cwe`/`owasp`/`asvs` ids on
  matchers and resolves a `standards` block (names, Top 25 rank, ASVS text) on
  every candidate. Reports render it; SARIF rules carry `external/cwe/*` tags
  and a MITRE `helpUri`.
- `references/evidence-base.md`: the research and incident numbers behind the
  skill (Veracode 2025, GitGuardian 2025, Pearce 2022, Perry 2023, Spracklen
  2025, CVE-2025-48757, Escape.tech 2025, Tea 2025, Moltbook 2026), each with
  source and caveat.

### Added — scoring with real data

- `scripts/vibesecurity_cvss.py`: CVSS v3.0/v3.1 base-score calculator per the
  FIRST specification, verified against ten known-answer vectors. Advisory
  candidates carry `cvss`, `severity_basis` (GHSA band, computed CVSS, or an
  explicit medium default), `epss`, and `kev`.
- `feed refresh` now also fetches FIRST EPSS scores for every CVE seen and npm
  and PyPI registry metadata (existence, first-publish date, latest version),
  with a thread pool for advisory and registry fetches. New config key
  `registry_lookups` (default true).
- `scan` emits `dependency-not-in-public-registry` (slopsquatting target),
  `dependency-recently-published` (under 90 days), and
  `dependency-declared-not-locked` (package.json entry absent from the
  lockfile), plus a `dependency_hygiene` summary.
- Priority scoring adds a CWE Top 25 bonus and, for advisories, KEV and EPSS
  bonuses with explicit `priority_reasons`.
- `scan` and `verify` use `.vibesecurity/cache/` automatically when it exists;
  `--advisory-db` remains the override.

### Added — detection

- Matcher format: `regex_patterns` (bounded; backreferences and nested
  unbounded quantifiers rejected), `exclude_patterns`, `same_line_terms`,
  `nearby_excludes`, and `cwe`/`owasp`/`asvs` metadata. The restricted YAML
  parser now unescapes `\"` and `''` correctly.
- New `vibecoder` pack: Supabase RLS disabled or `using (true)`, service keys
  in client code, public env prefixes on secrets, LLM SDK `dangerouslyAllowBrowser`,
  Firebase open or any-authenticated rules, `.env` files with secret values,
  webhook bodies trusted without signature checks, auth-middleware public
  wildcards, Convex and tRPC functions without auth checks, tokens in web storage.
- High-signal pack additions: NoSQL operator injection, open redirect, mass
  assignment, privileged fields from request bodies, CSRF disabled, insecure
  cookie attributes, weak password hashing, plaintext password comparison,
  default credentials, hardcoded JWT secrets, `jwt.decode` without verify.
  Existing rules gained excludes and same-line terms to cut noise; the route
  matcher is suppressed when an auth call sits within six lines.
- Trust-boundary pack: GitHub Actions script injection (`${{ github.event.* }}`
  in `run:`), broader permission patterns, Docker socket and privilege
  escalation flags. Supply-chain pack: remote script pipes, git/URL
  dependencies, digest-pinned image exclusion.
- AI pack: model-generated code execution, agent loops without bounds, tighter
  retrieval-as-instructions and secret-into-payload rules, MCP `npx -y` and
  `@latest` loading.
- Secret formats: 17 → 92, each tagged `vendor-doc`, `gitleaks-default-config`,
  or `observed`, including Anthropic, OpenAI (T3BlbkFJ marker), OpenRouter,
  Groq, xAI, Perplexity, Hugging Face, Replicate, LangSmith, Tavily, Pinecone,
  Supabase (`service_role` JWT by payload claim, `sb_secret_`,
  `sb_publishable_`, `sbp_`), Stripe/Clerk live, test, webhook and publishable
  keys, Resend, Convex, PlanetScale, Linear, Notion, Airtable, Shopify, Square,
  Slack (bot, user, app, config, webhook), Discord, Telegram, Teams, Twilio,
  SendGrid, Mailgun, Mailchimp, Brevo, Netlify, Typeform, Flutterwave, Shippo,
  AWS (ASIA/ABIA/ACCA, secret key by name, Bedrock), Azure storage and Entra
  secrets, GCP service-account JSON, Alibaba, DigitalOcean, Fly.io, Vault,
  Terraform Cloud, Cloudflare, Heroku, Pulumi, Databricks, Postman, Doppler,
  age, 1Password, Grafana, Dynatrace, New Relic, Sentry, GitHub, GitLab, npm,
  PyPI, RubyGems, Atlassian, PuTTY keys, literal bearer tokens.
- Overlap suppression: a later format never fires on a span an earlier,
  more specific format claimed on the same line. Format regexes also feed the
  snippet redactor.
- Inventory: `platforms` (Supabase, Firebase, Clerk, NextAuth, Convex, Prisma,
  Drizzle, Stripe, Resend, Upstash, Vercel storage, Neon) and `env_files`.

### Changed

- Skill and helper version 3.0.0 → 4.0.0.
- Secret corpus fixtures are shape templates (`sk-ant-api03-{alnum:95}`)
  expanded in memory by `expand_sample()`, so no complete token shape is stored
  in the repository and push protection never trips.
- Advisory severity without a GHSA band or CVSS vector defaults to medium with
  a stated basis (previously silently high).
- `database-connection-url` only fires when the URL carries a password in its
  query string; credential-bearing URLs are reported by
  `url-embedded-credentials`.
- Bridge: analyzers carry CWE ids from semgrep metadata and npm audit;
  summary-only analyzers run their real command line.

### Fixed

- `verify` crashed with a NameError when an advisory cache was supplied.
- `scan` ignored `.vibesecurity/cache/` unless `--advisory-db` was passed.
- Advisory severity parsing returned high for every CVSS vector.
- Matcher patterns beginning with `/` (for example the Docker socket path)
  were rejected as machine-specific; only globs are now.
- Dead line-number tracking removed from the history walker.

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
