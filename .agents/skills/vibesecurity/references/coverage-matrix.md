# Coverage Matrix

Use coverage metadata to keep VibeSecurity honest across arbitrary repositories.

Support levels:

- `candidate-detector`: bundled matchers can produce deterministic review candidates, but the agent must still validate reachability, boundary crossing, impact, and verification.
- `profile-only`: inventory detects the surface, but bundled matchers are not strong enough to claim candidate coverage. Review manually with the relevant checklist and framework notes.
- `unsupported`: the helper has no meaningful detector for this surface. State the caveat and review manually when it is security-relevant.

`candidate-detector` means at least one relevant bundled rule can fire. It never means complete weakness, framework, path, or data-flow coverage.

Current detector-first surfaces:

- Languages: TypeScript, JavaScript, Python, Go, Ruby, Rust, Java, C#, PHP, PowerShell, batch scripts, SQL migrations, and Firebase rules files.
- Workflows: GitHub Actions, GitLab CI, CircleCI, Jenkins, Docker, Kubernetes, Terraform.
- Platforms (vibecoder pack): Supabase (RLS, service keys in client code), Firebase rules, Next.js public env prefixes, Clerk and other auth middleware wildcards, Convex, tRPC, Stripe and Svix webhooks, browser-side LLM SDKs.
- Risk classes: authn/authz, command/file/query/NoSQL/archive injection, SSRF, open redirect, mass assignment, XSS, CSRF/CORS, cookie flags, secrets (92 token formats plus an entropy layer), TLS/token/crypto/password-hashing misuse, privacy logging, supply chain (advisories with CVSS/EPSS/KEV, registry existence, manifest drift, git deps, install hooks, remote script pipes), CI/CD (script injection, permissions, fork secrets), AI-agentic boundaries (output to shell/code/browser/file, tool privilege, retrieval as instructions, memory writes, dynamic MCP, delegated identity), and resource/cost abuse.
- Dependency ecosystems with lockfile parsing: npm (package-lock, yarn v1, pnpm), PyPI (poetry, pinned requirements, Pipfile.lock), Go modules, Cargo, RubyGems, Packagist. Registry existence and first-publish dates: npm and PyPI only.

Profile-only examples include Kotlin, Swift, Scala, Elixir, Clojure, C/C++, F#/VB, Dart, Lua, R, Solidity, Bicep, Azure Pipelines, and Bitbucket Pipelines unless valid local matchers are supplied under `.vibesecurity/matchers/*.yaml`. Maven, Gradle, yarn berry, Hex, NuGet, and Swift packages are inventoried as unsupported for advisory matching.

For every report, preserve:

- detected languages, frameworks, platforms, workflows, env files, and package managers;
- rule packs and matcher ids loaded;
- files considered and skipped;
- selection budgets, skipped counts/samples, selection and candidate truncation, and candidate ranking data;
- matcher validation warnings and restricted-format failures;
- advisory cache provenance (`advisory_db`: sources present, age, freshness) and `dependency_hygiene` counts;
- unsupported/profile-only surfaces;
- optional local analyzer availability.

Do not imply full coverage when the helper reports profile-only or unsupported surfaces.
