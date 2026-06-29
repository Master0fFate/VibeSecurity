# Coverage Matrix

Use coverage metadata to keep VibeSecurity honest across arbitrary repositories.

Support levels:

- `candidate-detector`: bundled matchers can produce deterministic review candidates, but the agent must still validate reachability, boundary crossing, impact, and verification.
- `profile-only`: inventory detects the surface, but bundled matchers are not strong enough to claim candidate coverage. Review manually with the relevant checklist and framework notes.
- `unsupported`: the helper has no meaningful detector for this surface. State the caveat and review manually when it is security-relevant.

Current detector-first surfaces:

- Languages: TypeScript, JavaScript, Python, Go, Ruby, Rust, Java, C#, PHP.
- Workflows: GitHub Actions, GitLab CI, CircleCI, Jenkins, Docker, Kubernetes, Terraform.
- Risk classes: authn/authz, command/file/query injection, SSRF, XSS, secrets, supply chain, CI/CD, AI-agentic boundaries, resource/cost abuse.

Profile-only examples include Kotlin, Swift, Scala, Elixir, Clojure, and SQL unless local matchers are supplied under `.vibesecurity/*.yaml`.

For every report, preserve:

- detected languages, frameworks, workflows, and package managers;
- rule packs and matcher ids loaded;
- files considered and skipped;
- truncation and candidate ranking data;
- unsupported/profile-only surfaces;
- optional local analyzer availability.

Do not imply full coverage when the helper reports profile-only or unsupported surfaces.
