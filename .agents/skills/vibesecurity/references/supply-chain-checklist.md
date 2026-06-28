# Supply-Chain Checklist

Review changes to package manifests, lockfiles, build scripts, containers, generated clients, and dependency sources.

Focus on:

- New dependencies and unexpected transitive churn.
- Lockfile drift without manifest changes.
- `preinstall`, `install`, `postinstall`, prepare, or build scripts.
- Typosquatting, dependency confusion, and lookalike package names.
- Git dependencies, tarball URLs, unpinned refs, and remote script pipes.
- Build steps that download executables or execute generated code.
- Container base images and package repositories.
- Unmaintained packages in auth, crypto, payment, serialization, parsing, or deployment paths.
- Provenance, signing, and reproducibility where relevant.

Do not claim a package is malicious without evidence. Flag suspicious changes as needs-review when confirmation requires external intelligence.
