# CI/CD Checklist

Review GitHub Actions and other CI/CD workflows for trust boundaries between forks, contributors, build artifacts, and deployment secrets.

Focus on:

- `pull_request_target` workflows that check out, build, test, or execute attacker-controlled code.
- Overbroad `GITHUB_TOKEN` or cloud permissions.
- Secrets exposed to untrusted forks, scripts, or matrix values.
- Unpinned third-party actions.
- Script injection through branch names, commit messages, PR titles, issue bodies, labels, or matrix values.
- Deployment workflows without environment protection or approval.
- Artifact poisoning between untrusted and trusted jobs.
- Cache poisoning through broad keys.
- Docker build contexts that include secrets.

Prefer least privilege permissions, pinned actions, separated untrusted validation, protected deployments, and explicit artifact trust boundaries.
