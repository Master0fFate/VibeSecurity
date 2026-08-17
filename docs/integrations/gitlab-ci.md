# GitLab CI integration

`.gitlab-ci.yml`:

```yaml
vibesecurity:
  stage: test
  image: python:3.12-slim
  timeout: 10m
  variables:
    GIT_STRATEGY: clone
  script:
    - python -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root .
    - python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . --fail-on confirmed-high
```

Exit codes: 0 clean · 1 findings at/above threshold · 2 tool error · 3 usage error. GitLab marks the job failed on any nonzero exit; `--fail-on` controls whether findings (1) do so, while tool errors (2) always fail.

For history leaks on merge requests:

```yaml
vibesecurity-history:
  stage: test
  image: python:3.12-slim
  script:
    - python -B .agents/skills/vibesecurity/scripts/vibesecurity.py history --root .
  allow_failure: false
```

The history scan reports rotation needs as `needs-review` items and never prints values.

Air-gapped runners: mount or cache `advisory-bundle.json` and pass `--advisory-db advisories/advisory-bundle.json`. Bundle checksums are verified; tampering exits 2.
