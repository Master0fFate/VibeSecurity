# GitHub Actions integration

VibeSecurity runs as a local step. It needs Python 3.11+ and the skill checkout; `feed refresh` needs network egress to api.osv.dev and cisa.gov.

## CI gate (fail on confirmed high or critical)

```yaml
name: vibesecurity
on: [pull_request, push]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@<pin-to-full-commit-sha>
      - uses: actions/setup-python@<pin-to-full-commit-sha>
        with:
          python-version: "3.12"
      - name: Refresh advisory cache
        run: python -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root .
      - name: Scan
        run: |
          python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . \
            --fail-on confirmed-high
```

Exit codes: 0 clean · 1 findings at/above threshold · 2 tool error · 3 usage error. Steps fail on 1 and 2 by default; `bash` step failure surfaces the verdict.

## SARIF upload to code scanning

```yaml
      - name: Scan to SARIF
        run: |
          python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . \
            --format sarif > vibesecurity.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@<pin-to-full-commit-sha>
        with:
          sarif_file: vibesecurity.sarif
        if: always()
```

`continue-on-error: true` keeps the SARIF upload working while a separate gated step owns the pass/fail decision.

## Air-gapped runners

Export a bundle from a networked machine, commit it to a private runner cache, then:

```yaml
      - run: python -B .../vibesecurity.py scan --root . --advisory-db advisories/advisory-bundle.json --fail-on confirmed
```

The bundle's section checksums are verified on load; a mismatch is a hard error (exit 2).
