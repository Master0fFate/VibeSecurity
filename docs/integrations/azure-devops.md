# Azure DevOps integration

`azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      python -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root .
    displayName: Refresh advisory cache
  - script: |
      python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . --fail-on confirmed-high
    displayName: VibeSecurity scan
```

Exit codes: 0 clean · 1 findings at/above threshold · 2 tool error · 3 usage error. The script step fails on 1 and 2; findings gating is controlled by `--fail-on`, tool failures always fail.

Publish the Markdown report as an artifact:

```yaml
  - script: |
      python -B .agents/skills/vibesecurity/scripts/vibesecurity.py report --root . \
        --input .vibesecurity/findings.json --output .vibesecurity/report.md
    condition: always()
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: .vibesecurity/report.md
      artifactName: vibesecurity-report
```

Self-hosted agents without egress: use `--advisory-db advisories/advisory-bundle.json`; bundle checksums are verified on load and tampering exits 2.
