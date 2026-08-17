# Finding Schema

Use this shape for findings and reports:

```json
{
  "id": "VSEC-0001",
  "title": "Short actionable title",
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "status": "confirmed|needs-review|fixed|wont-fix|false-positive",
  "category": "authz|authn|injection|ssrf|xss|secrets|supply-chain|ci-cd|ai-agentic|privacy|crypto|availability|other",
  "fingerprint": "stable locator hash emitted by the helper; preserved across line shifts",
  "sources": [
    {"type": "CVE|GHSA|OSV|KEV|vendor-advisory|standard|documented-pattern", "id": "CVE-2024-1234", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}
  ],
  "advisory_fix": {
    "advisory_id": "OSV-0000-0000",
    "installed_version": "1.1.0",
    "fixed_versions": ["1.2.0"],
    "recommended_version": "1.2.0"
  },
  "standard_refs": ["OWASP-ASVS-v5.0.0", "OWASP-LLM01:2025"],
  "affected_files": [
    {
      "path": "src/example.ts",
      "lines": [10, 25],
      "symbols": ["handler"]
    }
  ],
  "evidence": "Concise code-level evidence without dumping secrets.",
  "attack_scenario": "How an attacker or lower-privileged user reaches the issue.",
  "impact": "Concrete business or security impact.",
  "recommendation": "Specific remediation guidance.",
  "verification": "How to confirm the fix.",
  "created_at": "YYYY-MM-DD",
  "updated_at": "YYYY-MM-DD"
}
```

IDs use the `VSEC-0001` sequence. `needs-review` is for candidates with meaningful signal but incomplete confirmation.

`fingerprint` is the helper's stable locator hash (`sha256` prefix of kind, location, and evidence text). It survives line shifts, changes when the affected code or evidence changes, and is what baselines and `verify` track. Copy it from helper output; never recompute it by hand.

`sources` is required for every `confirmed` finding: at least one entry with a `type` from `CVE | GHSA | OSV | KEV | vendor-advisory | standard | documented-pattern`, a stable `id`, and a `url` when one exists. `fix-plan` refuses to produce patch guidance for confirmed findings without sources and reports them under `blocked: missing-source`. Advisory-driven findings additionally carry `advisory_fix`; `recommended_version` is copied verbatim from the advisory's fixed events and is never computed or guessed.

Severity expresses impact and exploitability. Confidence expresses evidence quality and missing context; do not raise one merely because the other is high. Use versioned standard identifiers when mapping a specific requirement.
