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

Severity expresses impact and exploitability. Confidence expresses evidence quality and missing context; do not raise one merely because the other is high. Use versioned standard identifiers when mapping a specific requirement.
