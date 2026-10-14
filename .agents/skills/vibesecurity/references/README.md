# VibeSecurity References

Load references only when the active review needs them.

| Need | File |
|---|---|
| Threat model and complete review lanes | `review-lanes.md` |
| Command behavior | `command-map.md` |
| Finding quality gate | `security-rubric.md` |
| Finding shape | `finding-schema.md` |
| Report structure | `reporting-rules.md` |
| Standards mapping (CWE, OWASP 2025, ASVS 5.0.0, CVSS/EPSS/KEV) | `standards-map.md` and the data files in `standards/` |
| Measured evidence and incident data with sources | `evidence-base.md` |
| Web/API review | `web-api-checklist.md` |
| AI/agentic review | `ai-agentic-checklist.md` |
| Supply chain review | `supply-chain-checklist.md` |
| Secrets review | `secrets-checklist.md` |
| CI/CD review | `ci-cd-checklist.md` |
| Coverage caveats | `coverage-matrix.md` |
| Framework-specific risk | one file in `framework-notes/` (Supabase, Firebase, Next.js, Express, FastAPI, Django, and more) |
| Worked examples | one file in `examples/` |
| Secret token formats | `formats/secrets.yaml` |
| Bundled matcher packs | `matchers/*.yaml` |
| Learning from findings | `matchers/local-project.yaml` plus `assets/templates/matcher.yaml` |

Do not load all examples, framework notes, or matcher files at once.
