# Standards Data

Machine-readable standards the helper resolves at scan and report time. Every file records its source URL and retrieval date; nothing here is paraphrased.

| File | Content | Source |
|---|---|---|
| `cwe-catalog.json` | Names for every CWE id referenced by bundled matchers, copied from the MITRE definition page titles (CWE 4.20). | `https://cwe.mitre.org/data/definitions/<id>.html` |
| `cwe-top25-2025.json` | The 2025 CWE Top 25: rank, id, name, score, KEV count, and rank change versus 2024. | `https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html` |
| `asvs-5.0.0.json` | The 76 ASVS 5.0.0 requirements cited by VibeSecurity categories and matchers, with verbatim requirement text and level, plus the category map. | Official OWASP ASVS 5.0.0 flat JSON export (CC BY-SA 4.0). |
| `owasp-top10-2025.json` | OWASP Top 10:2025, LLM Top 10 2025, and Agentic Top 10 2026 category names, plus the category map. | `https://owasp.org/Top10/2025/`, `https://genai.owasp.org/` |

How the helper uses them:

- Each matcher declares `cwe`, `owasp`, and `asvs` ids; the loader validates the id shapes and `vibesecurity_standards.py` expands them into the candidate's `standards` block (names, CWE Top 25 rank, ASVS requirement text).
- Secret-engine, advisory, registry, and bridge candidates get category defaults from the two `category_map` blocks when no explicit id is available; advisories use the `cwe_ids` published in the OSV record.
- `priority_score` receives a bonus when a candidate's CWE sits in the Top 25 (ten points for ranks 1 to 10, five for 11 to 25).
- SARIF rules carry `external/cwe/cwe-<n>` tags and a `helpUri` to the MITRE page so GitHub code scanning groups results by weakness.

Refreshing: rerun the retrieval against the sources above, update `retrieved`, and keep ids stable. Do not hand-edit requirement text.
