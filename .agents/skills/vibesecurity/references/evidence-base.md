# Evidence Base

Why this skill exists, with measured numbers. Every figure below is copied from the cited source as published; the "caveat" column records who produced the number and what it does not say. Use these to explain priority to a user, never to pad a finding. Retrieved 2026-10-14.

## AI-generated code ships with security defects at a measurable rate

| Finding | Number | Source | Caveat |
|---|---|---|---|
| LLMs introduced an OWASP Top 10 weakness when given a choice between a secure and an insecure implementation | 45% of test cases; Java over 70%; Python, C#, JavaScript 38% to 45% | Veracode, *2025 GenAI Code Security Report* (80 curated tasks, 100+ models), July 30 2025: <https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/> | Vendor study; measures model choice on curated tasks, not production code. |
| Models failed to prevent cross-site scripting (CWE-80) and log injection (CWE-117) | 86% and 88% of cases | Same Veracode report | Same scope as above. |
| Copilot-completed programs containing a weakness from the CWE Top 25 scenarios | about 40% of 1,689 generated programs across 89 scenarios | Pearce et al., *Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions*, IEEE S&P 2022: <https://arxiv.org/abs/2108.09293> | 2021 model generation; Python, C, and Verilog only. |
| Developers with an AI assistant wrote less secure code and were more confident it was secure | user study of 47 participants | Perry, Srivastava, Kumar, Boneh, *Do Users Write More Insecure Code with AI Assistants?*, ACM CCS 2023: <https://arxiv.org/abs/2211.03622> | Small sample; codex-davinci-002 era model. |
| Code-generating LLMs recommend packages that do not exist (the "slopsquatting" vector) | at least 5.2% of commercial-model and 21.7% of open-source-model outputs; 205,474 unique hallucinated names across 576,000 samples and 16 models | Spracklen et al., *We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs*, USENIX Security 2025: <https://arxiv.org/abs/2406.10279> | Python and JavaScript prompts; rates vary strongly by model. |

The helper's `dependency-not-in-public-registry` and `dependency-declared-not-locked` candidates exist because of the last row.

## Secrets leak faster than they are rotated

| Finding | Number | Source | Caveat |
|---|---|---|---|
| New hard-coded secrets leaked on public GitHub in 2024 | 23.8 million, a 25% year-over-year increase | GitGuardian, *The State of Secrets Sprawl 2025*, March 2025: <https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/> | Vendor telemetry over 1.4 billion commits. |
| Repositories with GitHub Copilot enabled that contained at least one secret, versus all public repositories | 6.4% versus 4.6% (the report's "40% higher" claim) | Same report, section "Copilot increases secrets incidence rate by 40%" | Correlation in a 20,000-repository sample; no causal design. |
| Secrets leaked in 2022 that were still valid at publication | 70% | Same report | Validity checked by the vendor's own detectors. |
| Private repositories containing plaintext secrets | 35% of customer private repositories | Same report | Customer-base sample, not all of GitHub. |

The secret format library (`references/formats/secrets.yaml`) and the `history` command exist because leaked keys stay valid for years.

## Vibe-coded apps fail at the data-access boundary, not at exotic bugs

| Incident or study | What was exposed | Root cause | Source |
|---|---|---|---|
| CVE-2025-48757 (Lovable-generated apps), disclosed May 2025 | 303 endpoints across 170 of 1,645 scanned apps let unauthenticated users read or write Supabase tables with the public anon key; NVD CVSS 3.1 base score 9.3 | Supabase Row Level Security missing or permissive | <https://nvd.nist.gov/vuln/detail/CVE-2025-48757>; summary at <https://www.superblocks.com/blog/lovable-vulnerabilities> |
| Escape.tech scan of vibe-coded apps, October 2025 | more than 2,000 vulnerabilities, 400+ exposed secrets, and 175 instances of PII across 5,600+ public apps (about 4,000 from Lovable, 449 from Create.xyz, 159 from Base44); Supabase service keys were "often trivially retrievable from frontend bundles" | Service keys and tokens shipped in client bundles; missing RLS | <https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/> |
| Tea app, July 2025 | about 72,000 images including 13,000 identity selfies, then a second database with about 1.1 million private messages | Unsecured Firebase storage bucket and database; no intrusion required | <https://cyberinsider.com/tea-app-suffers-data-breach-exposing-72000-users-photos-and-private-messages/> |
| Moltbook, January 2026 | production database behind an AI-agent social network: about 1.5 million agent API tokens, 35,000 email addresses, private agent messages | Supabase key in client JavaScript with no RLS on the agents table | Wiz Research: <https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys> |

The `vibecoder` matcher pack (`supabase-rls-disabled`, `supabase-service-key-in-client`, `public-env-prefix-on-secret`, `firebase-rules-open`, `llm-sdk-in-browser`, `webhook-body-trusted-without-signature`) targets exactly these failure modes.

## Which weaknesses matter most, by measured CVE data

MITRE's CWE Top 25 for 2025 ranks weakness classes by frequency and severity across CVE records disclosed between June 2024 and June 2025. The ranks relevant to web and AI applications:

| Rank | CWE | Name | Change vs 2024 |
|---|---|---|---|
| 1 | CWE-79 | Cross-site Scripting | 0 |
| 2 | CWE-89 | SQL Injection | +1 |
| 3 | CWE-352 | Cross-Site Request Forgery | +1 |
| 4 | CWE-862 | Missing Authorization | +5 |
| 6 | CWE-22 | Path Traversal | -1 |
| 9 | CWE-78 | OS Command Injection | -2 |
| 10 | CWE-94 | Code Injection | +1 |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | -2 |
| 15 | CWE-502 | Deserialization of Untrusted Data | +1 |
| 17 | CWE-863 | Incorrect Authorization | +1 |
| 21 | CWE-306 | Missing Authentication for Critical Function | +4 |
| 22 | CWE-918 | Server-Side Request Forgery | -3 |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | +6 |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling | +1 |

Source: <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>. The full list with scores and KEV counts is in `references/standards/cwe-top25-2025.json`; the helper adds a priority bonus to candidates whose CWE is on it. Authorization weaknesses (CWE-862, CWE-863, CWE-639, CWE-306) all rose, which matches the vibe-coded incident pattern above.

## Standards the helper cites

- OWASP Top 10:2025 (<https://owasp.org/Top10/2025/>): A01 Broken Access Control (now including SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.
- OWASP ASVS 5.0.0 (<https://github.com/OWASP/ASVS>): 345 requirements in 17 chapters; the 76 cited by bundled matchers are copied verbatim into `references/standards/asvs-5.0.0.json`.
- OWASP Top 10 for LLM Applications 2025 and Top 10 for Agentic Applications 2026 (<https://genai.owasp.org/>).
- MITRE CWE 4.20 names for every referenced weakness (`references/standards/cwe-catalog.json`).
- FIRST CVSS v3.1 specification (<https://www.first.org/cvss/v3.1/specification-document>) for the base-score calculator in `scripts/vibesecurity_cvss.py`, FIRST EPSS (<https://www.first.org/epss/>) for exploitation probability, and the CISA Known Exploited Vulnerabilities catalog (<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>).

## How to use this file

- Quote a number only with its source and caveat.
- Prefer the incident table when explaining why a Supabase or Firebase finding is critical to a non-security reader: the same misconfiguration already exposed real people.
- Refresh this file when a source publishes a new edition; the retrieval date at the top is part of the citation.
