# Standards Map

Use standards to sharpen a finding or verification step, not to decorate reports. Pin versioned identifiers when citing a specific requirement. The machine-readable data lives in `references/standards/`; candidates already carry a resolved `standards` block, so copy from it instead of recalling ids from memory.

## Application Security

OWASP ASVS 5.0.0 is the stable application baseline. Its chapters are:

- V1 encoding and sanitization; V2 validation and business logic; V3 web frontend; V4 API and web service; V5 file handling.
- V6 authentication; V7 session management; V8 authorization; V9 self-contained tokens; V10 OAuth/OIDC.
- V11 cryptography; V12 secure communication; V13 configuration; V14 data protection; V15 secure coding and architecture; V16 logging and error handling; V17 WebRTC.

The requirements VibeSecurity cites most, with their verbatim text in `standards/asvs-5.0.0.json`:

| Category | ASVS 5.0.0 | CWE | OWASP Top 10:2025 |
|---|---|---|---|
| authz | V8.2.1, V8.2.2, V8.3.1 | CWE-862, CWE-863, CWE-639 | A01 Broken Access Control |
| authn | V6.3.1, V7.2.1, V9.1.1, V9.1.2 | CWE-287, CWE-306, CWE-347 | A07 Authentication Failures |
| injection | V1.2.4, V1.2.5, V1.3.2, V1.5.2, V5.3.2 | CWE-89, CWE-78, CWE-94, CWE-502, CWE-22 | A05 Injection |
| ssrf | V1.3.6, V13.2.4, V15.3.2 | CWE-918 | A01 (SSRF merged into Broken Access Control in 2025) |
| xss | V1.2.1, V1.3.1 | CWE-79 | A05 Injection |
| secrets | V13.3.1, V13.3.2, V14.3.3 | CWE-798, CWE-312, CWE-200 | A02 Security Misconfiguration, A04 Cryptographic Failures |
| crypto | V11.4.2, V11.5.1, V12.3.2 | CWE-916, CWE-338, CWE-295 | A04 Cryptographic Failures |
| privacy | V14.2.3, V16.2.5, V16.5.1 | CWE-532, CWE-209 | A09 Security Logging and Alerting Failures |
| supply-chain | V15.2.1, V15.2.4 | CWE-829, CWE-494, CWE-1395 | A03 Software Supply Chain Failures |
| ci-cd | V13.2.2, V13.4.2 | CWE-250, CWE-522 | A08 Software or Data Integrity Failures |
| availability | V2.4.1, V15.2.2 | CWE-770, CWE-400 | A10 Mishandling of Exceptional Conditions |

Use the OWASP Cheat Sheet Series and Code Review Guide for implementation detail. CWE ids come from the MITRE catalog; the CWE Top 25 2025 rank is attached when it exists.

## AI and Agentic Systems

OWASP Top 10 for LLM Applications 2025: LLM01 prompt injection, LLM02 sensitive information disclosure, LLM03 supply chain, LLM04 data and model poisoning, LLM05 improper output handling, LLM06 excessive agency, LLM07 system prompt leakage, LLM08 vector and embedding weaknesses, LLM09 misinformation, LLM10 unbounded consumption.

OWASP Top 10 for Agentic Applications 2026: ASI01 agent goal hijack; ASI02 tool misuse and exploitation; ASI03 identity and privilege abuse; ASI04 agentic supply-chain vulnerabilities; ASI05 unexpected code execution; ASI06 memory and context poisoning; ASI07 insecure inter-agent communication; ASI08 cascading failures; ASI09 human-agent trust exploitation; ASI10 rogue agents.

CWE-1427 (Improper Neutralization of Input Used for LLM Prompting) is the weakness id for prompt injection. Use OWASP's Securing Agentic Applications guidance for technical controls and NIST SP 800-218A for AI-specific secure-development lifecycle practices.

## Vulnerability Scoring and Exploitation Data

- CVSS v3.1 (FIRST): the helper computes base scores from advisory vectors with the specification's formula and maps them to the None/Low/Medium/High/Critical bands. CVSS v4.0 vectors are reported but not scored.
- EPSS (FIRST): daily exploitation probability per CVE; the helper fetches it during `feed refresh` and attaches `epss.epss` and `epss.percentile` to advisory candidates.
- CISA KEV: known exploited vulnerabilities; a KEV listing escalates an advisory candidate to critical with an explicit `escalation_reason`.

## Software and Supply Chain

- NIST SSDF SP 800-218 and SP 800-218A: prepare, protect, produce, and respond; AI community-profile additions.
- SLSA: source and build integrity, provenance, trusted builders, and tamper resistance.
- CISA Secure by Design: safer defaults, durable elimination of recurring classes, and accountable product security.
- OpenSSF guidance where repository and dependency health materially affect the finding.

## Source Anchors

- OWASP ASVS 5.0.0: `https://owasp.org/www-project-application-security-verification-standard/`
- OWASP Top 10:2025: `https://owasp.org/Top10/2025/`
- OWASP Cheat Sheet Series: `https://cheatsheetseries.owasp.org/`
- OWASP Code Review Guide: `https://owasp.org/www-project-code-review-guide/`
- OWASP LLM Top 10 2025: `https://genai.owasp.org/llm-top-10/`
- OWASP Agentic Top 10 2026: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/`
- OWASP Securing Agentic Applications: `https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/`
- MITRE CWE and CWE Top 25 2025: `https://cwe.mitre.org/top25/`
- FIRST CVSS v3.1: `https://www.first.org/cvss/v3.1/specification-document`
- FIRST EPSS: `https://www.first.org/epss/`
- CISA KEV: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- NIST SSDF: `https://csrc.nist.gov/projects/ssdf`
- CISA Secure by Design: `https://www.cisa.gov/resources-tools/resources/secure-by-design`
- SLSA: `https://slsa.dev/`
