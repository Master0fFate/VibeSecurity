# Standards Map

Use standards to sharpen a finding or verification step, not to decorate reports. Pin versioned identifiers when citing a specific requirement.

## Application Security

OWASP ASVS 5.0.0 is the stable application baseline. Its chapters are:

- V1 encoding and sanitization; V2 validation and business logic; V3 web frontend; V4 API and web service; V5 file handling.
- V6 authentication; V7 session management; V8 authorization; V9 self-contained tokens; V10 OAuth/OIDC.
- V11 cryptography; V12 secure communication; V13 configuration; V14 data protection; V15 secure coding and architecture; V16 logging and error handling; V17 WebRTC.

Use the OWASP Cheat Sheet Series and Code Review Guide for implementation detail. Use CWE identifiers only when the weakness mapping is direct.

## AI and Agentic Systems

OWASP Top 10 for LLM Applications 2025 covers prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, and unbounded consumption.

OWASP Top 10 for Agentic Applications 2026 adds:

- ASI01 agent goal hijack; ASI02 tool misuse and exploitation; ASI03 identity and privilege abuse; ASI04 agentic supply-chain vulnerabilities; ASI05 unexpected code execution.
- ASI06 memory and context poisoning; ASI07 insecure inter-agent communication; ASI08 cascading failures; ASI09 human-agent trust exploitation; ASI10 rogue agents.

Use OWASP's Securing Agentic Applications guidance for technical controls and NIST SP 800-218A for AI-specific secure-development lifecycle practices.

## Software and Supply Chain

- NIST SSDF SP 800-218 and SP 800-218A: prepare, protect, produce, and respond; AI community-profile additions.
- SLSA: source and build integrity, provenance, trusted builders, and tamper resistance.
- CISA Secure by Design: safer defaults, durable elimination of recurring classes, and accountable product security.
- OpenSSF guidance where repository and dependency health materially affect the finding.

## Source Anchors

- OWASP ASVS 5.0.0: `https://owasp.org/www-project-application-security-verification-standard/`
- OWASP Cheat Sheet Series: `https://cheatsheetseries.owasp.org/`
- OWASP Code Review Guide: `https://owasp.org/www-project-code-review-guide/`
- OWASP LLM Top 10 2025: `https://genai.owasp.org/llm-top-10/`
- OWASP Agentic Top 10 2026: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/`
- OWASP Securing Agentic Applications: `https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/`
- NIST SSDF: `https://csrc.nist.gov/projects/ssdf`
- CISA Secure by Design: `https://www.cisa.gov/resources-tools/resources/secure-by-design`
- SLSA: `https://slsa.dev/`
