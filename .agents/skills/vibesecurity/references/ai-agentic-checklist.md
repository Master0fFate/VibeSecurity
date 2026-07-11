# AI and Agentic Checklist

Review AI systems as trust-boundary code, not just prompt text.

Focus on:

- **Goal hijack and prompt injection:** direct user input plus indirect instructions in retrieved docs, webpages, email, tickets, PDFs, code, database rows, memory, images, or tool output.
- **Tool misuse:** broad filesystem, shell, browser, network, payment, deployment, credential, or messaging capability; missing operation allowlists, policy enforcement, approval, or audit.
- **Identity and privilege abuse:** tools missing user, tenant, role, ownership, purpose, audience, or task binding; long-lived delegated credentials; confused-deputy paths.
- **Agentic supply chain:** unverified models, prompts, skills, tools, MCP servers, A2A agent cards, plugins, memory sources, or runtime discovery and update channels.
- **Unexpected code execution and improper output handling:** model output used as shell, SQL, path, HTML/markdown, browser action, code, workflow, or deployment input without typed validation.
- **Memory and context poisoning:** unauthorized writes, shared-tenant state, missing provenance/expiry, poisoned summaries, retrieval without document authorization, or stored instructions that later control tools.
- **Insecure inter-agent communication:** unauthenticated peers, unsigned or replayable messages, schema confusion, capability spoofing, missing confidentiality, and transitive trust.
- **Cascading failures:** recursive delegation, retry/fan-out storms, correlated bad context, missing circuit breakers, and irreversible downstream actions.
- **Human-agent trust exploitation:** opaque evidence, persuasive but unverifiable claims, approval fatigue, misleading confirmations, and high-impact actions without independent review.
- **Rogue or misaligned behavior:** goal drift, concealment, policy bypass, self-modification, persistence, unauthorized subagents, and missing runtime containment or kill paths.
- **Sensitive information disclosure:** secrets or personal data in prompts, traces, logs, vector stores, model training, memory, tool output, or cross-user context.
- **Resource abuse:** input/output and iteration bounds, quotas, rate limits, timeouts, cancellation, queue limits, per-user/tenant cost attribution, and denial-of-wallet controls.
- **Misinformation and package hallucination:** generated facts, packages, citations, or code crossing a consequential boundary without independent validation.

Prefer structured outputs, reference monitors outside the model, least-privilege and short-lived identity, allowlisted tools, provenance, isolation, explicit approval for consequential actions, tamper-evident logs, budgets, and deterministic shutdown controls.
