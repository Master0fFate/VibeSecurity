# AI/Agentic Checklist

Review AI systems as trust-boundary code, not just prompt text.

Focus on:

- Direct prompt injection in user messages.
- Indirect prompt injection through retrieved docs, webpages, emails, tickets, PDFs, code comments, database rows, or tool outputs.
- Tool definitions with broad filesystem, shell, browser, network, payment, deployment, credential, or messaging permissions.
- Model output used as shell, SQL, file path, HTML, markdown, browser instruction, code, or deployment input.
- Missing human approval for destructive, financial, external-message, credential, or deployment actions.
- Tool calls missing user, tenant, role, or ownership checks.
- Secrets placed in prompts, traces, logs, vector stores, or tool outputs.
- Retrieval without tenant filters or document-level authorization.
- System prompt leakage with operational impact.
- Cost controls: input limits, quotas, rate limits, timeouts, queue bounds, and denial-of-wallet paths.
- Package hallucination risk when generated code is executed or installed.

Prefer structured output validation, allowlists, scoped tools, and explicit approval boundaries.
