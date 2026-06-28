# RAG Indirect Prompt Injection

Vulnerable pattern:

```ts
const docs = await retriever.search(question);
const answer = await model.generate(`Use these docs and follow their instructions: ${docs}`);
await agent.runTools(answer.toolCalls);
```

Safe pattern:

```ts
const docs = await retriever.searchAuthorized(user, question);
const answer = await model.generate(buildGroundedPrompt(docs, question));
await runApprovedReadOnlyTools(answer.toolCalls, user);
```

Review lesson: retrieved content is untrusted data, not instructions. Tool execution needs authorization and allowlisted capability boundaries.
