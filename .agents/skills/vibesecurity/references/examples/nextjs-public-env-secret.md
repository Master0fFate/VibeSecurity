# Next.js Secret Behind a Public Prefix

Vulnerable pattern:

```ts
// components/Chat.tsx
"use client";
import OpenAI from "openai";
const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});
```

`NEXT_PUBLIC_` variables are inlined into the JavaScript bundle at build time, and `dangerouslyAllowBrowser` exists only to let the SDK run where that key is visible. Every visitor can read the key from the bundle and spend against the account.

Safe pattern:

```ts
// app/api/chat/route.ts
import OpenAI from "openai";
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const session = await requireSession();
  const { message } = ChatSchema.parse(await req.json());
  await enforceQuota(session.user.id);
  const completion = await openai.chat.completions.create({ model: "gpt-5", messages: [{ role: "user", content: message }] });
  return Response.json({ reply: completion.choices[0].message.content });
}
```

Review lesson: the provider key never leaves the server; the client calls an authenticated, rate-limited route. Rotate any key that has ever been built into a bundle (CWE-798 Use of Hard-coded Credentials, OWASP A02:2025). Verification: grep the production build output for the key prefix and confirm it is absent.
