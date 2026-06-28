# Next.js Missing Auth

Vulnerable pattern:

```ts
export async function GET() {
  return Response.json(await db.user.findMany());
}
```

Safe pattern:

```ts
export async function GET() {
  const session = await requireSession();
  await requireRole(session.user.id, "admin");
  return Response.json(await db.user.findMany());
}
```

Review lesson: route handlers must enforce auth and authorization in the handler or a proven shared wrapper. Middleware presence is only support context.
