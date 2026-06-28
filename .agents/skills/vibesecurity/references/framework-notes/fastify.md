# Fastify Notes

Prioritize hooks, schemas, plugins, and route-level authorization.

Check:

- `preHandler` or auth hooks protect sensitive routes and are registered in the right plugin scope.
- JSON schemas validate trust-boundary inputs but do not replace authorization.
- Object IDs are checked against user, role, and tenant context.
- User-controlled URLs, file paths, and query fragments do not reach dangerous sinks.
- Plugin encapsulation does not create routes that skip expected guards.
