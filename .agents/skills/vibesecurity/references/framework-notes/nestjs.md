# NestJS Notes

Prioritize guards, interceptors, pipes, and service-level authorization.

Check:

- Controllers that mutate or expose sensitive data use guards.
- Guards establish identity but services still enforce object-level authorization.
- Pipes validate input at boundaries.
- Raw query builders and repository methods remain parameterized.
- File uploads, queues, and scheduled jobs preserve user/tenant context.
- Exception filters do not leak secrets.
