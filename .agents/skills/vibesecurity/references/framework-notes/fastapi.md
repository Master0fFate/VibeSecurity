# FastAPI Notes

Prioritize dependencies, path-parameter routes, background tasks, and raw query use.

Check:

- Sensitive routes require auth dependencies.
- Path IDs are checked against current user, role, and tenant after loading resources.
- Pydantic models validate input but do not replace authorization.
- Raw SQL, template rendering, file paths, and background tasks avoid user-controlled unsafe sinks.
- Exceptions and logs do not reveal secrets.
