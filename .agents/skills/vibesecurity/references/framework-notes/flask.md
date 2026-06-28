# Flask Notes

Prioritize decorators, blueprints, templates, and extension configuration.

Check:

- Sensitive endpoints require auth decorators or centralized before-request guards.
- Authorization checks happen for path-parameter objects.
- Jinja escaping is not bypassed with unsafe markup.
- SQL, file paths, SSRF fetches, and uploads are controlled.
- Session secret, cookie flags, CORS, and error settings are production-safe.
