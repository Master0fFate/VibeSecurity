# Go HTTP Notes

Prioritize handlers, middleware registration, context propagation, SQL, URL fetches, file paths, and templates.

Check:

- Middleware sets verified user and tenant context before sensitive handlers.
- Handlers enforce object-level authorization after loading resources.
- `http.Get`, custom clients, and proxy code cannot fetch arbitrary internal URLs.
- `exec.Command`, path joins, and archive extraction do not accept untrusted input.
- SQL uses placeholders and prepared statements.
- Templates use contextual escaping.
