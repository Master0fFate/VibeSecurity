# React Notes

Prioritize client-side trust assumptions and rendering sinks.

Check:

- Authorization is enforced server-side; hidden buttons or client route guards are not security controls.
- `dangerouslySetInnerHTML`, markdown rendering, rich text, and URL attributes sanitize untrusted content.
- Tokens and secrets are not stored in source, logs, local storage, or public runtime config.
- Browser automation or extension-like behavior cannot be steered by untrusted model/user output.
- Form actions and API calls rely on server validation, not client-only checks.
