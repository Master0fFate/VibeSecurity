# Web/API Checklist

Walk this manual baseline for the active web/API scope, including public routes, handlers, controllers, middleware order, and effective deployment settings. These controls are not new deterministic detectors. For each control, record evidence and verification and a coverage outcome from `review-lanes.md`: absent, reviewed, needs-review, profile-only, unsupported, or out-of-scope. Give a reason for absent or out-of-scope controls; unknown deployment settings remain needs-review. Reviewed does not mean secure, and a missing control alone is not a vulnerability. Apply the evidence-first finding gate and confirm reachability, boundary crossing, impact, location, and a fix and verification path before reporting.

## Application Baseline

### 1. Hide API keys

- Review: Keep secrets server-side in a secret store with least-privilege access; inspect public environment prefixes, client imports, bundles, source maps, logs, and generated artifacts.
- Verify: Trace each credential class from configuration to its effective runtime and outputs; confirm no server credential reaches a client or log, without displaying values.

### 2. Purge Git secrets

- Review: Rotate or revoke exposed credentials first. Deleting a file or adding `.gitignore` does not purge history. Coordinate and obtain explicit approval before rewriting history or force-pushing; forks, clones, and caches may retain copies.
- Verify: Inspect authorized local history and current tracked artifacts for the secret class without revealing values; record rotation evidence and any unverified copies or rewrite limitations.

### 3. Use public DB key

- Review: Clients may use only explicitly publishable database API keys, with RLS or equivalent rules and least-privilege grants. Never expose generic database credentials, secret keys, or service-role keys. Supabase publishable and legacy anon keys are public; secret and legacy service_role keys bypass RLS.
- Verify: Trace client configuration and effective grants and policies for the public role; confirm privileged credentials remain server-side and note unavailable deployment settings.

### 4. Enable row-level security

- Review: Confirm RLS is enabled on exposed tables, or equivalent access rules are enforced. Inspect effective policies and grants for select, insert, update, and delete, including cross-tenant access, USING/WITH CHECK equivalents, and privileged bypass paths.
- Verify: Inspect applied policies and, where authorized, exercise each operation as separate users and tenants in a disposable environment; check privileged paths enforce their own authorization.

### 5. Encrypt sensitive data

- Review: Threat-model sensitive data in storage and backups; use authenticated encryption and managed keys with restricted access and rotation where encryption addresses the threat. Hash passwords instead of encrypting them.
- Verify: Trace sensitive fields and backups to effective encryption and key configuration; confirm the protection matches the threat model or record unknown settings.

### 6. Enforce server-side auth

- Review: Enforce authentication and authorization on the server for sensitive operations, not only client guards. Verify session validity or JWT signature, issuer, audience, and time claims as applicable.
- Verify: Trace registered routes and alternate execution paths to their effective guards; check missing, invalid, expired, and wrong-audience credentials are rejected in an authorized local environment.

### 7. Lock record access

- Review: Scope reads, writes, deletes, bulk operations, and exports to the authorized owner or tenant, including background and privileged paths.
- Verify: Trace resource lookup and policy enforcement and check another user or tenant cannot access or change records through each applicable operation.

### 8. Block field tampering

- Review: Use allowlisted update DTOs or schemas; derive roles, owner, tenant, price, and other privileged fields on the server, and explicitly authorize any permitted client changes.
- Verify: Trace request binding through persistence and check unauthorized changes to protected fields are rejected or ignored without changing stored values.

### 9. Secure session cookies

- Review: Set HttpOnly, Secure, appropriate SameSite, and bounded domain/path scope; protect cookie-authenticated state changes against CSRF and rotate sessions at authentication or privilege changes, with logout and expiry.
- Verify: Inspect effective Set-Cookie and session configuration and check rotation, expiry, logout, and CSRF enforcement on applicable local flows.

### 10. Hash passwords

- Review: Use managed authentication or a maintained adaptive password-hashing library with unique salts and current OWASP-aligned cost settings; prefer Argon2id, with alternatives selected for platform or compliance requirements. Do not use MD5, SHA alone, or reversible encryption for passwords.
- Verify: Trace password creation and verification to the effective provider or hash settings; confirm stored credentials are salted hashes and cost settings are applied without exposing values.

### 11. Rate limit login

- Review: Apply login, reset, and signup budgets shared across replicas, keyed by account and network, with trusted proxy handling and safeguards against trivial account-lockout denial of service. Include invite, payment, export, and AI-cost endpoints where applicable.
- Verify: Inspect effective limiter storage, keys, proxy trust, and recovery behavior; exercise bounded local requests across applicable instances and confirm limits and legitimate recovery work.

### 12. Add bot protection

- Review: Select risk-based bot defenses where abuse warrants them, not mandatory global CAPTCHA. Verify any challenge server-side for the intended action, expiry, and reuse; retain auth and rate controls.
- Verify: Trace challenge issuance and server verification and check missing, expired, wrong-action, and reused challenges fail on protected flows; document the risk basis where not applicable.

### 13. Parameterize queries

- Review: Keep values separate from query structure: parameterize SQL and raw ORM queries, use safe search APIs, and build NoSQL filters from validated scalar values rather than client-supplied operators. Allowlist identifiers and sort orders that cannot be bound.
- Verify: Trace untrusted inputs to query construction and inspect bound parameters and identifier selection on each applicable path.

### 14. Validate all input

- Review: Apply server-side schemas with types, lengths, and resource limits to untrusted inputs, including webhook and model output. Validation does not replace authorization.
- Verify: Trace entry points to validation and check malformed, oversized, and unexpected fields are rejected before sensitive processing, independently of authorization checks.

### 15. Escape user content

- Review: Use context-aware output encoding and framework safe sinks for HTML, attributes, URLs, scripts, markdown, and serialized content; use a maintained sanitizer for intentional HTML. Avoid blanket escaping and double encoding; CSP is not a substitute.
- Verify: Trace untrusted content to each browser or browser-automation rendering context and inspect the actual encoding or sanitizer configuration and safe sink behavior.

### 16. Restrict file uploads

- Review: Require authorization, type/signature checks, size and count limits, safe filenames, private non-executable storage, and authorized downloads; extension or MIME alone is insufficient. Bound parser and archive processing and scanning where relevant.
- Verify: Trace upload through storage and download; check authorization, mismatched types, limits, path containment, and applicable parser/archive bounds in a disposable environment.

### 17. Trim API responses

- Review: Allowlist response fields and paginate; exclude credentials, password hashes, unnecessary PII, and internal errors. Prevent cross-user or cross-tenant cache reuse.
- Verify: Inspect serializers, queries, cache keys and effective responses for different users and roles, including errors and pagination limits, without exposing sensitive values.

### 18. Add security headers

- Review: Inspect deployment-effective CSP, frame restrictions, nosniff, referrer and permissions policies as applicable, and correct API Content-Type. A missing header alone does not establish an exploitable issue.
- Verify: Inspect effective headers at the application and deployment boundary for representative pages and API responses; account for proxy overrides and document unknowns.

### 19. Force HTTPS

- Review: Redirect browser traffic to HTTPS and reject plaintext sensitive API requests; validate upstream TLS, avoid mixed content, and configure trusted proxies correctly. Use HSTS on HTTPS hosts; enable includeSubDomains or preload only after the affected hosts are ready.
- Verify: Inspect effective ingress, proxy, TLS and browser resource configuration; check authorized local or deployment configuration for redirects, certificate validation, and HSTS scope.

### 20. Scan dependencies

- Review: Compare exact lockfile versions, including transitives, with manifests and available advisories; note manifest drift, advisory source age, and fix evidence. Use cached feeds locally and refresh only when authorized; use available ecosystem checks without blind auto-fix.
- Verify: Inspect lockfile and local scanner results and advisory provenance, then trace whether an affected version and vulnerable behavior are reachable; a scanner match alone is not exploitability proof.

## Additional Web Boundaries

- SSRF: Trace URL fetches, webhooks, image proxies, importers, crawlers, and metadata fetchers through destination, redirect, DNS, scheme, timeout, and response-size controls; inspect effective egress settings.
- CSRF and CORS: Check cookie-authenticated state changes for CSRF protection and inspect effective CORS origins, credentials, and preflight handling against intended trust.
- Webhooks: Verify signatures over the correct raw payload before processing, with appropriate timestamp and replay controls; inspect effective secret configuration without exposing values.
- Downloads and archives: Check authorization, path containment, symlink handling, archive extraction, and resource bounds for applicable flows; exercise safe local cases where authorized.
- Errors and logs: Trace sensitive values through exceptions, logs, and responses; inspect effective debug and logging settings and ensure secrets and sensitive data are not disclosed.

## Sources

- https://supabase.com/docs/guides/api/api-keys
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
