# Fixing common findings

**Secret key in the frontend.** Revoke the key at the provider first, then move the call
to a server function and keep the key in its environment.

**Supabase table readable with the anon key.** Enable row level security on every table
and add policies that check `auth.uid()`.

**Firebase database open.** Replace test rules with rules that require `request.auth`.

**LLM call from the browser.** Proxy through a server route with authentication and a rate limit.

**Source maps public.** Disable production source maps or upload them only to your error tracker.

**Security headers.** Set CSP, HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy`
and frame protection in the hosting configuration.

These are starting points, not a complete fix. Check again after the change.
