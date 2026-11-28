# Typical flaws in AI-built apps

| Flaw | Why AI tools produce it | Check |
|---|---|---|
| Secret key in the frontend | the quickest way to make an API call work | `secrets.frontend` |
| Supabase without row level security | tables are created, policies are forgotten | `supabase.*` |
| Open Firebase rules | test mode rules stay in production | `firebase.*` |
| LLM call from the browser | no backend in the generated app | `ai.client-llm-call` |
| Public source maps | default build settings | `sourcemaps.exposed` |
| Missing security headers | hosting defaults | `headers.security` |
| Debug build in production | dev server or dev mode deployed | `build.dev-mode` |
| Data in `__NEXT_DATA__` | server props passed whole to the page | `next.data-leak` |

Add patterns you have seen, with an anonymised example.
