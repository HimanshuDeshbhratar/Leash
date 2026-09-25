# Leash

Leash is a scoped credential broker for AI agent tool calls. Giving agents raw, long-lived API keys is a real production risk — a compromised agent (or a prompt-injection that tricks one) can do anything those keys allow, forever. Leash demonstrates the alternative: a principal authorizes an agent to request a **short-lived, single-use, exactly-scoped** JWT for one action; the agent presents that token to `/execute`; the broker verifies signature, expiry, revocation, and scope, then (in this demo) mocks the downstream call and burns the token. Every allow and deny is written to an append-only audit log.

**Stack:** Node.js + Express + TypeScript, SQLite via the built-in `node:sqlite` module, `jsonwebtoken` for signing, vanilla HTML/CSS/JS frontend served by the same Express app (and as static `public/` on Vercel).

## Architecture

```
  Principal (human)                Agent                         Downstream
        |                            |                                |
        |  POST /request-token       |                                |
        |  {principal, scope, ttl}   |                                |
        |--------------------------->|                                |
        |  JWT (token_id, scope,     |                                |
        |   issued_by, exp) + DB row |                                |
        |<---------------------------|                                |
        |                            |                                |
        |                            |  POST /execute                 |
        |                            |  {token, action, payload?}     |
        |                            |------------------------------->|
        |                            |  verify JWT + DB state         |
        |                            |  (sig, exp, used, revoked,     |
        |                            |   exact scope match)           |
        |                            |  mark used=1                   |
        |                            |  mock call  - - - - - - - - - >|
        |                            |  {status: ok, simulated: ...}  |
        |                            |<-------------------------------|
        |                            |                                |
        |  POST /revoke {token_id}   |                                |
        |--------------------------->|  (kills live token instantly)  |
        |                            |                                |
        |  GET /audit-log  <--------- every decision, newest first ---|
```

**Why a DB row in addition to the JWT?** JWTs are signed and normally *stateless* — once issued you cannot take them back. Leash stores each token with `used` and `revoked` flags so `/execute` can enforce single-use and instant revocation even though the JWT itself cannot change.

**Why exact scope match?** Pattern matching (`github:*`) is easy to misconfigure into over-broad grants. Exact string equality (`action === scope`) is trivial to explain and hard to accidentally widen.

**Why single-use?** One token = one action. A captured JWT cannot be replayed even if it is still unexpired.

## Endpoints

### Issue a token

```bash
curl -s -X POST http://localhost:3000/request-token \
  -H "Content-Type: application/json" \
  -d '{"principal":"alice","scope":"github:comment:issue","ttl_seconds":300}'
```

### Execute (consumes the token)

```bash
curl -s -X POST http://localhost:3000/execute \
  -H "Content-Type: application/json" \
  -d '{"token":"<JWT>","action":"github:comment:issue"}'
```

### Revoke

```bash
curl -s -X POST http://localhost:3000/revoke \
  -H "Content-Type: application/json" \
  -d '{"token_id":"<uuid>","principal":"alice"}'
```

### Audit log

```bash
curl -s "http://localhost:3000/audit-log?limit=20&offset=0"
```

## What this doesn't do

This is a **demo of the pattern**, not a production auth system:

- No real GitHub / Slack / cloud API integration — `/execute` returns a simulated success payload
- No persistent principal or agent identity management (principals are free-form strings)
- Single shared `JWT_SECRET` rather than per-tenant signing keys
- No TLS, rate limiting, or hardened input validation beyond the demo path
- No policy engine — scope is whatever string you pass at issue time
- On Vercel, SQLite lives under `/tmp` and is **ephemeral** (not shared across serverless instances) — enough to demo the flow, not durable multi-region storage

## Run locally

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The UI lets you issue, execute, and revoke tokens while the audit table polls `/audit-log` every 2 seconds.

Requires Node.js 22.5+ (uses the built-in `node:sqlite` module — no native compile step). Copy `.env.example` to `.env` if you need to change `JWT_SECRET` or `PORT`.

## Deploy on Vercel

1. Push this repo to GitHub (already done if you followed the commit series).
2. In [Vercel](https://vercel.com): **Add New Project** → import `HimanshuDeshbhratar/Leash`.
3. Framework preset should detect **Express** from `src/server.ts` (default export). Leave build settings alone — no special build command required.
4. Set Environment Variable: `JWT_SECRET` = a long random string (Project → Settings → Environment Variables). Optional for a first deploy (a demo fallback exists), but set it before sharing the URL.
5. Deploy. The UI is served from `public/`; API routes (`/request-token`, `/execute`, `/revoke`, `/audit-log`) hit the Express function.

Or from the CLI:

```bash
npx vercel
npx vercel --prod
```

**Node version:** `package.json` pins `"engines": { "node": "22.x" }` so `node:sqlite` is available.
