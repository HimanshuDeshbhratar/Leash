import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import {
  getTokenById,
  insertToken,
  markTokenUsed,
  markTokenRevoked,
  type TokenRow,
} from "../db/queries";

export interface TokenClaims {
  token_id: string;
  scope: string;
  issued_by: string;
  issued_at: number; // unix seconds
  expires_at: number; // unix seconds
}

export type DenialReason =
  | "bad signature"
  | "expired"
  | "already used"
  | "revoked"
  | "scope mismatch"
  | "token not found";

export type VerifyResult =
  | { ok: true; claims: TokenClaims; row: TokenRow }
  | { ok: false; reason: DenialReason; claims?: Partial<TokenClaims> };

const DEFAULT_TTL_SECONDS = 300; // 5 minutes — short enough that a leaked token dies quickly

function getSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is not set. Copy .env.example to .env.");
  }
  return secret;
}

/**
 * Issue a scoped, short-lived token.
 *
 * Security decisions visible here:
 * - Short TTL (default 300s): limits the blast radius of a leaked JWT.
 * - Explicit token_id (uuid): lets us look up DB state for use/revoke checks.
 * - We persist the row *before* returning the JWT so revocation and single-use
 *   checks have something to read against from the first moment.
 */
export function issueToken(
  principal: string,
  scope: string,
  ttlSeconds: number = DEFAULT_TTL_SECONDS
): { token: string; token_id: string; expires_at: number; scope: string } {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + ttlSeconds;
  const tokenId = uuidv4();

  const claims: TokenClaims = {
    token_id: tokenId,
    scope,
    issued_by: principal,
    issued_at: now,
    expires_at: expiresAt,
  };

  // Persist first. If signing somehow fails after this, the orphan row is
  // harmless — it was never handed to an agent and will expire unused.
  insertToken({
    id: tokenId,
    scope,
    issued_by: principal,
    issued_at: now,
    expires_at: expiresAt,
  });

  // jwt.sign also sets `exp`, which jsonwebtoken checks automatically on verify.
  // We still keep expires_at in the payload for audit/UI clarity.
  const token = jwt.sign(claims, getSecret(), { expiresIn: ttlSeconds });

  return { token, token_id: tokenId, expires_at: expiresAt, scope };
}

/**
 * Verify a token for a specific action.
 *
 * Order of checks matters and is intentional:
 * 1. Signature + structural validity (crypto authenticity)
 * 2. Expiry (time-boxed even without a DB hit)
 * 3. DB row exists
 * 4. Not revoked  — JWT alone cannot express this; that's why we keep state
 * 5. Not already used — single-use enforces least privilege: one token = one action
 * 6. Scope exact match — no wildcards/prefixes; simpler and harder to misconfigure
 *
 * Why DB checks in addition to JWT validity?
 * JWTs are signed blobs. Once issued they cannot be mutated. Revocation and
 * single-use *require* mutable server-side state. The JWT answers "was this
 * issued by us?"; the DB answers "is this still authorized *right now*?"
 *
 * Why exact string match for scope?
 * Pattern matching ("github:*") looks flexible but is easy to get wrong
 * (over-broad grants, unexpected overlaps). Exact match means the scope on
 * the token is identical to the action being executed — trivial to explain
 * in an interview and hard to accidentally widen.
 */
export function verifyForExecute(
  token: string,
  action: string
): VerifyResult {
  let claims: TokenClaims;

  try {
    const decoded = jwt.verify(token, getSecret()) as jwt.JwtPayload &
      TokenClaims;
    claims = {
      token_id: decoded.token_id,
      scope: decoded.scope,
      issued_by: decoded.issued_by,
      issued_at: decoded.issued_at,
      expires_at: decoded.expires_at,
    };
  } catch (err) {
    // Distinguish expiry from other crypto/structural failures for clearer audits.
    if (err instanceof jwt.TokenExpiredError) {
      return { ok: false, reason: "expired" };
    }
    return { ok: false, reason: "bad signature" };
  }

  // Belt-and-suspenders: jwt.verify already checked `exp`, but we also store
  // expires_at in the payload/DB for auditing. Reject if either says expired.
  const now = Math.floor(Date.now() / 1000);
  if (claims.expires_at < now) {
    return { ok: false, reason: "expired", claims };
  }

  const row = getTokenById(claims.token_id);
  if (!row) {
    return { ok: false, reason: "token not found", claims };
  }

  if (row.revoked === 1) {
    return { ok: false, reason: "revoked", claims };
  }

  if (row.used === 1) {
    // Single-use: replay of a captured token must fail even if still unexpired.
    return { ok: false, reason: "already used", claims };
  }

  // Exact match only — see comment above.
  if (action !== claims.scope || action !== row.scope) {
    return { ok: false, reason: "scope mismatch", claims };
  }

  return { ok: true, claims, row };
}

/**
 * Consume the token after a successful authorization check.
 * Call this only after verifyForExecute returns ok — otherwise we burn a
 * valid token on a failed attempt.
 */
export function consumeToken(tokenId: string): void {
  markTokenUsed(tokenId);
}

/**
 * Instant kill switch. Marks revoked regardless of expiry or use status.
 * Subsequent /execute calls will fail at the DB check with reason "revoked".
 */
export function revokeToken(tokenId: string): boolean {
  return markTokenRevoked(tokenId);
}

/**
 * Build a human-readable mock of what the downstream call would have been.
 * Keeps the demo self-contained — no real GitHub/Slack credentials needed.
 */
export function simulateDownstreamCall(
  scope: string,
  payload?: unknown
): { status: "ok"; simulated: string; payload?: unknown } {
  // Map common demo scopes to readable fake responses.
  const descriptions: Record<string, string> = {
    "github:comment:issue":
      "would have called GitHub API: comment on issue #4",
    "github:create:pr": "would have called GitHub API: create pull request",
    "slack:send:message": "would have called Slack API: post message to channel",
    "slack:read:channel": "would have called Slack API: read channel history",
  };

  const simulated =
    descriptions[scope] ?? `would have executed action: ${scope}`;

  return {
    status: "ok",
    simulated,
    ...(payload !== undefined ? { payload } : {}),
  };
}
