import { Router, Request, Response } from "express";
import {
  issueToken,
  verifyForExecute,
  consumeToken,
  revokeToken,
  simulateDownstreamCall,
} from "../lib/token";
import { writeAudit } from "../lib/audit";

const router = Router();

/**
 * POST /request-token
 * Body: { principal, scope, ttl_seconds? }
 *
 * In a real system this would authenticate the principal and check that they
 * are allowed to mint tokens for this scope. Here the principal is just a
 * string so the demo stays focused on the token lifecycle itself.
 */
router.post("/request-token", (req: Request, res: Response) => {
  const { principal, scope, ttl_seconds } = req.body ?? {};

  if (
    typeof principal !== "string" ||
    !principal.trim() ||
    typeof scope !== "string" ||
    !scope.trim()
  ) {
    return res.status(400).json({
      error: "principal and scope are required non-empty strings",
    });
  }

  const ttl =
    typeof ttl_seconds === "number" && ttl_seconds > 0
      ? Math.min(ttl_seconds, 3600) // cap at 1h even in the demo
      : 300;

  const result = issueToken(principal.trim(), scope.trim(), ttl);

  writeAudit({
    action: "issue",
    token_id: result.token_id,
    scope: result.scope,
    principal: principal.trim(),
    decision: "allowed",
    reason: `issued with ttl=${ttl}s`,
  });

  return res.status(201).json({
    token: result.token,
    token_id: result.token_id,
    scope: result.scope,
    expires_at: result.expires_at,
    expires_at_iso: new Date(result.expires_at * 1000).toISOString(),
  });
});

/**
 * POST /execute
 * Body: { token, action, payload? }
 *
 * This is the authorization gate. Every failure path writes a denial with a
 * specific reason so the audit log explains *why* access was refused.
 */
router.post("/execute", (req: Request, res: Response) => {
  const { token, action, payload } = req.body ?? {};

  if (typeof token !== "string" || !token.trim()) {
    return res.status(400).json({ error: "token is required" });
  }
  if (typeof action !== "string" || !action.trim()) {
    return res.status(400).json({ error: "action is required" });
  }

  const verification = verifyForExecute(token.trim(), action.trim());

  if (!verification.ok) {
    writeAudit({
      action: "execute",
      token_id: verification.claims?.token_id ?? null,
      scope: verification.claims?.scope ?? action.trim(),
      principal: verification.claims?.issued_by ?? null,
      decision: "denied",
      reason: verification.reason,
    });

    return res.status(403).json({
      error: "forbidden",
      reason: verification.reason,
    });
  }

  // Authorization passed — burn the token (single-use) then mock the call.
  consumeToken(verification.claims.token_id);

  writeAudit({
    action: "execute",
    token_id: verification.claims.token_id,
    scope: verification.claims.scope,
    principal: verification.claims.issued_by,
    decision: "allowed",
    reason: "valid token, scope matched, marked used",
  });

  const simulated = simulateDownstreamCall(verification.claims.scope, payload);
  return res.json(simulated);
});

/**
 * POST /revoke
 * Body: { token_id, principal }
 *
 * Instant kill. Works even if the JWT is still cryptographically valid and
 * unexpired — because /execute always re-checks the DB `revoked` flag.
 */
router.post("/revoke", (req: Request, res: Response) => {
  const { token_id, principal } = req.body ?? {};

  if (typeof token_id !== "string" || !token_id.trim()) {
    return res.status(400).json({ error: "token_id is required" });
  }
  if (typeof principal !== "string" || !principal.trim()) {
    return res.status(400).json({ error: "principal is required" });
  }

  const found = revokeToken(token_id.trim());

  if (!found) {
    writeAudit({
      action: "revoke",
      token_id: token_id.trim(),
      scope: null,
      principal: principal.trim(),
      decision: "denied",
      reason: "token not found",
    });
    return res.status(404).json({ error: "token not found" });
  }

  writeAudit({
    action: "revoke",
    token_id: token_id.trim(),
    scope: null,
    principal: principal.trim(),
    decision: "allowed",
    reason: "token marked revoked",
  });

  return res.json({
    status: "ok",
    token_id: token_id.trim(),
    revoked: true,
  });
});

export default router;
