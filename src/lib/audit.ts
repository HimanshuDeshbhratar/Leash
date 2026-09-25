import { insertAudit, getAuditLog, getAuditLogCount } from "../db/queries";

export interface AuditEntry {
  action: "issue" | "execute" | "revoke";
  token_id: string | null;
  scope: string | null;
  principal: string | null;
  decision: "allowed" | "denied";
  reason: string;
}

/**
 * Append-only audit writer.
 *
 * We log both allows *and* denials. Denials are often more interesting in a
 * security incident: "someone tried to reuse a token" or "scope mismatch"
 * is the signal. Writing every decision also makes the live UI table useful
 * for demos — you can watch a deny appear the moment a bad /execute hits.
 */
export function writeAudit(entry: AuditEntry): void {
  insertAudit({
    timestamp: Math.floor(Date.now() / 1000),
    ...entry,
  });
}

export function fetchAuditLog(
  limit: number = 50,
  offset: number = 0
): { entries: ReturnType<typeof getAuditLog>; total: number; limit: number; offset: number } {
  // Clamp to keep a careless client from asking for a million rows.
  const safeLimit = Math.min(Math.max(1, limit), 200);
  const safeOffset = Math.max(0, offset);

  return {
    entries: getAuditLog(safeLimit, safeOffset),
    total: getAuditLogCount(),
    limit: safeLimit,
    offset: safeOffset,
  };
}
