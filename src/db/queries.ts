import { db } from "./schema";

export interface TokenRow {
  id: string;
  scope: string;
  issued_by: string;
  issued_at: number;
  expires_at: number;
  used: number; // SQLite boolean: 0 | 1
  revoked: number;
}

export interface AuditLogRow {
  id: number;
  timestamp: number;
  action: string;
  token_id: string | null;
  scope: string | null;
  principal: string | null;
  decision: string;
  reason: string;
}

export interface InsertTokenParams {
  id: string;
  scope: string;
  issued_by: string;
  issued_at: number;
  expires_at: number;
}

export interface InsertAuditParams {
  timestamp: number;
  action: string;
  token_id: string | null;
  scope: string | null;
  principal: string | null;
  decision: "allowed" | "denied";
  reason: string;
}

export function insertToken(params: InsertTokenParams): void {
  const stmt = db.prepare(`
    INSERT INTO tokens (id, scope, issued_by, issued_at, expires_at, used, revoked)
    VALUES (?, ?, ?, ?, ?, 0, 0)
  `);
  stmt.run(
    params.id,
    params.scope,
    params.issued_by,
    params.issued_at,
    params.expires_at
  );
}

export function getTokenById(id: string): TokenRow | undefined {
  const stmt = db.prepare(`SELECT * FROM tokens WHERE id = ?`);
  return stmt.get(id) as unknown as TokenRow | undefined;
}

export function markTokenUsed(id: string): void {
  const stmt = db.prepare(`UPDATE tokens SET used = 1 WHERE id = ?`);
  stmt.run(id);
}

export function markTokenRevoked(id: string): boolean {
  // Confirm the row exists first — node:sqlite run() doesn't always expose changes.
  const existing = getTokenById(id);
  if (!existing) return false;
  const stmt = db.prepare(`UPDATE tokens SET revoked = 1 WHERE id = ?`);
  stmt.run(id);
  return true;
}

export function insertAudit(params: InsertAuditParams): void {
  const stmt = db.prepare(`
    INSERT INTO audit_log (timestamp, action, token_id, scope, principal, decision, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    params.timestamp,
    params.action,
    params.token_id,
    params.scope,
    params.principal,
    params.decision,
    params.reason
  );
}

export function getAuditLog(limit: number, offset: number): AuditLogRow[] {
  const stmt = db.prepare(`
    SELECT * FROM audit_log
    ORDER BY timestamp DESC, id DESC
    LIMIT ? OFFSET ?
  `);
  return stmt.all(limit, offset) as unknown as AuditLogRow[];
}

export function getAuditLogCount(): number {
  const row = db.prepare(`SELECT COUNT(*) as count FROM audit_log`).get() as unknown as {
    count: number;
  };
  return row.count;
}
