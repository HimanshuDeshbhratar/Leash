import { DatabaseSync } from "node:sqlite";
import path from "path";
import os from "os";

/**
 * SQLite via Node's built-in `node:sqlite` (DatabaseSync).
 * Same idea as better-sqlite3 — synchronous, file-backed, zero external DB —
 * without a native addon that needs Visual Studio build tools on Windows.
 *
 * Path selection:
 * - Locally: ./leash.db in the project root (persists across restarts).
 * - On Vercel: /tmp/leash.db — the only writable dir in a serverless function.
 *   Storage is *ephemeral* (lost on cold starts / new instances). Fine for a
 *   demo of the token pattern; not fine for production multi-instance state.
 */
function resolveDbPath(): string {
  if (process.env.VERCEL) {
    return path.join(os.tmpdir(), "leash.db");
  }
  return path.join(process.cwd(), "leash.db");
}

const dbPath = resolveDbPath();
export const db = new DatabaseSync(dbPath);

// WAL improves concurrent read performance while we poll /audit-log from the UI.
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA foreign_keys = ON");

/**
 * tokens
 * ------
 * We store every issued token even though the JWT itself is self-contained.
 * Why? JWTs are normally *stateless* — once signed, you can't take them back.
 * By keeping a row with `used` and `revoked` flags, we can:
 *   1. Enforce single-use (mark used after /execute)
 *   2. Support instant revocation (mark revoked via /revoke)
 * The JWT proves authenticity; the DB row proves current authorization state.
 *
 * audit_log
 * ---------
 * Every decision (allow or deny) is append-only. This is the evidence trail
 * an interviewer will ask about: "how do you know who did what, and why
 * something was rejected?"
 */
export function initSchema(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      id         TEXT PRIMARY KEY,
      scope      TEXT NOT NULL,
      issued_by  TEXT NOT NULL,
      issued_at  INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0,
      revoked    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp  INTEGER NOT NULL,
      action     TEXT NOT NULL,
      token_id   TEXT,
      scope      TEXT,
      principal  TEXT,
      decision   TEXT NOT NULL,
      reason     TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
      ON audit_log(timestamp DESC);
  `);
}
