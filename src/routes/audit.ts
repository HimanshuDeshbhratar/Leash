import { Router, Request, Response } from "express";
import { fetchAuditLog } from "../lib/audit";

const router = Router();

/**
 * GET /audit-log?limit=&offset=
 * Newest first. The frontend polls this every 2s for the live table.
 */
router.get("/audit-log", (req: Request, res: Response) => {
  const limit = parseInt(String(req.query.limit ?? "50"), 10);
  const offset = parseInt(String(req.query.offset ?? "0"), 10);

  const result = fetchAuditLog(
    Number.isFinite(limit) ? limit : 50,
    Number.isFinite(offset) ? offset : 0
  );

  return res.json(result);
});

export default router;
