import "dotenv/config";
import express from "express";
import path from "path";
import { initSchema } from "./db/schema";
import tokenRoutes from "./routes/tokens";
import auditRoutes from "./routes/audit";

// Initialize SQLite tables before accepting any requests.
initSchema();

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

app.use(express.json());

// API routes
app.use(tokenRoutes);
app.use(auditRoutes);

// Static frontend (vanilla HTML/CSS/JS) — same origin, no CORS fuss for the demo.
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Leash listening on http://localhost:${PORT}`);
  console.log(`  POST /request-token  — issue a scoped token`);
  console.log(`  POST /execute        — use a token (single-use)`);
  console.log(`  POST /revoke         — kill a live token`);
  console.log(`  GET  /audit-log      — decision trail`);
});
