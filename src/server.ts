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
const isVercel = Boolean(process.env.VERCEL);

// process.cwd() is reliable on Vercel; __dirname can point inside the bundle.
const publicDir = path.join(process.cwd(), "public");

app.use(express.json());

// API routes
app.use(tokenRoutes);
app.use(auditRoutes);

// Always serve the UI from Express.
// On Vercel, framework mode routes "/" to this function (CDN public/ alone
// does not satisfy GET /), so we must handle static files here. vercel.json
// includeFiles ensures /public is present in the serverless bundle.
app.use(express.static(publicDir));

app.get("/", (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

// Only bind a port when running as a long-lived process (local / npm start).
// On Vercel the platform invokes this module as a serverless function.
if (!isVercel) {
  app.listen(PORT, () => {
    console.log(`Leash listening on http://localhost:${PORT}`);
    console.log(`  POST /request-token  — issue a scoped token`);
    console.log(`  POST /execute        — use a token (single-use)`);
    console.log(`  POST /revoke         — kill a live token`);
    console.log(`  GET  /audit-log      — decision trail`);
  });
}

// Default export is what Vercel's Express detector picks up (src/server.ts).
export default app;
