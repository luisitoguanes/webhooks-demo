// server/index.js
const path = require("path");
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 4000;

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(express.json());
// During development, allow your Vite app on port 5173 to hit the API:
app.use(cors({ origin: "http://localhost:5173" }));

// ─── API Routes ────────────────────────────────────────────────────────────────
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Missing username or password" });
  }
  // In a real app you'd validate against a database here
  return res.json({ success: true, token: "fake-jwt-token-1234" });
});

// ─── Static Serve (for production) ────────────────────────────────────────────
if (process.env.NODE_ENV === "production") {
  const clientDist = path.join(__dirname, "../client/dist");
  app.use(express.static(clientDist));

  // All remaining requests get sent to React's index.html
  app.get("*", (req, res) => {
    res.sendFile(path.join(clientDist, "index.html"));
  });
}

// ─── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🟢 Server listening on http://localhost:${PORT}`);
});
