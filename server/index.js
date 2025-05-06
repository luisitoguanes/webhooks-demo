// server/index.js
const path = require("path");
const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 4000;

// Initialize SQLite database
const db = new sqlite3.Database("./demo.db", (err) => {
  if (err) {
    console.error("Error opening database:", err);
  } else {
    console.log("Connected to SQLite database");
    // Create users table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }
});

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(express.json());
// During development, allow your Vite app on port 5173 to hit the API:
app.use(cors({ origin: "http://localhost:5173" }));

// ─── API Routes ────────────────────────────────────────────────────────────────
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Missing username or password",
    });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE constraint failed")) {
            return res.status(400).json({
              success: false,
              message: "Username already exists",
            });
          }
          return res.status(500).json({
            success: false,
            message: "Error creating user",
          });
        }

        res.json({
          success: true,
          message: "User registered successfully",
        });
      }
    );
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error processing registration",
    });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Missing username or password",
    });
  }

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Error during login",
        });
      }

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
        });
      }

      try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return res.status(401).json({
            success: false,
            message: "Invalid username or password",
          });
        }

        res.json({
          success: true,
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
          },
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Error during login",
        });
      }
    }
  );
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
