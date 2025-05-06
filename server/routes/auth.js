const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

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

// Register endpoint
router.post("/register", async (req, res) => {
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

// Login endpoint
router.post("/login", async (req, res) => {
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

module.exports = router;
