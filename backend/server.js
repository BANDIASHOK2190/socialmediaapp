import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

// Database setup (JSON file db.json)
const adapter = new JSONFile("db.json");
const db = new Low(adapter, { users: [] });
await db.read();
db.data ||= { users: [] };

// JWT secret key (use env variable in production!)
const JWT_SECRET = "supersecretkey";

// REGISTER (saves password securely)
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  // Check if user already exists
  const existingUser = db.data.users.find((u) => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: "User already exists" });
  }

  // Hash password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save new user in db.json
  const newUser = {
    id: Date.now().toString(),
    username,
    password: hashedPassword,
  };

  db.data.users.push(newUser);
  await db.write();

  res.status(201).json({ message: "User registered successfully" });
});

// LOGIN (retrieves user from db.json)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  // Load users from db.json
  await db.read();
  const user = db.data.users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  // Compare hashed password
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });

  // Create JWT
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ message: "Login successful", token });
});

// LOGOUT (adds token to blacklist)
let tokenBlacklist = [];

app.post("/api/logout", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(400).json({ error: "Token required" });

  tokenBlacklist.push(token);
  res.json({ message: "Logged out successfully" });
});

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  if (tokenBlacklist.includes(token))
    return res.status(401).json({ error: "Token is invalid" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Example protected route
app.get("/api/profile", authMiddleware, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}` });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
