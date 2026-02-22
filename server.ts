import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import path from "path";
import fs from "fs";

const db = new Database("students.db");
const JWT_SECRET = "your-secret-key-change-this-in-production";

// Configure Nodemailer (Using Ethereal for demo/real-time testing if no env provided)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.ethereal.email',
  port: Number(process.env.SMTP_PORT) || 587,
  auth: {
    user: process.env.SMTP_USER || 'mock-user@ethereal.email',
    pass: process.env.SMTP_PASS || 'mock-pass',
  },
});

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT CHECK(role IN ('ADMIN', 'STUDENT')),
    student_id INTEGER,
    FOREIGN KEY(student_id) REFERENCES students(id)
  );

  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    enrollment_date TEXT,
    major TEXT,
    gpa REAL DEFAULT 0.0
  );
`);

// Seed Admin if not exists
const adminExists = db.prepare("SELECT * FROM users WHERE role = 'ADMIN'").get();
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run("admin", hashedPassword, "ADMIN");
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  const isAdmin = (req: any, res: any, next: any) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    next();
  };

  // Auth Routes
  app.post("/api/auth/register", (req, res) => {
    const { username, password, first_name, last_name, email, major } = req.body;
    try {
      const hashedPassword = bcrypt.hashSync(password, 10);
      
      const studentResult = db.prepare("INSERT INTO students (first_name, last_name, email, major, enrollment_date) VALUES (?, ?, ?, ?, ?)").run(
        first_name, last_name, email, major, new Date().toISOString().split('T')[0]
      );
      
      db.prepare("INSERT INTO users (username, password, role, student_id) VALUES (?, ?, ?, ?)").run(
        username, hashedPassword, 'STUDENT', studentResult.lastInsertRowid
      );
      
      res.status(201).json({ message: "User registered successfully" });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as any;
    
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role, student_id: user.student_id }, JWT_SECRET);
      res.json({ token, user: { username: user.username, role: user.role, student_id: user.student_id } });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  });

  app.get("/api/auth/me", authenticateToken, (req: any, res) => {
    res.json(req.user);
  });

  app.post("/api/auth/forgot-password", async (req, res) => {
    const { email } = req.body;
    const student = db.prepare("SELECT * FROM students WHERE email = ?").get(email) as any;
    
    if (!student) {
      return res.status(404).json({ error: "No student found with this email address" });
    }

    const user = db.prepare("SELECT * FROM users WHERE student_id = ?").get(student.id) as any;
    if (!user) {
      return res.status(404).json({ error: "No user account associated with this student" });
    }

    const resetToken = jwt.sign({ id: user.id, type: 'reset' }, JWT_SECRET, { expiresIn: '1h' });
    const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

    try {
      // In a real app, you'd send a real email. 
      // For this environment, we'll log it and attempt to send via the configured transporter.
      console.log(`----------------------------------------`);
      console.log(`PASSWORD RESET REQUEST`);
      console.log(`Email: ${email}`);
      console.log(`Reset Link: ${resetLink}`);
      console.log(`----------------------------------------`);

      // Attempt to send via transporter
      const info = await transporter.sendMail({
        from: '"EduStream Support" <support@edustream.edu>',
        to: email,
        subject: "Password Reset Request",
        html: `
          <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 12px;">
            <h2 style="color: #4f46e5;">Password Reset</h2>
            <p>You requested a password reset for your EduStream account.</p>
            <p>Click the button below to reset your password. This link will expire in 1 hour.</p>
            <a href="${resetLink}" style="display: inline-block; background: #4f46e5; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin: 20px 0;">Reset Password</a>
            <p style="color: #6b7280; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
          </div>
        `
      });

      console.log("Message sent: %s", info.messageId);

      res.json({ 
        message: "Password reset link sent to your email",
        // For the preview environment, we'll return the link if no real SMTP is configured
        // so the user can actually test the flow.
        debug_link: process.env.SMTP_USER === 'mock-user@ethereal.email' ? resetLink : undefined
      });
    } catch (error) {
      console.error("Email error:", error);
      // Fallback for demo: still return success but provide the link in the response
      res.json({ 
        message: "Email service unavailable. Link generated for testing.",
        debug_link: resetLink 
      });
    }
  });

  app.post("/api/auth/reset-password", (req, res) => {
    const { token, password } = req.body;
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.type !== 'reset') throw new Error("Invalid token type");

      const hashedPassword = bcrypt.hashSync(password, 10);
      db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, decoded.id);
      
      res.json({ message: "Password updated successfully" });
    } catch (error: any) {
      res.status(400).json({ error: "Invalid or expired reset token" });
    }
  });

  // Student Routes
  app.get("/api/students", authenticateToken, (req: any, res) => {
    if (req.user.role === 'ADMIN') {
      const students = db.prepare("SELECT * FROM students").all();
      res.json(students);
    } else {
      const student = db.prepare("SELECT * FROM students WHERE id = ?").get(req.user.student_id);
      res.json([student]);
    }
  });

  app.post("/api/students", authenticateToken, isAdmin, (req, res) => {
    const { first_name, last_name, email, phone, major, gpa } = req.body;
    try {
      const result = db.prepare("INSERT INTO students (first_name, last_name, email, phone, major, gpa, enrollment_date) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
        first_name, last_name, email, phone, major, gpa, new Date().toISOString().split('T')[0]
      );
      res.status(201).json({ id: result.lastInsertRowid });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.put("/api/students/:id", authenticateToken, isAdmin, (req, res) => {
    const { first_name, last_name, email, phone, major, gpa } = req.body;
    try {
      db.prepare("UPDATE students SET first_name = ?, last_name = ?, email = ?, phone = ?, major = ?, gpa = ? WHERE id = ?").run(
        first_name, last_name, email, phone, major, gpa, req.params.id
      );
      res.json({ message: "Student updated" });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.delete("/api/students/:id", authenticateToken, isAdmin, (req, res) => {
    try {
      db.prepare("DELETE FROM users WHERE student_id = ?").run(req.params.id);
      db.prepare("DELETE FROM students WHERE id = ?").run(req.params.id);
      res.json({ message: "Student deleted" });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(process.cwd(), "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(process.cwd(), "dist", "index.html"));
    });
  }

  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
