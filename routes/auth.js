const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../middleware/authMiddleware");
const AccessLog = require("../models/AccessLog");
const BlacklistedToken = require("../models/BlacklistedToken");

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    res.json({ message: "User registered" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGIN =================
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    user.currentToken = token;
    await user.save();

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= PROTECTED =================
router.get("/protected", authMiddleware, async (req, res) => {
  try {
    const token = req.header("Authorization");

    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) {
      return res.status(401).json({ message: "Token expired" });
    }

    const ip =
  req.headers["x-forwarded-for"] ||
  req.connection.remoteAddress ||
  req.socket.remoteAddress ||
  "127.0.0.1";
    const device = req.headers["user-agent"];

    let riskScore = 0;
    let warnings = [];

    // 🔍 DEVICE CHECK
    const existingDevice = await AccessLog.findOne({
      userId: req.user.id,
      device
    });

    if (!existingDevice) {
      warnings.push("New device detected");
      riskScore += 1;
    }

    // 🔍 IP CHECK
    const existingIP = await AccessLog.findOne({
      userId: req.user.id,
      ip
    });

    if (!existingIP) {
      warnings.push("New IP detected");
      riskScore += 1;
    }

    // ⏱ FREQUENT REQUEST CHECK
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000);

    const recentLogs = await AccessLog.find({
      userId: req.user.id,
      createdAt: { $gte: oneMinuteAgo }
    });

    if (recentLogs.length > 8) {
      warnings.push("Too many requests (possible bot)");
      riskScore += 1;
    }

    // 🔒 DEVICE LIMIT (NO BLOCK)
    const devices = await AccessLog.distinct("device", {
      userId: req.user.id
    });

    if (!devices.includes(device) && devices.length >= 2) {
      warnings.push("Device limit reached");
      riskScore += 1;
    }

    // 🧠 FINAL RISK
    let risk = "LOW";
    if (riskScore >= 2) risk = "HIGH";

    // ================= SMART LOGGING (🔥 FIX) =================
    const lastLog = await AccessLog.findOne({ userId: req.user.id })
      .sort({ createdAt: -1 });

    const now = Date.now();

    if (
      !lastLog ||
      lastLog.ip !== ip ||
      lastLog.device !== device ||
      (now - new Date(lastLog.createdAt).getTime()) > 10000 // 10 sec gap
    ) {
      await new AccessLog({
        userId: req.user.id,
        ip,
        device
      }).save();
    }

    // 🚫 NO BLOCKING
    if (risk === "HIGH") {
      warnings.push("High risk behavior detected");
    }

    res.json({
      user: req.user,
      ip,
      device,
      risk,
      warnings
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= PROFILE =================
router.get("/profile", authMiddleware, async (req, res) => {
  try {
    const token = req.header("Authorization");

    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) {
      return res.status(401).json({ message: "Token expired" });
    }

    const user = await User.findById(req.user.id).select("-password");

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      session: "active"
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGOUT =================
router.post("/logout", authMiddleware, async (req, res) => {
  try {
    const token = req.header("Authorization");

    await new BlacklistedToken({ token }).save();

    res.json({ message: "Logged out successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET LOGS =================
router.get("/logs", authMiddleware, async (req, res) => {
  try {
    const logs = await AccessLog.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json(logs);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;