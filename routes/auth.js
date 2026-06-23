const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const crypto = require("crypto");

const User = require("../models/User");
const AccessLog = require("../models/AccessLog");
const BlacklistedToken = require("../models/BlacklistedToken");
const ThreatLog = require("../models/ThreatLog");
const Incident = require("../models/Incident");
const Device = require("../models/Device");
const authMiddleware = require("../middleware/authMiddleware");

// ================= HELPER: fingerprint =================
// Simple fingerprint = MD5-like hash of user-agent
function makeFingerprint(userAgent) {
  return crypto.createHash("sha256").update(userAgent || "unknown").digest("hex").slice(0, 16);
}

// ================= REGISTER =================
router.post(
  "/register",
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email required"),
    body("password").isLength({ min: 6 }).withMessage("Password min 6 chars"),
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, password } = req.body;

      const existing = await User.findOne({ email });
      if (existing) {
        return res.status(400).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = new User({ name, email, password: hashedPassword });
      await user.save();

      res.json({ message: "User registered successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ================= LOGIN =================
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Valid email required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ message: "User not found" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: "Wrong password" });

      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      // Single-session: overwrite current token
      user.currentToken = token;
      await user.save();

      res.json({
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ================= PROTECTED (RISK ENGINE) =================
router.get("/protected", authMiddleware, async (req, res) => {
  try {
    const ip =
      req.headers["x-forwarded-for"] ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      "127.0.0.1";

    const userAgent = req.headers["user-agent"] || "unknown";
    const fingerprint = makeFingerprint(userAgent);

    let riskScore = 0;   // 0–10 numeric scale
    let warnings = [];

    // ─── CHECK 1: New device ───
    const existingDevice = await AccessLog.findOne({
      userId: req.user.id,
      device: userAgent,
    });
    if (!existingDevice) {
      warnings.push("New device detected");
      riskScore += 2;
    }

    // ─── CHECK 2: New IP ───
    const existingIP = await AccessLog.findOne({
      userId: req.user.id,
      ip,
    });
    if (!existingIP) {
      warnings.push("New IP detected");
      riskScore += 2;
    }

    // ─── CHECK 3: Brute force / rapid requests ───
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
    const recentLogs = await AccessLog.find({
      userId: req.user.id,
      createdAt: { $gte: oneMinuteAgo },
    });
    if (recentLogs.length > 8) {
      warnings.push("Too many requests — possible bot");
      riskScore += 3;
    }

    // ─── CHECK 4: Device limit exceeded ───
    const distinctDevices = await AccessLog.distinct("device", {
      userId: req.user.id,
    });
    if (!distinctDevices.includes(userAgent) && distinctDevices.length >= 2) {
      warnings.push("Device limit reached");
      riskScore += 2;
    }

    // Cap at 10
    riskScore = Math.min(riskScore, 10);

    // ─── Risk Level ───
    let riskLevel;
    if (riskScore <= 2) riskLevel = "LOW";
    else if (riskScore <= 5) riskLevel = "MEDIUM";
    else if (riskScore <= 8) riskLevel = "HIGH";
    else riskLevel = "CRITICAL";

    // ─── Save ThreatLog (always) ───
    await new ThreatLog({
      userId: req.user.id,
      ip,
      device: userAgent,
      riskScore,
      riskLevel,
      reasons: warnings,
    }).save();

    // ─── Create Incident if HIGH or CRITICAL ───
    if (riskScore >= 6) {
      const incidentType =
        warnings.includes("Too many requests — possible bot")
          ? "BRUTE_FORCE"
          : warnings.includes("New device detected")
          ? "NEW_DEVICE"
          : warnings.includes("Device limit reached")
          ? "DEVICE_LIMIT"
          : "HIGH_RISK";

      await new Incident({
        userId: req.user.id,
        type: incidentType,
        severity: riskLevel,
        description: warnings.join("; "),
        ip,
        device: userAgent,
      }).save();
    }

    // ─── Track Device ───
    const existingDeviceRecord = await Device.findOne({
      userId: req.user.id,
      fingerprint,
    });
    if (!existingDeviceRecord) {
      await new Device({
        userId: req.user.id,
        fingerprint,
        userAgent,
        lastIp: ip,
      }).save();
    } else {
      existingDeviceRecord.lastSeen = new Date();
      existingDeviceRecord.lastIp = ip;
      await existingDeviceRecord.save();
    }

    // ─── Smart AccessLog (avoid duplicate spam) ───
    const lastLog = await AccessLog.findOne({ userId: req.user.id }).sort({
      createdAt: -1,
    });
    const now = Date.now();
    if (
      !lastLog ||
      lastLog.ip !== ip ||
      lastLog.device !== userAgent ||
      now - new Date(lastLog.createdAt).getTime() > 10000
    ) {
      await new AccessLog({ userId: req.user.id, ip, device: userAgent }).save();
    }

    res.json({
      user: req.user,
      ip,
      device: userAgent,
      fingerprint,
      riskScore,
      riskLevel,
      warnings,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= PROFILE =================
router.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -currentToken");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      session: "active",
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

    // Clear currentToken on user
    await User.findByIdAndUpdate(req.user.id, { currentToken: null });

    res.json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET MY LOGS =================
router.get("/logs", authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const logs = await AccessLog.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AccessLog.countDocuments({ userId: req.user.id });

    res.json({ logs, total, page, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GET MY DEVICES =================
router.get("/devices", authMiddleware, async (req, res) => {
  try {
    const devices = await Device.find({ userId: req.user.id }).sort({
      lastSeen: -1,
    });
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
