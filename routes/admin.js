const express = require("express");
const router = express.Router();

const User = require("../models/User");
const AccessLog = require("../models/AccessLog");
const Incident = require("../models/Incident");
const ThreatLog = require("../models/ThreatLog");
const Device = require("../models/Device");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");

// All admin routes require: valid JWT + admin role
router.use(authMiddleware, adminMiddleware);

// ================= DASHBOARD STATS =================
// GET /api/admin/stats
// Returns summary counts for the admin dashboard cards
router.get("/stats", async (req, res) => {
  try {
    const totalUsers    = await User.countDocuments();
    const totalLogs     = await AccessLog.countDocuments();
    const totalIncidents = await Incident.countDocuments();
    const openIncidents = await Incident.countDocuments({ resolved: false });
    const totalThreats  = await ThreatLog.countDocuments({ riskLevel: { $in: ["HIGH", "CRITICAL"] } });
    const totalDevices  = await Device.countDocuments();

    // Active sessions = users who have a non-null currentToken
    const activeSessions = await User.countDocuments({ currentToken: { $ne: null } });

    res.json({
      totalUsers,
      totalLogs,
      totalIncidents,
      openIncidents,
      totalThreats,
      totalDevices,
      activeSessions,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ALL USERS =================
// GET /api/admin/users?page=1&limit=20
router.get("/users", async (req, res) => {
  try {
    const page  = parseInt(req.query.page)  || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip  = (page - 1) * limit;

    const users = await User.find()
      .select("-password -currentToken")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments();

    res.json({ users, total, page, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= PROMOTE USER TO ADMIN =================
// PATCH /api/admin/users/:id/role
router.patch("/users/:id/role", async (req, res) => {
  try {
    const { role } = req.body;
    if (!["user", "admin"].includes(role)) {
      return res.status(400).json({ message: "Role must be 'user' or 'admin'" });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select("-password -currentToken");

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ message: "Role updated", user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ALL ACCESS LOGS =================
// GET /api/admin/logs?page=1&limit=20&userId=xxx
router.get("/logs", async (req, res) => {
  try {
    const page   = parseInt(req.query.page)  || 1;
    const limit  = parseInt(req.query.limit) || 20;
    const skip   = (page - 1) * limit;
    const filter = req.query.userId ? { userId: req.query.userId } : {};

    const logs = await AccessLog.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AccessLog.countDocuments(filter);

    res.json({ logs, total, page, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ALL INCIDENTS =================
// GET /api/admin/incidents?resolved=false&severity=HIGH
router.get("/incidents", async (req, res) => {
  try {
    const page   = parseInt(req.query.page)  || 1;
    const limit  = parseInt(req.query.limit) || 20;
    const skip   = (page - 1) * limit;

    const filter = {};
    if (req.query.resolved !== undefined) {
      filter.resolved = req.query.resolved === "true";
    }
    if (req.query.severity) {
      filter.severity = req.query.severity.toUpperCase();
    }

    const incidents = await Incident.find(filter)
      .populate("userId", "name email")   // join user name/email
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Incident.countDocuments(filter);

    res.json({ incidents, total, page, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= RESOLVE INCIDENT =================
// PATCH /api/admin/incidents/:id/resolve
router.patch("/incidents/:id/resolve", async (req, res) => {
  try {
    const incident = await Incident.findByIdAndUpdate(
      req.params.id,
      { resolved: true, resolvedAt: new Date() },
      { new: true }
    );

    if (!incident) return res.status(404).json({ message: "Incident not found" });

    res.json({ message: "Incident resolved", incident });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ALL THREAT LOGS =================
// GET /api/admin/threats?riskLevel=HIGH
router.get("/threats", async (req, res) => {
  try {
    const page   = parseInt(req.query.page)  || 1;
    const limit  = parseInt(req.query.limit) || 20;
    const skip   = (page - 1) * limit;

    const filter = {};
    if (req.query.riskLevel) {
      filter.riskLevel = req.query.riskLevel.toUpperCase();
    }

    const threats = await ThreatLog.find(filter)
      .populate("userId", "name email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await ThreatLog.countDocuments(filter);

    res.json({ threats, total, page, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= RISK TREND (last 7 days) =================
// GET /api/admin/risk-trend
// Returns daily HIGH+CRITICAL threat counts for charts
router.get("/risk-trend", async (req, res) => {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const trend = await ThreatLog.aggregate([
      {
        $match: {
          createdAt: { $gte: sevenDaysAgo },
          riskLevel: { $in: ["HIGH", "CRITICAL"] },
        },
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    res.json(trend);   // [ { _id: "2025-06-01", count: 5 }, ... ]
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ALL DEVICES =================
// GET /api/admin/devices
router.get("/devices", async (req, res) => {
  try {
    const devices = await Device.find()
      .populate("userId", "name email")
      .sort({ lastSeen: -1 });

    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
