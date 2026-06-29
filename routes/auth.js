const express = require("express");
const router = express.Router();
console.log("AUTH ROUTES LOADED");
const User = require("../models/User");
const AccessLog = require("../models/AccessLog");
const BlacklistedToken = require("../models/BlacklistedToken");
const Incident = require("../models/Incident");
const validatePassword = require("../utils/passwordPolicy");
const generateOTP = require("../utils/otpGenerator");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const authMiddleware = require("../middleware/authMiddleware");

const sendOTP = require("../utils/sendOTP");
// ================= INCIDENT HELPER =================
async function createIncident({
    userId,
    type,
    message,
    severity,
    ip,
    device,
    location
}) {
    try {
        await new Incident({
            userId,
            type,
            message,
            severity,
            ip,
            device,
            location
        }).save();
    } catch (err) {
        console.log("Incident Error:", err.message);
    }
}

// ================= REGISTER =================
router.post("/register", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const existing = await User.findOne({ email });

        if (existing) {
            return res.status(400).json({
                message: "User already exists"
            });
        }
const passwordCheck = validatePassword(password);

if (!passwordCheck.valid) {

    return res.status(400).json({
        message: passwordCheck.message
    });

}
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        res.json({
            message: "User registered successfully"
        });

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

// ================= LOGIN =================
router.post("/login", async (req, res) => {
  console.log("LOGIN API HIT");

    try {

        const { email, password } = req.body;

        if (!email || !password) {

            return res.status(400).json({
                message: "Email and Password required"
            });

        }

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(400).json({
                message: "User not found"
            });

        }

        if (user.status === "inactive") {

            return res.status(403).json({
                message: "Account has been deactivated. Contact Administrator."
            });

        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {

            return res.status(400).json({
                message: "Wrong password"
            });

        }

        // ================= OTP =================

        const otp = generateOTP();

        console.log("Generated OTP:", otp);

        user.otp = otp;
        user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
        user.otpAttempts = 0;

        console.log("OTP Saved:", user.otp);
        console.log("Expiry:", user.otpExpiry);
        // ================= SEND OTP EMAIL =================

await sendOTP(user.email, otp);

console.log("OTP Email Sent");

        // ================= JWT =================

        const token = jwt.sign(
            {
                id: user._id
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        user.currentToken = token;

        user.lastLogin = new Date();

        await user.save();

        res.json({

            token,

            user: {

                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department,
                status: user.status,
                lastLogin: user.lastLogin

            }

        });

    }

    catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

// ================= PROTECTED =================
router.get("/protected", authMiddleware, async (req, res) => {

    try {

        const token = req.header("Authorization");

        if (!token) {
            return res.status(401).json({
                message: "No token provided"
            });
        }

        const blacklisted = await BlacklistedToken.findOne({
            token
        });

        if (blacklisted) {
            return res.status(401).json({
                message: "Token expired"
            });
        }

        let ip =
            req.headers["x-forwarded-for"] ||
            req.socket.remoteAddress ||
            req.connection.remoteAddress ||
            "127.0.0.1";

        if (ip.includes(",")) {
            ip = ip.split(",")[0].trim();
        }

        const device =
            (req.headers["user-agent"] || "Unknown Device") +
            "-" +
            ip;

        let location = "Unknown";

        try {

            const geo = await axios.get(
                "http://ip-api.com/json/" + ip
            );

            location = geo.data.country || "Unknown";

        } catch (err) {

            console.log("Geo Error:", err.message);

        }

        let riskScore = 0;
        let warnings = [];

        const existingDevice = await AccessLog.findOne({
            userId: req.user.id,
            device
        });

        if (!existingDevice) {

            warnings.push("New device detected");
            riskScore++;

            await createIncident({
                userId: req.user.id,
                type: "DEVICE",
                message: "New device detected",
                severity: "MEDIUM",
                ip,
                device,
                location
            });

        }

        const existingIP = await AccessLog.findOne({
            userId: req.user.id,
            ip
        });

        if (!existingIP) {

            warnings.push("New IP detected");
            riskScore++;

            await createIncident({
                userId: req.user.id,
                type: "IP",
                message: "New IP detected",
                severity: "MEDIUM",
                ip,
                device,
                location
            });

        }
                // REQUEST SPAM CHECK
        const oneMinuteAgo = new Date(Date.now() - 60 * 1000);

        const recentLogs = await AccessLog.find({
            userId: req.user.id,
            createdAt: {
                $gte: oneMinuteAgo
            }
        });

        if (recentLogs.length > 8) {

            warnings.push("Too many requests");
            riskScore++;

        }

        // DEVICE LIMIT
        const devices = await AccessLog.distinct(
            "device",
            {
                userId: req.user.id
            }
        );

        if (
            !devices.includes(device) &&
            devices.length >= 2
        ) {

            warnings.push("Device limit reached");
            riskScore++;

        }

        // LAST LOGIN
        const lastLog = await AccessLog.findOne({
            userId: req.user.id
        }).sort({
            createdAt: -1
        });

        // SESSION HIJACK DETECTION
       

        // FINAL RISK
        let risk = "LOW";

        if (riskScore >= 2) {
            risk = "HIGH";
        }

        // SMART LOGGING
        const now = Date.now();

        if (

            !lastLog ||

            lastLog.ip !== ip ||

            lastLog.device !== device ||

            (now - new Date(lastLog.createdAt).getTime()) > 10000

        ) {

            await new AccessLog({

                userId: req.user.id,
                ip,
                device,
                location

            }).save();

        }

        // HIGH RISK
        if (risk === "HIGH") {

            await createIncident({

                userId: req.user.id,
                type: "ANOMALY",
                message: "High risk access detected",
                severity: "HIGH",
                ip,
                device,
                location

            });

            return res.status(403).json({

                message: "Access denied due to anomaly",
                risk,
                warnings

            });

        }

        res.json({

            user: req.user,
            ip,
            device,
            location,
            risk,
            warnings

        });

    } catch (err) {

        res.status(500).json({

            error: err.message

        });

    }

});

// ================= PROFILE =================
router.get("/profile", authMiddleware, async (req, res) => {

    try {

        const token = req.header("Authorization");

        const blacklisted = await BlacklistedToken.findOne({
            token
        });

        if (blacklisted) {

            return res.status(401).json({
                message: "Token expired"
            });

        }

        const user = await User.findById(
            req.user.id
        ).select("-password");

        if (!user) {

            return res.status(404).json({
                message: "User not found"
            });

        }

        res.json({

            id: user._id,
            name: user.name,
            email: user.email,
            session: "active"

        });

    } catch (err) {

        res.status(500).json({

            error: err.message

        });

    }

});
// ================= LOGOUT =================
router.post("/logout", authMiddleware, async (req, res) => {

    try {

        const token = req.header("Authorization");

        if (!token) {
            return res.status(400).json({
                message: "Token missing"
            });
        }

        await new BlacklistedToken({
            token
        }).save();

        // Optional: clear current token from user
        await User.findByIdAndUpdate(req.user.id, {
            currentToken: ""
        });

        res.json({
            message: "Logged out successfully"
        });

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

// ================= GET ACCESS LOGS =================
router.get("/logs", authMiddleware, async (req, res) => {

    try {

        const logs = await AccessLog.find({

            userId: req.user.id

        })
        .sort({
            createdAt: -1
        })
        .limit(20);

        res.json(logs);

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

// ================= TEST EMAIL =================

router.get("/test-email", async (req, res) => {

    try {

        await sendOTP(
            "aayushasus1777@gmail.com",
            "654321"
        );

        res.json({

            message: "Test email sent successfully."

        });

    }

    catch (err) {

        res.status(500).json({

            error: err.message

        });

    }

});


module.exports = router;