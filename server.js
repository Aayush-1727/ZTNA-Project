const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
require("dotenv").config();

const app = express();

// ================= SECURITY HEADERS =================
app.use(helmet());

// ================= CORS =================
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "*",  // set FRONTEND_ORIGIN in .env for production
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ================= BODY PARSER =================
app.use(express.json());

// ================= RATE LIMITING =================
// Auth routes: stricter (15 requests per 15 min)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { message: "Too many requests, please try again later." },
});

// General routes: lenient (100 per 15 min)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use("/api/auth/login",    authLimiter);
app.use("/api/auth/register", authLimiter);
app.use("/api/",              generalLimiter);

// ================= DB CONNECT =================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// ================= ROUTES =================
const authRoutes  = require("./routes/auth");
const adminRoutes = require("./routes/admin");

app.use("/api/auth",  authRoutes);
app.use("/api/admin", adminRoutes);

// ================= SERVE FRONTEND =================
app.use(express.static(path.join(__dirname, "public")));
app.use("/ztna", express.static(path.join(__dirname, "public/ztna")));

app.get("/", (req, res) => {
  res.redirect("/ztna");
});

// ================= 404 HANDLER =================
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// ================= GLOBAL ERROR HANDLER =================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Internal server error" });
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
