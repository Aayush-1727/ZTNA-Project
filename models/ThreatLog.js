const mongoose = require("mongoose");

// ================= THREAT LOG MODEL =================
// Saved every time a risk event is detected
// Feeds the admin analytics dashboard

const threatLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    ip: String,
    device: String,

    // Numeric score 0–10
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 10,
    },

    // Label: LOW / MEDIUM / HIGH / CRITICAL
    riskLevel: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "LOW",
    },

    // List of triggered warnings
    reasons: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("ThreatLog", threatLogSchema);
