const mongoose = require("mongoose");

// ================= INCIDENT MODEL =================
// Created when a HIGH risk event is detected
// Stored for admin review and incident response

const incidentSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    type: {
      type: String,
      enum: [
        "NEW_DEVICE",
        "NEW_IP",
        "BRUTE_FORCE",
        "DEVICE_LIMIT",
        "HIGH_RISK",
      ],
      required: true,
    },

    severity: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "HIGH",
    },

    description: {
      type: String,
      required: true,
    },

    ip: String,
    device: String,

    resolved: {
      type: Boolean,
      default: false,
    },

    resolvedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Incident", incidentSchema);
