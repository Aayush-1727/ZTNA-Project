const mongoose = require("mongoose");

// ================= DEVICE MODEL =================
// Tracks trusted devices per user
// Used for device fingerprinting

const deviceSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Fingerprint = hash of userAgent (simple version)
    fingerprint: {
      type: String,
      required: true,
    },

    userAgent: {
      type: String,
    },

    // Is this device trusted by admin/user?
    trusted: {
      type: Boolean,
      default: false,
    },

    lastIp: {
      type: String,
    },

    lastSeen: {
      type: Date,
      default: Date.now,
    },

    firstSeen: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Device", deviceSchema);
