const mongoose = require("mongoose");

// ================= USER MODEL =================
// Added: role (for RBAC), unique email index, createdAt

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,         // enforced at DB level
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },

    // RBAC: 'user' | 'admin'
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    // Single-session control (one active token at a time)
    currentToken: {
      type: String,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
