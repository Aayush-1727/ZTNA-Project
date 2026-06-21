const mongoose = require("mongoose");

const accessLogSchema = new mongoose.Schema({
  userId: String,
  ip: String,
  device: String
}, {
  timestamps: true   // 🔥 IMPORTANT (adds createdAt automatically)
});

module.exports = mongoose.model("AccessLog", accessLogSchema);