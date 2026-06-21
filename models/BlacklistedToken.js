const mongoose = require("mongoose");

const blacklistSchema = new mongoose.Schema({
  token: String,
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 3600
  }
});

module.exports = mongoose.model("BlacklistedToken", blacklistSchema);