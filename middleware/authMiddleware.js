const jwt = require("jsonwebtoken");
const User = require("../models/User");
const BlacklistedToken = require("../models/BlacklistedToken");

module.exports = async function (req, res, next) {
  try {
    const token = req.header("Authorization");

    // ✅ FIRST check token exists
    if (!token) {
      return res.status(401).json({ message: "No token" });
    }

    // ❌ Check if token is blacklisted
    const isBlacklisted = await BlacklistedToken.findOne({ token });

    if (isBlacklisted) {
      return res.status(401).json({ message: "Token is blacklisted. Login again." });
    }

    // ✅ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);

    // 🔐 Session control
    if (!user || user.currentToken !== token) {
      return res.status(401).json({ message: "Session expired. Login again." });
    }

    req.user = decoded;
    next();

  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};