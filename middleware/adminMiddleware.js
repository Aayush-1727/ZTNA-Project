const User = require("../models/User");

// ================= ADMIN MIDDLEWARE =================
// Run AFTER authMiddleware
// Blocks non-admin users from admin routes

module.exports = async function (req, res, next) {
  try {
    const user = await User.findById(req.user.id);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "Access denied. Admins only." });
    }

    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
