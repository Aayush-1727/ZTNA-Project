const jwt = require("jsonwebtoken");
const User = require("../models/User");
const BlacklistedToken = require("../models/BlacklistedToken");

module.exports = async function (req, res, next) {

    try {

        const token = req.header("Authorization");

        // ================= TOKEN CHECK =================
        if (!token) {

            return res.status(401).json({
                message: "No token provided"
            });

        }

        // ================= BLACKLIST CHECK =================
        const isBlacklisted = await BlacklistedToken.findOne({
            token
        });

        if (isBlacklisted) {

            return res.status(401).json({
                message: "Token is blacklisted. Please login again."
            });

        }

        // ================= VERIFY JWT =================
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        // ================= FIND USER =================
        const user = await User.findById(decoded.id);

        if (!user) {

            return res.status(404).json({
                message: "User not found"
            });

        }

        // ================= SESSION CHECK =================
        if (user.currentToken !== token) {

            return res.status(401).json({
                message: "Session expired. Please login again."
            });

        }

        // ================= USER STATUS =================
        if (user.status === "inactive") {

            return res.status(403).json({
                message: "Account has been deactivated."
            });

        }

        // ================= STORE USER INFO =================
        req.user = {

            id: user._id,

            name: user.name,

            email: user.email,

            role: user.role,

            department: user.department,

            status: user.status

        };

        next();

    }

    catch (err) {

        return res.status(401).json({

            message: "Invalid token"

        });

    }

};