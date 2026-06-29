const express = require("express");
const router = express.Router();

const User = require("../models/User");

const authMiddleware = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");

// ===========================================
// GET ALL USERS
// Only Admin
// ===========================================

router.get(
    "/users",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        try {

            const users = await User.find().select(
                "-password -currentToken -otp -otpExpiry -otpAttempts -mfaEnabled"
            );

            res.json(users);

        } catch (err) {

            res.status(500).json({
                error: err.message
            });

        }

    }

);

// ==========================================
// CHANGE USER ROLE
// Only Admin
// ==========================================

router.put(
    "/role",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        try {

            const { userId, role } = req.body;

            if (!userId || !role) {
                return res.status(400).json({
                    message: "User ID and Role are required."
                });
            }

            if (!["admin", "user"].includes(role)) {
                return res.status(400).json({
                    message: "Invalid role."
                });
            }

            const user = await User.findById(userId);

            if (!user) {
                return res.status(404).json({
                    message: "User not found."
                });
            }

            user.role = role;

            await user.save();

            res.json({
                message: "User role updated successfully.",
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });

        } catch (err) {

            res.status(500).json({
                error: err.message
            });

        }

    }

);
// ==========================================
// CHANGE USER STATUS
// Only Admin
// ==========================================

router.put(
    "/status",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        try {

            const { userId, status } = req.body;

            if (!userId || !status) {

                return res.status(400).json({
                    message: "User ID and Status are required."
                });

            }

            if (!["active", "inactive"].includes(status)) {

                return res.status(400).json({
                    message: "Invalid status."
                });

            }

            const user = await User.findById(userId);

            if (!user) {

                return res.status(404).json({
                    message: "User not found."
                });

            }

            user.status = status;

            await user.save();

            res.json({

                message: "User status updated successfully.",

                user: {

                    id: user._id,
                    name: user.name,
                    email: user.email,
                    status: user.status

                }

            });

        }

        catch (err) {

            res.status(500).json({

                error: err.message

            });

        }

    }

);
// ==========================================
// DELETE USER
// Only Admin
// ==========================================

router.delete(
    "/user/:id",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        try {

            const userId = req.params.id;

            // Prevent admin from deleting their own account
            if (req.user.id.toString() === userId) {

                return res.status(400).json({
                    message: "You cannot delete your own account."
                });

            }

            const user = await User.findById(userId);

            if (!user) {

                return res.status(404).json({
                    message: "User not found."
                });

            }

            await User.findByIdAndDelete(userId);

            res.json({

                message: "User deleted successfully."

            });

        }

        catch (err) {

            res.status(500).json({

                error: err.message

            });

        }

    }

);
// ==========================================
// ADMIN DASHBOARD STATISTICS
// Only Admin
// ==========================================

router.get(
    "/dashboard",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        try {

            const totalUsers = await User.countDocuments();

            const activeUsers = await User.countDocuments({
                status: "active"
            });

            const inactiveUsers = await User.countDocuments({
                status: "inactive"
            });

            const adminUsers = await User.countDocuments({
                role: "admin"
            });

            const normalUsers = await User.countDocuments({
                role: "user"
            });

            res.json({

                totalUsers,

                activeUsers,

                inactiveUsers,

                adminUsers,

                normalUsers

            });

        }

        catch (err) {

            res.status(500).json({

                error: err.message

            });

        }

    }

);
module.exports = router;