const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },

    password: {
        type: String,
        required: true
    },

    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    },

    status: {
        type: String,
        enum: ["active", "inactive"],
        default: "active"
    },

    department: {
        type: String,
        default: "General"
    },

    currentToken: {
        type: String,
        default: ""
    },

    lastLogin: {
        type: Date,
        default: null
    },
    otp: {
    type: String,
    default: null
},

otpExpiry: {
    type: Date,
    default: null
},

mfaEnabled: {
    type: Boolean,
    default: true
},

otpAttempts: {
    type: Number,
    default: 0
},

}, {
    timestamps: true
});

module.exports = mongoose.model("User", userSchema);