const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());

// ================= DATABASE =================
mongoose.connect(process.env.MONGO_URI)
.then(() => {
    console.log("MongoDB connected");
})
.catch((err) => {
    console.log(err);
});

// ================= ROUTES =================
const authRoutes = require("./routes/auth");
const adminRoutes = require("./routes/admin");
const incidentRoutes = require("./routes/incident");

app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/incidents", incidentRoutes);

// ================= FRONTEND =================
app.use(express.static(path.join(__dirname, "public")));
app.use("/ztna", express.static(path.join(__dirname, "public/ztna")));

app.get("/", (req, res) => {
    res.redirect("/ztna");
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});