const mongoose = require("mongoose");

const incidentSchema = new mongoose.Schema({
userId: {
type: String,
required: true
},
type: {
type: String,
enum: ["ANOMALY", "SESSION_HIJACK", "DEVICE", "IP"],
required: true
},
message: String,
severity: {
type: String,
enum: ["LOW", "MEDIUM", "HIGH"],
default: "LOW"
},
ip: String,
device: String,
location: String,
createdAt: {
type: Date,
default: Date.now
}
});

module.exports = mongoose.model("Incident", incidentSchema);
