const express = require("express");
const router = express.Router();
const Incident = require("../models/Incident");
const authMiddleware = require("../middleware/authMiddleware");

// GET INCIDENTS
router.get("/", authMiddleware, async (req, res) => {
try {
const incidents = await Incident.find({ userId: req.user.id })
.sort({ createdAt: -1 })
.limit(20);

```
res.json(incidents);
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

module.exports = router;
