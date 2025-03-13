const express = require("express");
const router = express.Router();
const User = require("../models/usermodels");
const authenticateToken = require("../middlewares/authMiddleware"); // Middleware for token authentication

// Protected route to fetch user profile
router.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    // Find user by ID (extracted from token)
    const user = await User.findById(req.user.id).select("-password"); // Exclude the password
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      username: user.email.split("@")[0], // Example of deriving a username
      email: user.email,
      role: "User", // Example role, can be enhanced with a role system
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
