const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET = "mysecretkey"; // move to .env in production
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Middleware 
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; // Expect "Bearer <token>"
  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// MongoDB 
mongoose.connect("mongodb://127.0.0.1:27017/eventDB")
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// Schemas 
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpire: Date
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  date: { type: Date, required: true },
  location: String,
  capacity: Number,
  bookedSeats: { type: Number, default: 0 },
  price: Number,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  // New fields
  priority: { type: String, enum: ["low", "medium", "high"], default: "low" },
  isCompleted: { type: Boolean, default: false }
}, { timestamps: true });

const Event = mongoose.model("Event", eventSchema);
//  Routes 

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, error: "Name, email and password are required" });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.json({ success: true, message: "User created successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: "Email and password are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, error: "Incorrect password" });

    const token = jwt.sign({ userId: user._id, name: user.name }, SECRET, { expiresIn: "1h" });

    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create Event (auth required)
app.post("/events", authMiddleware, async (req, res) => {
  try {
    const newEvent = new Event({ ...req.body, createdBy: req.user.userId });
    await newEvent.save();
    res.json({ success: true, event: newEvent });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get Events (auth required, only user’s own)
app.get("/events", authMiddleware, async (req, res) => {
  try {
    const events = await Event.find({ createdBy: req.user.userId });
    res.json(events);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: "User not found" });

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    // Save token in DB (valid for 15 min)
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpire = Date.now() + 15 * 60 * 1000;
    await user.save();

    // Reset URL (for frontend / email)
    const resetUrl = `http://localhost:5000/reset-password/${resetToken}`;

    res.json({ success: true, message: "Password reset link generated", resetUrl });
    //  In production: send resetUrl via email, not response
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Reset password
app.post("/reset-password/:token", async (req, res) => {
  try {
    const resetToken = req.params.token;
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    // Find user with valid token
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ success: false, error: "Invalid or expired token" });

    // Hash new password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.json({ success: true, message: "Password reset successful. You can log in now." });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put("/events/:id/priority", authMiddleware, async (req, res) => {
  try {
    const { priority } = req.body;
    if (!["low", "medium", "high"].includes(priority)) {
      return res.status(400).json({ success: false, error: "Invalid priority" });
    }

    const event = await Event.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user.userId }, // ✅ fix
      { priority },
      { new: true }
    );

    res.json({ success: true, event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put("/events/:id/complete", authMiddleware, async (req, res) => {
  try {
    const event = await Event.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user.userId }, // ✅ fix
      { isCompleted: true },
      { new: true }
    );

    res.json({ success: true, event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => console.log(` Server running at http://0.0.0.0:${PORT}`));
