const express    = require("express");
const mongoose   = require("mongoose");
const dotenv     = require("dotenv");
const cors       = require("cors");
const bcrypt     = require("bcrypt");
const jwt        = require("jsonwebtoken");
const { spawn }  = require("child_process");
const path       = require("path");
const fs         = require("fs");
const http       = require("http");
const socketIo   = require("socket.io");
const User       = require("./models/usermodels");

dotenv.config();
mongoose.set("strictQuery", true);

// ─── MongoDB Connection ──────────────────────────────────────
mongoose.connect(
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/iot_attack_guard",
  { useNewUrlParser: true, useUnifiedTopology: true }
)
.then(() => console.log("MongoDB connected"))
.catch(err => {
  console.error("DB error:", err.message);
  process.exit(1);
});

const app    = express();
const server = http.createServer(app);
const io     = socketIo(server, {
  cors: { origin: process.env.FRONTEND_URL || "http://localhost:3000" }
});

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));
app.use(express.json());

// ─── Auth Middleware ─────────────────────────────────────────
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Access denied." });
  const token = auth.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token." });
    req.user = user;
    next();
  });
}

// ─── Signup ──────────────────────────────────────────────────
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required." });
  try {
    if (await User.findOne({ email }))
      return res.status(409).json({ error: "User already exists." });
    const hash = await bcrypt.hash(password, 10);
    await new User({ email, password: hash }).save();
    res.status(201).json({ message: "Registered successfully." });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed." });
  }
});

// ─── Login ───────────────────────────────────────────────────
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required." });
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid credentials." });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "secret", { expiresIn: "1h" });
    res.json({ message: "Login successful!", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed." });
  }
});

// ─── Dashboard ──────────────────────────────────────────────
app.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const u = await User.findById(req.user.id).select("-password");
    res.json(u);
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ error: "Could not fetch user data." });
  }
});

// ─── Scan Control ───────────────────────────────────────────
let consumerProcess = null;

app.post("/start-scan", authenticateToken, (req, res) => {
  if (consumerProcess)
    return res.status(400).json({ error: "Scan already running." });

  const scriptPath = path.join(__dirname, "consumer.py");
  if (!fs.existsSync(scriptPath))
    return res.status(500).json({ error: "consumer.py not found." });

  consumerProcess = spawn("python", [scriptPath], {
    cwd: __dirname,
    env: process.env,
    stdio: ["ignore","pipe","pipe"]
  });
  consumerProcess.stdout.on("data", d => console.log("[consumer]", d.toString().trim()));
  consumerProcess.stderr.on("data", d => console.error("[consumer:error]", d.toString().trim()));
  consumerProcess.on("exit", (code) => {
    console.log(`Consumer exited (code=${code})`);
    consumerProcess = null;
  });

  res.json({ message: "Scan started." });
});

app.post("/stop-scan", authenticateToken, (req, res) => {
  if (!consumerProcess)
    return res.status(400).json({ error: "No scan in progress." });
  consumerProcess.kill();
  consumerProcess = null;
  res.json({ message: "Scan stopped." });
});

// ─── Packet Webhook ─────────────────────────────────────────
app.post("/api/packets", (req, res) => {
  // pick only the six fields we care about
  const { src_ip, src_port, dst_ip, dst_port, device_type, attack_label } = req.body;
  io.emit("new-packet", { src_ip, src_port, dst_ip, dst_port, device_type, attack_label });
  res.json({ status: "ok" });
});

// ─── Socket.IO ──────────────────────────────────────────────
io.on("connection", socket => {
  console.log("Client connected:", socket.id);
  socket.on("disconnect", () => console.log("Client disconnected:", socket.id));
});

// ─── Start Server ───────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
