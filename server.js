require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3000;

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const SECRET = process.env.JWT_SECRET;

app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));

// Firebase init
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// ================= AUTH =================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ role: "admin" }, SECRET, { expiresIn: "2h" });
    return res.json({ token });
  }
  return res.status(401).json({ error: "بيانات غير صحيحة" });
});

function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ================= API =================
app.get("/api/students", authenticate, async (req, res) => {
  const snapshot = await db.collection("students").get();
  const students = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
  res.json(students);
});

app.get("/api/attendance", authenticate, async (req, res) => {
  const snapshot = await db.collection("attendance_logs").get();
  const logs = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
  res.json(logs);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
