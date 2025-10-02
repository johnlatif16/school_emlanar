require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const cors = require('cors');
const { randomBytes } = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET لازم يتحدد في .env");
}

// Middlewares
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// === Firebase Admin init (من .env) ===
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// --- جلب بيانات الأدمن من Firestore أو .env ---
async function getAdminCreds() {
  try {
    const docRef = db.collection('admin').doc('creds');
    const doc = await docRef.get();
    if (doc.exists) {
      return doc.data(); // { username, password }
    }
  } catch (e) {
    console.error("Error reading admin creds:", e);
  }
  if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) {
    throw new Error("ADMIN_USER و ADMIN_PASS لازم يتحددوا في .env");
  }
  return {
    username: process.env.ADMIN_USER,
    password: process.env.ADMIN_PASS
  };
}

// === Utility: توليد random hex ===
function generateRandomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

// === Admin login ===
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const creds = await getAdminCreds();

  if (username === creds.username && password === creds.password) {
    const jti = generateRandomHex(16);
    const token = jwt.sign({ role: 'admin', jti }, JWT_SECRET, { expiresIn: '2h' });
    return res.json({ token });
  }
  return res.status(401).json({ error: 'بيانات غير صحيحة' });
});

// Middleware لفحص JWT
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.admin = decoded;
    next();
  });
}

// === API لتغيير اسم المستخدم أو الباسورد ===
app.post('/api/admin/change-username', authenticateAdmin, async (req, res) => {
  const { value } = req.body;
  if (!value) return res.status(400).json({ error: 'قيمة غير صحيحة' });

  await db.collection('admin').doc('creds').set({ username: value }, { merge: true });
  res.json({ success: true });
});

app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
  const { value } = req.body;
  if (!value) return res.status(400).json({ error: 'قيمة غير صحيحة' });

  await db.collection('admin').doc('creds').set({ password: value }, { merge: true });
  res.json({ success: true });
});

// === API جلب الطلاب ===
app.get('/api/students', authenticateAdmin, async (req, res) => {
  try {
    const snap = await db.collection('students').get();
    const students = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(students);
  } catch (e) {
    res.status(500).json({ error: 'خطأ أثناء جلب الطلاب' });
  }
});

// === API جلب سجلات الحضور ===
app.get('/api/attendance', authenticateAdmin, async (req, res) => {
  try {
    const snap = await db.collection('attendance_logs').orderBy('timestamp', 'desc').limit(1000).get();
    const logs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(logs);
  } catch (e) {
    res.status(500).json({ error: 'خطأ أثناء جلب السجلات' });
  }
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
