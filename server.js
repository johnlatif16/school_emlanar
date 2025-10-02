// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const cors = require('cors');
const { randomBytes } = require('crypto'); // لتوليد قيمة عشوائية
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_prod_secret';

app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// === Firebase Admin init ===
// ضع serviceAccountKey.json في نفس المجلد
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// --- مساعدة: جلب بيانات الأدمن (من Firestore إذا موجود، وإلا من .env) ---
async function getAdminCreds() {
  try {
    const docRef = db.collection('admin').doc('creds');
    const doc = await docRef.get();
    if (doc.exists) {
      return doc.data(); // { username: "...", password: "..." }
    }
  } catch (e) {
    console.error('Error reading admin creds from Firestore:', e);
  }
  // fallback إلى .env
  return {
    username: process.env.ADMIN_USER || 'admin',
    password: process.env.ADMIN_PASS || '123456'
  };
}

// === Utility: توليد قيمة عشوائية آمنة (hex) ===
// تستخدم crypto.randomBytes — آمنة للتشفير/مفاتيح.
function generateRandomHex(bytes = 32) {
  // سترجع سلسلة hex بطول bytes*2 (مثلاً bytes=32 => 64 حرف hex)
  return randomBytes(bytes).toString('hex');
}

// === Admin login ===
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const creds = await getAdminCreds();

  if (username === creds.username && password === creds.password) {
    // يمكنك إضافة حقل jti بقيمة عشوائية داخل البايلود
    const jti = generateRandomHex(16); // معرف فريد للـ token
    const token = jwt.sign({ role: 'admin', jti }, JWT_SECRET, { expiresIn: '2h' });
    return res.json({ token, jti });
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

// === تغيير اسم المستخدم و/أو كلمة المرور ===
// يتطلب مصادقة الأدمن (JWT)
app.post('/api/admin/change-credentials', authenticateAdmin, async (req, res) => {
  const { newUsername, newPassword } = req.body;
  if (!newUsername && !newPassword) {
    return res.status(400).json({ error: 'أرسل newUsername أو newPassword' });
  }

  try {
    const docRef = db.collection('admin').doc('creds');
    const updates = {};
    if (newUsername) updates.username = newUsername;
    if (newPassword) updates.password = newPassword; // في الإنتاج: خزّن هاش بدل النص الصريح

    // set with merge لتجنّب استبدال الحقول الأخرى
    await docRef.set(updates, { merge: true });

    return res.json({ ok: true, message: 'تم تحديث بيانات الأدمن' });
  } catch (e) {
    console.error('Error updating admin creds:', e);
    return res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// === مثال endpoint لإصدار secret جديد (محمية) ===
// (لو عايز تولّد secret جديد وتستخدمه كـ JWT secret لاحقًا — احذر: تغيير secret يؤدي لإبطال كل التوكنات القديمة)
app.post('/api/admin/generate-secret', authenticateAdmin, (req, res) => {
  const newSecret = generateRandomHex(32); // 64 حرف hex
  // **ملاحظة مهمة**: لا ننصح بتخزين هذا الـ JWT_SECRET في Firestore كنص عادي، الأفضل حفظه في Vault / متغيرات بيئية آمنة.
  // هنا نعيده فقط كقيمة يمكن نسخها يدويًا إلى .env أو أسرع طريقة نشر آمنة.
  res.json({ newSecret });
});

// === API قراءة طلاب / سجلات (محمي) ===
app.get('/api/students', authenticateAdmin, async (req, res) => {
  try {
    const snap = await db.collection('students').get();
    const students = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(students);
  } catch (e) {
    res.status(500).json({ error: 'خطأ أثناء جلب الطلاب' });
  }
});

app.get('/api/attendance', authenticateAdmin, async (req, res) => {
  try {
    const snap = await db.collection('attendance_logs').orderBy('timestamp', 'desc').limit(2000).get();
    const logs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(logs);
  } catch (e) {
    res.status(500).json({ error: 'خطأ أثناء جلب السجلات' });
  }
});

app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
