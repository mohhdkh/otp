const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./najdah-17dba-firebase-adminsdk-fbsvc-31c8259b85.json'); // ملف حساب الخدمة الخاص بك

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// تهيئة Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// إعداد nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mohhdkh2@gmail.com', // بريدك
    pass: 'wmsu lhvw gwwg iupk', // كلمة مرور التطبيق (app password)
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// إرسال OTP وتخزينه في Firestore
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'يجب تقديم البريد الإلكتروني' });
  }

  const otp = generateOTP();

  const mailOptions = {
    from: 'mohhdkh2@gmail.com',
    to: email,
    subject: 'رمز التحقق الخاص بك',
    text: `رمز التحقق الخاص بك هو: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);

    // تخزين OTP ووقت الإنشاء في Firestore
    await db.collection('otps').doc(email).set({
      otp,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, message: 'تم إرسال رمز التحقق' });
  } catch (error) {
    console.error('خطأ في إرسال البريد أو الحفظ:', error);
    res.status(500).json({ success: false, error: 'فشل في إرسال البريد أو حفظ البيانات' });
  }
});

// التحقق من OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'البريد الإلكتروني ورمز التحقق مطلوبان' });
  }

  try {
    const doc = await db.collection('otps').doc(email).get();

    if (!doc.exists) {
      return res.status(404).json({ success: false, message: 'رمز التحقق غير موجود' });
    }

    const data = doc.data();
    const createdAt = data.createdAt.toDate();
    const now = new Date();
    const diffMs = now - createdAt;
    const diffMinutes = diffMs / 1000 / 60;

    if (diffMinutes > 5) {
      return res.status(400).json({ success: false, message: 'رمز التحقق منتهي الصلاحية' });
    }

    if (data.otp === otp) {
      await db.collection('otps').doc(email).delete();
      return res.json({ success: true, message: 'تم التحقق بنجاح' });
    } else {
      return res.status(400).json({ success: false, message: 'رمز التحقق غير صحيح' });
    }
  } catch (error) {
    console.error('خطأ أثناء التحقق:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء التحقق' });
  }
});

// اختبار السيرفر
app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
