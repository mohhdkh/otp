const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./najdah-17dba-firebase-adminsdk-fbsvc-31c8259b85');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mohhdkh2@gmail.com',
    pass: 'wmsu lhvw gwwg iupk',
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    console.log('لم يتم تقديم البريد الإلكتروني');
    return res.status(400).json({ error: 'يجب تقديم البريد الإلكتروني' });
  }

  const otp = generateOTP();
  console.log(`تم إنشاء OTP: ${otp} للبريد: ${email}`);

  const mailOptions = {
    from: 'mohhdkh2@gmail.com',
    to: email,
    subject: 'رمز التحقق الخاص بك',
    text: `رمز التحقق الخاص بك هو: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('تم إرسال البريد بنجاح');

    await db.collection('otps').doc(email).set({
      otp,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log('تم حفظ OTP في Firestore');

    res.json({ success: true, message: 'تم إرسال رمز التحقق' });
  } catch (error) {
    console.error('خطأ في إرسال البريد أو الحفظ:', error);
    res.status(500).json({ success: false, error: 'فشل في إرسال البريد أو حفظ البيانات' });
  }
});

app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    console.log('البريد الإلكتروني أو رمز التحقق مفقود');
    return res.status(400).json({ success: false, message: 'البريد الإلكتروني ورمز التحقق مطلوبان' });
  }

  try {
    const doc = await db.collection('otps').doc(email).get();

    if (!doc.exists) {
      console.log(`لم يتم العثور على OTP للبريد: ${email}`);
      return res.status(404).json({ success: false, message: 'رمز التحقق غير موجود' });
    }

    const data = doc.data();
    if (!data.createdAt) {
      console.log('createdAt غير موجود في الوثيقة');
      return res.status(500).json({ success: false, message: 'خطأ في بيانات رمز التحقق' });
    }

    const createdAt = data.createdAt.toDate();
    const now = new Date();
    const diffMinutes = (now - createdAt) / 1000 / 60;

    if (diffMinutes > 5) {
      console.log('رمز التحقق منتهي الصلاحية');
      return res.status(400).json({ success: false, message: 'رمز التحقق منتهي الصلاحية' });
    }

    if (data.otp === otp) {
      await db.collection('otps').doc(email).delete();
      console.log(`تم التحقق بنجاح من OTP للبريد: ${email}`);
      return res.json({ success: true, message: 'تم التحقق بنجاح' });
    } else {
      console.log(`رمز التحقق غير صحيح للبريد: ${email}`);
      return res.status(400).json({ success: false, message: 'رمز التحقق غير صحيح' });
    }
  } catch (error) {
    console.error('خطأ أثناء التحقق:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء التحقق' });
  }
});

app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
