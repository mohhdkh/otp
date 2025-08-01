const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000; // ✅ تعديل ضروري

app.use(cors());
app.use(bodyParser.json());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mohhdkh2@gmail.com',
    pass: 'wmsu lhvw gwwg iupk', // ⚠️ لا تضع بياناتك الحقيقية هنا في الإنتاج
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

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
    res.json({ success: true, message: 'تم إرسال رمز التحقق', otp }); // ⚠️ احذف otp من الرد في الإنتاج
  } catch (error) {
    console.error('خطأ في إرسال البريد:', error);
    res.status(500).json({ success: false, error: 'فشل في إرسال البريد' });
  }
});

// Route تجريبي للتأكد أن السيرفر شغال
app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
