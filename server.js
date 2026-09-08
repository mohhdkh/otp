import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import {
  OTP_EXPIRY_MS,
  OTP_MAX_ATTEMPTS,
  evaluateOtpRecord,
  generateOtp,
  hashOtp,
  isAllowedPurpose,
  isValidEmail,
  normalizeEmail,
  otpDocumentId,
  rateLimitDocumentId,
} from './otp_security.js';

dotenv.config();

const OTP_COLLECTION = 'otps';
const RATE_LIMIT_COLLECTION = 'otpRateLimits';
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const APPS_SCRIPT_TIMEOUT_MS = 10 * 1000;

const SEND_RATE_LIMITS = {
  perEmailAndPurpose: 5,
  perIp: 20,
};

const VERIFY_RATE_LIMITS = {
  perEmailAndPurpose: 10,
  perIp: 50,
};

function requiredEnvironmentVariable(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parseServiceAccount() {
  try {
    return JSON.parse(requiredEnvironmentVariable('FIREBASE_SERVICE_ACCOUNT'));
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT must contain valid JSON');
  }
}

const otpHashSecret = requiredEnvironmentVariable('OTP_HASH_SECRET');
if (otpHashSecret.length < 32) {
  throw new Error('OTP_HASH_SECRET must be at least 32 characters');
}

admin.initializeApp({
  credential: admin.credential.cert(parseServiceAccount()),
});

const db = admin.firestore();
const app = express();
const port = process.env.PORT || 3000;
const appsScriptUrl = requiredEnvironmentVariable('APPS_SCRIPT_URL');
const appsScriptSecret = requiredEnvironmentVariable('APPS_SCRIPT_SECRET');

if (new URL(appsScriptUrl).protocol !== 'https:') {
  throw new Error('APPS_SCRIPT_URL must use HTTPS');
}

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '16kb' }));

class RateLimitError extends Error {}

function clientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown').slice(0, 128);
}

async function enforceRateLimits(rules) {
  const nowMs = Date.now();
  const refs = rules.map(({ scope, key }) =>
    db
      .collection(RATE_LIMIT_COLLECTION)
      .doc(rateLimitDocumentId(scope, key)),
  );

  await db.runTransaction(async (transaction) => {
    const snapshots = await Promise.all(refs.map((ref) => transaction.get(ref)));
    const updates = [];

    for (let index = 0; index < rules.length; index += 1) {
      const rule = rules[index];
      const snapshot = snapshots[index];
      const data = snapshot.exists ? snapshot.data() : null;
      const windowStartedAt = data?.windowStartedAt?.toMillis?.() ?? 0;
      const withinWindow = nowMs - windowStartedAt < RATE_LIMIT_WINDOW_MS;
      const currentCount = withinWindow ? Number(data?.count ?? 0) : 0;

      if (currentCount >= rule.limit) {
        throw new RateLimitError('Rate limit exceeded');
      }

      updates.push({
        ref: refs[index],
        data: {
          count: currentCount + 1,
          windowStartedAt: admin.firestore.Timestamp.fromMillis(
            withinWindow ? windowStartedAt : nowMs,
          ),
          expiresAt: admin.firestore.Timestamp.fromMillis(
            (withinWindow ? windowStartedAt : nowMs) + RATE_LIMIT_WINDOW_MS,
          ),
        },
      });
    }

    for (const update of updates) {
      transaction.set(update.ref, update.data);
    }
  });
}

function requestData(req) {
  const email = normalizeEmail(req.body?.email);
  const purpose = req.body?.purpose;
  const otp = typeof req.body?.otp === 'string' ? req.body.otp.trim() : '';
  return { email, purpose, otp };
}

function invalidOtpResponse(res) {
  return res.status(400).json({
    success: false,
    message: 'رمز التحقق غير صحيح أو منتهي الصلاحية',
  });
}

async function deleteOtpIfUnchanged(ref, otpHash) {
  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    if (snapshot.exists && snapshot.data()?.otpHash === otpHash) {
      transaction.delete(ref);
    }
  });
}

async function sendOtpWithAppsScript({ email, otp, purpose }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), APPS_SCRIPT_TIMEOUT_MS);

  try {
    const response = await fetch(appsScriptUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: appsScriptSecret,
        email,
        code: otp,
        purpose,
      }),
      signal: controller.signal,
    });

    const data = await response.json().catch(() => null);
    if (!response.ok || data?.ok !== true) {
      throw new Error('Apps Script rejected OTP delivery');
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function consumeOtp({ email, purpose, otp }) {
  const ref = db.collection(OTP_COLLECTION).doc(otpDocumentId(email, purpose));

  return db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists) {
      return 'invalid';
    }

    const evaluation = evaluateOtpRecord({
      record: snapshot.data(),
      email,
      purpose,
      otp,
      secret: otpHashSecret,
      nowMs: Date.now(),
    });

    if (evaluation.status === 'valid') {
      transaction.delete(ref);
      return 'valid';
    }

    if (
      evaluation.status === 'expired' ||
      evaluation.attemptsRemaining === 0
    ) {
      transaction.delete(ref);
    } else {
      transaction.update(ref, {
        attemptsRemaining: evaluation.attemptsRemaining,
      });
    }

    return evaluation.status;
  });
}

app.post('/send-otp', async (req, res) => {
  const { email, purpose } = requestData(req);

  if (!isValidEmail(email) || !isAllowedPurpose(purpose)) {
    return res.status(400).json({
      success: false,
      message: 'يجب تقديم بريد إلكتروني وغرض صالحين',
    });
  }

  try {
    await enforceRateLimits([
      {
        scope: 'send-email-purpose',
        key: `${email}\0${purpose}`,
        limit: SEND_RATE_LIMITS.perEmailAndPurpose,
      },
      {
        scope: 'send-ip',
        key: clientIp(req),
        limit: SEND_RATE_LIMITS.perIp,
      },
    ]);

    const otp = generateOtp();
    const otpHash = hashOtp(email, purpose, otp, otpHashSecret);
    const otpRef = db
      .collection(OTP_COLLECTION)
      .doc(otpDocumentId(email, purpose));
    const nowMs = Date.now();

    const otpRecord = {
      otpHash,
      purpose,
      attemptsRemaining: OTP_MAX_ATTEMPTS,
      createdAt: admin.firestore.Timestamp.fromMillis(nowMs),
      expiresAt: admin.firestore.Timestamp.fromMillis(nowMs + OTP_EXPIRY_MS),
    };

    // This atomically replaces the current OTP and removes the legacy plaintext
    // document format used by earlier versions of this service.
    const batch = db.batch();
    batch.set(otpRef, otpRecord);
    if (!email.includes('/')) {
      batch.delete(db.collection(OTP_COLLECTION).doc(email));
    }
    await batch.commit();

    try {
      await sendOtpWithAppsScript({ email, otp, purpose });
    } catch (error) {
      await deleteOtpIfUnchanged(otpRef, otpHash);
      throw error;
    }

    return res.json({
      success: true,
      message: 'تم إرسال رمز التحقق',
    });
  } catch (error) {
    if (error instanceof RateLimitError) {
      return res.status(429).json({
        success: false,
        message: 'تم تجاوز عدد الطلبات. حاول لاحقًا',
      });
    }

    console.error('Failed to send OTP');
    return res.status(500).json({
      success: false,
      message: 'فشل في إرسال رمز التحقق',
    });
  }
});

app.post('/verify-otp', async (req, res) => {
  const { email, purpose, otp } = requestData(req);

  if (
    !isValidEmail(email) ||
    !isAllowedPurpose(purpose) ||
    !/^\d{6}$/.test(otp)
  ) {
    return invalidOtpResponse(res);
  }

  try {
    await enforceRateLimits([
      {
        scope: 'verify-email-purpose',
        key: `${email}\0${purpose}`,
        limit: VERIFY_RATE_LIMITS.perEmailAndPurpose,
      },
      {
        scope: 'verify-ip',
        key: clientIp(req),
        limit: VERIFY_RATE_LIMITS.perIp,
      },
    ]);

    const result = await consumeOtp({ email, purpose, otp });
    if (result !== 'valid') {
      return invalidOtpResponse(res);
    }

    if (purpose === 'reset_password') {
      try {
        const user = await admin.auth().getUserByEmail(email);
        const token = await admin.auth().createCustomToken(user.uid);
        return res.json({
          success: true,
          message: 'تم التحقق بنجاح',
          token,
        });
      } catch (error) {
        if (error?.code === 'auth/user-not-found') {
          return invalidOtpResponse(res);
        }

        console.error('Failed to issue reset-password token');
        return res.status(500).json({
          success: false,
          message: 'حدث خطأ أثناء التحقق',
        });
      }
    }

    return res.json({
      success: true,
      message: 'تم التحقق بنجاح',
    });
  } catch (error) {
    if (error instanceof RateLimitError) {
      return res.status(429).json({
        success: false,
        message: 'تم تجاوز عدد المحاولات. حاول لاحقًا',
      });
    }

    console.error('Failed to verify OTP');
    return res.status(500).json({
      success: false,
      message: 'حدث خطأ أثناء التحقق',
    });
  }
});

app.get('/', (req, res) => {
  res.send('Server is running');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
