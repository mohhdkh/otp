import {
  createHash,
  createHmac,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';

export const ALLOWED_PURPOSES = new Set(['register', 'reset_password']);
export const OTP_EXPIRY_MS = 5 * 60 * 1000;
export const OTP_MAX_ATTEMPTS = 5;

export function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

export function isValidEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isAllowedPurpose(purpose) {
  return typeof purpose === 'string' && ALLOWED_PURPOSES.has(purpose);
}

export function generateOtp() {
  return randomInt(100000, 1000000).toString();
}

export function hashIdentifier(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function otpDocumentId(email, purpose) {
  return hashIdentifier(`otp\0${email}\0${purpose}`);
}

export function rateLimitDocumentId(scope, key) {
  return hashIdentifier(`rate-limit\0${scope}\0${key}`);
}

export function hashOtp(email, purpose, otp, secret) {
  return createHmac('sha256', secret)
    .update(`${email}\0${purpose}\0${otp}`)
    .digest('hex');
}

export function otpMatches(storedHash, email, purpose, otp, secret) {
  if (typeof storedHash !== 'string' || !/^[a-f0-9]{64}$/i.test(storedHash)) {
    return false;
  }

  const expected = Buffer.from(storedHash, 'hex');
  const actual = Buffer.from(hashOtp(email, purpose, otp, secret), 'hex');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function timestampToMillis(timestamp) {
  if (timestamp && typeof timestamp.toMillis === 'function') {
    return timestamp.toMillis();
  }

  if (timestamp instanceof Date) {
    return timestamp.getTime();
  }

  return Number(timestamp);
}

export function evaluateOtpRecord({
  record,
  email,
  purpose,
  otp,
  secret,
  nowMs,
}) {
  if (!record || record.purpose !== purpose) {
    return { status: 'invalid', attemptsRemaining: 0 };
  }

  if (timestampToMillis(record.expiresAt) <= nowMs) {
    return { status: 'expired', attemptsRemaining: 0 };
  }

  const attemptsRemaining = Number(record.attemptsRemaining);
  if (!Number.isInteger(attemptsRemaining) || attemptsRemaining <= 0) {
    return { status: 'invalid', attemptsRemaining: 0 };
  }

  if (otpMatches(record.otpHash, email, purpose, otp, secret)) {
    return { status: 'valid', attemptsRemaining };
  }

  return {
    status: 'invalid',
    attemptsRemaining: Math.max(0, attemptsRemaining - 1),
  };
}
