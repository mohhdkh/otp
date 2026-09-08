import assert from 'node:assert/strict';
import test from 'node:test';
import {
  OTP_EXPIRY_MS,
  OTP_MAX_ATTEMPTS,
  evaluateOtpRecord,
  generateOtp,
  hashOtp,
  isAllowedPurpose,
  normalizeEmail,
  otpDocumentId,
  otpMatches,
} from './otp_security.js';

const secret = 'test-only-secret-with-at-least-32-characters';
const email = 'person@example.com';

function recordFor(purpose, otp, overrides = {}) {
  return {
    otpHash: hashOtp(email, purpose, otp, secret),
    purpose,
    attemptsRemaining: OTP_MAX_ATTEMPTS,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    ...overrides,
  };
}

test('normalizes email and restricts purpose', () => {
  assert.equal(normalizeEmail(' Person@Example.COM '), email);
  assert.equal(isAllowedPurpose('register'), true);
  assert.equal(isAllowedPurpose('reset_password'), true);
  assert.equal(isAllowedPurpose('other'), false);
});

test('generates a six-digit OTP', () => {
  for (let index = 0; index < 100; index += 1) {
    assert.match(generateOtp(), /^\d{6}$/);
  }
});

test('stores and compares only the keyed OTP hash', () => {
  const otp = '123456';
  const storedHash = hashOtp(email, 'reset_password', otp, secret);
  assert.notEqual(storedHash, otp);
  assert.equal(otpMatches(storedHash, email, 'reset_password', otp, secret), true);
  assert.equal(otpMatches(storedHash, email, 'reset_password', '654321', secret), false);
});

test('separates registration and reset-password OTP records', () => {
  assert.notEqual(
    otpDocumentId(email, 'register'),
    otpDocumentId(email, 'reset_password'),
  );

  const result = evaluateOtpRecord({
    record: recordFor('register', '123456'),
    email,
    purpose: 'reset_password',
    otp: '123456',
    secret,
    nowMs: Date.now(),
  });
  assert.equal(result.status, 'invalid');
});

test('accepts a valid OTP and rejects an expired OTP', () => {
  const otp = '123456';
  const valid = evaluateOtpRecord({
    record: recordFor('reset_password', otp),
    email,
    purpose: 'reset_password',
    otp,
    secret,
    nowMs: Date.now(),
  });
  assert.equal(valid.status, 'valid');

  const expired = evaluateOtpRecord({
    record: recordFor('reset_password', otp, { expiresAt: Date.now() - 1 }),
    email,
    purpose: 'reset_password',
    otp,
    secret,
    nowMs: Date.now(),
  });
  assert.equal(expired.status, 'expired');
});

test('decrements failed attempts and exhausts the final attempt', () => {
  const wrong = evaluateOtpRecord({
    record: recordFor('reset_password', '123456'),
    email,
    purpose: 'reset_password',
    otp: '654321',
    secret,
    nowMs: Date.now(),
  });
  assert.equal(wrong.status, 'invalid');
  assert.equal(wrong.attemptsRemaining, OTP_MAX_ATTEMPTS - 1);

  const finalAttempt = evaluateOtpRecord({
    record: recordFor('reset_password', '123456', { attemptsRemaining: 1 }),
    email,
    purpose: 'reset_password',
    otp: '654321',
    secret,
    nowMs: Date.now(),
  });
  assert.equal(finalAttempt.attemptsRemaining, 0);
});
