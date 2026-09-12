import assert from 'node:assert/strict';
import test from 'node:test';
import {
  VERIFICATION_STATUS,
  verifyOtpForPurpose,
} from './verification_flow.js';

const email = 'person@example.com';
const correctOtp = '123456';
const legitimateUid = 'legitimate-user';

function createServices() {
  const state = {
    registrationOtpConsumed: false,
    resetOtpConsumed: false,
    verifiedUsers: new Set(),
    resetTokens: [],
  };

  return {
    state,
    services: {
      findUserByEmail: async (requestedEmail) =>
        requestedEmail === email ? { uid: legitimateUid } : null,
      consumeRegistrationOtpAndVerifyUser: async ({
        purpose,
        otp,
        verifiedUid,
      }) => {
        if (
          purpose !== 'register' ||
          otp !== correctOtp ||
          state.registrationOtpConsumed
        ) {
          return VERIFICATION_STATUS.invalid;
        }

        state.registrationOtpConsumed = true;
        state.verifiedUsers.add(verifiedUid);
        return VERIFICATION_STATUS.valid;
      },
      consumeOtp: async ({ purpose, otp }) => {
        if (
          purpose !== 'reset_password' ||
          otp !== correctOtp ||
          state.resetOtpConsumed
        ) {
          return VERIFICATION_STATUS.invalid;
        }

        state.resetOtpConsumed = true;
        return VERIFICATION_STATUS.valid;
      },
      issueResetPasswordToken: async (uid) => {
        state.resetTokens.push(uid);
        return `token-for-${uid}`;
      },
    },
  };
}

test('valid registration OTP verifies the Auth user resolved by email', async () => {
  const { state, services } = createServices();

  const result = await verifyOtpForPurpose(
    { email, purpose: 'register', otp: correctOtp },
    services,
  );

  assert.equal(result.status, VERIFICATION_STATUS.valid);
  assert.deepEqual([...state.verifiedUsers], [legitimateUid]);
});

test('wrong registration OTP does not verify a user', async () => {
  const { state, services } = createServices();

  const result = await verifyOtpForPurpose(
    { email, purpose: 'register', otp: '654321' },
    services,
  );

  assert.equal(result.status, VERIFICATION_STATUS.invalid);
  assert.equal(state.verifiedUsers.size, 0);
});

test('reset-password OTP never changes registration verification', async () => {
  const { state, services } = createServices();

  const result = await verifyOtpForPurpose(
    { email, purpose: 'reset_password', otp: correctOtp },
    services,
  );

  assert.equal(result.status, VERIFICATION_STATUS.valid);
  assert.equal(result.token, `token-for-${legitimateUid}`);
  assert.equal(state.verifiedUsers.size, 0);
  assert.deepEqual(state.resetTokens, [legitimateUid]);
});

test('replaying the same registration OTP is idempotent', async () => {
  const { state, services } = createServices();
  const request = { email, purpose: 'register', otp: correctOtp };

  const first = await verifyOtpForPurpose(request, services);
  const replay = await verifyOtpForPurpose(request, services);

  assert.equal(first.status, VERIFICATION_STATUS.valid);
  assert.equal(replay.status, VERIFICATION_STATUS.invalid);
  assert.deepEqual([...state.verifiedUsers], [legitimateUid]);
});

test('a forged client UID cannot select the user being verified', async () => {
  const { state, services } = createServices();

  const result = await verifyOtpForPurpose(
    {
      email,
      purpose: 'register',
      otp: correctOtp,
      uid: 'attacker-selected-user',
    },
    services,
  );

  assert.equal(result.status, VERIFICATION_STATUS.valid);
  assert.equal(state.verifiedUsers.has(legitimateUid), true);
  assert.equal(state.verifiedUsers.has('attacker-selected-user'), false);
});
