export const VERIFICATION_STATUS = Object.freeze({
  valid: 'valid',
  invalid: 'invalid',
});

export async function verifyOtpForPurpose(
  { email, purpose, otp },
  services,
) {
  if (purpose === 'register') {
    const user = await services.findUserByEmail(email);
    if (!user) {
      return { status: VERIFICATION_STATUS.invalid };
    }

    const status = await services.consumeRegistrationOtpAndVerifyUser({
      email,
      purpose,
      otp,
      verifiedUid: user.uid,
    });

    return { status };
  }

  if (purpose !== 'reset_password') {
    return { status: VERIFICATION_STATUS.invalid };
  }

  const status = await services.consumeOtp({ email, purpose, otp });
  if (status !== VERIFICATION_STATUS.valid) {
    return { status };
  }

  const user = await services.findUserByEmail(email);
  if (!user) {
    return { status: VERIFICATION_STATUS.invalid };
  }

  const token = await services.issueResetPasswordToken(user.uid);
  return { status, token };
}
