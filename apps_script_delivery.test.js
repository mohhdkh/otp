import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AppsScriptDeliveryError,
  appsScriptFailureLog,
  sendOtpWithAppsScript,
} from './apps_script_delivery.js';

const request = {
  url: 'https://example.test/apps-script',
  secret: 'test-secret-value',
  email: 'person@example.com',
  otp: '123456',
  purpose: 'reset_password',
};

test('accepts a successful Apps Script response', async () => {
  let sentBody;
  await sendOtpWithAppsScript({
    ...request,
    fetchImpl: async (_url, options) => {
      sentBody = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });

  assert.deepEqual(sentBody, {
    secret: request.secret,
    email: request.email,
    code: request.otp,
    purpose: request.purpose,
  });
});

test('classifies HTTP status and safely includes data.error', async () => {
  await assert.rejects(
    sendOtpWithAppsScript({
      ...request,
      fetchImpl: async () => ({
        ok: false,
        status: 503,
        json: async () => ({
          error: `Failure ${request.secret} ${request.email} ${request.otp}`,
        }),
      }),
    }),
    (error) => {
      const details = appsScriptFailureLog(error);
      assert.deepEqual(details, {
        type: 'http_status',
        httpStatus: 503,
        serviceError:
          'Failure [REDACTED_SECRET] [REDACTED_EMAIL] [REDACTED_CODE]',
      });
      return true;
    },
  );
});

test('classifies invalid JSON without logging response content', async () => {
  await assert.rejects(
    sendOtpWithAppsScript({
      ...request,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError('invalid JSON containing sensitive content');
        },
      }),
    }),
    (error) => {
      assert.deepEqual(appsScriptFailureLog(error), {
        type: 'invalid_json',
        httpStatus: 200,
      });
      return true;
    },
  );
});

test('classifies Apps Script data.error on a successful HTTP response', async () => {
  await assert.rejects(
    sendOtpWithAppsScript({
      ...request,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ ok: false, error: 'Mail service unavailable' }),
      }),
    }),
    (error) => {
      assert.deepEqual(appsScriptFailureLog(error), {
        type: 'service_error',
        httpStatus: 200,
        serviceError: 'Mail service unavailable',
      });
      return true;
    },
  );
});

test('classifies a request timeout', async () => {
  await assert.rejects(
    sendOtpWithAppsScript({
      ...request,
      timeoutMs: 5,
      fetchImpl: async (_url, options) =>
        new Promise((_resolve, reject) => {
          options.signal.addEventListener('abort', () => {
            const error = new Error('timed out');
            error.name = 'AbortError';
            reject(error);
          });
        }),
    }),
    (error) => {
      assert.equal(error instanceof AppsScriptDeliveryError, true);
      assert.deepEqual(appsScriptFailureLog(error), { type: 'timeout' });
      return true;
    },
  );
});
