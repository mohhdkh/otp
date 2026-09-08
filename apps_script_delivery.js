export const APPS_SCRIPT_TIMEOUT_MS = 10 * 1000;

export class AppsScriptDeliveryError extends Error {
  constructor(type, details = {}) {
    super('Apps Script delivery failed');
    this.name = 'AppsScriptDeliveryError';
    this.type = type;
    this.httpStatus = details.httpStatus;
    this.serviceError = details.serviceError;
  }
}

function safeServiceError(value, secret) {
  if (value === undefined || value === null) {
    return undefined;
  }

  let result;
  try {
    result = typeof value === 'string' ? value : JSON.stringify(value);
  } catch {
    result = 'Unserializable Apps Script error';
  }

  if (secret) {
    result = result.split(secret).join('[REDACTED_SECRET]');
  }

  return result
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/\b\d{6}\b/g, '[REDACTED_CODE]')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 300);
}

export function appsScriptFailureLog(error) {
  if (!(error instanceof AppsScriptDeliveryError)) {
    return { type: 'unknown' };
  }

  const details = { type: error.type };
  if (Number.isInteger(error.httpStatus)) {
    details.httpStatus = error.httpStatus;
  }
  if (error.serviceError) {
    details.serviceError = error.serviceError;
  }
  return details;
}

export async function sendOtpWithAppsScript({
  url,
  secret,
  email,
  otp,
  purpose,
  timeoutMs = APPS_SCRIPT_TIMEOUT_MS,
  fetchImpl = globalThis.fetch,
}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, email, code: otp, purpose }),
        signal: controller.signal,
      });
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new AppsScriptDeliveryError('timeout');
      }
      throw new AppsScriptDeliveryError('request_failed');
    }

    let data;
    let hasValidJson = true;
    try {
      data = await response.json();
    } catch {
      hasValidJson = false;
    }

    const serviceError = safeServiceError(data?.error, secret);

    if (!response.ok) {
      throw new AppsScriptDeliveryError('http_status', {
        httpStatus: response.status,
        serviceError,
      });
    }

    if (!hasValidJson) {
      throw new AppsScriptDeliveryError('invalid_json', {
        httpStatus: response.status,
      });
    }

    if (data?.ok !== true) {
      throw new AppsScriptDeliveryError(
        serviceError ? 'service_error' : 'rejected',
        { httpStatus: response.status, serviceError },
      );
    }
  } finally {
    clearTimeout(timeout);
  }
}
