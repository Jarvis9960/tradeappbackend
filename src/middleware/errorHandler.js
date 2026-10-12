import { ZodError } from "zod";

/**
 * Error responses carry a stable `code` so the client can tell the cases apart, plus a `caseId`
 * for blocks. The case id is the first 12 characters of the signed evidence hash, so a user who
 * contacts support can be matched to the exact record that caused their block.
 */
const ERROR_MAP = {
  INVALID_CREDENTIALS: { status: 401, error: "Invalid credentials" },
  ACCOUNT_BLOCKED: { status: 423, error: "Account blocked" },
  ACCOUNT_BLOCKED_SHARING: {
    status: 423,
    error: "Account blocked: two devices were in use at the same time",
  },
  ACCOUNT_BLOCKED_SWITCH_LIMIT: {
    status: 423,
    error: "Account blocked: too many device changes",
  },

  CHALLENGE_NOT_FOUND: { status: 400, error: "This verification request is no longer valid" },
  CHALLENGE_EXPIRED: { status: 410, error: "Verification code expired, please sign in again" },
  TOO_MANY_ATTEMPTS: { status: 429, error: "Too many incorrect codes, please sign in again" },
  INVALID_CODE: { status: 400, error: "Incorrect verification code" },
  DEVICE_MISMATCH: {
    status: 400,
    error: "This code was requested from a different device and cannot be used here",
  },
  DEVICE_NOT_FOUND: { status: 400, error: "Device record not found" },
  EVIDENCE_APPEND_CONTENTION: { status: 503, error: "Please retry in a moment" },
};

export const errorHandler = (error, _req, res, _next) => {
  if (error instanceof ZodError) {
    res.status(400).json({ error: "Invalid payload", issues: error.flatten() });
    return;
  }

  if (typeof error?.statusCode === "number") {
    const payload = { error: error.message };
    if (error.code) payload.code = error.code;
    res.status(error.statusCode).json(payload);
    return;
  }

  const mapped = error instanceof Error ? ERROR_MAP[error.message] : null;
  if (mapped) {
    const payload = { error: mapped.error, code: error.message };
    if (error.caseId) payload.caseId = error.caseId;
    if (error.attemptsRemaining !== undefined) payload.attemptsRemaining = error.attemptsRemaining;
    res.status(mapped.status).json(payload);
    return;
  }

  console.error("Unhandled error", error);
  res.status(500).json({ error: "Unexpected server error" });
};
