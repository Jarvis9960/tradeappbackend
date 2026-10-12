import { createHash, randomInt, randomUUID } from "crypto";
import { DeviceChallengeModel } from "../models/DeviceChallenge.js";
import { DeviceModel } from "../models/Device.js";
import { config } from "../config.js";
import { appendEvidence } from "./evidenceService.js";
import { sendDeviceVerificationEmail } from "./emailService.js";

/**
 * Email-code verification for signing in on a new device.
 *
 * This is the piece that makes strict single-device access defensible. Users do legitimately
 * change phones, reinstall browsers and buy new laptops. Instead of guessing whether a new
 * fingerprint is the same person, we ask them to prove it with something only the account owner
 * has - and we record that proof. A blocked user can then be shown either "you verified this
 * switch yourself at 14:02" or "two devices were live at once", both backed by signed records.
 */

const hashCode = (code) => createHash("sha256").update(String(code)).digest("hex");

const generateCode = () => String(randomInt(0, 1_000_000)).padStart(6, "0");

export const issueDeviceChallenge = async (user, device, context) => {
  // One live challenge per device at a time.
  await DeviceChallengeModel.deleteMany({
    user: user._id,
    deviceKey: device.deviceKey,
    consumedAt: { $exists: false },
  });

  const code = generateCode();
  const challengeId = `chl_${randomUUID()}`;
  const expiresAt = new Date(Date.now() + config.device.verificationTtlMinutes * 60 * 1000);

  await DeviceChallengeModel.create({
    challengeId,
    user: user._id,
    deviceKey: device.deviceKey,
    codeHash: hashCode(code),
    maxAttempts: config.device.verificationMaxAttempts,
    clientDeviceId: context.clientDeviceId,
    strictHash: context.strictHash,
    ip: context.geo?.ip,
    expiresAt,
  });

  await appendEvidence({
    user,
    kind: "VERIFICATION_SENT",
    deviceKey: device.deviceKey,
    payload: {
      observation: context.observation,
      challengeId,
      expiresAt: expiresAt.toISOString(),
      reason: "new_or_unverified_device",
    },
    narrative: `Verification code emailed to ${user.email} to authorise sign-in on ${device.label}.`,
  });

  await sendDeviceVerificationEmail({
    to: user.email,
    code,
    device,
    context,
    expiresInMinutes: config.device.verificationTtlMinutes,
  });

  return { challengeId, expiresAt };
};

/**
 * Verify a submitted code.
 *
 * The challenge is bound to the fingerprint that requested it, so a code intercepted from the
 * user's inbox cannot be redeemed from a different machine.
 */
export const verifyDeviceChallenge = async ({ user, challengeId, code, context }) => {
  const challenge = await DeviceChallengeModel.findOne({
    challengeId,
    user: user._id,
    consumedAt: { $exists: false },
  });

  if (!challenge) {
    return { ok: false, error: "CHALLENGE_NOT_FOUND" };
  }

  if (challenge.expiresAt <= new Date()) {
    await DeviceChallengeModel.deleteOne({ _id: challenge._id });
    return { ok: false, error: "CHALLENGE_EXPIRED" };
  }

  if (challenge.attempts >= challenge.maxAttempts) {
    await DeviceChallengeModel.deleteOne({ _id: challenge._id });
    await appendEvidence({
      user,
      kind: "VERIFICATION_FAILED",
      deviceKey: challenge.deviceKey,
      payload: { observation: context.observation, challengeId, reason: "max_attempts_exceeded" },
      narrative: "Device verification abandoned after too many incorrect codes.",
    });
    return { ok: false, error: "TOO_MANY_ATTEMPTS" };
  }

  // The code must be redeemed from the same browser that asked for it.
  if (challenge.strictHash !== context.strictHash) {
    challenge.attempts += 1;
    await challenge.save();
    await appendEvidence({
      user,
      kind: "VERIFICATION_FAILED",
      deviceKey: challenge.deviceKey,
      payload: {
        observation: context.observation,
        challengeId,
        reason: "fingerprint_mismatch",
        expectedStrictHash: challenge.strictHash,
        presentedStrictHash: context.strictHash,
      },
      narrative:
        "A verification code was submitted from a different device than the one that requested it.",
    });
    return { ok: false, error: "DEVICE_MISMATCH" };
  }

  if (challenge.codeHash !== hashCode(code)) {
    challenge.attempts += 1;
    await challenge.save();
    return {
      ok: false,
      error: "INVALID_CODE",
      attemptsRemaining: Math.max(0, challenge.maxAttempts - challenge.attempts),
    };
  }

  const device = await DeviceModel.findOne({ user: user._id, deviceKey: challenge.deviceKey });
  if (!device) {
    return { ok: false, error: "DEVICE_NOT_FOUND" };
  }

  challenge.consumedAt = new Date();
  await challenge.save();

  const wasUntrusted = !device.trusted;
  device.trusted = true;
  device.verifiedAt = new Date();
  device.verificationMethod = "email-code";
  await device.save();

  await appendEvidence({
    user,
    kind: "VERIFICATION_PASSED",
    deviceKey: device.deviceKey,
    payload: {
      observation: context.observation,
      challengeId,
      emailedTo: user.email,
      reason: wasUntrusted ? "new_device_verified" : "device_reverified",
    },
    narrative:
      `Account owner proved control of ${user.email} and authorised ${device.label} at ` +
      `${new Date().toISOString()}.`,
  });

  return { ok: true, device };
};

/**
 * Demote every other trusted device after a successful switch, so exactly one device is ever
 * authorised. The switch itself is recorded - that record is both the user's receipt and the
 * counter used by the switch-rate limit.
 */
export const demoteOtherDevices = async (user, keepDeviceKey, context) => {
  const others = await DeviceModel.find({
    user: user._id,
    deviceKey: { $ne: keepDeviceKey },
    trusted: true,
    revokedAt: { $exists: false },
  });

  if (others.length === 0) return [];

  for (const device of others) {
    device.trusted = false;
    device.revokedAt = new Date();
    device.revokedReason = "Replaced by a newly verified device";
    await device.save();
  }

  await appendEvidence({
    user,
    kind: "DEVICE_SWITCHED",
    deviceKey: keepDeviceKey,
    payload: {
      observation: context?.observation ?? null,
      newDeviceKey: keepDeviceKey,
      replacedDevices: others.map((device) => ({
        deviceKey: device.deviceKey,
        label: device.label,
        lastSeenAt: device.lastSeenAt,
        loginCount: device.loginCount,
      })),
    },
    narrative:
      `Authorised device changed. ${others.map((device) => device.label).join(", ")} ` +
      "deauthorised after the account owner verified a different device by email.",
  });

  return others;
};
