import { SecurityEventModel } from "../models/SecurityEvent.js";
import { sendSecurityNotification } from "./emailService.js";

/**
 * Event types that email the operations inbox.
 *
 * Only outcomes that need a human are here. Routine observations - including individual
 * developer-tools reports, of which there can be many under the default review policy - are
 * recorded and surfaced in the admin panel rather than emailed, so the inbox stays signal.
 */
const ALERT_TYPES = new Set([
  "CONCURRENT_DEVICE_BLOCKED",
  "DEVICE_SWITCH_LIMIT_BLOCKED",
  "DEVICE_SHARING_BLOCKED",
  "DEVTOOLS_BLOCKED",
  "SECOND_DEVICE_ATTEMPT",
]);

export const recordSecurityEvent = async (params) => {
  const doc = new SecurityEventModel({
    type: params.type,
    message: params.message,
    email: params.email?.toLowerCase(),
    deviceId: params.deviceId,
    deviceKey: params.deviceKey,
    user: params.user?._id,
    metadata: params.metadata,
  });
  await doc.save();

  if (!ALERT_TYPES.has(params.type)) return;

  const subject = `Security Alert: ${params.type}`;
  const text =
    `A security event has been detected in the Tradingwala platform.\n\n` +
    `Event: ${params.type}\n` +
    `User: ${params.email || "Unknown"}\n` +
    `Message: ${params.message}`;

  try {
    await sendSecurityNotification({ subject, text, eventData: params });
  } catch (error) {
    // Alerting must never fail the action that triggered it.
    console.error("Failed to send security notification email:", error.message);
  }
};
