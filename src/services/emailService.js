import nodemailer from "nodemailer";
import { config } from "../config.js";

const FROM_ADDRESS = process.env.SMTP_USER ?? "ankitfukte11@gmail.com";
const ADMIN_ALERT_ADDRESS = process.env.SECURITY_ALERT_EMAIL ?? "ankittalks10@gmail.com";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: FROM_ADDRESS,
    pass: process.env.GOOGLE_PASSWORD, // Google App Password
  },
});

const send = async (mailOptions) => {
  try {
    const info = await transporter.sendMail({ from: FROM_ADDRESS, ...mailOptions });
    return { ok: true, messageId: info.messageId };
  } catch (error) {
    console.error(`Failed to send "${mailOptions.subject}":`, error.message);
    return { ok: false, error: error.message };
  }
};

const formatLocation = (geo) => {
  if (!geo) return "unknown location";
  const parts = [geo.city, geo.region, geo.country].filter(Boolean);
  const place = parts.length > 0 ? parts.join(", ") : "unknown location";
  return geo.isp ? `${place} (${geo.isp})` : place;
};

/**
 * The code a user needs to authorise a new device.
 * The body states the device and location so the user can spot an attempt that is not theirs.
 */
export const sendDeviceVerificationEmail = async ({ to, code, device, context, expiresInMinutes }) => {
  const location = formatLocation(context?.geo);
  const text = [
    "Someone is trying to sign in to your Tradingwala account on a device we have not seen before.",
    "",
    `Verification code: ${code}`,
    `This code expires in ${expiresInMinutes} minutes.`,
    "",
    "Sign-in details:",
    `  Device   : ${device?.label ?? "unknown device"}`,
    `  Location : ${location}`,
    `  IP        : ${context?.geo?.ip ?? "unknown"}`,
    `  Time     : ${new Date().toUTCString()}`,
    "",
    "If this was you, enter the code to continue. Your other device will be signed out, because",
    "your account allows one device at a time.",
    "",
    "If this was NOT you, do not share this code. Change your password and contact",
    `${config.supportEmail} immediately.`,
  ].join("\n");

  return send({ to, subject: `Tradingwala verification code: ${code}`, text });
};

/**
 * Sent to the user when their account is blocked, with the concrete observations behind it.
 * Users dispute blocks they cannot see the reasoning for, so the reasoning goes in the email.
 */
export const sendAccountBlockedEmail = async ({ to, reason, proofText, caseId }) => {
  const text = [
    "Your Tradingwala account has been locked.",
    "",
    `Reason: ${reason}`,
    caseId ? `Case reference: ${caseId}` : "",
    "",
    "What we recorded:",
    "",
    proofText ?? "(no detail available)",
    "",
    "If you believe this is a mistake, reply to this email quoting the case reference above and",
    "our team will review the signed records for your account.",
    "",
    `Support: ${config.supportEmail}`,
  ]
    .filter(Boolean)
    .join("\n");

  return send({ to, subject: "Tradingwala account locked - security review", text });
};

/** A new device was authorised. Sent so a silent takeover cannot go unnoticed. */
export const sendDeviceSwitchNotice = async ({ to, newDevice, replacedDevices, context }) => {
  const text = [
    "The device authorised on your Tradingwala account has changed.",
    "",
    `  New device : ${newDevice?.label ?? "unknown"}`,
    `  Location   : ${formatLocation(context?.geo)}`,
    `  Time       : ${new Date().toUTCString()}`,
    "",
    replacedDevices?.length
      ? `Signed out: ${replacedDevices.map((device) => device.label).join(", ")}`
      : "",
    "",
    `If you did not do this, contact ${config.supportEmail} immediately.`,
  ]
    .filter(Boolean)
    .join("\n");

  return send({ to, subject: "Tradingwala: authorised device changed", text });
};

/** Internal alert for the operations inbox. */
export const sendSecurityNotification = async (params) => {
  const { subject, text, eventData = {} } = params;
  const eventDetails = [
    `Event Type : ${eventData.type ?? "unknown"}`,
    `Timestamp  : ${new Date().toISOString()}`,
    `User Email : ${eventData.email ?? "Unknown"}`,
    `Device Key : ${eventData.deviceKey ?? "Unknown"}`,
    `Device ID  : ${eventData.deviceId ?? "Unknown"}`,
    `Message    : ${eventData.message ?? "No message provided"}`,
    `User Agent : ${eventData.metadata?.userAgent ?? "Unknown"}`,
    `IP Address : ${eventData.metadata?.ipAddress ?? "Unknown"}`,
  ].join("\n");

  const result = await send({
    to: ADMIN_ALERT_ADDRESS,
    subject,
    text: `${text}\n\nEvent Details:\n${eventDetails}`,
  });
  return result.ok;
};
