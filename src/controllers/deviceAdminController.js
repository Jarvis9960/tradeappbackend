import { asyncHandler } from "../utils/asyncHandler.js";
import { findUserById } from "../services/userService.js";
import { buildSharingReport, renderProofNarrative } from "../services/evidenceService.js";
import { DeviceModel } from "../models/Device.js";
import { DeviceEvidenceModel } from "../models/DeviceEvidence.js";
import { verifyChain } from "../utils/evidenceChain.js";
import { listInspectionReports } from "../services/inspectionService.js";
import { config } from "../config.js";

const notFound = () => {
  const error = new Error("User not found");
  error.statusCode = 404;
  error.code = "USER_NOT_FOUND";
  return error;
};

/**
 * The structured proof report for one account: every device, every network, the full signed
 * timeline, and the integrity check on the evidence chain.
 */
export const sharingReportHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();
  const report = await buildSharingReport(user);
  res.json(report);
});

/**
 * The same report rendered as plain text, ready to paste into a reply to a disputing user.
 * `?format=text` returns it as text/plain so it can be read directly in a browser.
 */
export const sharingProofTextHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();
  const report = await buildSharingReport(user);
  const text = renderProofNarrative(report);

  if (req.query.format === "text") {
    res.type("text/plain").send(text);
    return;
  }
  res.json({ proof: text, verdict: report.verdict, chainIntact: report.chainVerification.intact });
});

/** Devices known for a user, including the counts that distinguish wiped storage from sharing. */
export const listUserDevicesHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();

  const devices = await DeviceModel.find({ user: user._id }).sort({ lastSeenAt: -1 }).lean();
  res.json(
    devices.map((device) => ({
      deviceKey: device.deviceKey,
      label: device.label,
      platform: device.platform,
      trusted: device.trusted,
      verifiedAt: device.verifiedAt,
      verificationMethod: device.verificationMethod,
      firstSeenAt: device.firstSeenAt,
      lastSeenAt: device.lastSeenAt,
      loginCount: device.loginCount,
      lastMatchType: device.lastMatchType,
      lastMatchScore: device.lastMatchScore,
      revokedAt: device.revokedAt,
      revokedReason: device.revokedReason,
      // A device with many client ids but one fingerprint is a user who keeps clearing storage.
      // Surfacing this stops support from mistaking it for multiple devices.
      clientIdCount: device.clientIds?.length ?? 0,
      distinctFingerprints: device.strictHashes?.length ?? 0,
      networks: device.observedIps,
      signals: device.signals,
    })),
  );
});

/**
 * Developer-tools reports for a user. Surfaced separately because these are probabilistic
 * signals under review, not findings - the panel must not present them as proven.
 */
export const listInspectionReportsHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();

  const limit = Number.parseInt(req.query.limit ?? "", 10);
  const reports = await listInspectionReports(user, Number.isNaN(limit) ? 100 : limit);

  res.json({
    policy: config.inspection.policy,
    blockScore: config.inspection.blockScore,
    requiredReports: config.inspection.requiredReports,
    windowMinutes: config.inspection.windowMinutes,
    strongReportCount: reports.filter((r) => r.hasStrongSignal).length,
    weakReportCount: reports.filter((r) => !r.hasStrongSignal).length,
    reports,
  });
});

/** Raw signed evidence records, for an auditor who wants to verify the chain independently. */
export const listUserEvidenceHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();

  const limit = Number.parseInt(req.query.limit ?? "", 10);
  const records = await DeviceEvidenceModel.find({ user: user._id })
    .sort({ seq: 1 })
    .limit(Number.isNaN(limit) ? 500 : limit)
    .lean();

  res.json({
    verification: verifyChain(records),
    records: records.map((record) => ({
      seq: record.seq,
      kind: record.kind,
      deviceKey: record.deviceKey,
      recordedAt: record.recordedAt,
      narrative: record.narrative,
      payload: record.payload,
      prevHash: record.prevHash,
      recordHash: record.recordHash,
      signature: record.signature,
    })),
  });
});

/**
 * Clear a device binding so a user can start fresh - the correct remedy when a block turns out
 * to be wrong, or when a user genuinely replaced their hardware. Does not unblock the account;
 * that stays a separate, explicit action.
 */
export const resetUserDevicesHandler = asyncHandler(async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) throw notFound();

  const reason = req.body?.reason?.trim() || "Device bindings reset by administrator";
  const result = await DeviceModel.updateMany(
    { user: user._id, revokedAt: { $exists: false } },
    { $set: { revokedAt: new Date(), revokedReason: reason, trusted: false } },
  );

  const { appendEvidence } = await import("../services/evidenceService.js");
  await appendEvidence({
    user,
    kind: "DEVICE_OBSERVED",
    deviceKey: null,
    payload: { reason: "admin_device_reset", detail: reason, devicesReset: result.modifiedCount },
    narrative: `Administrator reset ${result.modifiedCount} device binding(s): ${reason}`,
  });

  res.json({ ok: true, devicesReset: result.modifiedCount });
});
