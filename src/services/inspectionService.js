import { DeviceEvidenceModel } from "../models/DeviceEvidence.js";
import { config } from "../config.js";
import { appendEvidence } from "./evidenceService.js";
import { recordSecurityEvent } from "./securityEventService.js";
import { markUserBlocked } from "./userService.js";
import { revokeAllSessionsForUser } from "./sessionService.js";
import { sendAccountBlockedEmail } from "./emailService.js";

/**
 * Client-side inspection reports (developer tools).
 *
 * The previous design let the browser decide a block: any POST to /security/event with a valid
 * token permanently blocked the account, and the client-side heuristics that triggered it fired
 * on ordinary behaviour - a slow animation frame, browser zoom, split screen, rotating a phone,
 * or an extension sidebar changing the window size.
 *
 * Two things are wrong with that, and both are fixed here:
 *
 *   1. A client cannot be trusted to adjudicate. Anyone holding a token could block an account
 *      by posting to the endpoint, and no evidence was kept to review the decision afterwards.
 *   2. These signals are probabilistic. They belong in a log that a human reviews, not wired
 *      directly to an irreversible penalty.
 *
 * So a report is now scored by how reliable its signals actually are, written to the signed
 * evidence chain with its full diagnostic context, and - unless an operator explicitly opts into
 * blocking - left for review. Nothing here blocks on a single report.
 */

/**
 * Signal reliability weights.
 *
 * Deliberately lopsided. Only signals that are hard to produce accidentally carry real weight;
 * the ones that were causing false blocks are kept for context but scored near zero.
 */
const SIGNAL_WEIGHTS = {
  /**
   * An object logged to the console had its getter or toString invoked. That only happens when
   * a console pane actually renders the object, so it is the one genuinely strong signal here.
   */
  console_object_inspected: 45,

  /** The page was opened with an element-inspection overlay active. Rare accidentally. */
  element_picker_active: 25,

  /**
   * Keyboard shortcut for devtools. Evidence of intent, not of devtools being open - F12 is a
   * normal key, and these chords collide with other software.
   */
  devtools_shortcut_pressed: 10,

  /**
   * Window inner/outer size delta. The classic heuristic and the main source of the false
   * blocks: browser zoom, OS display scaling, split screen, device rotation, on-screen
   * keyboards, the bookmarks bar and extension sidebars all move it. Context only.
   */
  window_dimension_delta: 5,

  /**
   * Timing a console write. Was treated as proof at a 100 ms threshold, which any throttled
   * background tab or slow frame exceeds. Kept only so reports stay comparable; scored at zero.
   */
  console_timing_anomaly: 0,
};

/** Signals that, on their own, can never justify a block however often they repeat. */
const WEAK_SIGNALS = new Set([
  "window_dimension_delta",
  "console_timing_anomaly",
  "devtools_shortcut_pressed",
]);

export const scoreReport = (signals = []) => {
  const seen = new Set();
  let score = 0;
  const counted = [];

  for (const signal of signals) {
    const name = signal?.name;
    if (!name || seen.has(name)) continue;
    const weight = SIGNAL_WEIGHTS[name];
    if (weight === undefined) continue;

    seen.add(name);
    score += weight;
    counted.push({ name, weight, detail: signal.detail ?? null });
  }

  const hasStrongSignal = [...seen].some((name) => !WEAK_SIGNALS.has(name));

  return {
    score,
    signals: counted,
    hasStrongSignal,
    // Without a strong signal the report is capped below any actionable threshold, no matter
    // how many weak signals piled up.
    effectiveScore: hasStrongSignal ? score : Math.min(score, config.inspection.blockScore - 1),
  };
};

/**
 * Record one inspection report.
 *
 * Always returns normally - a report never fails the request, and never logs the user out
 * unless the configured policy explicitly calls for a block.
 */
export const recordInspectionReport = async ({ user, session, report, context }) => {
  const assessment = scoreReport(report.signals);

  const payload = {
    observation: context?.observation ?? null,
    reportedSignals: assessment.signals,
    rawScore: assessment.score,
    effectiveScore: assessment.effectiveScore,
    hasStrongSignal: assessment.hasStrongSignal,
    policy: config.inspection.policy,
    blockScore: config.inspection.blockScore,
    page: report.page ?? null,
    clientMessage: report.message ?? null,
    diagnostics: report.diagnostics ?? null,
    sessionId: session ? String(session._id) : null,
  };

  const narrative = assessment.hasStrongSignal
    ? `Developer tools activity reported from ${context?.observation?.deviceDescription ?? "an unknown device"} ` +
      `(confidence ${assessment.effectiveScore}/100): ${assessment.signals.map((s) => s.name).join(", ")}.`
    : `Possible developer tools activity reported, but only weak signals fired ` +
      `(${assessment.signals.map((s) => s.name).join(", ") || "none"}). These also fire on browser ` +
      "zoom, split screen, device rotation and slow frames, so this is recorded for review only.";

  const evidence = await appendEvidence({
    user,
    kind: "CLIENT_INSPECTION_REPORTED",
    deviceKey: context?.deviceKey ?? null,
    payload,
    narrative,
  });

  await recordSecurityEvent({
    type: "DEVTOOLS_REPORTED",
    email: user.email,
    deviceId: context?.clientDeviceId,
    deviceKey: context?.deviceKey,
    message: narrative,
    user,
    metadata: {
      caseId: evidence.recordHash.slice(0, 12),
      effectiveScore: assessment.effectiveScore,
      signals: assessment.signals.map((s) => s.name),
      ipAddress: context?.geo?.ip,
      userAgent: context?.headers?.["user-agent"],
    },
  });

  // Review-only is the default: record and alert, never penalise.
  if (config.inspection.policy !== "block") {
    return { blocked: false, caseId: evidence.recordHash.slice(0, 12), assessment };
  }

  if (!assessment.hasStrongSignal || assessment.effectiveScore < config.inspection.blockScore) {
    return { blocked: false, caseId: evidence.recordHash.slice(0, 12), assessment };
  }

  /**
   * Corroboration: a single report never blocks, even a strong one. A browser extension or a
   * one-off rendering quirk can produce one. Repetition across separate reports is what makes it
   * a pattern.
   */
  const since = new Date(Date.now() - config.inspection.windowMinutes * 60 * 1000);

  // The record for this report was already appended above, so it is excluded by id here and
  // counted explicitly below. Without that, `requiredReports` would be off by one and the
  // narrative would overstate how many reports there actually were.
  const priorStrongReports = await DeviceEvidenceModel.countDocuments({
    _id: { $ne: evidence._id },
    user: user._id,
    kind: "CLIENT_INSPECTION_REPORTED",
    recordedAt: { $gte: since },
    "payload.hasStrongSignal": true,
  });

  const totalStrongReports = priorStrongReports + 1;

  if (totalStrongReports < config.inspection.requiredReports) {
    return {
      blocked: false,
      caseId: evidence.recordHash.slice(0, 12),
      assessment,
      awaitingCorroboration: {
        have: totalStrongReports,
        need: config.inspection.requiredReports,
      },
    };
  }

  const reason = `Developer tools use detected (case ${evidence.recordHash.slice(0, 12)})`;
  const blockedUser = await markUserBlocked(user, reason);
  await revokeAllSessionsForUser(blockedUser, reason);

  // A distinct type from the per-report DEVTOOLS_REPORTED, because this one alerts the
  // operations inbox - the individual reports deliberately do not.
  await recordSecurityEvent({
    type: "DEVTOOLS_BLOCKED",
    email: blockedUser.email,
    deviceId: context?.clientDeviceId,
    deviceKey: context?.deviceKey,
    message: reason,
    user: blockedUser,
    metadata: {
      caseId: evidence.recordHash.slice(0, 12),
      strongReportsInWindow: totalStrongReports,
      windowMinutes: config.inspection.windowMinutes,
      ipAddress: context?.geo?.ip,
    },
  });

  await appendEvidence({
    user: blockedUser,
    kind: "CLIENT_INSPECTION_BLOCKED",
    deviceKey: context?.deviceKey ?? null,
    payload: {
      ...payload,
      strongReportsInWindow: totalStrongReports,
      priorStrongReports,
      requiredReports: config.inspection.requiredReports,
      windowMinutes: config.inspection.windowMinutes,
    },
    narrative:
      `Account blocked after ${totalStrongReports} separate reports of developer tools activity ` +
      `within ${config.inspection.windowMinutes} minutes, each carrying at least one signal that ` +
      "does not fire accidentally.",
  });

  try {
    const { buildSharingReport, renderProofNarrative } = await import("./evidenceService.js");
    const fullReport = await buildSharingReport(blockedUser);
    await sendAccountBlockedEmail({
      to: blockedUser.email,
      reason: "Developer tools were used on the trading workspace.",
      proofText: renderProofNarrative(fullReport),
      caseId: evidence.recordHash.slice(0, 12),
    });
  } catch (error) {
    console.error("Failed to send inspection block email:", error.message);
  }

  return { blocked: true, caseId: evidence.recordHash.slice(0, 12), assessment };
};

/** Inspection reports for one user, newest first, for the admin panel. */
export const listInspectionReports = async (user, limit = 100) => {
  const records = await DeviceEvidenceModel.find({
    user: user._id,
    kind: { $in: ["CLIENT_INSPECTION_REPORTED", "CLIENT_INSPECTION_BLOCKED"] },
  })
    .sort({ seq: -1 })
    .limit(limit)
    .lean();

  return records.map((record) => ({
    seq: record.seq,
    kind: record.kind,
    recordedAt: record.recordedAt,
    narrative: record.narrative,
    caseId: record.recordHash.slice(0, 12),
    recordHash: record.recordHash,
    page: record.payload?.page ?? null,
    effectiveScore: record.payload?.effectiveScore ?? 0,
    hasStrongSignal: Boolean(record.payload?.hasStrongSignal),
    signals: record.payload?.reportedSignals ?? [],
    diagnostics: record.payload?.diagnostics ?? null,
    device: record.payload?.observation?.deviceDescription ?? null,
    ip: record.payload?.observation?.network?.ip ?? null,
  }));
};
