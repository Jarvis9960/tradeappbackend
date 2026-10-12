import { DeviceEvidenceModel } from "../models/DeviceEvidence.js";
import { DeviceModel } from "../models/Device.js";
import { sealRecord, verifyChain, GENESIS_HASH } from "../utils/evidenceChain.js";
import { describeDevice, similarity, isDifferentHardwareClass } from "../utils/fingerprint.js";
import { impliedTravel } from "./geoService.js";

/**
 * Appends one record to a user's evidence chain.
 *
 * Writes are serialised per user by retrying on the unique (user, seq) index: two concurrent
 * logins must not claim the same sequence number, or the chain would be unverifiable.
 */
export const appendEvidence = async ({ user, kind, deviceKey, payload, narrative }) => {
  const maxAttempts = 5;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const previous = await DeviceEvidenceModel.findOne({ user: user._id })
      .sort({ seq: -1 })
      .select("seq recordHash")
      .lean();

    const seq = (previous?.seq ?? 0) + 1;
    const prevHash = previous?.recordHash ?? GENESIS_HASH;

    const recordedAt = new Date();
    const sealedPayload = {
      ...payload,
      kind,
      deviceKey: deviceKey ?? null,
      recordedAt: recordedAt.toISOString(),
      userId: String(user._id),
      email: user.email ?? null,
    };

    const { recordHash, signature } = sealRecord({ payload: sealedPayload, prevHash });

    try {
      const doc = await DeviceEvidenceModel.create({
        user: user._id,
        email: user.email,
        seq,
        kind,
        deviceKey,
        payload: sealedPayload,
        narrative,
        prevHash,
        recordHash,
        signature,
        recordedAt,
      });
      return doc;
    } catch (error) {
      // Duplicate seq or recordHash means another login appended first. Re-read the head and retry.
      if (error?.code === 11000 && attempt < maxAttempts - 1) continue;
      throw error;
    }
  }

  throw new Error("EVIDENCE_APPEND_CONTENTION");
};

/** Build the snapshot that goes into every observation record. */
export const buildObservation = ({ signals, strictHash, hardwareHash, confidence, clientDeviceId, geo, headers }) => ({
  observedAt: new Date().toISOString(),
  clientDeviceId: clientDeviceId ?? null,
  strictHash,
  hardwareHash,
  fingerprintConfidence: confidence,
  signals,
  deviceDescription: describeDevice(signals),
  network: {
    ip: geo?.ip ?? null,
    asn: geo?.asn ?? null,
    isp: geo?.isp ?? null,
    city: geo?.city ?? null,
    region: geo?.region ?? null,
    country: geo?.country ?? null,
    latitude: geo?.latitude ?? null,
    longitude: geo?.longitude ?? null,
    lookupStatus: geo?.lookupStatus ?? null,
  },
  requestHeaders: {
    userAgent: headers?.["user-agent"] ?? null,
    acceptLanguage: headers?.["accept-language"] ?? null,
    secChUa: headers?.["sec-ch-ua"] ?? null,
    secChUaPlatform: headers?.["sec-ch-ua-platform"] ?? null,
    secChUaPlatformVersion: headers?.["sec-ch-ua-platform-version"] ?? null,
    secChUaModel: headers?.["sec-ch-ua-model"] ?? null,
    secChUaMobile: headers?.["sec-ch-ua-mobile"] ?? null,
  },
});

const fieldLabels = {
  platform: "Operating system",
  gpuRenderer: "Graphics chip",
  gpuVendor: "Graphics vendor",
  screenWidth: "Screen width",
  screenHeight: "Screen height",
  cpuCores: "CPU cores",
  deviceMemory: "Device memory (GB)",
  colorDepth: "Colour depth",
  pixelRatio: "Pixel ratio",
  maxTouchPoints: "Touchscreen",
  timezone: "Time zone",
  canvasHash: "Canvas rendering hash",
  audioHash: "Audio stack hash",
  fontsHash: "Installed fonts hash",
  languages: "Languages",
  browserName: "Browser",
  browserMajorVersion: "Browser version",
};

/**
 * Side-by-side comparison of two devices, listing only the fields that actually differ.
 * This table is the core of what a disputing user is shown.
 */
export const compareDevices = (a = {}, b = {}) => {
  const differences = [];
  for (const [field, label] of Object.entries(fieldLabels)) {
    const left = a[field];
    const right = b[field];
    if (left === null || left === undefined || left === "") continue;
    if (right === null || right === undefined || right === "") continue;
    if (left === right) continue;
    differences.push({ field, label, deviceA: left, deviceB: right });
  }
  return {
    differences,
    similarity: similarity(a, b),
    differentHardwareClass: isDifferentHardwareClass(a, b),
  };
};

/**
 * The full, user-presentable proof report for one account.
 *
 * Everything here is derived from signed records, and `chainVerification` states plainly whether
 * those records are intact. If the chain does not verify, the report says so rather than
 * presenting the findings as fact.
 */
export const buildSharingReport = async (user) => {
  const [records, devices] = await Promise.all([
    DeviceEvidenceModel.find({ user: user._id }).sort({ seq: 1 }).lean(),
    DeviceModel.find({ user: user._id }).sort({ lastSeenAt: -1 }).lean(),
  ]);

  const chainVerification = verifyChain(records);

  const deviceSummaries = devices.map((device) => ({
    deviceKey: device.deviceKey,
    label: device.label,
    platform: device.platform,
    trusted: device.trusted,
    verifiedAt: device.verifiedAt,
    firstSeenAt: device.firstSeenAt,
    lastSeenAt: device.lastSeenAt,
    loginCount: device.loginCount,
    revokedAt: device.revokedAt,
    revokedReason: device.revokedReason,
    // How many separate client ids this device burned through. A high count with a single
    // fingerprint is the signature of a user repeatedly clearing storage - not of sharing.
    clientIdCount: device.clientIds?.length ?? 0,
    strictHashCount: device.strictHashes?.length ?? 0,
    networks: (device.observedIps ?? []).map((entry) => ({
      ip: entry.ip,
      isp: entry.isp,
      city: entry.city,
      country: entry.country,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
      hitCount: entry.hitCount,
    })),
    signals: device.signals,
  }));

  const SHARING_BLOCK_KINDS = ["CONCURRENT_USE_BLOCKED", "SWITCH_LIMIT_BLOCKED"];
  const blockRecords = records.filter((record) => SHARING_BLOCK_KINDS.includes(record.kind));

  // Inspection (developer-tools) findings are reported separately. They rest on probabilistic
  // client-side signals rather than on two measured devices, so putting them in the same section
  // as device evidence would overstate them.
  const inspectionBlocks = records.filter((record) => record.kind === "CLIENT_INSPECTION_BLOCKED");
  const inspectionReports = records.filter(
    (record) => record.kind === "CLIENT_INSPECTION_REPORTED",
  );

  const timeline = records.map((record) => ({
    seq: record.seq,
    kind: record.kind,
    recordedAt: record.recordedAt,
    deviceKey: record.deviceKey,
    narrative: record.narrative,
    device: record.payload?.observation?.deviceDescription ?? null,
    ip: record.payload?.observation?.network?.ip ?? null,
    city: record.payload?.observation?.network?.city ?? null,
    country: record.payload?.observation?.network?.country ?? null,
    recordHash: record.recordHash,
  }));

  return {
    user: {
      id: String(user._id),
      email: user.email,
      blocked: user.blocked,
      blockedReason: user.blockedReason,
      blockedAt: user.blockedAt,
    },
    verdict: blockRecords.length > 0 ? "SHARING_EVIDENCE_RECORDED" : "NO_SHARING_EVIDENCE",
    chainVerification,
    devices: deviceSummaries,
    inspection: {
      blockCount: inspectionBlocks.length,
      reportCount: inspectionReports.length,
      strongReportCount: inspectionReports.filter((record) => record.payload?.hasStrongSignal)
        .length,
      blocks: inspectionBlocks.map((record) => ({
        seq: record.seq,
        recordedAt: record.recordedAt,
        narrative: record.narrative,
        recordHash: record.recordHash,
        signature: record.signature,
        detail: record.payload,
      })),
    },
    blockingEvidence: blockRecords.map((record) => ({
      seq: record.seq,
      recordedAt: record.recordedAt,
      narrative: record.narrative,
      recordHash: record.recordHash,
      signature: record.signature,
      detail: record.payload,
    })),
    timeline,
    generatedAt: new Date().toISOString(),
  };
};

/**
 * Plain-English explanation of one block, written to be sent to the user as-is.
 * Deliberately concrete: what was observed, when, from where, and how it was verified.
 */
export const renderProofNarrative = (report) => {
  const lines = [];
  lines.push(`Account: ${report.user.email}`);
  lines.push(`Report generated: ${report.generatedAt}`);
  lines.push("");

  const inspection = report.inspection ?? { blockCount: 0, reportCount: 0, blocks: [] };

  if (report.verdict === "NO_SHARING_EVIDENCE") {
    lines.push("No concurrent-device evidence is on record for this account.");

    if (inspection.blockCount > 0) {
      lines.push("");
      lines.push("This account was blocked for developer-tools use instead:");

      for (const item of inspection.blocks) {
        lines.push("");
        lines.push(`Finding #${item.seq} - recorded ${item.recordedAt}`);
        lines.push(item.narrative ?? "");

        const signals = item.detail?.reportedSignals ?? [];
        if (signals.length > 0) {
          lines.push("");
          lines.push("Signals recorded:");
          for (const signal of signals) {
            const note = signal.detail ? ` - ${signal.detail}` : "";
            lines.push(`  ${signal.name} (weight ${signal.weight})${note}`);
          }
        }

        // The raw measurements are included so a user who says "I only zoomed in" can be
        // checked against what was actually recorded, rather than taken on trust either way.
        if (item.detail?.diagnostics) {
          lines.push("");
          lines.push(`Raw measurements: ${JSON.stringify(item.detail.diagnostics)}`);
        }

        lines.push("");
        lines.push(`Evidence record hash : ${item.recordHash}`);
        lines.push(`Server signature     : ${item.signature}`);
      }

      lines.push("");
      lines.push(
        "Note: developer-tools detection is probabilistic, unlike the device evidence above. " +
          "These signals are recorded for human review, and the raw measurements are included " +
          "so the finding can be checked rather than assumed.",
      );
    } else if (report.user.blocked) {
      lines.push(
        "The account is nonetheless blocked, so the block was manual or came from a different rule.",
      );
    }

    if (inspection.reportCount > 0 && inspection.blockCount === 0) {
      lines.push("");
      lines.push(
        `${inspection.reportCount} developer-tools report(s) are on file for review ` +
          `(${inspection.strongReportCount} carrying a signal that does not fire accidentally). ` +
          "No block was applied for them.",
      );
    }

    lines.push("");
    lines.push(`Integrity check: ${report.chainVerification.summary}`);
    return lines.join("\n");
  }

  for (const item of report.blockingEvidence) {
    const detail = item.detail ?? {};
    const existing = detail.existingDevice ?? {};
    const incoming = detail.incomingDevice ?? {};
    const overlap = detail.overlap ?? {};

    lines.push(`Finding #${item.seq} - recorded ${item.recordedAt}`);
    lines.push(item.narrative ?? "");
    lines.push("");
    lines.push("Device already signed in:");
    lines.push(`  Device        : ${existing.deviceDescription ?? "unknown"}`);
    lines.push(`  Last active   : ${existing.lastSeenAt ?? "unknown"}`);
    lines.push(`  Network       : ${existing.isp ?? "unknown"} (${existing.ip ?? "unknown"})`);
    lines.push(`  Location      : ${existing.city ?? "unknown"}, ${existing.country ?? "unknown"}`);
    lines.push("");
    lines.push("Device that attempted access:");
    lines.push(`  Device        : ${incoming.deviceDescription ?? "unknown"}`);
    lines.push(`  Attempted at  : ${incoming.observedAt ?? "unknown"}`);
    lines.push(`  Network       : ${incoming.isp ?? "unknown"} (${incoming.ip ?? "unknown"})`);
    lines.push(`  Location      : ${incoming.city ?? "unknown"}, ${incoming.country ?? "unknown"}`);
    lines.push("");

    if (overlap.minutesApart !== undefined) {
      lines.push(`Both devices were active ${overlap.minutesApart} minutes apart.`);
    }
    if (detail.travel?.distanceKm != null) {
      // A huge km/h figure reads like a glitch and undermines the document. When the two
      // sessions are effectively simultaneous, say that instead of quoting a speed.
      const travel = detail.travel;
      if (!Number.isFinite(travel.speedKmh) || travel.hours < 0.05) {
        lines.push(
          `The two networks are ${travel.distanceKm} km apart, and the sessions were effectively ` +
            "simultaneous. One person cannot be in both places at once.",
        );
      } else {
        lines.push(
          `The two networks are ${travel.distanceKm} km apart, which would require travelling at ` +
            `${Math.round(travel.speedKmh).toLocaleString("en-US")} km/h between the two sessions ` +
            "- faster than a commercial aircraft.",
        );
      }
    }

    const differences = detail.comparison?.differences ?? [];
    if (differences.length > 0) {
      lines.push("");
      lines.push("Hardware differences measured between the two devices:");
      for (const diff of differences) {
        lines.push(`  ${diff.label}: ${diff.deviceA}  vs  ${diff.deviceB}`);
      }
      lines.push("");
      lines.push(
        `Fingerprint similarity between the two devices: ${Math.round((detail.comparison?.similarity ?? 0) * 100)}%. ` +
          "The same device after clearing its browser data scores above 82%; these did not.",
      );
    }

    lines.push("");
    lines.push(`Evidence record hash : ${item.recordHash}`);
    lines.push(`Server signature     : ${item.signature}`);
    lines.push("");
  }

  lines.push(
    report.chainVerification.intact
      ? `Integrity check: ${report.chainVerification.summary}`
      : `Integrity check: ${report.chainVerification.summary}`,
  );

  return lines.join("\n");
};

export { impliedTravel };
