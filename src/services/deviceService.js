import { randomUUID } from "crypto";
import { DeviceModel } from "../models/Device.js";
import { SessionModel } from "../models/Session.js";
import { config } from "../config.js";
import {
  normalizeFingerprint,
  strictHashOf,
  hardwareHashOf,
  confidenceOf,
  similarity,
  describeDevice,
  isDifferentHardwareClass,
  sharesBrowserInstanceSignal,
} from "../utils/fingerprint.js";
import { lookupIp, impliedTravel } from "./geoService.js";
import { appendEvidence, buildObservation, compareDevices } from "./evidenceService.js";

const FINGERPRINT_HISTORY_LIMIT = 25;
const CLIENT_ID_LIMIT = 50;

/**
 * Turn a raw request into everything downstream needs: canonical signals, hashes, confidence
 * and network/geo context. Called once per login or heartbeat.
 */
export const buildDeviceContext = async ({ fingerprint, clientDeviceId, ip, headers }) => {
  const signals = normalizeFingerprint({
    ...fingerprint,
    userAgent: fingerprint?.userAgent ?? headers?.["user-agent"],
  });

  const geo = await lookupIp(ip);

  return {
    signals,
    strictHash: strictHashOf(signals),
    hardwareHash: hardwareHashOf(signals),
    confidence: confidenceOf(signals),
    clientDeviceId: clientDeviceId ?? null,
    geo,
    headers: headers ?? {},
    observation: null,
  };
};

/**
 * Match an incoming context against the user's known devices.
 *
 * The order matters. Each tier recognises a legitimate situation that the old code mistook for a
 * second device:
 *   exact-client-id  - normal repeat visit
 *   strict-hash      - storage was cleared / incognito / new browser profile, same browser+machine
 *   hardware-hash    - user switched browser on the same machine
 *   fuzzy            - browser, driver or OS update shifted a few signals
 */
export const matchDevice = async (user, context) => {
  const devices = await DeviceModel.find({ user: user._id, revokedAt: { $exists: false } }).sort({
    lastSeenAt: -1,
  });

  if (devices.length === 0) {
    return { device: null, matchType: "none", score: 0, candidates: [] };
  }

  if (context.clientDeviceId) {
    const byClientId = devices.find((device) => device.clientIds?.includes(context.clientDeviceId));
    if (byClientId) {
      return { device: byClientId, matchType: "exact-client-id", score: 1, candidates: devices };
    }
  }

  const byStrictHash = devices.find((device) => device.strictHashes?.includes(context.strictHash));
  if (byStrictHash) {
    return { device: byStrictHash, matchType: "strict-hash", score: 1, candidates: devices };
  }

  // Only trust hardware/fuzzy matching when the fingerprint is rich enough to be meaningful.
  if (context.confidence >= config.device.minConfidence) {
    /**
     * A hardware-hash match is accepted only with a browser-level corroborator. Mass-produced
     * devices share hardware signals exactly - two iPhone 15s on the same iOS build produce the
     * same hardware hash - so the hash alone would merge two different people's phones into one
     * device record. Requiring a matching canvas, audio or font signal keeps the genuine case
     * (same machine, different browser profile, cleared storage) while rejecting the collision.
     * A device that fails this gate can still match on its overall similarity score below.
     */
    const byHardware = devices.find(
      (device) =>
        device.hardwareHashes?.includes(context.hardwareHash) &&
        sharesBrowserInstanceSignal(context.signals, device.signals ?? {}),
    );
    if (byHardware) {
      return { device: byHardware, matchType: "hardware-hash", score: 0.95, candidates: devices };
    }

    let best = null;
    let bestScore = 0;
    for (const device of devices) {
      const score = similarity(context.signals, device.signals ?? {});
      if (score > bestScore) {
        bestScore = score;
        best = device;
      }
    }
    if (best && bestScore >= config.device.matchThreshold) {
      return { device: best, matchType: "fuzzy", score: bestScore, candidates: devices };
    }
    return { device: null, matchType: "none", score: bestScore, candidates: devices };
  }

  return { device: null, matchType: "low-confidence", score: 0, candidates: devices };
};

/** Record this observation against a device document, keeping history bounded. */
export const recordObservation = async (device, context, { matchType, score, countLogin } = {}) => {
  const now = new Date();

  if (context.clientDeviceId && !device.clientIds.includes(context.clientDeviceId)) {
    device.clientIds.push(context.clientDeviceId);
    if (device.clientIds.length > CLIENT_ID_LIMIT) {
      device.clientIds = device.clientIds.slice(-CLIENT_ID_LIMIT);
    }
  }
  if (!device.strictHashes.includes(context.strictHash)) {
    device.strictHashes.push(context.strictHash);
  }
  if (!device.hardwareHashes.includes(context.hardwareHash)) {
    device.hardwareHashes.push(context.hardwareHash);
  }

  device.signals = context.signals;
  device.label = describeDevice(context.signals);
  device.platform = context.signals.platform;
  device.lastSeenAt = now;
  if (matchType) device.lastMatchType = matchType;
  if (score !== undefined) device.lastMatchScore = score;
  if (countLogin) device.loginCount = (device.loginCount ?? 0) + 1;

  const ip = context.geo?.ip;
  if (ip) {
    const existingIp = device.observedIps.find((entry) => entry.ip === ip);
    if (existingIp) {
      existingIp.lastSeenAt = now;
      existingIp.hitCount = (existingIp.hitCount ?? 1) + 1;
    } else {
      device.observedIps.push({
        ip,
        asn: context.geo.asn,
        isp: context.geo.isp,
        city: context.geo.city,
        region: context.geo.region,
        country: context.geo.country,
        latitude: context.geo.latitude,
        longitude: context.geo.longitude,
        firstSeenAt: now,
        lastSeenAt: now,
        hitCount: 1,
      });
    }
  }

  device.fingerprintHistory.unshift({
    strictHash: context.strictHash,
    hardwareHash: context.hardwareHash,
    signals: context.signals,
    confidence: context.confidence,
    capturedAt: now,
  });
  if (device.fingerprintHistory.length > FINGERPRINT_HISTORY_LIMIT) {
    device.fingerprintHistory = device.fingerprintHistory.slice(0, FINGERPRINT_HISTORY_LIMIT);
  }

  await device.save();
  return device;
};

export const createDevice = async (user, context, { trusted = false, verificationMethod } = {}) => {
  const now = new Date();
  const device = new DeviceModel({
    user: user._id,
    deviceKey: `dev_${randomUUID()}`,
    clientIds: context.clientDeviceId ? [context.clientDeviceId] : [],
    strictHashes: [context.strictHash],
    hardwareHashes: [context.hardwareHash],
    signals: context.signals,
    label: describeDevice(context.signals),
    platform: context.signals.platform,
    trusted,
    verifiedAt: trusted ? now : undefined,
    verificationMethod: trusted ? verificationMethod : undefined,
    firstSeenAt: now,
    lastSeenAt: now,
    loginCount: 1,
    observedIps: context.geo?.ip
      ? [
          {
            ip: context.geo.ip,
            asn: context.geo.asn,
            isp: context.geo.isp,
            city: context.geo.city,
            region: context.geo.region,
            country: context.geo.country,
            latitude: context.geo.latitude,
            longitude: context.geo.longitude,
            firstSeenAt: now,
            lastSeenAt: now,
            hitCount: 1,
          },
        ]
      : [],
    fingerprintHistory: [
      {
        strictHash: context.strictHash,
        hardwareHash: context.hardwareHash,
        signals: context.signals,
        confidence: context.confidence,
        capturedAt: now,
      },
    ],
  });
  await device.save();
  return device;
};

/**
 * Was another device provably in use at the same time?
 *
 * "In use" means it held a live, non-revoked session whose last heartbeat is inside the
 * concurrency window. This is the only condition that justifies a block, because it is the only
 * one a cleared cache cannot produce: a wiped browser yields a *matching* fingerprint, never a
 * second live session on different hardware.
 *
 * The score is additive so the report can show exactly which factors fired.
 */
export const assessConcurrentUse = async (user, context, matchedDevice) => {
  const now = new Date();
  const windowStart = new Date(now.getTime() - config.device.concurrencyWindowMinutes * 60 * 1000);

  const liveSessions = await SessionModel.find({
    user: user._id,
    revokedAt: { $exists: false },
    expiresAt: { $gt: now },
    lastSeenAt: { $gte: windowStart },
  }).lean();

  const matchedKey = matchedDevice?.deviceKey ?? null;
  const foreign = liveSessions.filter((session) => session.deviceKey && session.deviceKey !== matchedKey);
  if (foreign.length === 0) {
    return { concurrent: false, score: 0, factors: [] };
  }

  const otherKeys = [...new Set(foreign.map((session) => session.deviceKey))];
  const otherDevices = await DeviceModel.find({ user: user._id, deviceKey: { $in: otherKeys } }).lean();

  let worst = null;

  for (const other of otherDevices) {
    const session = foreign
      .filter((item) => item.deviceKey === other.deviceKey)
      .sort((a, b) => new Date(b.lastSeenAt) - new Date(a.lastSeenAt))[0];

    const comparison = compareDevices(context.signals, other.signals ?? {});
    const otherIp = (other.observedIps ?? []).slice(-1)[0] ?? null;
    const travel = otherIp ? impliedTravel(otherIp, context.geo, otherIp.lastSeenAt, now) : null;
    const factors = [];
    let score = 0;

    // A live session on a device whose fingerprint does not match is the base finding.
    if (comparison.similarity < config.device.matchThreshold) {
      score += 40;
      factors.push({
        factor: "live_session_on_different_fingerprint",
        weight: 40,
        detail: `Another device held a live session ${Math.round(
          (now - new Date(session.lastSeenAt)) / 60000,
        )} minutes ago with a fingerprint similarity of ${Math.round(comparison.similarity * 100)}%.`,
      });
    }

    if (comparison.differentHardwareClass) {
      score += 15;
      factors.push({
        factor: "different_hardware_class",
        weight: 15,
        detail: `Measured hardware differs: ${comparison.differences
          .slice(0, 4)
          .map((diff) => `${diff.label} ${diff.deviceA} vs ${diff.deviceB}`)
          .join("; ")}.`,
      });
    }

    /**
     * Two devices on the same public IP are one household, and almost always one person who
     * left a tab open on their desktop and then picked up their phone. Blocking that is the
     * most common way a single-device rule punishes an honest user, so a shared IP is treated
     * as a strong mitigator rather than ignored. Sharing that matters happens across networks.
     */
    if (otherIp?.ip && context.geo?.ip && otherIp.ip === context.geo.ip) {
      score -= 35;
      factors.push({
        factor: "same_public_ip_mitigator",
        weight: -35,
        detail:
          `Both devices were on the same public IP (${context.geo.ip}), i.e. the same network. ` +
          "Consistent with one person using two of their own devices in one place.",
      });
    }

    if (otherIp?.country && context.geo?.country && otherIp.country !== context.geo.country) {
      score += 25;
      factors.push({
        factor: "different_country",
        weight: 25,
        detail: `Sessions originated in ${otherIp.country} and ${context.geo.country}.`,
      });
    }

    if (travel?.impossible) {
      score += 30;
      factors.push({
        factor: "impossible_travel",
        weight: 30,
        detail: `${travel.distanceKm} km apart within ${travel.hours} hours, implying ${travel.speedKmh} km/h.`,
      });
    }

    if (otherIp?.asn && context.geo?.asn && otherIp.asn !== context.geo.asn) {
      score += 15;
      factors.push({
        factor: "different_network_operator",
        weight: 15,
        detail: `Different ISPs: ${otherIp.isp ?? otherIp.asn} and ${context.geo.isp ?? context.geo.asn}.`,
      });
    }

    /**
     * Geo lookups can fail or be disabled, in which case we have no network evidence at all.
     * A block resting only on "the fingerprints differ" is not defensible to a user, so without
     * corroborating network divergence the finding is capped below the block threshold and the
     * login is sent to email verification instead.
     */
    const hasNetworkEvidence = factors.some((item) =>
      ["different_country", "impossible_travel", "different_network_operator"].includes(item.factor),
    );
    if (!hasNetworkEvidence) {
      score = Math.min(score, config.device.blockScore - 1);
      factors.push({
        factor: "no_network_corroboration",
        weight: 0,
        detail:
          "No network divergence could be established, so this finding alone does not justify a " +
          "block. The login was sent to email verification instead.",
      });
    }

    score = Math.max(0, score);

    const minutesApart = Math.round((now - new Date(session.lastSeenAt)) / 60000);

    const finding = {
      concurrent: true,
      score,
      factors,
      comparison,
      travel,
      otherDevice: other,
      overlap: {
        minutesApart,
        otherDeviceLastSeenAt: session.lastSeenAt,
        otherSessionCreatedAt: session.createdAt,
        incomingAt: now.toISOString(),
        windowMinutes: config.device.concurrencyWindowMinutes,
      },
    };

    if (!worst || finding.score > worst.score) worst = finding;
  }

  return worst ?? { concurrent: false, score: 0, factors: [] };
};

/**
 * Catch two physically distinct units that share one fingerprint.
 *
 * Fingerprinting cannot separate two identical phones on the same OS build - identical hardware
 * signals, and canvas/audio/font hashes that may also collide. Such a pair merges into one
 * device record, so the concurrency check above never sees a "second device".
 *
 * Location does separate them. If the same device record is observed from two places minutes
 * apart that no person could travel between, that is two units, and it is provable without any
 * reference to the fingerprint at all.
 */
export const assessSameDeviceAnomaly = (device, context) => {
  if (!context.geo?.latitude || !context.geo?.longitude) {
    return { anomalous: false, score: 0, factors: [] };
  }

  const recent = (device.observedIps ?? [])
    .filter((entry) => entry.latitude != null && entry.longitude != null && entry.ip !== context.geo.ip)
    .sort((a, b) => new Date(b.lastSeenAt) - new Date(a.lastSeenAt))[0];

  if (!recent) return { anomalous: false, score: 0, factors: [] };

  const travel = impliedTravel(recent, context.geo, recent.lastSeenAt, new Date());
  if (!travel?.impossible) return { anomalous: false, score: 0, factors: [] };

  /**
   * Impossible travel on its own is NOT enough here, because a phone moving between WiFi and
   * mobile data gets a carrier gateway address that can geolocate to a different city instantly.
   * On Indian networks in particular, Jio and Airtel CGNAT pools routinely place a Pune user in
   * Mumbai or Delhi. Treating that as two devices is precisely the false block this work exists
   * to remove.
   *
   * So this finding additionally requires a different country AND a different network operator
   * AND more than 1000 km of separation. What survives all three is a genuinely different
   * continent on a genuinely different carrier - not a handoff.
   */
  const differentCountry =
    recent.country && context.geo.country && recent.country !== context.geo.country;
  const differentOperator = recent.asn && context.geo.asn && recent.asn !== context.geo.asn;
  const farApart = travel.distanceKm > 1000;

  if (!differentCountry || !differentOperator || !farApart) {
    return { anomalous: false, score: 0, factors: [] };
  }

  return {
    anomalous: true,
    score: 75,
    travel,
    otherDevice: device,
    comparison: { similarity: 1, differences: [], differentHardwareClass: false },
    overlap: {
      minutesApart: Math.round((Date.now() - new Date(recent.lastSeenAt).getTime()) / 60000),
      otherDeviceLastSeenAt: recent.lastSeenAt,
      incomingAt: new Date().toISOString(),
    },
    factors: [
      {
        factor: "impossible_travel_same_fingerprint",
        weight: 75,
        detail:
          `This device was used in ${recent.city ?? "an unknown city"}, ${recent.country ?? "unknown"} ` +
          `and then in ${context.geo.city ?? "an unknown city"}, ${context.geo.country ?? "unknown"} ` +
          `${travel.hours} hours later - ${travel.distanceKm} km apart, implying ${travel.speedKmh} km/h. ` +
          "Two separate units of the same model produce one fingerprint, so location is what " +
          "distinguishes them.",
      },
    ],
  };
};

/** Device switches inside the rolling window, used to catch two people taking turns. */
export const countRecentSwitches = async (user) => {
  const since = new Date(Date.now() - config.device.switchWindowDays * 24 * 60 * 60 * 1000);
  const { DeviceEvidenceModel } = await import("../models/DeviceEvidence.js");
  return DeviceEvidenceModel.countDocuments({
    user: user._id,
    kind: "DEVICE_SWITCHED",
    recordedAt: { $gte: since },
  });
};

/**
 * Decide what to do with a login attempt.
 *
 * Returns one of:
 *   allow     - recognised, trusted device
 *   verify    - new or unverified device, no sharing evidence: prove ownership by email
 *   block     - two devices provably in use at once, or switch limit exceeded
 *
 * Note what is NOT here: "an id we have not seen before" is never on its own a reason to block.
 */
export const evaluateLogin = async (user, context) => {
  const match = await matchDevice(user, context);

  context.observation = buildObservation(context);

  // First device on the account. Trust it and record the baseline.
  if (!match.device && (match.candidates?.length ?? 0) === 0) {
    const device = await createDevice(user, context, {
      trusted: true,
      verificationMethod: "first-device",
    });
    await appendEvidence({
      user,
      kind: "DEVICE_REGISTERED",
      deviceKey: device.deviceKey,
      payload: { observation: context.observation, reason: "first_device_on_account" },
      narrative: `First device registered for this account: ${device.label}.`,
    });
    return { decision: "allow", device, matchType: "first-device", score: 1 };
  }

  if (match.device) {
    await recordObservation(match.device, context, {
      matchType: match.matchType,
      score: match.score,
      countLogin: true,
    });

    // Recognising a device through its fingerprint after its client id disappeared is the exact
    // case that used to cause a false block. Record it explicitly so support can point at it.
    if (match.matchType !== "exact-client-id") {
      await appendEvidence({
        user,
        kind: "DEVICE_RECOGNIZED",
        deviceKey: match.device.deviceKey,
        payload: {
          observation: context.observation,
          matchType: match.matchType,
          matchScore: match.score,
          reason: "known_device_presented_new_client_id",
        },
        narrative:
          `Known device recognised by ${match.matchType} (score ${match.score}) after presenting a new ` +
          "browser id. Treated as the same device, not a new one.",
      });
    }

    if (!match.device.trusted) {
      return { decision: "verify", device: match.device, matchType: match.matchType, score: match.score };
    }

    const concurrency = await assessConcurrentUse(user, context, match.device);
    if (concurrency.concurrent && concurrency.score >= config.device.blockScore) {
      return {
        decision: "block",
        reason: "CONCURRENT_USE",
        device: match.device,
        concurrency,
        matchType: match.matchType,
        score: match.score,
      };
    }

    // Two identical units sharing one fingerprint are caught by geography, not by signals.
    const anomaly = assessSameDeviceAnomaly(match.device, context);
    if (anomaly.anomalous && anomaly.score >= config.device.blockScore) {
      return {
        decision: "block",
        reason: "CONCURRENT_USE",
        device: match.device,
        concurrency: anomaly,
        matchType: match.matchType,
        score: match.score,
      };
    }

    return { decision: "allow", device: match.device, matchType: match.matchType, score: match.score };
  }

  // Genuinely unrecognised device on an account that already has one.
  const concurrency = await assessConcurrentUse(user, context, null);
  if (concurrency.concurrent && concurrency.score >= config.device.blockScore) {
    return { decision: "block", reason: "CONCURRENT_USE", device: null, concurrency, matchType: match.matchType };
  }

  const switches = await countRecentSwitches(user);
  if (switches >= config.device.maxSwitchesPerWindow) {
    return { decision: "block", reason: "SWITCH_LIMIT", device: null, switches, matchType: match.matchType };
  }

  const device = await createDevice(user, context, { trusted: false });
  return { decision: "verify", device, matchType: match.matchType, score: match.score, isNewDevice: true };
};

export { similarity, isDifferentHardwareClass, describeDevice };
