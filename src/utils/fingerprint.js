import { createHash } from "crypto";

/**
 * Device fingerprinting utilities.
 *
 * A device identity is built from three layers, strongest first:
 *   1. clientDeviceId - an id we handed the browser (localStorage + cookie). Cheap, but wiped easily.
 *   2. strictHash     - hash of hardware + browser signals. Survives any storage wipe, incognito
 *                       and reinstalls. Changes only when the browser itself changes.
 *   3. hardwareHash   - hash of hardware-only signals. Survives changing browser on the same machine.
 *
 * Layers 2 and 3 are what stop a cleared cache from looking like a second device.
 */

const HARDWARE_FIELDS = [
  "platform",
  "cpuCores",
  "deviceMemory",
  "screenWidth",
  "screenHeight",
  "colorDepth",
  "pixelRatio",
  "maxTouchPoints",
  "gpuVendor",
  "gpuRenderer",
];

const BROWSER_FIELDS = [
  "browserName",
  "browserMajorVersion",
  "canvasHash",
  "audioHash",
  "fontsHash",
  "languages",
  "timezone",
];

/**
 * Field weights used by `similarity`. Hardware signals weigh most because they identify the
 * physical machine; browser-version style signals weigh little because they change on every
 * auto-update and must never on their own look like a different device.
 */
const SIMILARITY_WEIGHTS = {
  platform: 14,
  gpuRenderer: 14,
  gpuVendor: 6,
  screenWidth: 8,
  screenHeight: 8,
  cpuCores: 8,
  deviceMemory: 7,
  colorDepth: 3,
  pixelRatio: 5,
  maxTouchPoints: 5,
  timezone: 6,
  canvasHash: 6,
  audioHash: 5,
  fontsHash: 4,
  languages: 4,
  browserName: 3,
  browserMajorVersion: 0.5,
};

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const normalizeString = (value) => {
  if (value === undefined || value === null) return "";
  return String(value).trim().toLowerCase().replace(/\s+/g, " ");
};

const normalizeNumber = (value) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
};

/**
 * Screen dimensions are reported differently depending on orientation, so they are sorted
 * long-edge first. A phone rotated to landscape must not read as a different device.
 */
const normalizeScreen = (width, height) => {
  const w = normalizeNumber(width);
  const h = normalizeNumber(height);
  if (w === null || h === null) return { screenWidth: null, screenHeight: null };
  const [long, short] = w >= h ? [w, h] : [h, w];
  return { screenWidth: long, screenHeight: short };
};

/**
 * GPU renderer strings carry driver detail that changes on every driver update, e.g.
 * "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)". Strip the volatile parts,
 * keep the model.
 */
const normalizeGpuRenderer = (value) => {
  let text = normalizeString(value);
  if (!text) return "";
  text = text.replace(/\((?:r|tm)\)/g, " ");
  text = text.replace(/direct3d\d*/g, " ");
  text = text.replace(/vs_[\d_]+|ps_[\d_]+/g, " ");
  text = text.replace(/opengl es [\d.]+/g, " ");
  text = text.replace(/version[^,)]*/g, " ");
  text = text.replace(/[\d.]+\s*(?:gb|mb)/g, " ");
  text = text.replace(/[(),]/g, " ");
  return text.replace(/\s+/g, " ").trim();
};

const parseBrowser = (userAgent) => {
  const ua = String(userAgent ?? "");
  const patterns = [
    { name: "edge", re: /Edg(?:e|A|iOS)?\/(\d+)/ },
    { name: "opera", re: /OPR\/(\d+)/ },
    { name: "samsung", re: /SamsungBrowser\/(\d+)/ },
    { name: "firefox", re: /(?:Firefox|FxiOS)\/(\d+)/ },
    { name: "chrome", re: /(?:Chrome|CriOS)\/(\d+)/ },
    { name: "safari", re: /Version\/(\d+).*Safari/ },
  ];
  for (const { name, re } of patterns) {
    const match = ua.match(re);
    if (match) return { browserName: name, browserMajorVersion: Number(match[1]) };
  }
  return { browserName: "unknown", browserMajorVersion: null };
};

/**
 * The OS family, deliberately coarse: a Windows 10 to Windows 11 upgrade, or iOS 17 to iOS 18,
 * must not register as a new device. Cross-family differences are what matter for sharing.
 */
const parsePlatform = (raw, userAgent) => {
  const haystack = `${normalizeString(raw)} ${normalizeString(userAgent)}`;
  if (/iphone/.test(haystack)) return "ios-phone";
  if (/ipad/.test(haystack)) return "ios-tablet";
  if (/android/.test(haystack)) return "android";
  if (/cros/.test(haystack)) return "chromeos";
  if (/win/.test(haystack)) return "windows";
  if (/mac/.test(haystack)) return "macos";
  if (/linux/.test(haystack)) return "linux";
  return "unknown";
};

/** Memory and core counts are bucketed because browsers round them inconsistently. */
const bucket = (value, steps) => {
  const num = normalizeNumber(value);
  if (num === null) return null;
  let chosen = steps[0];
  for (const step of steps) {
    if (num >= step) chosen = step;
  }
  return chosen;
};

/**
 * Turn a raw client payload into a canonical signal set. Everything downstream - hashing,
 * similarity, evidence - works off this, so normalization lives in exactly one place.
 */
export const normalizeFingerprint = (raw = {}) => {
  const screen = normalizeScreen(raw.screenWidth, raw.screenHeight);
  const browser = parseBrowser(raw.userAgent);

  return {
    platform: parsePlatform(raw.platform, raw.userAgent),
    cpuCores: bucket(raw.cpuCores, [1, 2, 4, 6, 8, 12, 16, 24, 32]),
    deviceMemory: bucket(raw.deviceMemory, [0.5, 1, 2, 4, 8]),
    screenWidth: screen.screenWidth,
    screenHeight: screen.screenHeight,
    colorDepth: normalizeNumber(raw.colorDepth),
    pixelRatio: raw.pixelRatio === undefined ? null : Math.round(Number(raw.pixelRatio) * 2) / 2,
    maxTouchPoints: Number(raw.maxTouchPoints) > 0 ? 1 : 0,
    gpuVendor: normalizeString(raw.gpuVendor),
    gpuRenderer: normalizeGpuRenderer(raw.gpuRenderer),
    browserName: browser.browserName,
    browserMajorVersion: browser.browserMajorVersion,
    canvasHash: normalizeString(raw.canvasHash),
    audioHash: normalizeString(raw.audioHash),
    fontsHash: normalizeString(raw.fontsHash),
    languages: normalizeString(
      Array.isArray(raw.languages) ? raw.languages.join(",") : raw.languages,
    ),
    timezone: normalizeString(raw.timezone),
  };
};

const hashFields = (signals, fields) => {
  const canonical = fields.map((field) => `${field}=${signals[field] ?? ""}`).join("|");
  return sha256(canonical);
};

export const hardwareHashOf = (signals) => hashFields(signals, HARDWARE_FIELDS);
export const strictHashOf = (signals) => hashFields(signals, [...HARDWARE_FIELDS, ...BROWSER_FIELDS]);

/**
 * How complete the fingerprint is (0..1). A browser with WebGL blocked, or a privacy extension
 * spoofing signals, yields a thin fingerprint - and a thin fingerprint must never be used to
 * justify a block.
 */
export const confidenceOf = (signals) => {
  const scored = [...HARDWARE_FIELDS, ...BROWSER_FIELDS];
  const present = scored.filter((field) => {
    const value = signals[field];
    return value !== null && value !== undefined && value !== "";
  });
  return Number((present.length / scored.length).toFixed(3));
};

/**
 * Weighted similarity between two canonical signal sets, 0..1.
 * Fields missing on either side are excluded from the denominator rather than counted as a
 * mismatch, so a browser that hides one signal does not drag the score down.
 */
export const similarity = (a = {}, b = {}) => {
  let matched = 0;
  let total = 0;

  for (const [field, weight] of Object.entries(SIMILARITY_WEIGHTS)) {
    const left = a[field];
    const right = b[field];
    const leftMissing = left === null || left === undefined || left === "";
    const rightMissing = right === null || right === undefined || right === "";
    if (leftMissing || rightMissing) continue;

    total += weight;
    if (field === "browserMajorVersion") {
      // Browsers auto-update constantly; anything within a few releases is the same browser.
      if (Math.abs(Number(left) - Number(right)) <= 3) matched += weight;
    } else if (left === right) {
      matched += weight;
    }
  }

  if (total === 0) return 0;
  return Number((matched / total).toFixed(4));
};

/**
 * Signals produced by the specific browser instance rather than by the hardware. Mass-produced
 * devices (two iPhone 15s on the same iOS build) have identical hardware signals, so the
 * hardware hash alone cannot tell two units apart - these can.
 */
const BROWSER_INSTANCE_FIELDS = ["canvasHash", "audioHash", "fontsHash"];

/**
 * True when at least one browser-instance signal is present on both sides and equal.
 *
 * Used to gate the hardware-hash match tier: a hardware match needs one browser-level
 * corroborator before it counts as the same unit, otherwise two identical phones would be
 * treated as one device.
 */
export const sharesBrowserInstanceSignal = (a = {}, b = {}) =>
  BROWSER_INSTANCE_FIELDS.some((field) => {
    const left = a[field];
    const right = b[field];
    return left && right && left === right;
  });

/**
 * True when neither side exposes any browser-instance signal, e.g. a hardened browser or a
 * privacy extension blocking canvas, WebGL and font enumeration. Such a pair is indistinguishable
 * by fingerprint, so it must be resolved by email verification rather than guessed at.
 */
export const lacksBrowserInstanceSignals = (a = {}, b = {}) =>
  BROWSER_INSTANCE_FIELDS.every((field) => !a[field]) ||
  BROWSER_INSTANCE_FIELDS.every((field) => !b[field]);

/** True when two signal sets describe different classes of physical machine. */
export const isDifferentHardwareClass = (a = {}, b = {}) => {
  if (a.platform && b.platform && a.platform !== b.platform) return true;
  if (a.gpuRenderer && b.gpuRenderer && a.gpuRenderer !== b.gpuRenderer) return true;
  if (
    a.screenWidth &&
    b.screenWidth &&
    (a.screenWidth !== b.screenWidth || a.screenHeight !== b.screenHeight)
  ) {
    return true;
  }
  return false;
};

/** A short human-readable device name for admin screens and user-facing emails. */
export const describeDevice = (signals = {}) => {
  const platformNames = {
    "ios-phone": "iPhone",
    "ios-tablet": "iPad",
    android: "Android device",
    windows: "Windows PC",
    macos: "Mac",
    chromeos: "Chromebook",
    linux: "Linux PC",
    unknown: "Unknown device",
  };
  const browserNames = {
    edge: "Edge",
    opera: "Opera",
    samsung: "Samsung Internet",
    firefox: "Firefox",
    chrome: "Chrome",
    safari: "Safari",
    unknown: "unknown browser",
  };
  const platform = platformNames[signals.platform] ?? platformNames.unknown;
  const browser = browserNames[signals.browserName] ?? browserNames.unknown;
  const screen =
    signals.screenWidth && signals.screenHeight
      ? ` ${signals.screenWidth}x${signals.screenHeight}`
      : "";
  return `${platform} - ${browser}${screen}`;
};

export const FINGERPRINT_FIELDS = {
  HARDWARE_FIELDS,
  BROWSER_FIELDS,
  BROWSER_INSTANCE_FIELDS,
  SIMILARITY_WEIGHTS,
};
