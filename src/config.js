import "dotenv/config";

const requiredEnv = ["MONGODB_URI", "JWT_SECRET", "PORT"];

if (process.env.NODE_ENV === "production") {
  requiredEnv.push("CORS_ORIGIN");
}

requiredEnv.forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
});

/**
 * EVIDENCE_SECRET signs the evidence chain. It is deliberately NOT in `requiredEnv`: making it
 * mandatory would take the API down on the first deploy after this change, before anyone had a
 * chance to set it. It falls back to JWT_SECRET, which is already present and stable, so records
 * stay verifiable either way.
 *
 * It should still be set explicitly, and then never rotated - rotating it makes every previously
 * signed record fail verification, which is exactly the evidence you would need in a dispute.
 */
if (process.env.NODE_ENV === "production" && !process.env.EVIDENCE_SECRET) {
  console.warn(
    "[config] EVIDENCE_SECRET is not set; falling back to JWT_SECRET to sign evidence records. " +
      "Set EVIDENCE_SECRET to a long random value and keep it stable. Note that changing either " +
      "secret later will make existing evidence records unverifiable.",
  );
}

const num = (value, fallback) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const config = {
  mongodbUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  port: num(process.env.PORT, 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  corsOrigin:
    process.env.CORS_ORIGIN?.split(",")
      .map((value) => value.trim())
      .filter(Boolean) ?? ["http://localhost:3000"],
  sessionTtlMinutes: num(process.env.SESSION_TTL_MINUTES, 480),
  cookieDomain: process.env.COOKIE_DOMAIN,

  evidenceSecret: process.env.EVIDENCE_SECRET ?? process.env.JWT_SECRET,

  device: {
    /**
     * Similarity at or above this means "same physical device, storage was wiped" and the device
     * is silently re-linked. Tuned high enough that two different machines will not collide, low
     * enough that a browser update, driver update or OS upgrade does not break recognition.
     */
    matchThreshold: num(process.env.DEVICE_MATCH_THRESHOLD, 0.82),

    /**
     * Below this, a fingerprint is too incomplete to reason about (WebGL blocked, privacy
     * extension, very old browser). Such a login is never used as evidence of sharing - we fall
     * back to email verification instead.
     */
    minConfidence: num(process.env.DEVICE_MIN_CONFIDENCE, 0.55),

    /** Two devices active within this window count as concurrent use. */
    concurrencyWindowMinutes: num(process.env.DEVICE_CONCURRENCY_WINDOW_MINUTES, 15),

    /** Sharing score at or above this blocks the account. Below it, we challenge by email. */
    blockScore: num(process.env.DEVICE_BLOCK_SCORE, 70),

    /** Implied travel faster than this between two logins is physically impossible. */
    maxTravelKmh: num(process.env.DEVICE_MAX_TRAVEL_KMH, 900),

    /** How many legitimate device switches a user may make inside the rolling window. */
    maxSwitchesPerWindow: num(process.env.DEVICE_MAX_SWITCHES, 3),
    switchWindowDays: num(process.env.DEVICE_SWITCH_WINDOW_DAYS, 30),

    /** Email verification code settings for signing in on a new device. */
    verificationTtlMinutes: num(process.env.DEVICE_VERIFICATION_TTL_MINUTES, 10),
    verificationMaxAttempts: num(process.env.DEVICE_VERIFICATION_MAX_ATTEMPTS, 5),

    /** Session heartbeat cadence the client is told to use, in seconds. */
    heartbeatSeconds: num(process.env.DEVICE_HEARTBEAT_SECONDS, 60),
  },

  inspection: {
    /**
     * What to do with a developer-tools report from the client.
     *
     *   "review" (default) - record it in the signed evidence chain, alert the operations inbox,
     *                        never penalise the user. Client-side detection is probabilistic, so
     *                        a human decides.
     *   "block"            - additionally block the account, but only once several separate
     *                        reports each carrying a non-accidental signal arrive in the window.
     *
     * The old behaviour was an immediate permanent block on a single unverified client claim.
     * That is not reachable any more in either mode.
     */
    policy: process.env.DEVTOOLS_POLICY === "block" ? "block" : "review",

    /** Minimum confidence (0-100) before a report can contribute to a block. */
    blockScore: num(process.env.DEVTOOLS_BLOCK_SCORE, 45),

    /** How many separate strong reports are needed, and over what window. */
    requiredReports: num(process.env.DEVTOOLS_REQUIRED_REPORTS, 3),
    windowMinutes: num(process.env.DEVTOOLS_WINDOW_MINUTES, 30),
  },

  geo: {
    /** Set false to disable outbound IP lookups entirely (evidence then omits geo fields). */
    enabled: process.env.GEO_LOOKUP_ENABLED !== "false",
    endpoint: process.env.GEO_LOOKUP_ENDPOINT ?? "http://ip-api.com/json",
    timeoutMs: num(process.env.GEO_LOOKUP_TIMEOUT_MS, 2500),
    cacheTtlMinutes: num(process.env.GEO_CACHE_TTL_MINUTES, 720),
  },

  supportEmail: process.env.SUPPORT_EMAIL ?? "support@tradingwala.com",
};
