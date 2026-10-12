import { createHash, createHmac, timingSafeEqual } from "crypto";
import { config } from "../config.js";

/**
 * Tamper-evident evidence records.
 *
 * Every evidence record is hashed over its canonical JSON together with the hash of the previous
 * record for the same user, forming a per-user hash chain, and then signed with a server-side
 * secret. That gives two properties we need when a user disputes a block:
 *
 *   - Immutability: changing any past record breaks every later record in the chain, so we can
 *     show the record was not written or edited after the fact.
 *   - Authenticity: the HMAC proves the record came from our server, not from an admin typing
 *     into the database.
 *
 * This is what turns "our system flagged you" into "here is the signed log, verify it yourself".
 */

/** Deterministic JSON: keys sorted at every level, so the same data always hashes the same. */
export const canonicalJson = (value) => {
  if (value === null || value === undefined) return "null";
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};

export const GENESIS_HASH = "0".repeat(64);

/**
 * Compute the hash and signature for a record.
 * `payload` must contain every field that is part of the evidence - anything left out is not
 * protected by the chain.
 */
export const sealRecord = ({ payload, prevHash }) => {
  const body = canonicalJson({ prevHash: prevHash ?? GENESIS_HASH, payload });
  const recordHash = createHash("sha256").update(body).digest("hex");
  const signature = createHmac("sha256", config.evidenceSecret).update(recordHash).digest("hex");
  return { recordHash, signature, prevHash: prevHash ?? GENESIS_HASH };
};

const safeEqualHex = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
};

/** Re-derive one record's hash and signature and compare against what is stored. */
export const verifyRecord = (record) => {
  const expected = sealRecord({ payload: record.payload, prevHash: record.prevHash });
  return {
    hashValid: safeEqualHex(expected.recordHash, record.recordHash),
    signatureValid: safeEqualHex(expected.signature, record.signature),
  };
};

/**
 * Verify a whole chain in sequence order. Returns a per-record result plus an overall verdict
 * that is safe to show a user or paste into a support reply.
 */
export const verifyChain = (records) => {
  const ordered = [...records].sort((a, b) => a.seq - b.seq);
  const results = [];
  let expectedPrev = GENESIS_HASH;
  let intact = true;

  for (const record of ordered) {
    const { hashValid, signatureValid } = verifyRecord(record);
    const linkValid = record.prevHash === expectedPrev;
    const ok = hashValid && signatureValid && linkValid;
    if (!ok) intact = false;

    results.push({
      seq: record.seq,
      kind: record.kind,
      recordedAt: record.recordedAt,
      recordHash: record.recordHash,
      hashValid,
      signatureValid,
      linkValid,
      ok,
    });
    expectedPrev = record.recordHash;
  }

  return {
    intact,
    recordCount: ordered.length,
    headHash: expectedPrev,
    records: results,
    summary: intact
      ? `All ${ordered.length} evidence records verify against the server signature and form an unbroken chain.`
      : "Evidence chain verification FAILED - one or more records were altered or are missing.",
  };
};
