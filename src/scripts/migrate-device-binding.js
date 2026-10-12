/**
 * Migration for the device-binding rewrite.
 *
 * Run once after deploying. It does three things:
 *
 *   1. Releases users who were blocked by the old rule. That rule flagged any previously unseen
 *      localStorage id as account sharing, so it blocked people who had merely cleared their
 *      browser data. Those blocks have no evidence behind them and cannot be defended, so they
 *      are reversed. Blocks an administrator made by hand are left alone.
 *
 *   2. Seeds a Device record from each user's old `devices` array, so returning users are
 *      recognised on their next login instead of being treated as new.
 *
 *   3. Backfills `deviceKey` and `lastSeenAt` on live sessions, which the concurrency check
 *      needs.
 *
 * Usage:
 *   node src/scripts/migrate-device-binding.js            # report only, changes nothing
 *   node src/scripts/migrate-device-binding.js --apply    # perform the migration
 */

import mongoose from "mongoose";
import { randomUUID } from "crypto";
import { config } from "../config.js";
import { UserModel } from "../models/User.js";
import { DeviceModel } from "../models/Device.js";
import { SessionModel } from "../models/Session.js";
import { appendEvidence } from "../services/evidenceService.js";

const APPLY = process.argv.includes("--apply");

/**
 * Block reasons written by the old automatic rule. Anything else - a reason typed by an
 * administrator, or one of the new evidence-backed reasons - is deliberately not touched.
 */
const AUTO_BLOCK_PATTERNS = [
  /suspected account sharing/i,
  /unrecognized device/i,
  /unrecognised device/i,
  /blocked for suspected sharing/i,
];

const isAutomaticOldBlock = (reason) =>
  typeof reason === "string" && AUTO_BLOCK_PATTERNS.some((pattern) => pattern.test(reason));

const log = (...args) => console.log(...args);

const run = async () => {
  await mongoose.connect(config.mongodbUri);
  log(`Connected. Mode: ${APPLY ? "APPLY" : "DRY RUN (nothing will be written)"}\n`);

  // ---- 1. Release users blocked by the old rule -------------------------------------------
  const blocked = await UserModel.find({ blocked: true }).lean();
  const autoBlocked = blocked.filter((user) => isAutomaticOldBlock(user.blockedReason));
  const manuallyBlocked = blocked.filter((user) => !isAutomaticOldBlock(user.blockedReason));

  log(`Blocked users found: ${blocked.length}`);
  log(`  - blocked by the old automatic device rule : ${autoBlocked.length}  (will be released)`);
  log(`  - blocked for other reasons               : ${manuallyBlocked.length}  (left as-is)`);

  if (manuallyBlocked.length > 0) {
    log("\n  Left blocked:");
    for (const user of manuallyBlocked) {
      log(`    ${user.email} -> ${user.blockedReason ?? "(no reason recorded)"}`);
    }
  }

  if (autoBlocked.length > 0) {
    log("\n  To be released:");
    for (const user of autoBlocked) {
      log(`    ${user.email} -> ${user.blockedReason}`);
    }
  }

  if (APPLY && autoBlocked.length > 0) {
    await UserModel.updateMany(
      { _id: { $in: autoBlocked.map((user) => user._id) } },
      {
        $set: { blocked: false, blockedReason: null, blockedAt: null },
        $push: {
          auditTrail: {
            $each: [
              {
                type: "ACCOUNT_UNBLOCKED",
                detail:
                  "Released by migration: the previous block came from a rule that treated a " +
                  "cleared browser storage id as a second device, and carries no supporting evidence.",
                createdAt: new Date(),
              },
            ],
            $position: 0,
            $slice: 100,
          },
        },
      },
    );
    log(`\n  Released ${autoBlocked.length} user(s).`);
  }

  // ---- 2. Seed Device records from the old devices array ----------------------------------
  const usersWithDevices = await UserModel.find({ "devices.0": { $exists: true } }).lean();
  let seeded = 0;
  let skipped = 0;

  log(`\nUsers with legacy device entries: ${usersWithDevices.length}`);

  for (const user of usersWithDevices) {
    const already = await DeviceModel.countDocuments({ user: user._id });
    if (already > 0) {
      skipped += 1;
      continue;
    }

    /**
     * The legacy array holds no fingerprint, so these ids cannot be matched by hardware. They
     * are seeded as client ids only: the user's next login matches on the id if their storage
     * survived, and otherwise registers the device properly with a real fingerprint. Either way
     * nobody is blocked for it.
     *
     * The most recently seen entry becomes the trusted device, so existing users are not forced
     * through email verification on their first login after the deploy.
     */
    const sorted = [...user.devices].sort(
      (a, b) => new Date(b.lastSeenAt ?? 0) - new Date(a.lastSeenAt ?? 0),
    );
    const newest = sorted[0];

    if (APPLY) {
      await DeviceModel.create({
        user: user._id,
        deviceKey: `dev_${randomUUID()}`,
        clientIds: sorted.map((device) => device.deviceId).filter(Boolean),
        strictHashes: [],
        hardwareHashes: [],
        signals: null,
        label: newest.deviceLabel ? `Legacy device (${newest.deviceLabel.slice(0, 80)})` : "Legacy device",
        platform: "unknown",
        trusted: true,
        verifiedAt: new Date(),
        verificationMethod: "migrated-legacy",
        firstSeenAt: newest.firstSeenAt ?? new Date(),
        lastSeenAt: newest.lastSeenAt ?? new Date(),
        loginCount: 0,
        observedIps: newest.lastIp
          ? [{ ip: newest.lastIp, firstSeenAt: newest.firstSeenAt, lastSeenAt: newest.lastSeenAt }]
          : [],
      });

      await appendEvidence({
        user,
        kind: "DEVICE_REGISTERED",
        deviceKey: null,
        payload: {
          reason: "migrated_from_legacy_devices_array",
          legacyDeviceIds: sorted.map((device) => device.deviceId),
          legacyDeviceCount: sorted.length,
        },
        narrative:
          `Migrated ${sorted.length} legacy device id(s) into a single device record. The legacy ` +
          "ids carry no fingerprint, so they are treated as one device until a real fingerprint " +
          "is observed.",
      });
    }
    seeded += 1;
  }

  log(`  - seeded   : ${seeded}`);
  log(`  - skipped  : ${skipped} (already have Device records)`);

  // ---- 3. Backfill session fields ---------------------------------------------------------
  const staleSessions = await SessionModel.countDocuments({
    revokedAt: { $exists: false },
    lastSeenAt: { $exists: false },
  });
  log(`\nLive sessions missing lastSeenAt: ${staleSessions}`);

  if (APPLY && staleSessions > 0) {
    // Backdated, not set to now: a session we have never seen a heartbeat from must not be
    // counted as "currently in use" by the concurrency check.
    await SessionModel.updateMany(
      { revokedAt: { $exists: false }, lastSeenAt: { $exists: false } },
      [{ $set: { lastSeenAt: { $ifNull: ["$createdAt", new Date(0)] } } }],
    );
    log(`  - backfilled ${staleSessions} session(s) from createdAt`);
  }

  log(
    APPLY
      ? "\nMigration complete."
      : "\nDry run complete. Re-run with --apply to perform these changes.",
  );

  await mongoose.disconnect();
};

run().catch(async (error) => {
  console.error("Migration failed:", error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
