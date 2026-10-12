# Device binding and account sharing

How single-device access is enforced, why it no longer blocks innocent users, and what to send
someone who disputes a block.

## The bug this replaced

Device identity was a `crypto.randomUUID()` stored in `localStorage` and nothing else
(`lib/security/device.ts`). The server then blocked the account the first time it saw an id it
did not recognise (`userService.upsertAllowedDevice`: `shouldFlagSharing = devices.length > 0`).

A second device was never required to trigger that. Only a changed id was. All of these change
it, for a user who did nothing wrong:

| What the user did | Why the id changed |
|---|---|
| Did not open the site for 7 days on iPhone | Safari's ITP caps script-written storage at 7 days and deletes it |
| Cleared browsing data / "cookies and site data" | `localStorage` wiped |
| Opened a private / incognito window | Separate storage partition |
| Used a second browser on the same PC | Per-browser storage |
| Browser set to clear data on exit | Wiped every close |
| Android Chrome under storage pressure | Eviction |
| Got a new phone, or reinstalled | No storage to carry over |

The evidence stored alongside the block was the random id, the user-agent string and an IP. That
data is **identical** in the "cleared cache" case and the "shared password" case, so the block
could not be justified to the user, and often was not justified at all.

## How identity works now

A device is matched in tiers, strongest first (`services/deviceService.js` → `matchDevice`):

| Tier | Matches on | Catches |
|---|---|---|
| `exact-client-id` | an id we previously issued | normal repeat visit |
| `strict-hash` | hardware + browser fingerprint | storage cleared, incognito, reinstall |
| `hardware-hash` | hardware-only fingerprint (plus a browser-level corroborator) | user switched browser on the same machine |
| `fuzzy` | weighted similarity ≥ `DEVICE_MATCH_THRESHOLD` (0.82) | driver update, OS upgrade, browser auto-update |

Because tiers 2–4 do not depend on stored state, **losing the stored id is no longer fatal**. The
id is also mirrored across `localStorage`, `sessionStorage`, a 2-year cookie and IndexedDB, so
losing it is rarer to begin with — any surviving layer restores the others.

Signals are normalised before hashing so routine churn does not look like a new device: screen
dimensions are sorted long-edge first (rotation), GPU strings have driver versions stripped,
OS version is coarsened to a family, and browser versions match within 3 releases.

The `hardware-hash` tier additionally requires a matching canvas, audio or font signal. Without
that gate, two iPhones of the same model — which have byte-identical hardware signals — would
merge into one device record.

## When an account is actually blocked

Never for "a device we have not seen". Only for **provable concurrent use**, scored additively
(`assessConcurrentUse`), blocking at `DEVICE_BLOCK_SCORE` (70):

| Factor | Score |
|---|---|
| Another device held a live session (recent heartbeat) with a non-matching fingerprint | +40 |
| Measurably different hardware class (OS, GPU or screen) | +15 |
| Different country | +25 |
| Impossible travel between the two networks | +30 |
| Different ISP / network operator | +15 |
| **Both devices on the same public IP** | **−35** |

Two deliberate safety valves:

- **Same public IP subtracts 35.** Two devices on one network is a household, and nearly always
  one person who left a tab open on their desktop and picked up their phone. That was the most
  likely remaining source of wrong blocks.
- **No network divergence caps the score below the threshold.** A finding that rests only on
  "the fingerprints differ" is not defensible, so it routes to email verification instead.

A new device with no concurrency evidence is **challenged, not blocked**: a 6-digit code to the
account's email address. On success the device becomes the authorised one and the previous device
is signed out — single-device access is still enforced, but the user can move devices.

Two further checks:

- **Session token used from different hardware** (`heartbeatSession`): requires a rich
  fingerprint, similarity below threshold **and** a different hardware class. A driver or browser
  update shifts similarity but never hardware class, so it cannot trip this.
- **Impossible travel on one fingerprint** (`assessSameDeviceAnomaly`): catches two identical
  units that fingerprint the same. Requires different country **and** different operator **and**
  >1000 km, because Indian carrier CGNAT routinely places a Pune user in Mumbai or Delhi, and
  treating that as two devices is exactly the false block being removed.

## The proof

Every observation is appended to a per-user hash chain (`models/DeviceEvidence.js`,
`utils/evidenceChain.js`). Each record is hashed over its canonical JSON plus the previous
record's hash, then HMAC-signed with `EVIDENCE_SECRET`. This gives:

- **Immutability** — altering any past record breaks every later record, so you can show the
  record was written at the time and not edited afterwards.
- **Authenticity** — the HMAC proves the record came from the server, not from someone editing
  the database.

A record captures the full fingerprint of both devices, both IPs with ISP/ASN and city, the
overlap window in minutes, the measured hardware differences, the similarity score, and the
scoring factors that fired.

### Admin endpoints

```
GET  /api/v1/admin/users/:id/devices                  # devices, with clientIdCount vs distinctFingerprints
GET  /api/v1/admin/users/:id/sharing-report           # structured report + chain verification
GET  /api/v1/admin/users/:id/sharing-proof?format=text  # plain text, ready to paste to the user
GET  /api/v1/admin/users/:id/evidence                 # raw signed records for an auditor
POST /api/v1/admin/users/:id/devices/reset            # clear bindings (does NOT unblock)
```

### Reading the device table

```
Windows PC - Chrome 1920x1080
  trusted=True  logins=3  clientIds=3  fingerprints=1  match=strict-hash
```

`clientIds=3, fingerprints=1` means **one physical device that lost its stored id three times**.
That is a user clearing their cache, not three devices. Under the old system this was three
blocks. Check this before accepting any sharing claim.

### Handling a dispute

1. `GET /admin/users/:id/sharing-proof?format=text`.
2. Check `chainVerification.intact`. If false, **do not defend the block** — the records are not
   trustworthy; unblock and investigate the data.
3. If `verdict` is `NO_SHARING_EVIDENCE` but the account is blocked, the block was manual or came
   from a different rule (e.g. devtools). Say so rather than claiming sharing.
4. Otherwise send the user the rendered report. It names both devices, both networks, both
   locations, the minutes apart, and the measured hardware differences — concrete and checkable.
5. Wrong call? `POST /admin/users/:id/devices/reset`, then unblock. Reset alone does not unblock;
   that stays a separate, explicit action.

The user also receives this report by email automatically at the moment of the block, with a case
reference (the first 12 characters of the evidence hash). The login screen shows them the same
reference. Ask for it — it identifies the exact record.

## Deploying

1. Set `EVIDENCE_SECRET` to a long random value and **never rotate it** — rotating it makes
   previously signed records unverifiable. Required in production.
2. Dry-run the migration, read the output, then apply:
   ```
   node src/scripts/migrate-device-binding.js
   node src/scripts/migrate-device-binding.js --apply
   ```
   It releases users blocked by the old automatic rule, leaves administrator and devtools blocks
   alone, seeds a trusted `Device` per existing user so nobody is forced to re-verify, and
   backfills `lastSeenAt`. It is idempotent.
3. `trust proxy` is enabled in `app.js`. Without it every evidence record would show the
   DigitalOcean load balancer's IP and the network half of the proof would be worthless.
4. `GOOGLE_PASSWORD` must be a valid Gmail App Password, or verification codes will not send and
   nobody can authorise a new device.

## Tuning

| Variable | Default | Effect |
|---|---|---|
| `DEVICE_MATCH_THRESHOLD` | 0.82 | Lower = fewer verification prompts, higher collision risk |
| `DEVICE_MIN_CONFIDENCE` | 0.55 | Below this a fingerprint is never used as sharing evidence |
| `DEVICE_CONCURRENCY_WINDOW_MINUTES` | 15 | How recent a heartbeat must be to count as "in use" |
| `DEVICE_BLOCK_SCORE` | 70 | Raise to block less often |
| `DEVICE_MAX_TRAVEL_KMH` | 900 | Above this, travel is impossible |
| `DEVICE_MAX_SWITCHES` / `DEVICE_SWITCH_WINDOW_DAYS` | 3 / 30 | Catches two people taking turns |
| `DEVICE_VERIFICATION_TTL_MINUTES` | 10 | Code lifetime |
| `GEO_LOOKUP_ENABLED` | true | Off disables network evidence — blocks then effectively never fire |

If false blocks reappear, raise `DEVICE_BLOCK_SCORE` to 85 first: that requires network
divergence *plus* hardware difference, and is the safest lever.

## Known limits

State these honestly rather than overclaiming:

- **Two identical devices on the same network, used at different times, are indistinguishable.**
  Identical hardware signals, possibly identical canvas hashes, one IP. Single-session
  enforcement means they sign each other out constantly, which deters sharing without accusing
  anyone — but it is not detected as sharing.
- **A privacy browser that randomises canvas output** produces a changing fingerprint. Confidence
  drops below `DEVICE_MIN_CONFIDENCE` and such logins route to email verification. They are never
  used as evidence of sharing.
- **A VPN defeats the network half of the evidence.** Fingerprint and concurrency still apply,
  but geo factors will not fire.
- **City-level geolocation is unreliable**, especially on mobile carriers. Nothing blocks on city
  alone; country plus operator plus distance is required.

## Developer-tools detection

Previously: any POST to `/security/event` carrying a token blocked the account permanently, and
the client-side heuristics driving it were a 100 ms console-timing probe (exceeded by any
throttled tab or slow frame) and a window inner/outer size delta (moved by browser zoom, OS
display scaling, split screen, device rotation, on-screen keyboards, the bookmarks bar and
extension sidebars). The browser decided the penalty, and nothing was recorded to review.

Removed outright, with reasons, in `lib/security/devtools-detector.ts`:

| Removed | Why |
|---|---|
| `console.log` timing at 100 ms | Any slow frame or throttled background tab exceeds it. It also called `console.clear()` on a timer. |
| `debugger` in a 1s `setInterval` | Freezes the tab repeatedly if devtools is ever open, and is trivially bypassed. |
| Firebug checks | Firebug has been dead since 2017. |
| `querySelector('.__devtools__')` | No browser has ever exposed that class. |
| Blocking on the F12 keydown | Pressing a key is not proof devtools opened, and the chords collide with other software. |

What remains is a **reporter**, not an enforcer. It never logs anyone out. Signals are weighted
server-side by how hard they are to trigger accidentally (`services/inspectionService.js`):

| Signal | Weight | Note |
|---|---|---|
| `console_object_inspected` | 45 | A logged object's getter fired, which needs a console pane rendering it. The one strong signal. |
| `element_picker_active` | 25 | Inspection overlay present. |
| `devtools_shortcut_pressed` | 10 | Intent only. |
| `window_dimension_delta` | 5 | The old false-positive source. Context only, and only reported when zoom is within 10% of 1. |
| `console_timing_anomaly` | 0 | Kept for comparability, scored at zero. |

Three guarantees, each covered by a test:

- **Weak signals can never block**, however many arrive. Without at least one non-accidental
  signal the score is capped below the threshold.
- **`DEVTOOLS_POLICY=review` is the default** and never penalises anyone. Reports are recorded as
  signed evidence and surfaced in the admin panel for a human.
- **Even with `DEVTOOLS_POLICY=block`**, a single report never blocks. `DEVTOOLS_REQUIRED_REPORTS`
  (default 3) separate strong reports must arrive inside `DEVTOOLS_WINDOW_MINUTES` (default 30).

Every report stores its raw measurements - window sizes, zoom level, device pixel ratio,
visibility - so a user who says "I only zoomed in" can be checked against what was recorded
rather than taken on trust either way.

| Variable | Default | Effect |
|---|---|---|
| `DEVTOOLS_POLICY` | `review` | `block` opts into penalties |
| `DEVTOOLS_BLOCK_SCORE` | 45 | Minimum confidence to count toward a block |
| `DEVTOOLS_REQUIRED_REPORTS` | 3 | Strong reports needed, including the triggering one |
| `DEVTOOLS_WINDOW_MINUTES` | 30 | Window they must fall inside |

Recommended: leave the policy on `review`, watch the panel for a few weeks to see what actually
fires in production, and only then decide whether blocking is justified.

## Admin panel

At `/admin` in the Next.js app. It uses its own token (`adminToken`), separate from the trader
token, so signing in to the panel never disturbs a trader session in the same browser.

| Route | Purpose |
|---|---|
| `/admin` | Sign in |
| `/admin/dashboard` | Counts, plus every currently blocked account with a direct link to its proof |
| `/admin/users` | Searchable account list, filterable to blocked only |
| `/admin/users/[id]` | The proof view |

The proof view is ordered so a reviewer reaches a defensible conclusion:

1. **Integrity banner first.** If the evidence chain does not verify, the page says so and tells
   you not to present the findings - a broken chain means the records were altered, and the
   correct action is to unblock and investigate the data.
2. **Verdict banner.** Distinguishes four cases honestly, including "blocked with no automated
   evidence" (a manual block) and "blocked for developer-tools use" (probabilistic, not measured).
   It explicitly warns against telling the user it was device sharing when it was not.
3. **Proof tab.** Each finding with the two devices side by side, the overlap in minutes, the
   distance between networks, a table of measured hardware differences, the similarity percentage
   against the 82% same-device threshold, and an expandable breakdown of how the score was
   reached - including negative factors such as the same-IP mitigator.
4. **Devices tab.** Per device, and this is the important one: a device showing several browser
   ids but one fingerprint is flagged inline as **one device that lost its stored id**, not
   several devices. That conflation was the original bug.
5. **Dev-tools reports tab.** Separated from device evidence, weak signals visually greyed out,
   raw measurements expandable, with the active policy shown.
6. **Full timeline.** Every signed record in sequence.
7. **Copy for user.** The exact plain-text proof the user is emailed, with a copy button.

Actions on the page: block, unblock, and reset device bindings. Reset deliberately does not
unblock - that stays a separate decision - and every action takes a reason that goes into the
audit trail.
