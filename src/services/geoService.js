import { config } from "../config.js";

/**
 * IP -> network/location lookup, used only as corroborating evidence.
 *
 * Geo data is never the sole reason for a block: mobile carriers route through distant gateways,
 * VPNs are legitimate, and city-level accuracy is poor. What it is good for is the one signal a
 * user cannot argue with - two sessions on different continents minutes apart.
 */

const cache = new Map();

const cacheTtlMs = () => config.geo.cacheTtlMinutes * 60 * 1000;

const isPrivateIp = (ip) => {
  if (!ip) return true;
  const clean = ip.replace(/^::ffff:/, "");
  if (clean === "127.0.0.1" || clean === "::1" || clean === "localhost") return true;
  if (/^10\./.test(clean)) return true;
  if (/^192\.168\./.test(clean)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(clean)) return true;
  if (/^169\.254\./.test(clean)) return true;
  if (/^f[cd]/i.test(clean)) return true;
  return false;
};

/** Normalise whatever Express hands us (may be a comma-joined XFF chain). */
export const normalizeIp = (value) => {
  if (!value) return null;
  const first = String(value).split(",")[0].trim();
  return first.replace(/^::ffff:/, "") || null;
};

const emptyResult = (ip) => ({
  ip: ip ?? null,
  asn: null,
  isp: null,
  city: null,
  region: null,
  country: null,
  latitude: null,
  longitude: null,
  lookupStatus: "skipped",
});

export const lookupIp = async (rawIp) => {
  const ip = normalizeIp(rawIp);
  if (!ip) return emptyResult(ip);
  if (isPrivateIp(ip)) return { ...emptyResult(ip), lookupStatus: "private" };
  if (!config.geo.enabled) return { ...emptyResult(ip), lookupStatus: "disabled" };

  const cached = cache.get(ip);
  if (cached && Date.now() - cached.at < cacheTtlMs()) return cached.value;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.geo.timeoutMs);

  try {
    const fields = "status,country,regionName,city,lat,lon,isp,as,query";
    const response = await fetch(`${config.geo.endpoint}/${encodeURIComponent(ip)}?fields=${fields}`, {
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Geo lookup HTTP ${response.status}`);
    const data = await response.json();
    if (data.status !== "success") throw new Error(data.message ?? "Geo lookup failed");

    const value = {
      ip,
      asn: data.as ?? null,
      isp: data.isp ?? null,
      city: data.city ?? null,
      region: data.regionName ?? null,
      country: data.country ?? null,
      latitude: typeof data.lat === "number" ? data.lat : null,
      longitude: typeof data.lon === "number" ? data.lon : null,
      lookupStatus: "ok",
    };
    cache.set(ip, { at: Date.now(), value });
    return value;
  } catch (error) {
    // A failed lookup must never fail a login. Evidence simply records that geo was unavailable.
    return { ...emptyResult(ip), lookupStatus: `error: ${error.message}` };
  } finally {
    clearTimeout(timer);
  }
};

const EARTH_RADIUS_KM = 6371;

export const distanceKm = (a, b) => {
  if (
    a?.latitude == null ||
    a?.longitude == null ||
    b?.latitude == null ||
    b?.longitude == null
  ) {
    return null;
  }
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.latitude)) * Math.cos(toRad(b.latitude)) * Math.sin(dLon / 2) ** 2;
  return Number((2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(h))).toFixed(1));
};

/**
 * Implied travel speed between two timestamped locations. Anything above ~900 km/h means the
 * same person could not have been in both places, which is strong evidence of two people.
 */
export const impliedTravel = (from, to, fromAt, toAt) => {
  const km = distanceKm(from, to);
  if (km === null) return null;
  const hours = Math.abs(new Date(toAt).getTime() - new Date(fromAt).getTime()) / 3_600_000;
  if (hours <= 0) {
    return { distanceKm: km, hours: 0, speedKmh: km > 0 ? Infinity : 0, impossible: km > 50 };
  }
  const speedKmh = Number((km / hours).toFixed(1));
  return {
    distanceKm: km,
    hours: Number(hours.toFixed(3)),
    speedKmh,
    impossible: speedKmh > config.device.maxTravelKmh && km > 100,
  };
};
