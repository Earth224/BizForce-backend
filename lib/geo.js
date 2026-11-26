"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   CITY-LEVEL PLACES AND DISTANCE (H1, Nov 25 2026; migration 207).

   A member's place stays what they typed: a city (or "Neighbourhood, City"),
   a region and a country. Never a street address, never the device's
   location. For Local and the distances on Home, the typed place is turned
   into the centre point of that city by the free OpenStreetMap Nominatim
   service, and only that point is kept, rounded to 2 decimals (about 1 km):
     bf_profiles.place_lat / place_lng   the profile place (Settings, Local)
     posts.need_lat / need_lng           a Need's own place
     home_prefs.local_lat / local_lng    "Use a different city" on Local

   NOMINATIM'S RULES (operations.osmfoundation.org/policies/nominatim):
     at most 1 request a second ACROSS THE WHOLE SERVER (one slot queue here,
       shared by every caller in the process; a caller that would wait more
       than QUEUE_MAX_MS is told "busy" and nothing is looked up);
     a real User-Agent naming BizForce and its support address (USER_AGENT);
     every answer cached (geo_cache, keyed by the normalized place text), so a
       place is looked up once: a found point, and "not found" too. A failed
       request (no answer: network, timeout, an HTTP error) is not an answer
       and is not cached; the member's place still saves and Local falls back
       to matching the city's name as text.
   Where a member picks their place, the page shows ATTRIBUTION.

   DISTANCE is the great-circle distance between two city centres, shown
   rounded: under 1 mile with one decimal ("0.8 mi"), whole miles above
   ("12 mi"). City-level only: it is the distance between two cities' centres,
   never between two people.
   ══════════════════════════════════════════════════════════════════════════ */

const NOMINATIM_URL = "https://nominatim.openstreetmap.org/search";
// the support address from lib/legal.js, the one place that holds it (checkLegalPages C1)
const USER_AGENT = "BizForce/1.0 (https://bizforceai.net; " + require("./legal").CONTACT_EMAIL + ")";
const ATTRIBUTION = "Data from OpenStreetMap contributors";
const SLOT_MS = 1000;            // one request a second, server-wide
const QUEUE_MAX_MS = 8000;       // a caller never waits longer than this for a slot
const TIMEOUT_MS = 8000;
const KEY_MAX = 300;
const EARTH_MILES = 3958.8;
const REACHES = ["city", "25", "anywhere"];
const REACH_MILES = 25;
const DEFAULT_REACH = "25";

/* ── text ── */
function clean(v) { return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim() : ""; }
/* The cache key: the place's parts, lower case, single-spaced, joined by ", ". */
function placeKey(parts) {
  var list = (Array.isArray(parts) ? parts : [parts]).map(clean).filter(Boolean).map(function (s) { return s.toLowerCase(); });
  var key = list.join(", ");
  return key && key.length < KEY_MAX + 1 ? key : null;
}
/* "North Park, San Diego" -> area "North Park", city "San Diego"; "San Diego" -> area null, city "San Diego". A neighbourhood
   shows only when the member typed one (a comma in what they typed). */
function splitPlace(text) {
  var t = clean(text);
  if (!t) return { area: null, city: null };
  var parts = t.split(",").map(clean).filter(Boolean);
  if (parts.length < 2) return { area: null, city: parts[0] || null };
  return { area: parts[0], city: parts[1] };
}
/* What a line shows for a place: the neighbourhood if one was typed, else the city. */
function placeLabel(text) { var s = splitPlace(text); return s.area || s.city || null; }
/* The city-name text match (the fallback when a point is missing, and "My city"): a and b are what was typed for a city
   (a profile's place_city, a Need's place, a chosen city), never with the region added. They match when any comma part of
   one (longer than 2 letters, so a state code alone never matches) equals a part of the other, ignoring case:
   "North Park, San Diego" matches "San Diego"; "San Diego, CA" matches "San Diego"; "Austin, TX" never matches "Dallas, TX". */
function cityParts(t) {
  return clean(t).split(",").map(function (s) { return clean(s).toLowerCase(); }).filter(function (s) { return s.length > 2; });
}
function sameCity(a, b) {
  var x = cityParts(a), y = cityParts(b);
  return x.some(function (s) { return y.indexOf(s) !== -1; });
}

/* ── numbers ── */
function round2(v) { var n = Number(v); return isFinite(n) ? Math.round(n * 100) / 100 : null; }
function point(lat, lng) {
  var a = round2(lat), b = round2(lng);
  if (a === null || b === null || lat === null || lng === null || lat === undefined || lng === undefined) return null;
  if (Math.abs(a) > 90 || Math.abs(b) > 180) return null;
  return { lat: a, lng: b };
}
function rad(d) { return d * Math.PI / 180; }
function milesBetween(a, b) {
  if (!a || !b) return null;
  var dLat = rad(b.lat - a.lat), dLng = rad(b.lng - a.lng);
  var h = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return 2 * EARTH_MILES * Math.asin(Math.min(1, Math.sqrt(h)));
}
/* "0.8 mi" under 1 mile (never "0.0": 0.1 at least), whole miles from 1 up. */
function distanceLabel(miles) {
  if (miles === null || miles === undefined || !isFinite(miles) || miles < 0) return null;
  if (miles < 0.95) return Math.max(0.1, Math.round(miles * 10) / 10).toFixed(1) + " mi";
  return Math.round(miles) + " mi";
}
/* The box around a point that holds every point within `miles` (a cheap first filter; milesBetween decides). */
function boxAround(p, miles) {
  var dLat = miles / 69.0;
  var dLng = miles / (69.0 * Math.max(0.01, Math.cos(rad(p.lat))));
  return { minLat: p.lat - dLat, maxLat: p.lat + dLat, minLng: p.lng - dLng, maxLng: p.lng + dLng };
}
function normalReach(v) { return REACHES.indexOf(v) !== -1 ? v : DEFAULT_REACH; }
/* Is `there` within `reach` of `here`? city: the same city by name; 25: within 25 miles by the two points, or (when either
   point is missing) the same city by name; anywhere: always. */
function withinReach(reach, here, there) {
  if (reach === "anywhere") return true;
  if (reach === "25" && here.point && there.point) return milesBetween(here.point, there.point) < REACH_MILES + 0.0001;
  return sameCity(here.text, there.text);
}

/* ── the one slot queue: 1 request a second across the server ── */
var nextSlotAt = 0;
function clockOf(deps) { return deps && deps.clock ? deps.clock() : Date.now(); }
function sleepOf(deps) { return deps && deps.sleep ? deps.sleep : function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); }; }
/* Take the next free slot. Returns the wait in ms, or -1 when the queue is longer than QUEUE_MAX_MS (busy: do not look up). */
function takeSlot(deps) {
  var t = clockOf(deps);
  var at = Math.max(t, nextSlotAt);
  if (at - t > QUEUE_MAX_MS) return -1;
  nextSlotAt = at + SLOT_MS;
  return at - t;
}
function resetQueue() { nextSlotAt = 0; }

/* ── the cache ── */
async function cached(sb, key) {
  var r = await sb.from("geo_cache").select("place_key, lat, lng, found").eq("place_key", key).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}
async function remember(sb, key, p, nowIso) {
  var row = { place_key: key, lat: p ? p.lat : null, lng: p ? p.lng : null, found: !!p, looked_up_at: nowIso };
  var w = await sb.from("geo_cache").upsert(row, { onConflict: "place_key" });
  if (w.error) throw w.error;
}

/* The request Nominatim gets: the typed place as one free-text query, limited to the member's country when they chose one. */
function lookupUrl(key, country) {
  var q = "?format=jsonv2&limit=1&addressdetails=0&q=" + encodeURIComponent(key);
  if (typeof country === "string" && /^[A-Za-z]{2}$/.test(country)) q += "&countrycodes=" + country.toLowerCase();
  return NOMINATIM_URL + q;
}

/* geocode(deps, { text, region, country }) -> { point, source } where source is "cache", "lookup", "not_found", "busy",
   "failed", "empty" or "off" (no deps.request: nothing is looked up or read). point is null unless found.
   deps: { sb, now() (ISO), request(url, opts) -> { status, json } (guardedJsonRequest), clock(), sleep(ms) }. A read or
   write error on the cache throws. */
async function geocode(deps, place) {
  place = place || {};
  var key = placeKey([place.text, place.region, place.country]);
  if (!key) return { point: null, source: "empty" };
  // no request function given: no lookup at all (a check's own deps never reach the real service); server.js gives
  // guardedJsonRequest in postDeps()
  if (typeof deps.request !== "function") return { point: null, source: "off" };
  var hit = await cached(deps.sb, key);
  if (hit) return { point: hit.found ? point(hit.lat, hit.lng) : null, source: "cache" };
  var wait = takeSlot(deps);
  if (wait < 0) return { point: null, source: "busy" };
  if (wait > 0) await sleepOf(deps)(wait);
  var request = deps.request;
  var r;
  try {
    r = await request(lookupUrl(key, place.country), { method: "GET", headers: { "User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Language": "en" }, timeoutMs: TIMEOUT_MS });
  } catch (e) {
    return { point: null, source: "failed" };
  }
  if (!r || r.status !== 200 || !Array.isArray(r.json)) return { point: null, source: "failed" };
  var first = r.json[0];
  var p = first ? point(parseFloat(first.lat), parseFloat(first.lon)) : null;
  await remember(deps.sb, key, p, deps.now ? deps.now() : new Date().toISOString());
  return { point: p, source: p ? "lookup" : "not_found" };
}

/* The profile place as one text: "City, Region" (the country goes in separately). */
function profileText(row) {
  if (!row || !clean(row.place_city)) return null;
  return [clean(row.place_city), clean(row.place_region)].filter(Boolean).join(", ");
}

module.exports = {
  NOMINATIM_URL, USER_AGENT, ATTRIBUTION, SLOT_MS, QUEUE_MAX_MS, TIMEOUT_MS, EARTH_MILES, REACHES, REACH_MILES, DEFAULT_REACH,
  clean, placeKey, splitPlace, placeLabel, sameCity, round2, point, milesBetween, distanceLabel, boxAround, normalReach, withinReach,
  takeSlot, resetQueue, lookupUrl, geocode, profileText
};
