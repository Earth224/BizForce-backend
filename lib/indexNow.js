"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   INDEXNOW (LR-4, Nov 25 2026). Free; Bing, Yandex, Seznam, Naver and others
   read it. Google does not, so nothing here is claimed for Google.

   OFF BY DEFAULT. It runs only when ENABLE_INDEXNOW is exactly "true" AND
   INDEXNOW_KEY is a valid key (8 to 128 letters, digits and dashes). Off, queue()
   does nothing and nothing is sent or stored.

   WHAT IS SENT. When an indexable profile, listing or post is created or changes
   (server.js's INDEXNOW_TRIGGERS, after the save has answered), its public address
   is queued. One batched tick, DELAY_MS after the first address queued, sends
   every queued address in one request to api.indexnow.org, with the key and the
   key file's address (keyLocation): bizforceai.net/indexnow-key.txt, which Netlify
   proxies to GET /api/indexnow/key.txt (lib/getFoundRoutes.js). The key file sits
   at the site's root, so every address on the site may be submitted with it.

   AT MOST ONCE PER ADDRESS PER UTC DAY (migration 206b, indexnow_sent). Before a
   batch is sent, the addresses already sent today are dropped, and the rest are
   written as sent today FIRST. A failed write sends nothing; a failed send is not
   retried that day. So no address is ever sent twice in a day, even across a
   restart.

   NEVER BLOCKS A SAVE. queue() returns at once; the tick runs on a timer that does
   not hold the process open; every error is logged and swallowed.
   ══════════════════════════════════════════════════════════════════════════ */

var SITE = "https://bizforceai.net";
var HOST = "bizforceai.net";
var ENDPOINT = "https://api.indexnow.org/indexnow";
var KEY_PATH = "/indexnow-key.txt";
var KEY_RE = /^[A-Za-z0-9-]{8,128}$/;
var DELAY_MS = 60 * 1000;
var BATCH_MAX = 1000;
var TIMEOUT_MS = 10 * 1000;
var URL_RE = /^https:\/\/bizforceai\.net\/[^\s"'<>\\]{1,480}$/;

function keyOf(env) { var k = env && env.INDEXNOW_KEY; return typeof k === "string" && KEY_RE.test(k) ? k : null; }
function enabled(env) { return !!env && env.ENABLE_INDEXNOW === "true" && keyOf(env) !== null; }
function dayOf(ms) { return new Date(ms).toISOString().slice(0, 10); }
function payload(key, urls) { return { host: HOST, key: key, keyLocation: SITE + KEY_PATH, urlList: urls }; }

/* deps: { sb, env, fetch, now() -> ms, setTimeout, clearTimeout, log } */
function createQueue(deps) {
  var pending = new Set(), timer = null, running = null;
  var log = deps.log || function (m) { console.warn("[indexnow] " + m); };
  var later = deps.setTimeout || setTimeout;

  function queue(urls) {
    try {
      if (!enabled(deps.env)) return false;
      var added = 0;
      (Array.isArray(urls) ? urls : [urls]).forEach(function (u) { if (typeof u === "string" && URL_RE.test(u) && pending.size < BATCH_MAX * 5) { pending.add(u); added++; } });
      if (added && !timer) {
        timer = later(function () { timer = null; flush(); }, DELAY_MS);
        if (timer && typeof timer.unref === "function") timer.unref();
      }
      return added > 0;
    } catch (e) { log("queue failed: " + ((e && e.message) || e)); return false; }
  }

  /* One tick: drop what was sent today, mark the rest sent today, then send them in one request. Never throws. */
  async function tick() {
    if (!enabled(deps.env) || !pending.size) { pending.clear(); return { sent: 0 }; }
    var key = keyOf(deps.env), today = dayOf(deps.now ? deps.now() : Date.now());
    var urls = Array.from(pending).slice(0, BATCH_MAX);
    urls.forEach(function (u) { pending.delete(u); });
    var seen = await deps.sb.from("indexnow_sent").select("url, sent_on").in("url", urls);
    if (seen.error) { log("could not read what was sent today; nothing sent: " + (seen.error.message || seen.error)); return { sent: 0 }; }
    var already = new Set((seen.data || []).filter(function (r) { return r.sent_on === today; }).map(function (r) { return r.url; }));
    var fresh = urls.filter(function (u) { return !already.has(u); });
    if (!fresh.length) return { sent: 0 };
    var mark = await deps.sb.from("indexnow_sent").upsert(fresh.map(function (u) { return { url: u, sent_on: today }; }), { onConflict: "url" });
    if (mark.error) { log("could not record the batch; nothing sent: " + (mark.error.message || mark.error)); return { sent: 0 }; }
    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var stop = ctrl ? later(function () { ctrl.abort(); }, TIMEOUT_MS) : null;
    try {
      var r = await deps.fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify(payload(key, fresh)), signal: ctrl ? ctrl.signal : undefined });
      if (!r || !(r.status === 200 || r.status === 202)) log("api.indexnow.org answered " + (r ? r.status : "nothing") + " for " + fresh.length + " address(es); not retried today.");
      return { sent: fresh.length, status: r ? r.status : null };
    } finally { if (stop && deps.clearTimeout) deps.clearTimeout(stop); else if (stop) clearTimeout(stop); }
  }

  function flush() {
    if (running) return running;
    running = tick().catch(function (e) { log("tick failed: " + ((e && e.message) || e)); return { sent: 0 }; })
      .then(function (r) { running = null; if (pending.size && enabled(deps.env) && !timer) { timer = later(function () { timer = null; flush(); }, DELAY_MS); if (timer && timer.unref) timer.unref(); } return r; });
    return running;
  }

  return { queue: queue, flush: flush, pending: function () { return Array.from(pending); }, scheduled: function () { return timer !== null; } };
}

module.exports = { SITE, HOST, ENDPOINT, KEY_PATH, KEY_RE, DELAY_MS, BATCH_MAX, TIMEOUT_MS, keyOf, enabled, dayOf, payload, createQueue };
