"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   THREADS ROUTES (LR-2). NAMED (Nov 23 2026, LR-2). mountThreadsRoutes(app,
   deps) registers the seven routes below (four until LR-2B); server.js calls it once.

     GET  /api/social/threads/connect     M  { url } (Threads' sign-in page), or 503
                                             { error: "Threads is not set up yet",
                                             code: "threads_not_set_up" } while
                                             THREADS_APP_ID or THREADS_APP_SECRET is missing
     GET  /api/social/threads/callback    P  Meta's redirect: the signed state is
                                             checked and spent once, the code exchanged,
                                             the short token swapped at once for the
                                             long-lived one, SEALED, and only then /me
                                             read; redirects to FRONTEND
                                             /integrations.html?threads=connected|error
     GET  /api/social/threads/status      F  { state, username, keyword_search }
     POST /api/social/threads/disconnect  F  { disconnected: true }: the row deleted
     NAMED (Nov 24 2026, LR-2B): Meta's two required callbacks and the deletion page's lookup.
     POST /api/social/threads/deauthorize   P  Meta's "Uninstall Callback URL". Body signed_request
                                             (form field, Meta's format). The member's threads_connections
                                             row is deleted. 200 { ok: true }.
     POST /api/social/threads/data-deletion P  Meta's "Delete Callback URL". signed_request as above. The
                                             member's Threads leads (member_leads source threads), Threads
                                             replies (member_lead_replies platform threads) and the
                                             connection are deleted, then 200 { url, confirmation_code }:
                                             url is FRONTEND /threads-deletion.html?code=<code>.
     GET  /api/social/threads/deletion-status?code=  P  { found: true, done: true, at } or 404
                                             { found: false }: what threads-deletion.html shows.
     A signed_request is "<signature>.<payload>", both base64url; the signature is HMAC-SHA256 of the
     payload part under THREADS_APP_SECRET, compared in constant time. Refused (400, nothing deleted):
     no signed_request, a bad or missing signature, an algorithm other than HMAC-SHA256, a user_id that
     is not digits, or an issued_at more than SIGNED_MAX_AGE_S old (or more than 5 minutes ahead). A
     signed request issued BEFORE the member's current connection was made deletes nothing (a replay
     cannot remove a newer connection). 503 while Threads is not set up.
     The confirmation code keeps no personal data and nothing is stored for it: it is the time of the
     deletion and "done", signed (HMAC under a key derived from THREADS_APP_SECRET). A code is issued
     only after every delete succeeded; a failed delete answers 500 and Meta asks again.

   M = members (requireAuth + requireActiveSubscription), F = any signed-in
   account (requireAuth), P = public (the state is the only key). Status and
   disconnect stay open to a free account, as every connection's do: a member
   can always see and take back their account's access.

   deps (every key read once, at mount):
     requireAuth               the session middleware (sets req.user)
     requireActiveSubscription the members-only middleware (402 for a free account)
     supabase                  the service-role client (threads_connections, migration 204e)
     crypt                     { encrypt, decrypt }: lib/apiKeyCrypto.js
     frontendUrl               FRONTEND_URL: where the callback sends the browser back
     apiBase                   the backend's public origin (server.js STORE_API_BASE): the
                               redirect URI is apiBase + "/api/social/threads/callback"
     env                       optional, default process.env (THREADS_APP_ID, THREADS_APP_SECRET)
     connectLimiter            optional middleware on connect only, e.g. a rateLimit keyed by
                               req.user.id (the callback carries no user, so it is never limited
                               by it: the signed single-use state is its guard)
     logger                    optional, default console: only short codes are ever logged
     now                       optional, default Date.now
     OWNER_ACCOUNT_ID          optional, accepted and unused: Threads has no owner
                               fallback (every reply goes from the member's own account)
   Nothing here logs or answers a token, a code or a state.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");
const TA = require("./threadsAuth");
const TAPI = require("./threadsApi");

/* ── Meta's signed_request and the deletion code (NAMED Nov 24 2026, LR-2B) ── */
const SIGNED_MAX_AGE_S = 24 * 60 * 60;
const SIGNED_FUTURE_S = 5 * 60;
const SIGNED_MAX_LEN = 4096;
const B64URL = /^[A-Za-z0-9_-]+$/;

function fromB64url(part) {
  return Buffer.from(String(part).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/* { ok: true, threadsUserId, issuedAt } or { ok: false, reason }. */
function readSignedRequest(config, raw, nowMs) {
  if (!config) return { ok: false, reason: "not_set_up" };
  if (typeof raw !== "string" || !raw || raw.length > SIGNED_MAX_LEN) return { ok: false, reason: "missing" };
  var parts = raw.split(".");
  if (parts.length !== 2 || !B64URL.test(parts[0]) || !B64URL.test(parts[1])) return { ok: false, reason: "malformed" };
  var got = fromB64url(parts[0]);
  var want = crypto.createHmac("sha256", String(config.appSecret)).update(parts[1], "utf8").digest();
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return { ok: false, reason: "bad_signature" };
  var payload;
  try { payload = JSON.parse(fromB64url(parts[1]).toString("utf8")); } catch (e) { return { ok: false, reason: "malformed" }; }
  if (!payload || typeof payload !== "object") return { ok: false, reason: "malformed" };
  if (String(payload.algorithm || "").toUpperCase() !== "HMAC-SHA256") return { ok: false, reason: "algorithm" };
  var uid = payload.user_id;
  if ((typeof uid !== "string" && typeof uid !== "number") || !/^[0-9]{1,30}$/.test(String(uid))) return { ok: false, reason: "user_id" };
  var issuedAt = null;
  if (payload.issued_at !== undefined) {
    issuedAt = Number(payload.issued_at);
    if (!Number.isInteger(issuedAt)) return { ok: false, reason: "issued_at" };
    var nowS = Math.floor(nowMs / 1000);
    if (issuedAt < nowS - SIGNED_MAX_AGE_S || issuedAt > nowS + SIGNED_FUTURE_S) return { ok: false, reason: "stale" };
  }
  return { ok: true, threadsUserId: String(uid), issuedAt: issuedAt };
}

function codeKey(config) {
  return crypto.createHmac("sha256", String(config.appSecret)).update("bizforce threads deletion code v1", "utf8").digest();
}
function codeMac(config, body) {
  return crypto.createHmac("sha256", codeKey(config)).update(body, "utf8").digest("hex").slice(0, 20);
}
/* "td-<seconds base36>-<mac>": the time and "done", signed. Nothing else, nothing stored. */
function deletionCode(config, nowMs) {
  var body = "td-" + Math.floor(nowMs / 1000).toString(36);
  return body + "-" + codeMac(config, body + "|done");
}
function readDeletionCode(config, code) {
  var m = /^(td-([0-9a-z]{1,10}))-([0-9a-f]{20})$/.exec(String(code || ""));
  if (!config || !m) return null;
  var want = codeMac(config, m[1] + "|done");
  if (!crypto.timingSafeEqual(Buffer.from(m[3]), Buffer.from(want))) return null;
  return { done: true, at: new Date(parseInt(m[2], 36) * 1000).toISOString() };
}

/* The connection Meta named, unless it was made after the signed request was issued. */
async function connectionFor(supabase, signed) {
  var read = await supabase.from("threads_connections").select("id, user_id, created_at").eq("threads_user_id", signed.threadsUserId);
  if (read.error) throw read.error;
  return (read.data || []).filter(function (row) {
    return signed.issuedAt === null || !row.created_at || Date.parse(row.created_at) <= (signed.issuedAt + SIGNED_FUTURE_S) * 1000;
  });
}

function mountThreadsRoutes(app, deps) {
  if (!app || !deps || typeof deps.requireAuth !== "function" || typeof deps.requireActiveSubscription !== "function" ||
      !deps.supabase || !deps.crypt || typeof deps.frontendUrl !== "string" || typeof deps.apiBase !== "string") {
    throw new TypeError("mountThreadsRoutes: app, requireAuth, requireActiveSubscription, supabase, crypt, frontendUrl and apiBase are required");
  }
  var supabase = deps.supabase;
  var crypt = deps.crypt;
  var env = deps.env || process.env;
  var logger = deps.logger || console;
  var now = typeof deps.now === "function" ? deps.now : function () { return Date.now(); };
  var limiter = typeof deps.connectLimiter === "function" ? deps.connectLimiter : function (req, res, next) { next(); };
  var ctx = { supabase: supabase, crypt: crypt, now: now };
  // NAMED (Nov 24 2026, LR-2B): the public Meta callbacks and the deletion lookup, limited per address.
  var metaLimiter = typeof deps.metaLimiter === "function" ? deps.metaLimiter
    : require("express-rate-limit")({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

  function backTo(res, outcome) {
    res.set("Cache-Control", "no-store");
    return res.redirect(302, String(deps.frontendUrl).replace(/\/+$/, "") + "/integrations.html?threads=" + outcome);
  }
  function logCode(where, err) {
    try { logger.error("[threads/" + where + "] " + ((err && (err.code || err.kind)) || "error")); } catch (e) { /* never throws */ }
  }

  app.get("/api/social/threads/connect", deps.requireAuth, deps.requireActiveSubscription, limiter, function (req, res, next) {
    try {
      res.set("Cache-Control", "no-store");
      var config = TA.configured(env);
      if (!config) return res.status(503).json({ error: TA.MESSAGES.notSetUp, code: "threads_not_set_up" });
      var state = TA.signState(config, req.user.id, now());
      return res.json({ url: TA.authorizeUrl(config.appId, TA.redirectUri(deps.apiBase), state) });
    } catch (error) {
      logCode("connect", error);
      next(error);
    }
  });

  app.get("/api/social/threads/callback", async function (req, res) {
    var shape = TA.callbackShape(req.query);
    try {
      var config = TA.configured(env);
      if (!config || !shape.ok) return backTo(res, "error");
      var nowMs = now();
      var st = TA.readState(config, shape.state, nowMs);
      if (!st.ok || !TA.useNonce(st.nonce, st.expiresMs, nowMs)) return backTo(res, "error");
      var redirect = TA.redirectUri(deps.apiBase);
      var short, grant;
      try {
        short = await TA.exchangeCode(config, shape.code, redirect);
        // The short-lived token is never stored: it is swapped at once for the long-lived one.
        grant = await TA.longLived(config, short.shortToken);
      } finally {
        shape.code = null;
        if (short) short.shortToken = null;
      }
      // Sealed first: the long-lived token is encrypted before Threads is asked anything.
      var sealed = crypt.encrypt(grant.accessToken);
      var tokenExpiry = TA.expiresAt(now(), grant.expiresIn);
      var me;
      try {
        me = await TAPI.readMe(grant.accessToken);
      } finally {
        grant = null;
      }
      if (!me) return backTo(res, "error");
      // The account Threads named at the exchange is the one /me reads.
      if (short.threadsUserId && short.threadsUserId !== me.threads_user_id) return backTo(res, "error");
      var stamp = new Date(now()).toISOString();
      // keyword_search_state is not written: a new row takes 'unknown', a reconnect keeps what was learned.
      var saved = await supabase.from("threads_connections").upsert({
        user_id:           st.userId,
        threads_user_id:   me.threads_user_id,
        username:          me.username,
        access_ciphertext: sealed.ciphertext,
        access_iv:         sealed.iv,
        access_auth_tag:   sealed.authTag,
        access_expires_at: tokenExpiry,
        granted_scopes:    short.scopes || null,
        status:            "connected",
        last_ok_at:        stamp,
        last_error_at:     null,
        last_error_code:   null,
        updated_at:        stamp
      }, { onConflict: "user_id" }).select("id").single();
      if (saved.error) throw saved.error;
      return backTo(res, "connected");
    } catch (error) {
      logCode("callback", error);
      return backTo(res, "error");
    }
  });

  app.get("/api/social/threads/status", deps.requireAuth, async function (req, res, next) {
    try {
      res.set("Cache-Control", "no-store");
      var row = await TAPI.readConnection(supabase, req.user.id);
      return res.json(TAPI.statusView(row, TA.configured(env) !== null, now()));
    } catch (error) {
      logCode("status", error);
      next(error);
    }
  });

  // Always open, member or not, set up or not: a member can always take their account's access back.
  app.post("/api/social/threads/disconnect", deps.requireAuth, async function (req, res, next) {
    try {
      res.set("Cache-Control", "no-store");
      var dropped = await supabase.from("threads_connections").delete().eq("user_id", req.user.id).select("id");
      if (dropped.error) throw dropped.error;
      return res.json({ disconnected: true });
    } catch (error) {
      logCode("disconnect", error);
      next(error);
    }
  });

  /* NAMED (Nov 24 2026, LR-2B): Meta's Uninstall Callback. */
  app.post("/api/social/threads/deauthorize", metaLimiter, async function (req, res) {
    res.set("Cache-Control", "no-store");
    try {
      var config = TA.configured(env);
      if (!config) return res.status(503).json({ error: TA.MESSAGES.notSetUp, code: "threads_not_set_up" });
      var signed = readSignedRequest(config, req.body && req.body.signed_request, now());
      if (!signed.ok) return res.status(400).json({ error: "The signed request was refused.", code: signed.reason });
      var rows = await connectionFor(supabase, signed);
      for (var i = 0; i < rows.length; i++) {
        var gone = await supabase.from("threads_connections").delete().eq("id", rows[i].id).eq("user_id", rows[i].user_id);
        if (gone.error) throw gone.error;
      }
      return res.json({ ok: true });
    } catch (error) {
      logCode("deauthorize", error);
      return res.status(500).json({ error: "Not done. Try again." });
    }
  });

  /* NAMED (Nov 24 2026, LR-2B): Meta's Delete Callback. Leads and replies first, the connection (the only link from
     Meta's user id to the member) last, so a failure part-way is finished by Meta's next try. */
  app.post("/api/social/threads/data-deletion", metaLimiter, async function (req, res) {
    res.set("Cache-Control", "no-store");
    try {
      var config = TA.configured(env);
      if (!config) return res.status(503).json({ error: TA.MESSAGES.notSetUp, code: "threads_not_set_up" });
      var nowMs = now();
      var signed = readSignedRequest(config, req.body && req.body.signed_request, nowMs);
      if (!signed.ok) return res.status(400).json({ error: "The signed request was refused.", code: signed.reason });
      var rows = await connectionFor(supabase, signed);
      for (var i = 0; i < rows.length; i++) {
        var uid = rows[i].user_id;
        var replies = await supabase.from("member_lead_replies").delete().eq("user_id", uid).eq("platform", "threads");
        if (replies.error) throw replies.error;
        var leads = await supabase.from("member_leads").delete().eq("user_id", uid).eq("source", "threads");
        if (leads.error) throw leads.error;
        var conn = await supabase.from("threads_connections").delete().eq("id", rows[i].id).eq("user_id", uid);
        if (conn.error) throw conn.error;
      }
      var code = deletionCode(config, nowMs);
      return res.json({ url: String(deps.frontendUrl).replace(/\/+$/, "") + "/threads-deletion.html?code=" + code, confirmation_code: code });
    } catch (error) {
      logCode("data-deletion", error);
      return res.status(500).json({ error: "Not done. Try again." });
    }
  });

  /* NAMED (Nov 24 2026, LR-2B): what threads-deletion.html shows for a code. */
  app.get("/api/social/threads/deletion-status", metaLimiter, function (req, res) {
    res.set("Cache-Control", "no-store");
    var config = TA.configured(env);
    if (!config) return res.status(503).json({ error: TA.MESSAGES.notSetUp, code: "threads_not_set_up" });
    var seen = readDeletionCode(config, req.query && req.query.code);
    if (!seen) return res.status(404).json({ found: false });
    return res.json({ found: true, done: seen.done, at: seen.at });
  });

  return ctx;
}

module.exports = {
  mountThreadsRoutes: mountThreadsRoutes,
  SIGNED_MAX_AGE_S: SIGNED_MAX_AGE_S,
  readSignedRequest: readSignedRequest,
  deletionCode: deletionCode,
  readDeletionCode: readDeletionCode
};
