"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkOpsAlerts.js — failures reach the owner (launch audit #6).

   WHAT THIS PROVES, on the real lib/opsAlert.js and the real /health and
   Stripe webhook routes lifted from server.js:
     H. /health answers 200 { ok, status, db "ok", commit, icu } when the
        database answers, and 503 with db "down" when the read errors or does
        not answer within the timeout. No error text and no secret in the
        body. Concurrent calls share one read, and a result is reused for 10 s.
        Three failed probes in a row send one alert; the next good probe sends
        one "resolved".
     W. a webhook event the handler fails on alerts once; a signature failure
        does not alert and is counted; a send that throws never reaches the
        webhook (no rejection, the 500 still goes out).
     J. job_runs: a new last_error sends exactly one email; the same error
        within 6 hours sends none; a changed error sends again; the same error
        after 6 hours sends a reminder; clearing sends one "resolved"; a run
        still in progress is not "resolved".
     B. a failed backup alerts and is recorded with no finished_at; a
        successful one resolves and records finished_at; no success in 30 hours
        alerts while ENABLE_NIGHTLY_BACKUP is "true", and not when it is off.
     R. OPS_ALERT_EMAIL, else BACKUP_EMAIL_TO; with neither, nothing is sent
        and one line is logged however many alerts there are.
     S. a send that throws or is rejected resolves { sent: false }, never
        rejects, and the next alert tries again.
     G. only the exact "false" disables alerts.
     E. the email: what broke, UTC and Pacific time, the error cut to 500
        characters, Railway logs and Supabase.
     C. the scan: every 30 minutes UTC, gated, no boot-time run, claimed
        through job_runs (a held slot does not scan); a failing scan alerts.
     T. Termaximus: "Ops: N open alerts" with key and since, owner only, and
        an unreadable ops_alerts throws (fail-loud) instead of saying 0.

   NO NETWORK. NO DATABASE. Supabase and Resend are in-memory stubs.

   /health PINS (named, BEFORE → AFTER). No check pinned /health's body
   before this one; checkCollaborationsRemoved and checkDormantRoutesDeleted
   only poll it for "the server is listening", which any status satisfies.
     health-body   BEFORE always 200 { ok: true, status: "healthy", commit, icu }.
                   AFTER  200 { ok: true, status: "healthy", db: "ok", commit,
                          icu } when the database answers; 503 { ok: false,
                          status: "unhealthy", db: "down", commit, icu } when not.

   MUTATE=<name> edits lib/opsAlert.js or server.js IN MEMORY. MUTATE=all runs
   each in its own process (scripts/_shared.js): a search text that does not
   match exactly once is an ERROR, never a catch.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const LIB_PATH = path.join(REPO, "lib", "opsAlert.js");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the same alert is emailed again and again
  "dedupe-removed": [["lib", "      if (prev && prev.fingerprint === fingerprint && prev.last_sent_at && nowMs - Date.parse(prev.last_sent_at) < DEDUPE_MS) {\n",
    "      if (false) {\n"]],
  // a forged signature emails the owner
  "signature-alerts": [["server", "      opsAlerts.noteSignatureFailure();\n      return res.status(400)",
    "      opsAlerts.stripeWebhookFailed(event, error);\n      return res.status(400)"]],
  // /health says healthy whatever the database does
  "health-always-200": [["server", "  res.status(probe.ok ? 200 : 503).json({\n", "  res.status(200).json({\n"]],
  // the never-throw guard is gone: a failed send rejects into the webhook
  "alert-throws-into-webhook": [
    ["lib", "      log.error(TAG + \" \" + kind + \" email for \" + alert.key + \" was NOT sent: the send threw — \" + errorText(err));\n      return false;\n",
      "      throw err;\n"],
    ["lib", "      log.error(TAG + \" raising \" + key + \" failed: \" + errorText(err));\n      return { sent: false, reason: \"error\" };\n",
      "      throw err;\n"]],
  // an unset ENABLE_OPS_ALERTS turns alerts off
  "gate-unset-off": [["lib", "  return (env || {}).ENABLE_OPS_ALERTS !== \"false\";\n", "  return (env || {}).ENABLE_OPS_ALERTS === \"true\";\n"]],
  // the probe waits for the database forever
  "probe-no-timeout": [["lib", "      var result = await Promise.race([read, timeout]);\n", "      var result = await read;\n"]],
  // a stale backup is never reported
  "backup-stale-ignored": [["lib", "      if (now() - since > BACKUP_STALE_MS) {\n", "      if (false) {\n"]],
  // clearing is silent
  "resolve-silent": [["lib", "      var sent = prev.last_sent_at ? await deliver(\"resolved\", prev) : false;\n", "      var sent = false;\n"]],
  // a run still in progress is reported fixed
  "resolve-in-progress": [["lib", "      var clear = !row || (!(row.last_error && String(row.last_error).trim()) && !!row.finished_at);\n",
    "      var clear = !row || !(row.last_error && String(row.last_error).trim());\n"]],
  // the scan runs at every boot
  "boot-time-run": [["server", "    console.log(\"[startup] ops alert scan scheduled — every 30 minutes UTC, claimed through job_runs.\" +\n",
    "    opsAlerts.scanTick();\n    console.log(\"[startup] ops alert scan scheduled — every 30 minutes UTC, claimed through job_runs.\" +\n"]],
  // the scan ignores its claim
  "scan-ignores-claim": [["lib", "      if (!claimed) return { claimed: false, reason: \"held\" };\n", ""]],
  // no recipient logs on every alert
  "no-recipient-every-time": [["lib", "    if (loggedOnce.has(key)) return;\n", ""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const SRC = {
  lib: fs.readFileSync(LIB_PATH, "utf8").replace(/\r\n/g, "\n"),
  server: s.after
};
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) SRC[file] = s.replaceOnce(SRC[file], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

/* The library, compiled from the (possibly mutated) text at its own path. */
const mod = new Module(LIB_PATH, null);
mod.filename = LIB_PATH;
mod.paths = Module._nodeModulePaths(path.dirname(LIB_PATH));
mod._compile(SRC.lib, LIB_PATH);
const ops = mod.exports;

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const rejections = [];
process.on("unhandledRejection", function (reason) { rejections.push(String((reason && reason.message) || reason)); });
const flush = async () => { for (let i = 0; i < 40; i++) await new Promise(r => setImmediate(r)); };

const HOUR = 3600000;
const T0 = Date.parse("2026-10-20T18:51:02.000Z");

/* ── stubs ───────────────────────────────────────────────────────────────── */
/* A Supabase stub: job_runs and ops_alerts in memory, every call recorded.
   opts.jobRows: the job_runs rows a select returns. opts.probe: "ok", "error"
   or "hang" for the /health read. opts.opsUnreadable: ops_alerts errors. */
function fakeDb(opts) {
  opts = opts || {};
  const calls = [];
  const opsRows = new Map();
  const db = {
    calls, opsRows, jobRows: opts.jobRows || [],
    probe: opts.probe || "ok", probeReads: 0, claimHeld: !!opts.claimHeld, claimExists: !!opts.claimExists,
    from(table) {
      const q = { table, op: "select", filters: [], payload: null, head: null };
      const done = () => {
        calls.push({ table, op: q.op, payload: q.payload, filters: q.filters.slice() });
        if (table === "ops_alerts") {
          if (opts.opsUnreadable) return Promise.resolve({ data: null, error: { message: "relation \"public.ops_alerts\" does not exist" } });
          if (q.op === "select") return Promise.resolve({ data: Array.from(opsRows.values()), error: null });
          if (q.op === "upsert") { opsRows.set(q.payload.alert_key, Object.assign({}, q.payload)); return Promise.resolve({ data: null, error: null }); }
          if (q.op === "delete") { opsRows.delete(q.filters.find(f => f[0] === "alert_key")[1]); return Promise.resolve({ data: null, error: null }); }
        }
        if (table === "job_runs") {
          if (q.op === "select" && q.limit === 1) {
            db.probeReads++;
            if (db.probe === "hang") return new Promise(() => {});
            if (db.probe === "error") return Promise.resolve({ data: null, error: { message: "connect ECONNREFUSED 10.0.0.1:5432 key=sb_secret_123" } });
            return Promise.resolve({ data: [{ job_name: "x" }], error: null });
          }
          if (q.op === "select") return opts.jobRunsUnreadable ? Promise.resolve({ data: null, error: { message: "job_runs timeout" } })
            : Promise.resolve({ data: db.jobRows, error: null });
          if (q.op === "insert") {
            if (db.claimExists) return Promise.resolve({ data: null, error: { code: "23505", message: "duplicate" } });
            db.claimExists = true;
            return Promise.resolve({ data: [{ job_name: q.payload.job_name }], error: null });
          }
          if (q.op === "update" && q.or) return Promise.resolve({ data: db.claimHeld ? [] : [{ job_name: "ops_alert_scan" }], error: null });
          return Promise.resolve({ data: null, error: null });
        }
        return Promise.resolve({ data: null, error: null });
      };
      const chain = {
        select(cols) { if (q.op === "select") q.cols = cols; return chain; },
        insert(p) { q.op = "insert"; q.payload = p; return chain; },
        update(p) { q.op = "update"; q.payload = p; return chain; },
        upsert(p) { q.op = "upsert"; q.payload = p; return chain; },
        delete() { q.op = "delete"; return chain; },
        eq(k, v) { q.filters.push([k, v]); return chain; },
        or(expr) { q.or = expr; q.filters.push(["or", expr]); return chain; },
        limit(n) { q.limit = n; return chain; },
        then(res, rej) { return done().then(res, rej); }
      };
      return chain;
    }
  };
  return db;
}

function harness(opts) {
  opts = opts || {};
  const db = opts.db || fakeDb(opts);
  const sent = [];
  const logs = [];
  const clock = { t: opts.t0 || T0 };
  const env = Object.assign({ OPS_ALERT_EMAIL: "owner@example.test", RESEND_API_KEY: "re_test" }, opts.env || {});
  // Drops the default OPS_ALERT_EMAIL; a BACKUP_EMAIL_TO passed in opts.env stays.
  if (opts.noRecipient) delete env.OPS_ALERT_EMAIL;
  const send = opts.send || (async function (message) { sent.push(message); return { ok: true, id: "msg_" + sent.length }; });
  const alerts = ops.createOpsAlerts({
    supabase: db, env, now: () => clock.t, send,
    log: { log: m => logs.push(["log", String(m)]), error: m => logs.push(["error", String(m)]), warn: m => logs.push(["warn", String(m)]) }
  });
  return { alerts, db, sent, logs, clock, env };
}

/* /health and the Stripe webhook, lifted from (possibly mutated) server.js. */
/* From the route's signature to the ";" after its handler's closing brace.
   `body` marks where the handler's own "{" is, past any option literal. */
function lift(signature, body) {
  const src = SRC.server;
  const start = src.indexOf(signature);
  if (start < 0) throw new Error("not found in server.js: " + signature);
  const at = src.indexOf(body, start);
  if (at < 0) throw new Error("handler body not found after " + signature);
  const end = s.braceMatch(src, at + body.length - 1);
  return src.slice(start, src.indexOf(";", end) + 1);
}
const HEALTH_SIG = 'app.get("/health", async (req, res) => {';
const WEBHOOK_SIG = 'app.post(\n  "/api/webhook",';
function mountRoutes(h, stubs) {
  const routes = {};
  const ctx = {
    app: { get(p, fn) { routes["GET " + p] = fn; }, post(p, a, fn) { routes["POST " + p] = fn; } },
    express: { raw: () => function raw() {} },
    opsAlerts: h.alerts,
    process: { env: { RAILWAY_GIT_COMMIT_SHA: "abc1234", SUPABASE_SERVICE_KEY: "sb_secret_123", STRIPE_WEBHOOK_SECRET: "whsec_x" } },
    icuHealth: () => ({ timezone_applied: true, graphemes_counted: true }),
    constructStripeEventFromSecrets: stubs && stubs.construct || (() => ({ id: "evt_1", type: "checkout.session.completed" })),
    handleStripeEvent: stubs && stubs.handle || (async () => {}),
    console: { log() {}, error() {}, warn() {} }
  };
  vm.createContext(ctx);
  vm.runInContext(lift(HEALTH_SIG, "=> {") + "\n" + lift(WEBHOOK_SIG, "async function (req, res) {"), ctx);
  return routes;
}
async function call(route, req) {
  const res = { code: 200, body: undefined,
    status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; }, send(b) { this.body = b; return this; } };
  await route(req || { headers: {}, body: Buffer.from("{}") }, res);
  return res;
}

(async function main() {
  console.log("checkOpsAlerts — lib/opsAlert.js and server.js; no network, no database");

  /* ── H. /health ─────────────────────────────────────────────────────── */
  console.log("\n══ H. /health proves the database answers ══");
  let h = harness();
  let routes = mountRoutes(h);
  let r = await call(routes["GET /health"]);
  check("H1. the database answers: 200", r.code === 200, r.code);
  check("H2. body is exactly ok, status, db, commit, icu: true, \"healthy\", \"ok\", the commit, the icu probe",
    JSON.stringify(Object.keys(r.body)) === JSON.stringify(["ok", "status", "db", "commit", "icu"]) &&
    r.body.ok === true && r.body.status === "healthy" && r.body.db === "ok" && r.body.commit === "abc1234" && r.body.icu.timezone_applied === true,
    JSON.stringify(r.body));
  check("H3. the probe is ONE read of ONE row of job_runs", h.db.probeReads === 1 &&
    h.db.calls.filter(c => c.table === "job_runs").length === 1, h.db.probeReads);

  h = harness({ probe: "error" });
  routes = mountRoutes(h);
  r = await call(routes["GET /health"]);
  check("H4. the read errors: 503, ok false, status \"unhealthy\", db \"down\", commit and icu kept",
    r.code === 503 && r.body.ok === false && r.body.status === "unhealthy" && r.body.db === "down" && r.body.commit === "abc1234" && !!r.body.icu,
    JSON.stringify([r.code, r.body]));
  const bodyText = JSON.stringify(r.body);
  check("H5. no error text and no secret in the body", !/ECONNREFUSED|sb_secret|whsec|5432|error/i.test(bodyText), bodyText);

  h = harness({ probe: "hang" });
  routes = mountRoutes(h);
  const t = Date.now();
  // The check's own deadline, so a probe with no timeout fails here instead of hanging the run.
  r = await Promise.race([call(routes["GET /health"]), new Promise(res => setTimeout(() => res({ code: "no answer", body: {} }), ops.HEALTH_TIMEOUT_MS + 2000))]);
  const took = Date.now() - t;
  check("H6. the read never answers: 503 db \"down\" after the " + ops.HEALTH_TIMEOUT_MS + " ms timeout", r.code === 503 && r.body.db === "down" &&
    took >= ops.HEALTH_TIMEOUT_MS - 50 && took < ops.HEALTH_TIMEOUT_MS + 1500, took + " ms, " + r.code);

  h = harness();
  routes = mountRoutes(h);
  await Promise.all([call(routes["GET /health"]), call(routes["GET /health"]), call(routes["GET /health"])]);
  await call(routes["GET /health"]);
  check("H7. three concurrent calls and one more within 10 s: ONE database read", h.db.probeReads === 1, h.db.probeReads);
  h.clock.t += ops.HEALTH_CACHE_MS + 1;
  await call(routes["GET /health"]);
  check("H8. after 10 s the next call reads again", h.db.probeReads === 2, h.db.probeReads);

  h = harness({ probe: "error" });
  routes = mountRoutes(h);
  for (let i = 0; i < 2; i++) { await call(routes["GET /health"]); await h.alerts.settled(); h.clock.t += ops.HEALTH_CACHE_MS + 1; }
  check("H9. two failed probes in a row: no alert yet", h.sent.length === 0, h.sent.length);
  await call(routes["GET /health"]); await h.alerts.settled(); h.clock.t += ops.HEALTH_CACHE_MS + 1;
  check("H10. the third: one alert, health_db", h.sent.length === 1 && /did not answer 3 times in a row/.test(h.sent[0].subject), h.sent.map(m => m.subject).join(" | "));
  await call(routes["GET /health"]); await h.alerts.settled(); h.clock.t += ops.HEALTH_CACHE_MS + 1;
  check("H11. a fourth failure inside 6 hours: still one", h.sent.length === 1, h.sent.length);
  h.db.probe = "ok";
  await call(routes["GET /health"]); await h.alerts.settled();
  check("H12. the database answers again: one \"resolved\"", h.sent.length === 2 && /^\[BizForce RESOLVED\]/.test(h.sent[1].subject), h.sent.map(m => m.subject).join(" | "));

  /* ── W. the Stripe webhook ─────────────────────────────────────────── */
  console.log("\n══ W. the Stripe webhook ══");
  h = harness();
  routes = mountRoutes(h, { handle: async () => { throw new Error("subscriptions upsert failed: timeout"); } });
  r = await call(routes["POST /api/webhook"]); await flush();
  check("W1. the handler fails: 500 as before", r.code === 500 && r.body.error === "Webhook handler failed", JSON.stringify([r.code, r.body]));
  check("W2. ...and one alert naming the event and the error", h.sent.length === 1 && /Stripe webhook failed/.test(h.sent[0].subject) &&
    /evt_1 \(checkout\.session\.completed\): subscriptions upsert failed: timeout/.test(h.sent[0].text), h.sent.map(m => m.text).join(" | "));
  await call(routes["POST /api/webhook"]); await flush();
  check("W3. the same failure on the next event: no second email inside 6 hours", h.sent.length === 1, h.sent.length);

  h = harness();
  routes = mountRoutes(h, { construct: () => { throw new Error("No signatures found matching the expected signature"); } });
  r = await call(routes["POST /api/webhook"]); await call(routes["POST /api/webhook"]); await flush();
  check("W4. a signature failure: 400 as before", r.code === 400 && /^Webhook Error: /.test(r.body), JSON.stringify([r.code, r.body]));
  check("W5. ...and NO alert", h.sent.length === 0 && h.db.calls.filter(c => c.table === "ops_alerts" && c.op !== "select").length === 0, h.sent.length);
  check("W6. ...only counted (2)", h.alerts.signatureFailures() === 2, h.alerts.signatureFailures());

  const before = rejections.length;
  h = harness({ send: async () => { throw new Error("Resend is down"); } });
  routes = mountRoutes(h, { handle: async () => { throw new Error("boom"); } });
  r = await call(routes["POST /api/webhook"]); await flush(); await new Promise(res => setTimeout(res, 20));
  check("W7. the alert's send throws: the webhook still answers 500", r.code === 500, r.code);
  check("W8. ...and nothing rejects into it (no unhandled rejection)", rejections.length === before, rejections.slice(before).join(" | "));
  check("W9. ...and the failed send is logged", h.logs.some(l => l[0] === "error" && /was NOT sent: the send threw — Resend is down/.test(l[1])), JSON.stringify(h.logs));

  /* ── J. job_runs ────────────────────────────────────────────────────── */
  console.log("\n══ J. job_runs errors ══");
  h = harness({ jobRows: [{ job_name: "daily_store_proposals", last_error: "Anthropic 529 overloaded", started_at: "2026-10-20T13:00:00Z", finished_at: "2026-10-20T13:02:00Z" },
    { job_name: "self_review", last_error: null, started_at: "2026-10-20T14:00:00Z", finished_at: "2026-10-20T14:01:00Z" }] });
  await h.alerts.scanOps();
  check("J1. a new last_error: exactly one email", h.sent.length === 1 && /daily_store_proposals/.test(h.sent[0].subject), h.sent.map(m => m.subject).join(" | "));
  check("J2. ...and the key is stored open in ops_alerts", h.db.opsRows.has("job:daily_store_proposals"));
  h.clock.t += 1 * HOUR; await h.alerts.scanOps();
  check("J3. the same error an hour later: none", h.sent.length === 1, h.sent.length);
  h.db.jobRows[0].last_error = "Anthropic 401 invalid key";
  h.clock.t += 1 * HOUR; await h.alerts.scanOps();
  check("J4. a changed error: one more, carrying the new text", h.sent.length === 2 && /401 invalid key/.test(h.sent[1].text), h.sent.length);
  h.clock.t += 5 * HOUR; await h.alerts.scanOps();
  check("J5. the same error 5 hours after its email: none", h.sent.length === 2, h.sent.length);
  h.clock.t += 1 * HOUR + 1; await h.alerts.scanOps();
  check("J6. the same error 6 hours after its email: one reminder", h.sent.length === 3 && /^\[BizForce ALERT\]/.test(h.sent[2].subject), h.sent.length);
  h.db.jobRows[0].last_error = null; h.db.jobRows[0].finished_at = null;
  await h.alerts.scanOps();
  check("J7. last_error cleared but the run still in progress: not resolved yet", h.sent.length === 3 && h.db.opsRows.has("job:daily_store_proposals"), h.sent.length);
  h.db.jobRows[0].finished_at = "2026-10-21T13:02:00Z";
  await h.alerts.scanOps();
  check("J8. cleared and finished: exactly one \"resolved\"", h.sent.length === 4 && /^\[BizForce RESOLVED\] Scheduled job daily_store_proposals/.test(h.sent[3].subject), h.sent.map(m => m.subject).join(" | "));
  check("J9. ...and the key is closed in ops_alerts", !h.db.opsRows.has("job:daily_store_proposals"));
  await h.alerts.scanOps();
  check("J10. the next scan: nothing more", h.sent.length === 4, h.sent.length);

  /* Persistence: a new process (a deploy) reads the open keys back. */
  const db2 = fakeDb({ jobRows: [{ job_name: "email_sequences_09", last_error: "Resend 500", started_at: "x", finished_at: "y" }] });
  const p1 = harness({ db: db2 });
  await p1.alerts.scanOps();
  const p2 = harness({ db: db2 });
  p2.clock.t += 1 * HOUR;
  await p2.alerts.scanOps();
  check("J11. after a deploy, an alert already sent is not sent again inside 6 hours", p1.sent.length === 1 && p2.sent.length === 0, p1.sent.length + "/" + p2.sent.length);
  db2.jobRows[0].last_error = null;
  await p2.alerts.scanOps();
  check("J12. ...and its \"resolved\" is still sent by the new process", p2.sent.length === 1 && /RESOLVED/.test(p2.sent[0].subject), p2.sent.length);

  h = harness({ opsUnreadable: true, jobRows: [{ job_name: "a", last_error: "e1", finished_at: "x" }] });
  await h.alerts.scanOps(); await h.alerts.scanOps();
  check("J13. ops_alerts missing (migration 140 not applied): alerts still send, once", h.sent.length === 1, h.sent.length);
  check("J14. ...and that is logged once", h.logs.filter(l => /could not be read/.test(l[1])).length === 1, JSON.stringify(h.logs));

  /* ── B. the nightly backup ──────────────────────────────────────────── */
  console.log("\n══ B. the nightly backup ══");
  h = harness({ env: { ENABLE_NIGHTLY_BACKUP: "true" } });
  await h.alerts.backupFinished({ sent: false, reason: "provider_error" }, T0 - 60000);
  let up = h.db.calls.filter(c => c.table === "job_runs" && c.op === "upsert").pop();
  check("B1. a failed backup: one alert", h.sent.length === 1 && /nightly backup failed/.test(h.sent[0].subject) && /provider_error/.test(h.sent[0].text), h.sent.map(m => m.subject).join(" | "));
  check("B2. ...recorded in job_runs.nightly_backup with last_error and NO finished_at",
    !!up && up.payload.job_name === "nightly_backup" && /provider_error/.test(up.payload.last_error) && !("finished_at" in up.payload), JSON.stringify(up && up.payload));
  await h.alerts.backupFinished({ sent: true, bytes: 100 }, T0);
  up = h.db.calls.filter(c => c.table === "job_runs" && c.op === "upsert").pop();
  check("B3. the next success: one \"resolved\"", h.sent.length === 2 && /RESOLVED/.test(h.sent[1].subject), h.sent.length);
  check("B4. ...recorded with finished_at and last_error null", up.payload.finished_at && up.payload.last_error === null, JSON.stringify(up.payload));
  check("B5. ...never rejects even when job_runs cannot be written",
    await harness({ db: Object.assign(fakeDb(), { from: () => { throw new Error("db gone"); } }) }).alerts.backupFinished({ sent: true }, T0).then(() => true, () => false));

  h = harness({ env: { ENABLE_NIGHTLY_BACKUP: "true" }, jobRows: [{ job_name: "nightly_backup", last_error: null, finished_at: new Date(T0 - 31 * HOUR).toISOString() }] });
  await h.alerts.scanOps();
  check("B6. last success 31 hours ago, backups on: one alert", h.sent.length === 1 && /No nightly backup has succeeded in the last 30 hours/.test(h.sent[0].subject), h.sent.map(m => m.subject).join(" | "));
  h.db.jobRows[0].finished_at = new Date(T0 - 1 * HOUR).toISOString();
  await h.alerts.scanOps();
  check("B7. a backup succeeds: resolved", h.sent.length === 2 && /RESOLVED/.test(h.sent[1].subject), h.sent.length);
  h = harness({ env: { ENABLE_NIGHTLY_BACKUP: "true" }, jobRows: [{ job_name: "nightly_backup", last_error: null, finished_at: new Date(T0 - 29 * HOUR).toISOString() }] });
  await h.alerts.scanOps();
  check("B8. last success 29 hours ago: no alert", h.sent.length === 0, h.sent.length);
  h = harness({ jobRows: [{ job_name: "nightly_backup", last_error: null, finished_at: new Date(T0 - 300 * HOUR).toISOString() }] });
  await h.alerts.scanOps();
  check("B9. backups off (ENABLE_NIGHTLY_BACKUP unset): no staleness alert", h.sent.length === 0, h.sent.length);
  h = harness({ env: { ENABLE_NIGHTLY_BACKUP: "true" }, jobRows: [] });
  await h.alerts.scanOps();
  check("B10. never recorded, fresh process: not stale yet", h.sent.length === 0);
  h.clock.t += 31 * HOUR; await h.alerts.scanOps();
  check("B11. never recorded, 31 hours after the process started: stale", h.sent.length === 1, h.sent.length);
  h = harness({ env: { ENABLE_NIGHTLY_BACKUP: "true" }, jobRows: [{ job_name: "nightly_backup", last_error: "sent: false, reason provider_error", finished_at: new Date(T0 - 1 * HOUR).toISOString() }] });
  await h.alerts.scanOps();
  check("B12. the job_runs scan leaves nightly_backup to backup_failed (no second email for it)", h.sent.length === 0, h.sent.length);

  /* ── R. the recipient ───────────────────────────────────────────────── */
  console.log("\n══ R. who is emailed ══");
  h = harness({ noRecipient: true });
  await h.alerts.raise("job:a", { what: "A", error: "e1" });
  await h.alerts.raise("job:b", { what: "B", error: "e2" });
  check("R1. neither OPS_ALERT_EMAIL nor BACKUP_EMAIL_TO: nothing sent", h.sent.length === 0, h.sent.length);
  check("R2. ...and it is logged once, not per alert", h.logs.filter(l => /Neither OPS_ALERT_EMAIL nor BACKUP_EMAIL_TO is set/.test(l[1])).length === 1,
    h.logs.filter(l => /Neither/.test(l[1])).length);
  check("R3. OPS_ALERT_EMAIL wins over BACKUP_EMAIL_TO", ops.opsAlertRecipient({ OPS_ALERT_EMAIL: " ops@x.test ", BACKUP_EMAIL_TO: "b@x.test" }) === "ops@x.test");
  check("R4. BACKUP_EMAIL_TO when OPS_ALERT_EMAIL is unset or blank", ops.opsAlertRecipient({ OPS_ALERT_EMAIL: "  ", BACKUP_EMAIL_TO: "b@x.test" }) === "b@x.test");
  h = harness({ noRecipient: true, env: { BACKUP_EMAIL_TO: "backup@example.test" } });
  await h.alerts.raise("job:a", { what: "A", error: "e1" });
  check("R5. ...and the email goes there", h.sent.length === 1 && h.sent[0].to === "backup@example.test", JSON.stringify(h.sent.map(m => m.to)));
  check("R6. from the existing Resend sender", !!h.sent[0] && h.sent[0].from === "BizForce AI <hello@mail.bizforceai.net>", h.sent[0] && h.sent[0].from);

  /* ── S. a failed send ───────────────────────────────────────────────── */
  console.log("\n══ S. a failed send never throws ══");
  let attempts = 0;
  h = harness({ send: async () => { attempts++; throw new Error("network down"); } });
  let outcome = await h.alerts.raise("job:a", { what: "A", error: "e1" }).then(v => v, e => "REJECTED " + e.message);
  check("S1. the send throws: raise resolves { sent: false }", outcome && outcome.sent === false, JSON.stringify(outcome));
  await h.alerts.raise("job:a", { what: "A", error: "e1" });
  check("S2. ...and the next alert tries again (an unsent alert is not deduped)", attempts === 2, attempts);
  h = harness({ send: async () => ({ ok: false, error: "domain not verified" }) });
  outcome = await h.alerts.raise("job:a", { what: "A", error: "e1" });
  check("S3. the provider rejects: { sent: false }, logged with the reason", outcome.sent === false && h.logs.some(l => /domain not verified/.test(l[1])), JSON.stringify(h.logs));
  outcome = await harness({ db: Object.assign(fakeDb(), { from: () => { throw new Error("db gone"); } }) }).alerts.raise("job:a", { what: "A", error: "e" })
    .then(v => v, e => "REJECTED " + e.message);
  check("S4. the database throws on every call: raise still resolves", outcome && typeof outcome === "object", String(outcome));

  /* ── G. the gate ────────────────────────────────────────────────────── */
  console.log("\n══ G. ENABLE_OPS_ALERTS: only the exact \"false\" disables ══");
  const gate = [undefined, "", "true", "1", "FALSE", " false", "false "].map(v => ops.opsAlertsEnabled(v === undefined ? {} : { ENABLE_OPS_ALERTS: v }));
  check("G1. unset, blank, true, 1, FALSE, \" false\", \"false \": all ON", gate.every(Boolean), JSON.stringify(gate));
  check("G2. exactly \"false\": OFF", ops.opsAlertsEnabled({ ENABLE_OPS_ALERTS: "false" }) === false);
  h = harness({ env: { ENABLE_OPS_ALERTS: "false" } });
  await h.alerts.raise("job:a", { what: "A", error: "e1" });
  check("G3. off: nothing sent, nothing stored", h.sent.length === 0 && h.db.calls.length === 0, h.db.calls.length);
  h = harness();
  await h.alerts.raise("job:a", { what: "A", error: "e1" });
  check("G4. unset (as in production today): the alert is sent", h.sent.length === 1, h.sent.length);

  /* ── E. the email ───────────────────────────────────────────────────── */
  console.log("\n══ E. the email ══");
  h = harness();
  await h.alerts.raise("job:daily_store_proposals", { what: "Scheduled job daily_store_proposals recorded an error", error: "x".repeat(800),
    where: "Table editor > job_runs, row daily_store_proposals", log_tag: "daily_store_proposals" });
  const m = h.sent[0];
  check("E1. subject: [BizForce ALERT] + what broke", m.subject === "[BizForce ALERT] Scheduled job daily_store_proposals recorded an error", m.subject);
  check("E2. when, in UTC and Pacific", /When: 2026-10-20 18:51:02 UTC \(10\/20\/2026, 11:51:02 PDT\)/.test(m.text), m.text.split("\n")[2]);
  const errLine = m.text.split("\n")[m.text.split("\n").indexOf("Error (first 500 characters):") + 1];
  check("E3. the error, cut to exactly 500 characters", errLine === "x".repeat(500), errLine && errLine.length);
  check("E4. where to look: Railway logs and Supabase", /- Railway: the BizForce backend service > Deployments > View logs; search for daily_store_proposals/.test(m.text) &&
    /- Supabase: Table editor > job_runs, row daily_store_proposals/.test(m.text), m.text);
  check("E5. plain text only, no html, no List-Unsubscribe", !("html" in m) && !("headers" in m), Object.keys(m).join(","));
  console.log("\n--- example email ---\nSubject: " + m.subject.replace("x".repeat(500), "x…") + "\n" + m.text.replace("x".repeat(500), "xxxx… (500 characters)") + "\n--- end ---");

  /* ── C. the scan's schedule and claim ─────────────────────────────── */
  console.log("\n══ C. the 30-minute scan ══");
  const srv = SRC.server;
  const cronAt = srv.indexOf('cron.schedule("*/30 * * * *", function () {\n      opsAlerts.scanTick();\n    }, {\n      timezone: "UTC"\n    });');
  check("C1. scheduled every 30 minutes on the UTC clock", cronAt !== -1);
  check("C2. ...inside if (opsAlertsEnabled(process.env))", cronAt !== -1 && srv.lastIndexOf("if (opsAlertsEnabled(process.env)) {\n    cron.schedule(\"*/30", cronAt) === cronAt - "if (opsAlertsEnabled(process.env)) {\n    ".length);
  check("C3. no boot-time run: scanTick is called from the cron and nowhere else", (srv.match(/opsAlerts\.scanTick\(/g) || []).length === 1);
  h = harness({ jobRows: [{ job_name: "a", last_error: "e1", finished_at: "x" }] });
  let tick = await h.alerts.scanTick();
  const claimInsert = h.db.calls.find(c => c.table === "job_runs" && c.op === "insert");
  check("C4. the first tick claims job_runs.ops_alert_scan and scans", tick.claimed === true && claimInsert && claimInsert.payload.job_name === "ops_alert_scan" && h.sent.length === 1,
    JSON.stringify(tick));
  h = harness({ claimExists: true, claimHeld: true, jobRows: [{ job_name: "a", last_error: "e1", finished_at: "x" }] });
  tick = await h.alerts.scanTick();
  check("C5. this half-hour already claimed elsewhere: no scan, nothing sent", tick.claimed === false && tick.reason === "held" && h.sent.length === 0, JSON.stringify(tick));
  const orFilter = (h.db.calls.find(c => c.op === "update" && c.filters.some(f => f[0] === "or")) || { filters: [] }).filters.find(f => f[0] === "or");
  check("C6. ...the claim wins only for a row started before this half-hour", !!orFilter && orFilter[1] === 'started_at.is.null,started_at.lt."2026-10-20T18:30:00.000Z"', orFilter && orFilter[1]);
  h = harness({ jobRunsUnreadable: true });
  tick = await h.alerts.scanTick();
  const fin = h.db.calls.filter(c => c.table === "job_runs" && c.op === "update" && c.payload && "finished_at" in c.payload).pop();
  check("C7. a scan that fails records last_error on its own row", tick.claimed === true && fin && /job_runs could not be read/.test(fin.payload.last_error), JSON.stringify(fin && fin.payload));
  check("C8. ...and alerts at once (ops_scan)", h.sent.length === 1 && /ops alert scan failed/.test(h.sent[0].subject), h.sent.map(x => x.subject).join(" | "));

  /* ── T. Termaximus ──────────────────────────────────────────────────── */
  console.log("\n══ T. Termaximus: Ops: N open alerts ══");
  h = harness();
  await h.alerts.raise("job:b", { what: "B", error: "e" });
  h.clock.t += 60000;
  await h.alerts.raise("backup_failed", { what: "Backup", error: "e" });
  const openList = await h.alerts.openAlerts();
  check("T1. each open alert with its key and since-time", openList.length === 2 && openList[0].key === "backup_failed" && openList[1].key === "job:b" &&
    openList[1].since === "2026-10-20T18:51:02.000Z", JSON.stringify(openList));
  const failLoud = await harness({ opsUnreadable: true }).alerts.openAlerts().then(() => "returned", e => "threw: " + e.message);
  check("T2. ops_alerts unreadable: throws (fail-loud), never \"0 open\"", /^threw: public\.ops_alerts could not be read/.test(failLoud), failLoud);
  const records = s.definitionOf(SRC.server, "buildOracleAgentRecords");
  const ownerAt = records.indexOf("if (userId === OUTREACH_CREDENTIAL_OWNER_ID) {");
  const opsAt = records.indexOf('await section("Ops alerts", async function () {');
  check("T3. the line is in Agent records, inside the owner-only block, through section() (unreadable is reported as unreadable)",
    ownerAt !== -1 && opsAt > ownerAt && s.braceMatch(records, records.indexOf("{", ownerAt)) > opsAt);
  check("T4. it reads \"- Ops: N open alert(s)\" then \"- <key> since <time>\"",
    records.indexOf('["- Ops: " + openOps.length + " open alert" + (openOps.length === 1 ? "" : "s")]') !== -1 &&
    records.indexOf('return "- " + a.key + " since " + a.since;') !== -1);

  check("Z. no unhandled rejection in the whole run", rejections.length === 0, rejections.join(" | "));

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
/* A crash is a FAIL (exit 1), not exit 3: 3 is _shared.js's "mutation anchor did not match". */
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error((e && e.stack) || e); process.exit(1); });
