"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkConsentConfirmation — double opt-in: a form grants, only the link sent
   to that address confirms, and marketing mail waits for the confirmation.

   POST /api/contacts/capture, GET and POST /api/confirm, POST /api/unsubscribe,
   sendEmail and sendMarketingEmail are lifted from server.js and run in a vm
   against an in-memory Supabase that keeps its rows between calls, so a
   capture, a confirmation, an unsubscribe and a marketing send can run in
   sequence the way they would for one person. Resend is a class that records
   what it is asked to send and sends nothing. No network, no model, no rows,
   no mail.

   WHAT THIS PROVES
     1. Capture records "granted" and sends exactly one confirmation through
        sendEmail as transactional, template "consent_confirmation", to the
        address, saying who is asking, why, and that ignoring it means nothing
        more is sent. The response and the recorded consent are what BEFORE
        wrote.
     2. The 24 hour limit: a second capture of the address (any case) records
        the grant and sends nothing; LIKE metacharacters in an address match
        only themselves; a row older than 24 hours does not count; a count that
        fails, is missing, or throws sends nothing — and the capture succeeds.
     3. A failed confirmation never fails the capture: provider error, provider
        throw, ledger insert failure, no API key, no JWT_SECRET.
     4. The token: "c1.<contactId>.<expiresAt>.<digest>", seven days, the
        address absent from it; reading it is total.
     5. GET /api/confirm makes no database call at all, for any token.
     6. POST /api/confirm with a genuine token writes one "confirmed" row with
        the recorded fields; an expired, tampered, re-dated, unsubscribe, or
        other-address token writes nothing, as does a contact whose address has
        changed; after "revoked" it writes nothing. An unsubscribe POST given a
        confirm token revokes nothing.
     7. Marketing: "granted" refuses with not_confirmed; "confirmed" sends; a
        new grant after a confirmation refuses again until reconfirmed; an
        unsubscribe after a confirmation refuses with no_consent; sendEmail's
        own check accepts "confirmed".
     8. Transactional sends are byte-identical to BEFORE.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { execSync, spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const BEFORE = "f71dcd9";
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // an unsubscribe token is accepted where a confirm token belongs
  "unsub-token-confirms": [
    ["    var claims = readConsentConfirmToken(token);\n    if (!claims || consentConfirmTokenExpired(claims)) {",
     "    var unsubscribed = verifyUnsubscribeToken(token);\n    var claims = readConsentConfirmToken(token) || (unsubscribed ? { contactId: unsubscribed, expiresAt: 9999999999 } : null);\n    if (!claims || consentConfirmTokenExpired(claims)) {"],
    ["!verifyConsentConfirmToken(token, contact.email)", "!(verifyConsentConfirmToken(token, contact.email) || unsubscribed)"]],
  // the GET records the confirmation itself
  "record-on-get": [["    return res.status(200).send(renderConfirmAskPage(token));",
    "    await recordEmailConfirmation(claims.contactId, req);\n    return res.status(200).send(renderConfirmAskPage(token));"]],
  // the 24 hour limit is never applied
  "skip-24h-limit": [["      if (recentConfirmations.count > 0) {", "      if (false) {"]],
  // marketing takes a grant that was never confirmed
  "marketing-accepts-granted": [["  if (consent.action !== \"confirmed\") {", "  if (consent.action !== \"confirmed\" && consent.action !== \"granted\") {"]],
  // an old link undoes an unsubscribe
  "confirm-after-revoked": [["    if (latest.action !== \"granted\" && latest.action !== \"confirmed\") {", "    if (false) {"]],
  // the token no longer signs the address
  "drop-address-binding": [[".update(\"confirm:\" + contactId + \":\" + String(address).trim().toLowerCase() + \":\" + expiresAt)",
    ".update(\"confirm:\" + contactId + \":\" + expiresAt)"]],
  // a confirmation that did not go out fails the capture
  "failed-send-fails-capture": [["    await sendConsentConfirmation(contactId, email);\n",
    "    var confirmation = await sendConsentConfirmation(contactId, email);\n    if (!confirmation.sent) throw new Error(\"the confirmation email was not sent\");\n"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(26) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  console.log(survived === 0 ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught" : "\nCHECKS FAILED: " + survived + " mutation(s) survived");
  process.exit(survived === 0 ? 0 : 1);
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the sources ────────────────────────────────────────────────────────── */
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    if (SRC.split(from).length !== 2) { console.log("    FAIL  mutation anchor not found exactly once: " + from.slice(0, 80)); process.exit(1); }
    SRC = SRC.replace(from, () => to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}
const OLD = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");

/* _shared.definitionOf, uncached for the reason checkMarketingEmail gives: its
   cache keys every source that is not the working tree as one, and this check
   holds two of those at once. Cached here per source instead. */
const SPANS = new Map();
function spansOf(src) {
  if (SPANS.has(src)) return SPANS.get(src);
  const out = []; const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(src))) { const end = s.braceMatch(src, src.indexOf("{", m.index)); if (end > 0) out.push([m.index, end]); }
  SPANS.set(src, out); return out;
}
function definitionOf(src, name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) return src.slice(m.index, s.braceMatch(src, src.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(src)) && spansOf(src).some(([x, y]) => m.index > x && m.index < y)) { /* a local, not a definition */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(src))) {
    const next = src[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return src.slice(m.index, b.index + 1);
  }
  return null;
}
const DEFS = new Map();
function definitionOfCached(src, name) {
  const key = (src === SRC ? "S:" : "O:") + name;
  if (!DEFS.has(key)) DEFS.set(key, definitionOf(src, name));
  return DEFS.get(key);
}
const CLOSURES = new Map();
function closure(src, root) {
  const key = (src === SRC ? "S:" : "O:") + root;
  if (CLOSURES.has(key)) return CLOSURES.get(key);
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "Resend", "express", "app", "crypto", "Buffer", "setTimeout", "OWNER_ACCOUNT_ID"]);
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOfCached(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  const out = [...have.values()].sort((x, y) => src.indexOf(x) - src.indexOf(y)).join("\n\n") + "\n\n" + root;
  CLOSURES.set(key, out);
  return out;
}
function routeText(src, method, route) {
  const start = src.indexOf("app." + method + "(\"" + route + "\", async function (req, res, next) {");
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(src, src.indexOf("{", start));
  if (src.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return src.slice(start, end + 2);
}

/* ── the fakes ──────────────────────────────────────────────────────────── */
// LIKE / ILIKE as Postgres reads them: backslash escapes, % any run, _ one char.
function likeMatch(pattern, value, caseBlind) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\" && i + 1 < pattern.length) { re += pattern[++i].replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); continue; }
    re += c === "%" ? "[\\s\\S]*" : c === "_" ? "[\\s\\S]" : c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$", caseBlind ? "i" : "").test(String(value == null ? "" : value));
}

// An in-memory Supabase that keeps its rows. `fail(q)` may return an error
// object (answered as { error }) or the string "throw" (the query rejects).
function fakeDb(seed, fail) {
  const tables = { contacts: [], consent_events: [], email_sends: [] };
  Object.keys(seed || {}).forEach(t => { tables[t] = seed[t].map(r => Object.assign({}, r)); });
  const log = [];
  let seq = 0;
  function cell(row, col) {
    if (col.indexOf(".") !== -1) { const parts = col.split("."); const c = tables.contacts.find(x => x.id === row.contact_id); return c ? c[parts[1]] : undefined; }
    return row[col];
  }
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return cell(row, f[1]) === f[2];
      if (f[0] === "in") return f[2].indexOf(cell(row, f[1])) !== -1;
      if (f[0] === "ilike") return likeMatch(f[2], cell(row, f[1]), true);
      if (f[0] === "like") return likeMatch(f[2], cell(row, f[1]), false);
      if (f[0] === "gte") return String(cell(row, f[1])) >= String(f[2]);
      return true;
    });
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected === "throw") return Promise.reject(new Error("the database connection dropped"));
    if (injected) return Promise.resolve({ data: null, count: null, error: injected });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++seq).padStart(12, "0"), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(q.payload)));
      if (q.table === "consent_events") row.occurred_at = String(++seq).padStart(8, "0");
      rows.push(row);
      return Promise.resolve({ data: q.single ? { id: row.id } : null, error: null });
    }
    if (q.op === "update") {
      rows.filter(r => keep(q, r)).forEach(r => Object.assign(r, q.payload));
      return Promise.resolve({ data: null, error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const order = q.filters.find(f => f[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, count: hits.length, error: null });
    const copies = hits.map(r => Object.assign({}, r));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null });
    return Promise.resolve({ data: copies, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select(cols, opts) { if (q.op === "select") { q.cols = cols; if (opts) q.opts = opts; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "in", "ilike", "like", "gte", "order", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

const OWNER = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";
const POSTAL = "BizForce AI\n123 Example Street\nSpringfield, ST 00000";
const ENV = { RESEND_API_KEY: "re_test_key", JWT_SECRET: "check-jwt-secret", MAIL_POSTAL_ADDRESS: POSTAL };
const ROUTES = [["post", "/api/contacts/capture"], ["post", "/api/confirm"], ["get", "/api/confirm"], ["post", "/api/unsubscribe"]];
const API = ["sendEmail", "sendMarketingEmail", "makeUnsubscribeToken", "verifyUnsubscribeToken", "makeConsentConfirmToken",
  "consentConfirmDigest", "readConsentConfirmToken", "verifyConsentConfirmToken"];
function rootFor(src, routes) {
  return routes.map(([m, r]) => routeText(src, m, r)).join("\n\n") + "\n\nthis.api = { " +
    API.map(n => n + ": typeof " + n + " === \"function\" ? " + n + " : null").join(", ") + " };";
}

function build(src, opts) {
  const o = opts || {};
  const db = fakeDb(o.seed, o.fail);
  const sent = [], logs = [];
  class Resend {
    constructor(key) {
      this.key = key;
      this.emails = { send: async (args) => {
        sent.push(JSON.parse(JSON.stringify(args)));
        if (o.providerThrows) throw new Error("socket hang up");
        return o.providerError ? { data: null, error: { message: "provider said no" } } : { data: { id: "re_" + sent.length }, error: null };
      } };
    }
  }
  const ctx = {
    supabase: db.client, Resend, crypto, Buffer, URL, Date, JSON, Math, Promise, require, OWNER_ACCOUNT_ID: OWNER,
    express: { raw: () => "raw" }, nowIso: () => "2026-10-09T12:00:00.000Z",
    process: { env: Object.assign({}, o.env === undefined ? ENV : o.env) },
    console: { log: m => logs.push(String(m)), error: m => logs.push(String(m)), warn: m => logs.push(String(m)) }
  };
  const handlers = {};
  ctx.app = {
    post(p) { handlers["post " + p] = arguments[arguments.length - 1]; },
    get(p) { handlers["get " + p] = arguments[arguments.length - 1]; }
  };
  vm.createContext(ctx);
  vm.runInContext(closure(src, rootFor(src, o.routes || ROUTES)), ctx);

  async function call(key, req) {
    const res = { code: 200, body: null, headers: {}, error: null,
      status(c) { this.code = c; return this; }, set(k, v) { this.headers[k] = v; return this; },
      json(x) { this.body = x; return this; }, send(x) { this.body = x; return this; } };
    const hdrs = Object.assign({ "user-agent": "CheckAgent/1.0", accept: "text/html" }, req.headers || {});
    await handlers[key]({ body: req.body || {}, query: req.query || {}, ip: req.ip || "203.0.113.7", get: h => hdrs[h.toLowerCase()] },
      res, e => { res.error = e; res.code = 500; });
    return res;
  }
  return {
    db, sent, logs, api: ctx.api, ctx,
    capture: (email, extra) => call("post /api/contacts/capture", { body: Object.assign({ email, name: "Pat", source: "landing", page_url: "https://bizforceai.net/join" }, extra || {}) }),
    confirmGet: (token) => call("get /api/confirm", { query: { token } }),
    confirmPost: (token, req) => call("post /api/confirm", Object.assign({ body: { token } }, req || {})),
    unsubscribe: (token) => call("post /api/unsubscribe", { body: { token } }),
    marketing: async (contactId) => {
      try { return { result: await ctx.api.sendMarketingEmail({ contactId, subject: "News", html: "<p>Hi</p>", text: "Hi", template: "news" }) }; }
      catch (e) { return { error: e }; }
    },
    contactOf: (email) => db.tables.contacts.find(c => c.email === email),
    consentOf: (id) => db.tables.consent_events.filter(r => r.contact_id === id).map(r => r.action),
    tokenFrom: (mail) => { const m = /\/confirm\?token=([A-Za-z0-9._-]+)/.exec((mail && mail.text) || ""); return m && m[1]; }
  };
}

function sendMarketingEmailCallers(src) {
  const out = [];
  const re = /\bsendMarketingEmail\(/g; let m;
  while ((m = re.exec(src)) !== null) {
    if (src.slice(m.index - 15, m.index) === "async function ") continue;   // the definition
    const heads = [...src.slice(0, m.index).matchAll(/^(?:async )?function ([A-Za-z0-9_$]+)\(|^app\.(get|post|put|patch|delete)\("([^"]+)"/gm)];
    const head = heads[heads.length - 1];
    out.push(!head ? "(top level)" : head[1] || head[2].toUpperCase() + " " + head[3]);
  }
  return out;
}
const writesOf = (log, table) => log.filter(q => q.table === table && (q.op === "insert" || q.op === "update"));
const confirmations = (b) => b.db.tables.consent_events.filter(r => r.action === "confirmed");
const minusSecs = (n) => Math.floor(Date.now() / 1000) - n;
function tokenWith(api, contactId, address, expiresAt) {
  return "c1." + contactId + "." + expiresAt + "." + api.consentConfirmDigest(contactId, address, expiresAt);
}

(async function main() {
  /* ── 1. capture sends one confirmation and records the grant ───────────── */
  console.log("\n══ 1. capture ══");
  let b = build(SRC);
  let res = await b.capture("  Person@Example.com ");
  let contact = b.contactOf("person@example.com");
  check("capture answers { ok: true, contact_id }", res.code === 200 && res.body && res.body.ok === true && contact && res.body.contact_id === contact.id &&
    Object.keys(res.body).join() === "ok,contact_id", JSON.stringify(res.body) + " " + (res.error && res.error.message));
  check("capture records one consent row: granted, email, with its evidence",
    JSON.stringify(b.db.tables.consent_events.map(r => [r.action, r.channel, r.source, r.page_url, r.ip_address, r.user_agent])) ===
    JSON.stringify([["granted", "email", "landing", "https://bizforceai.net/join", "203.0.113.7", "CheckAgent/1.0"]]), JSON.stringify(b.db.tables.consent_events));
  check("exactly one email is sent", b.sent.length === 1, b.sent.length);
  const mail = b.sent[0] || {};
  check("it goes to the address as stored (trimmed, lowercased)", mail.to === "person@example.com", mail.to);
  check("from BizForce AI, as every send", mail.from === "BizForce AI <hello@mail.bizforceai.net>", mail.from);
  const sendRow = b.db.tables.email_sends[0] || {};
  check("one email_sends row, template consent_confirmation, marked sent",
    b.db.tables.email_sends.length === 1 && sendRow.template === "consent_confirmation" && sendRow.status === "sent" && sendRow.contact_id === contact.id,
    JSON.stringify(b.db.tables.email_sends));
  check("sent as transactional: consent is never read during capture", !b.db.log.some(q => q.table === "consent_events" && q.op === "select"));
  const token = b.tokenFrom(mail);
  check("the text carries a link to the frontend's /confirm with a token", !!token && (mail.text || "").includes("https://bizforceai.net/confirm?token=" + token), mail.text);
  check("the HTML carries the same link", !!token && (mail.html || "").includes('href="https://bizforceai.net/confirm?token=' + token + '"'), mail.html);
  for (const part of ["text", "html"]) {
    const body = String(mail[part] || "");
    check("the " + part + " says who is asking (BizForce AI)", /BizForce AI/.test(body));
    check("the " + part + " says why (this address was entered on a form to hear from us)", /entered this email address on a BizForce AI form and asked to hear from us/.test(body));
    check("the " + part + " says ignoring it means nothing further is sent", /ignore this email\. Nothing further will be sent/.test(body));
  }
  check("the subject asks for confirmation", /confirm/i.test(mail.subject || ""), mail.subject);
  const countQ = b.db.log.find(q => q.table === "email_sends" && q.opts && q.opts.head);
  check("the 24 hour count: consent_confirmation rows for this address since a day ago",
    countQ && countQ.filters.some(f => f[0] === "eq" && f[1] === "template" && f[2] === "consent_confirmation") &&
    countQ.filters.some(f => f[0] === "ilike" && f[1] === "to_email" && f[2] === "person@example.com") &&
    countQ.filters.some(f => f[0] === "gte" && f[1] === "created_at" && Math.abs(Date.now() - 864e5 - Date.parse(f[2])) < 60000),
    countQ && JSON.stringify(countQ.filters));
  check("the count is read before the send row is written",
    b.db.log.indexOf(countQ) < b.db.log.findIndex(q => q.table === "email_sends" && q.op === "insert"));

  // Against BEFORE: the response and everything capture wrote, minus the email.
  for (const [label, seed] of [["a new contact", {}], ["a returning contact", { contacts: [{ id: "c-old", owner_id: OWNER, email: "back@example.com", name: null }] }]]) {
    const email = label === "a new contact" ? "fresh@example.com" : "back@example.com";
    const a = build(SRC, { seed }), o = build(OLD, { seed, routes: [["post", "/api/contacts/capture"]] });
    const ra = await a.capture(email), ro = await o.capture(email);
    const strip = (log) => JSON.stringify(log.filter(q => q.table !== "email_sends").map(q => [q.table, q.op, q.cols, q.payload, q.filters]));
    check("capture of " + label + ": response, contacts and consent traffic identical to " + BEFORE,
      JSON.stringify([ra.code, ra.body]) === JSON.stringify([ro.code, ro.body]) && strip(a.db.log) === strip(o.db.log),
      JSON.stringify([ra.body, ro.body]));
    check("capture of " + label + ": at " + BEFORE + " no email was sent; now one", o.sent.length === 0 && a.sent.length === 1, o.sent.length + "/" + a.sent.length);
  }

  /* ── 2. the 24 hour limit ─────────────────────────────────────────────── */
  console.log("\n══ 2. at most one confirmation per address per 24 hours ══");
  res = await b.capture("PERSON@example.COM");
  check("a second capture within 24 h answers as the first", res.code === 200 && res.body.ok === true && res.body.contact_id === contact.id, JSON.stringify(res.body));
  check("…records a second grant", JSON.stringify(b.consentOf(contact.id)) === JSON.stringify(["granted", "granted"]), b.consentOf(contact.id));
  check("…and sends no second email (any case)", b.sent.length === 1 && b.db.tables.email_sends.length === 1, b.sent.length);
  await b.capture("person@example.com");
  check("a third capture still sends nothing", b.sent.length === 1, b.sent.length);

  b = build(SRC);
  await b.capture("a_b%c@example.com");
  await b.capture("axbyc@example.com");
  check("LIKE metacharacters match only themselves: a_b%c@ does not limit axbyc@", b.sent.length === 2, b.sent.map(m => m.to).join(","));

  b = build(SRC, { seed: { email_sends: [{ id: "old-1", contact_id: "x", to_email: "late@example.com", template: "consent_confirmation", status: "sent",
    created_at: new Date(Date.now() - 25 * 3600 * 1000).toISOString() }] } });
  await b.capture("late@example.com");
  check("a confirmation older than 24 hours does not count", b.sent.length === 1, b.sent.length);
  b = build(SRC, { seed: { email_sends: [{ id: "old-2", contact_id: "x", to_email: "Late@Example.com", template: "consent_confirmation", status: "failed",
    created_at: new Date(Date.now() - 23 * 3600 * 1000).toISOString() }] } });
  await b.capture("late@example.com");
  check("a failed confirmation 23 hours ago still counts (every row counts)", b.sent.length === 0, b.sent.length);
  b = build(SRC, { seed: { email_sends: [{ id: "old-3", contact_id: "x", to_email: "late@example.com", template: "password_reset", status: "sent",
    created_at: new Date().toISOString() }] } });
  await b.capture("late@example.com");
  check("other templates to the address do not count", b.sent.length === 1, b.sent.length);

  const countFails = {
    "the count errors": q => q.table === "email_sends" && q.opts && q.opts.head ? { message: "count failed" } : null,
    "the count throws": q => q.table === "email_sends" && q.opts && q.opts.head ? "throw" : null
  };
  for (const [label, fail] of Object.entries(countFails)) {
    b = build(SRC, { fail });
    res = await b.capture("person@example.com");
    check(label + ": nothing is sent and no send row is written", b.sent.length === 0 && writesOf(b.db.log, "email_sends").length === 0, b.sent.length);
    check(label + ": the capture still succeeds and records the grant",
      res.code === 200 && res.body && res.body.ok === true && JSON.stringify(b.consentOf(res.body.contact_id)) === "[\"granted\"]",
      res.code + " " + JSON.stringify(res.body) + " " + (res.error && res.error.message));
  }
  b = build(SRC);
  b.db.client.from = (function (from) {
    return function (t) {
      const q = from(t);
      const sel = q.select;
      q.select = function (cols, opts) { const r = sel.call(q, cols, opts); if (opts && opts.head) { q.then = (ok) => Promise.resolve({ data: null, error: null }).then(ok); } return r; };
      return q;
    };
  })(b.db.client.from);
  res = await b.capture("person@example.com");
  check("the count missing from the answer: nothing is sent, the capture succeeds", b.sent.length === 0 && res.code === 200 && res.body.ok === true, b.sent.length + " " + res.code);

  /* ── 3. a failed confirmation never fails the capture ─────────────────── */
  console.log("\n══ 3. a failed confirmation never fails the capture ══");
  const failures3 = [
    ["the provider returns an error", { providerError: true }],
    ["the provider throws", { providerThrows: true }],
    ["the send row cannot be written", { fail: q => q.table === "email_sends" && q.op === "insert" ? { message: "insert failed" } : null }],
    ["the send row write throws", { fail: q => q.table === "email_sends" && q.op === "insert" ? "throw" : null }],
    ["RESEND_API_KEY unset", { env: { JWT_SECRET: "check-jwt-secret" } }],
    ["JWT_SECRET unset (no token can be made)", { env: { RESEND_API_KEY: "re_test_key" } }]
  ];
  for (const [label, opts] of failures3) {
    b = build(SRC, opts);
    res = await b.capture("person@example.com");
    const c = b.contactOf("person@example.com");
    check(label + ": capture answers { ok: true, contact_id } and records the grant",
      res.code === 200 && res.body && res.body.ok === true && c && res.body.contact_id === c.id && JSON.stringify(b.consentOf(c.id)) === "[\"granted\"]",
      res.code + " " + JSON.stringify(res.body) + " " + (res.error && res.error.message));
  }

  /* ── 4. the token ─────────────────────────────────────────────────────── */
  console.log("\n══ 4. the token ══");
  b = build(SRC);
  await b.capture("person@example.com");
  contact = b.contactOf("person@example.com");
  const tok = b.tokenFrom(b.sent[0]);
  const parts = String(tok).split(".");
  check("format c1.<contactId>.<expiresAt>.<43-char base64url digest>",
    parts.length === 4 && parts[0] === "c1" && parts[1] === contact.id && /^[0-9]+$/.test(parts[2]) && /^[A-Za-z0-9_-]{43}$/.test(parts[3]), tok);
  check("it expires seven days after issue", Math.abs(Number(parts[2]) - (Math.floor(Date.now() / 1000) + 7 * 86400)) < 60, parts[2]);
  check("the address is not in it", !/person|example/i.test(tok));
  check("the digest signs purpose, contact, address and expiry",
    parts[3] === crypto.createHmac("sha256", "check-jwt-secret").update("confirm:" + contact.id + ":person@example.com:" + parts[2]).digest("base64url"));
  check("verifies for its address (any case), not another", b.api.verifyConsentConfirmToken(tok, "Person@Example.com") === true &&
    b.api.verifyConsentConfirmToken(tok, "other@example.com") === false);
  check("a confirm token is not an unsubscribe token", b.api.verifyUnsubscribeToken(tok) === null);
  const unsubTok = b.api.makeUnsubscribeToken(contact.id);
  check("an unsubscribe token is not a confirm token", b.api.readConsentConfirmToken(unsubTok) === null && b.api.verifyConsentConfirmToken(unsubTok, "person@example.com") === false);
  let total = true;
  for (const v of [null, undefined, 7, [], {}, ["c1"], Symbol("x"), "", ".", "c1...", "x".repeat(5000), { toString() { throw new Error("hostile"); } }]) {
    try { if (b.api.readConsentConfirmToken(v) !== null || b.api.verifyConsentConfirmToken(v, "person@example.com") !== false) total = false; } catch (e) { total = false; }
  }
  check("reading and verifying are total: odd values are null / false, never a throw", total);

  /* ── 5. GET writes nothing ────────────────────────────────────────────── */
  console.log("\n══ 5. GET /api/confirm changes nothing ══");
  const getCases = [
    ["a genuine token", tok, true],
    ["an expired token", tokenWith(b.api, contact.id, "person@example.com", minusSecs(5)), false],
    ["a malformed token", "not-a-token", false],
    ["an unsubscribe token", unsubTok, false],
    ["no token", undefined, false],
    ["an array", ["x"], false]
  ];
  for (const [label, t, ask] of getCases) {
    const before = b.db.log.length;
    res = await b.confirmGet(t);
    check("GET with " + label + ": 200 and no database call at all", res.code === 200 && b.db.log.length === before, res.code + " " + (b.db.log.length - before));
    if (ask) {
      check("GET with " + label + ": a Confirm button that POSTs the token to /api/confirm",
        /<form method="post" action="\/api\/confirm"/.test(res.body) && res.body.includes('name="token" value="' + tok + '"') && />\s*Confirm\s*<\/button>/.test(res.body), res.body);
    } else {
      check("GET with " + label + ": a plain message and no button", !/<form|<button/.test(res.body) && /not valid/.test(res.body), res.body);
    }
  }
  check("still only the grant in the ledger", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\"]", b.consentOf(contact.id));

  /* ── 6. POST confirms, and only for a genuine token ──────────────────── */
  console.log("\n══ 6. POST /api/confirm ══");
  const refusedTokens = [
    ["an expired token", tokenWith(b.api, contact.id, "person@example.com", minusSecs(1))],
    ["a tampered digest", tok.slice(0, -1) + (tok.slice(-1) === "A" ? "B" : "A")],
    ["a re-dated token (expiry pushed out, digest kept)", parts.slice(0, 2).concat([String(Number(parts[2]) + 86400), parts[3]]).join(".")],
    ["an unsubscribe token", unsubTok],
    ["a token for a different address", tokenWith(b.api, contact.id, "someone-else@example.com", Number(parts[2]))],
    ["a token signed with another secret", "c1." + contact.id + "." + parts[2] + "." + crypto.createHmac("sha256", "wrong").update("confirm:" + contact.id + ":person@example.com:" + parts[2]).digest("base64url")],
    ["a malformed token", "c1." + contact.id + ".abc.def"],
    ["an object", { token: "x" }],
    ["no token", undefined]
  ];
  for (const [label, t] of refusedTokens) {
    const before = writesOf(b.db.log, "consent_events").length;
    res = await b.confirmPost(t);
    check("POST with " + label + ": writes nothing, shows a plain message",
      writesOf(b.db.log, "consent_events").length === before && res.code === 200 && /not valid/.test(res.body) && !res.error,
      res.code + " " + String(res.body).slice(0, 120) + " " + (res.error && res.error.message));
  }
  check("still only the grant in the ledger", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\"]", b.consentOf(contact.id));

  res = await b.confirmPost(tok, { ip: "198.51.100.9", headers: { "user-agent": "Mozilla/5.0 Confirmer" } });
  const confirmed = confirmations(b);
  check("POST with the genuine token writes exactly one confirmed row", confirmed.length === 1, JSON.stringify(b.db.tables.consent_events));
  check("…with the fields capture records: contact, email, confirm_link, page_url, ip, user agent",
    confirmed[0] && confirmed[0].contact_id === contact.id && confirmed[0].channel === "email" && confirmed[0].source === "confirm_link" &&
    confirmed[0].page_url === "https://bizforceai.net/confirm" && confirmed[0].ip_address === "198.51.100.9" && confirmed[0].user_agent === "Mozilla/5.0 Confirmer",
    JSON.stringify(confirmed[0]));
  check("…and the token is stored nowhere", !JSON.stringify(b.db.tables).includes(parts[3]));
  check("…and the page says so", res.code === 200 && /you are confirmed/.test(res.body), String(res.body).slice(0, 200));

  b.db.tables.contacts.find(c => c.id === contact.id).email = "new-address@example.com";
  const beforeMove = writesOf(b.db.log, "consent_events").length;
  res = await b.confirmPost(tok);
  check("the contact's address has changed since: the old link writes nothing", writesOf(b.db.log, "consent_events").length === beforeMove && /not valid/.test(res.body));
  b.db.tables.contacts.find(c => c.id === contact.id).email = "person@example.com";

  // confirming after an unsubscribe
  b = build(SRC);
  await b.capture("person@example.com");
  contact = b.contactOf("person@example.com");
  const tok2 = b.tokenFrom(b.sent[0]);
  await b.unsubscribe(b.api.makeUnsubscribeToken(contact.id));
  check("(the unsubscribe was recorded)", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\",\"revoked\"]", b.consentOf(contact.id));
  res = await b.confirmPost(tok2);
  check("confirming after revoked writes nothing", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\",\"revoked\"]", b.consentOf(contact.id));
  check("…and says the address has unsubscribed", res.code === 200 && /unsubscribed/.test(res.body), String(res.body).slice(0, 200));
  await b.capture("person@example.com");
  res = await b.confirmPost(tok2);
  check("a new form submission is what undoes it: the link then confirms", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\",\"revoked\",\"granted\",\"confirmed\"]", b.consentOf(contact.id));

  b = build(SRC);
  await b.capture("person@example.com");
  contact = b.contactOf("person@example.com");
  res = await b.unsubscribe(b.tokenFrom(b.sent[0]));
  check("an unsubscribe POST given a confirm token revokes nothing", JSON.stringify(b.consentOf(contact.id)) === "[\"granted\"]", b.consentOf(contact.id));

  for (const [label, fail] of [["the contact lookup fails", q => q.table === "contacts" && q.op === "select" && q.filters.some(f => f[1] === "id") ? { message: "down" } : null],
    ["the consent lookup fails", q => q.table === "consent_events" && q.op === "select" ? { message: "down" } : null]]) {
    const ok = build(SRC);
    await ok.capture("person@example.com");
    const t = ok.tokenFrom(ok.sent[0]);
    const bf = build(SRC, { seed: ok.db.tables, fail });
    res = await bf.confirmPost(t);
    check(label + ": writes nothing and says it was not recorded", confirmations(bf).length === 0 && /not recorded/.test(res.body) && !res.error, String(res.body).slice(0, 160));
  }
  b = build(SRC, { env: { RESEND_API_KEY: "re_test_key" } });
  res = await b.confirmPost(tok);
  check("JWT_SECRET unset: POST writes nothing and does not throw", confirmations(b).length === 0 && !res.error && res.code === 200);

  /* ── 7. who may receive marketing ─────────────────────────────────────── */
  console.log("\n══ 7. marketing requires confirmed ══");
  b = build(SRC);
  await b.capture("person@example.com");
  contact = b.contactOf("person@example.com");
  let m = await b.marketing(contact.id);
  check("granted (unconfirmed): refused with not_confirmed, nothing sent",
    m.error && m.error.code === "marketing_refused" && m.error.reason === "not_confirmed" && b.sent.length === 1, m.error ? m.error.reason : JSON.stringify(m.result));
  await b.confirmPost(b.tokenFrom(b.sent[0]));
  m = await b.marketing(contact.id);
  check("confirmed: marketing sends", !m.error && m.result && m.result.sent === true && b.sent.length === 2 && b.sent[1].to === "person@example.com",
    m.error ? m.error.reason + " " + m.error.message : JSON.stringify(m.result));
  await b.capture("person@example.com");
  m = await b.marketing(contact.id);
  check("a new grant after confirmed: refused again with not_confirmed", m.error && m.error.reason === "not_confirmed", m.error ? m.error.reason : "sent");
  await b.confirmPost(b.tokenFrom(b.sent[0]));
  m = await b.marketing(contact.id);
  check("…until reconfirmed", !m.error && m.result && m.result.sent === true, m.error && m.error.reason);
  await b.unsubscribe(b.api.makeUnsubscribeToken(contact.id));
  m = await b.marketing(contact.id);
  check("an unsubscribe after confirmed: refused with no_consent", m.error && m.error.reason === "no_consent", m.error ? m.error.reason : "sent");
  const nb = build(SRC, { seed: { contacts: [{ id: "c-none", owner_id: OWNER, email: "none@example.com" }] } });
  m = await nb.marketing("c-none");
  check("no consent row: refused with no_consent", m.error && m.error.reason === "no_consent", m.error ? m.error.reason : "sent");
  const fb = build(SRC, { seed: b.db.tables, fail: q => q.table === "consent_events" && q.op === "select" ? { message: "down" } : null });
  m = await fb.marketing(contact.id);
  check("consent unreadable: refused with no_consent", m.error && m.error.reason === "no_consent", m.error ? m.error.reason : "sent");

  const seedConfirmed = { contacts: [{ id: "c-1", owner_id: OWNER, email: "a@example.com" }], consent_events: [{ id: "e1", contact_id: "c-1", channel: "email", action: "confirmed", occurred_at: "1" }] };
  const MSGX = { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" };
  const now = build(SRC, { seed: seedConfirmed }), then = build(OLD, { seed: seedConfirmed, routes: [] });
  const rn = await now.api.sendEmail(Object.assign({}, MSGX)), rt = await then.api.sendEmail(Object.assign({}, MSGX));
  check("sendEmail's own consent check accepts confirmed (at " + BEFORE + " it refused)", rn.sent === true && rt.sent === false && rt.reason === "no_consent",
    JSON.stringify([rn, rt]));

  /* ── 8. transactional sends, against BEFORE ───────────────────────────── */
  console.log("\n══ 8. transactional sends, byte-identical to " + BEFORE + " ══");
  const ev = (action) => ({ contacts: [{ id: "c-1", owner_id: OWNER, email: "a@example.com" }], consent_events: action ? [{ id: "e1", contact_id: "c-1", channel: "email", action, occurred_at: "1" }] : [] });
  const cases = [
    ["verification (skipConsentCheck)", { contactId: "c-1", to: "a@example.com", subject: "Confirm your email for BizForce AI", html: "<p>v</p>", text: "v", template: "email_verification", skipConsentCheck: true }, {}],
    ["password reset (skipConsentCheck)", { contactId: "c-1", to: "a@example.com", subject: "Reset your BizForce AI password", html: "<p>r</p>", text: "r", template: "password_reset", skipConsentCheck: true }, {}],
    ["password reset, contact revoked", { contactId: "c-1", to: "a@example.com", subject: "Reset", html: "<p>r</p>", text: "r", template: "password_reset", skipConsentCheck: true }, { seed: ev("revoked") }],
    ["consent-checked, granted", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { seed: ev("granted") }],
    ["consent-checked, revoked", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { seed: ev("revoked") }],
    ["consent-checked, no row", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { seed: ev(null) }],
    ["consent-checked, lookup fails", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { fail: q => q.table === "consent_events" ? { message: "down" } : null }],
    ["no contactId", { to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, {}],
    ["ledger insert fails", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { fail: q => q.table === "email_sends" && q.op === "insert" ? { message: "x" } : null }],
    ["provider error", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { providerError: true }],
    ["provider throws", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { providerThrows: true }],
    ["no API key", { contactId: "c-1", to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { env: { JWT_SECRET: "check-jwt-secret" } }]
  ];
  for (const [name, opts, o] of cases) {
    const before = build(OLD, Object.assign({ routes: [] }, o)), after = build(SRC, Object.assign({ routes: [] }, o));
    const rb = await before.api.sendEmail(JSON.parse(JSON.stringify(opts)));
    const ra = await after.api.sendEmail(JSON.parse(JSON.stringify(opts)));
    const shape = (x) => JSON.stringify([x.r, x.b.sent, x.b.db.log.map(q => [q.table, q.op, q.cols, q.opts, q.payload, q.filters])]);
    check(name + ": result, Resend call and database traffic identical", shape({ r: ra, b: after }) === shape({ r: rb, b: before }),
      JSON.stringify([ra, after.sent.length]) + " vs " + JSON.stringify([rb, before.sent.length]));
  }

  /* ── 9. the wiring ────────────────────────────────────────────────────── */
  console.log("\n══ 9. the wiring ══");
  check("server.js still calls Resend in exactly one place (sendEmail)", (SRC.match(/\.emails\.send\(/g) || []).length === 1);
  check("sendConsentConfirmation is called once, from the capture route",
    (SRC.match(/\bsendConsentConfirmation\(/g) || []).length === 2 && routeText(SRC, "post", "/api/contacts/capture").includes("sendConsentConfirmation("));
  // Send approved sequences, one due step at a time: its one caller, named.
  check("sendMarketingEmail is called only by runEmailSequencePass", JSON.stringify(sendMarketingEmailCallers(SRC)) === JSON.stringify(["runEmailSequencePass"]),
    JSON.stringify(sendMarketingEmailCallers(SRC)));
  check("the confirmation goes through sendEmail with skipConsentCheck and template consent_confirmation",
    /return sendEmail\(\{[\s\S]{0,400}template:\s+CONSENT_CONFIRMATION_TEMPLATE,\s+skipConsentCheck: true/.test(definitionOf(SRC, "sendConsentConfirmation") || ""));
  check("the only \"confirmed\" write is recordEmailConfirmation, reached only from POST /api/confirm",
    (SRC.match(/action:\s+"confirmed"/g) || []).length === 1 && (SRC.match(/\brecordEmailConfirmation\(/g) || []).length === 2 &&
    routeText(SRC, "post", "/api/confirm").includes("recordEmailConfirmation(") && !routeText(SRC, "get", "/api/confirm").includes("recordEmailConfirmation("));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
