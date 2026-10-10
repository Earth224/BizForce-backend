"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMarketingEmail — marketing email cannot leave without its gates, and
   transactional email is exactly what it was.

   sendMarketingEmail, sendEmail and the Resend webhook are lifted from
   server.js and run in a vm. Resend is a class that records what it is asked
   to send and sends nothing; Supabase is a recorder answering from a plan.
   No network, no model, no rows, no mail.

   WHAT THIS PROVES
     1. Each refusal throws code "marketing_refused" with its reason, makes no
        Resend call and writes no email_sends row: postal address unset and
        blank; consent absent, revoked and unreadable; consent granted but not
        confirmed (not_confirmed, before any other gate); a complaint; a permanent
        bounce; a bounce whose type is unreadable, empty, or neither Permanent
        nor Transient; a bounce found only by the address (another contact, other
        case); a history lookup that fails; the cap reached; the count unreadable
        or missing; a malformed cap ("abc", "0", "-5", "2.5"); a body missing.
     2. The order: no postal address refuses before any database read; no
        consent refuses before the contact, history or count is read.
     3. What passes: a temporary bounce alone; the cap minus one (and the
        default 50 when unset); the mail goes to the CONTACT's address with
        template "marketing:<name>", the unsubscribe link and the postal address
        in BOTH bodies (escaped in HTML), the List-Unsubscribe headers as before,
        and a link whose token verifyUnsubscribeToken resolves to the contact.
     4. Transactional sends are byte-identical to BEFORE: the same Resend call
        and the same database traffic, with and without the consent check, with
        MAIL_POSTAL_ADDRESS set and unset, and on the refusal paths.
     5. The webhook keeps the bounce type: Permanent, Transient and a missing
        type are written as "[bounce type=… subtype=…] <message>" and read back
        as permanent, temporary and unknown; a complaint is handled exactly as
        at BEFORE; an unset RESEND_WEBHOOK_SECRET still refuses with 403 and no
        database work.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { execSync, spawnSync } = require("child_process");
const { Webhook } = require("svix");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const BEFORE = "f516f8c";
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the bounce history is never consulted
  "skip-bounce-check": [["    if (history[i].status === \"bounced\") {", "    if (false) {"]],
  // a bounce of unknown type is treated as safe
  "unknown-bounce-safe": [["      if (bounceType !== \"temporary\") {", "      if (bounceType === \"permanent\") {"]],
  // a count that could not be read lets the send through
  "failed-count-sends": [["    if (counted.error || typeof counted.count !== \"number\") {", "    if (false) {"]],
  // a malformed cap falls back to the default
  "default-malformed-cap": [["    return parsed;\n  }\n  return null;\n}\n\n// A bounce field", "    return parsed;\n  }\n  return EMAIL_MARKETING_DEFAULT_DAILY_CAP;\n}\n\n// A bounce field"]],
  // the postal address is dropped from both bodies
  "drop-postal": [["      '<p style=\"margin:0\">' + escapeHtml(postal).replace(/\\r?\\n/g, \"<br>\") + '</p>' +\n", ""],
    ["\"Unsubscribe: \" + unsubscribeUrl + \"\\n\" + postal;", "\"Unsubscribe: \" + unsubscribeUrl;"]],
  // the unsubscribe link is dropped from both bodies
  "drop-body-unsubscribe": [["      '<a href=\"' + escapeHtml(unsubscribeUrl) + '\" style=\"color:#6b6b80\">Unsubscribe</a></p>' +\n", "      '</p>' +\n"],
    ["\"Unsubscribe: \" + unsubscribeUrl + \"\\n\" + postal;", "postal;"]],
  // the marketing gates reach transactional mail
  "gates-on-transactional": [["    if (opts.skipConsentCheck !== true) {\n      if (!(await emailConsentGranted(contactId))) {",
    "    if (!String(process.env.MAIL_POSTAL_ADDRESS || \"\").trim()) { return { sent: false, reason: \"no_postal_address\" }; }\n    if (opts.skipConsentCheck !== true) {\n      if (!(await emailConsentGranted(contactId))) {"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(24) + " " + fails.length + " failing check(s)" +
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

/* _shared.definitionOf, uncached. Its cache keys every source that is not the
   working tree as one, and this check holds two of those at once — a mutated
   server.js and BEFORE — so the same lookup is repeated here without it. */
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
const CLOSURES = new Map();
function closure(src, root) {
  const key = (src === SRC ? "S:" : "O:") + root;
  if (!CLOSURES.has(key)) CLOSURES.set(key, closureRaw(src, root));
  return CLOSURES.get(key);
}
const DEFS = new Map();
function definitionOfCached(src, name) {
  const key = (src === SRC ? "S:" : "O:") + name;
  if (!DEFS.has(key)) DEFS.set(key, definitionOf(src, name));
  return DEFS.get(key);
}
function closureRaw(src, root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "Resend", "SvixWebhook", "express", "app", "crypto", "Buffer", "setTimeout"]);
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOfCached(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => src.indexOf(x) - src.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function webhookRoute(src) {
  const start = src.indexOf('app.post(\n  "/api/webhooks/resend",');
  if (start < 0) throw new Error("webhook route not found");
  const fn = src.indexOf("async function (req, res) {", start);
  const end = s.braceMatch(src, src.indexOf("{", fn));
  if (src.slice(end, end + 3) !== "\n);") throw new Error("webhook route did not end where expected");
  return src.slice(start, end + 3);
}

/* ── the fakes ──────────────────────────────────────────────────────────── */
function fakeDb(plan) {
  const log = [];
  function answer(q) {
    if (q.table === "consent_events" && q.op === "select") {
      return plan.consentError ? { data: null, error: { message: "consent read failed" } } : { data: plan.consent || [], error: null };
    }
    if (q.table === "consent_events" && q.op === "insert") return { data: null, error: null };
    if (q.table === "contacts") {
      return plan.contactError ? { data: null, error: { message: "contact read failed" } } : { data: plan.contact === undefined ? null : plan.contact, error: null };
    }
    if (q.table === "email_sends" && q.op === "insert") {
      return plan.insertError ? { data: null, error: { message: "insert failed" } } : { data: { id: "send-row-1" }, error: null };
    }
    if (q.table === "email_sends" && q.op === "update") return { data: null, error: null };
    if (q.table === "email_sends" && q.opts && q.opts.head) {
      if (plan.countError) return { data: null, count: null, error: { message: "count failed" } };
      return { data: null, count: plan.count === undefined ? 0 : plan.count, error: null };
    }
    if (q.table === "email_sends" && q.filters.some(f => f[0] === "ilike")) {
      if (plan.byAddressError) return { data: null, error: { message: "address history failed" } };
      return { data: plan.byAddress || [], error: null };
    }
    if (q.table === "email_sends" && q.filters.some(f => f[0] === "eq" && f[1] === "contact_id")) {
      if (plan.byContactError) return { data: null, error: { message: "contact history failed" } };
      return { data: plan.byContact || [], error: null };
    }
    if (q.table === "email_sends" && q.filters.some(f => f[0] === "eq" && f[1] === "provider_id")) {
      return { data: plan.webhookRow ? [plan.webhookRow] : [], error: null };
    }
    return { data: null, error: { message: "unplanned query on " + q.table } };
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [] };
    log.push(q);
    const b = {
      select(cols, opts) { q.cols = cols; if (opts) q.opts = opts; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "in", "ilike", "like", "gte", "order", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => Promise.resolve(answer(q));
    b.then = (res, rej) => Promise.resolve(answer(q)).then(res, rej);
    return b;
  }
  return { log, client: { from } };
}

function build(src, root, plan, env) {
  const db = fakeDb(plan || {});
  const sent = [], logs = [];
  class Resend {
    constructor(key) { this.key = key; this.emails = { send: async (args) => { sent.push(JSON.parse(JSON.stringify(args))); return plan && plan.providerError ? { data: null, error: { message: "provider said no" } } : { data: { id: "re_123" }, error: null }; } }; }
  }
  const ctx = {
    supabase: db.client, Resend, SvixWebhook: Webhook, crypto, Buffer, URL, Date, JSON, Math, Promise,
    express: { raw: () => "raw" }, nowIso: () => "2026-10-09T12:00:00.000Z", require,
    process: { env: Object.assign({ RESEND_API_KEY: "re_test_key", JWT_SECRET: "check-jwt-secret" }, env || {}) },
    console: { log: m => logs.push(String(m)), error: m => logs.push(String(m)), warn: m => logs.push(String(m)) }
  };
  let handler = null;
  ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(closure(src, root), ctx);
  return { api: ctx.api, handler, db, sent, logs, ctx };
}

const CONTACT = "3f1c2b8a-1111-4222-8333-444455556666";
const OWNER = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";
const POSTAL = "BizForce AI\n123 Example Street, Suite 4 & 5\nSpringfield, ST 00000";
// The baseline contact is CONFIRMED: marketing requires the latest email
// consent to be "confirmed" (double opt-in), so every gate after consent runs.
const GOOD = {
  consent: [{ action: "confirmed" }],
  contact: { id: CONTACT, email: "Person@Example.com", owner_id: OWNER },
  byAddress: [], byContact: [], count: 0
};
const MSG = { contactId: CONTACT, subject: "Spring news", html: "<p>Hello</p>", text: "Hello", template: "spring-news" };
const ROOT = "this.api = { sendEmail: sendEmail, sendMarketingEmail: sendMarketingEmail, verifyUnsubscribeToken: verifyUnsubscribeToken, emailBounceTypeOf: emailBounceTypeOf, emailBounceToken: emailBounceToken };";
const plan = (over) => Object.assign({}, GOOD, over || {});
const ENV = { MAIL_POSTAL_ADDRESS: POSTAL };

async function marketing(planOver, env, msg) {
  const b = build(SRC, ROOT, plan(planOver), env === undefined ? ENV : env);
  let result = null, error = null;
  try { result = await b.api.sendMarketingEmail(Object.assign({}, MSG, msg || {})); } catch (e) { error = e; }
  const claimsSent = b.db.log.some(q => q.table === "email_sends" && (q.op === "insert" || (q.op === "update" && q.payload && q.payload.status === "sent")));
  return { b, result, error, claimsSent };
}
function refused(label, r, reason) {
  check(label + ": refuses with reason " + reason, r.error && r.error.code === "marketing_refused" && r.error.reason === reason,
    r.error ? r.error.code + "/" + r.error.reason + " " + r.error.message : "no throw; result " + JSON.stringify(r.result));
  check(label + ": no Resend call", r.b.sent.length === 0, r.b.sent.length);
  check(label + ": no email_sends row written or marked sent", !r.claimsSent);
}
const bounce = (id, type, subtype, msg, extra) => Object.assign({ id, to_email: "person@example.com", status: "bounced",
  error_message: "[bounce type=" + type + " subtype=" + (subtype || "General") + "] " + (msg || "bounced") }, extra || {});

(async function main() {
  /* ── 1 & 2. refusals and their order ─────────────────────────────────── */
  console.log("\n══ 1. the refusals ══");
  let r = await marketing({}, {});
  refused("MAIL_POSTAL_ADDRESS unset", r, "no_postal_address");
  check("MAIL_POSTAL_ADDRESS unset: refused before any database read", r.b.db.log.length === 0, r.b.db.log.map(q => q.table).join(","));
  r = await marketing({}, { MAIL_POSTAL_ADDRESS: "   " });
  refused("MAIL_POSTAL_ADDRESS blank", r, "no_postal_address");

  r = await marketing({ consent: [] });
  refused("no consent row", r, "no_consent");
  check("no consent: refused before the contact, history or count is read", r.b.db.log.every(q => q.table === "consent_events"), r.b.db.log.map(q => q.table).join(","));
  // A grant from a form that was never confirmed is not enough: refused with
  // not_confirmed before the contact, history or count is read, and no Resend call.
  r = await marketing({ consent: [{ action: "granted" }] });
  refused("latest consent granted but not confirmed", r, "not_confirmed");
  check("granted but not confirmed: refused before any other gate runs", r.b.db.log.every(q => q.table === "consent_events"), r.b.db.log.map(q => q.table).join(","));
  refused("latest consent revoked", await marketing({ consent: [{ action: "revoked" }] }), "no_consent");
  refused("consent lookup fails", await marketing({ consentError: true }), "no_consent");

  refused("a complained row", await marketing({ byContact: [{ id: "c1", to_email: "person@example.com", status: "complained", error_message: null }] }), "suppressed");
  refused("a permanent bounce", await marketing({ byContact: [bounce("b1", "Permanent")] }), "suppressed");
  refused("a bounce with no type bracket (written before types were kept)", await marketing({ byContact: [{ id: "b2", to_email: "person@example.com", status: "bounced", error_message: "Mailbox does not exist" }] }), "suppressed");
  refused("a bounce with an empty type", await marketing({ byContact: [bounce("b3", "")] }), "suppressed");
  refused("a bounce of type Undetermined", await marketing({ byContact: [bounce("b4", "Undetermined")] }), "suppressed");
  refused("a bounce with a null error_message", await marketing({ byContact: [{ id: "b5", to_email: "person@example.com", status: "bounced", error_message: null }] }), "suppressed");
  refused("a permanent bounce found only by address, other contact, other case",
    await marketing({ byAddress: [bounce("b6", "Permanent", "General", "gone", { to_email: "PERSON@example.COM" })] }), "suppressed");
  refused("a complaint found only by address", await marketing({ byAddress: [{ id: "c2", to_email: "person@example.com", status: "complained", error_message: null }] }), "suppressed");
  refused("address history lookup fails", await marketing({ byAddressError: true }), "lookup_failed");
  refused("contact history lookup fails", await marketing({ byContactError: true }), "lookup_failed");
  refused("a permanent bounce alongside a temporary one", await marketing({ byContact: [bounce("t0", "Transient"), bounce("b7", "Permanent")] }), "suppressed");

  refused("cap reached (default 50, count 50)", await marketing({ count: 50 }), "cap_reached");
  refused("cap reached (cap 3, count 3)", await marketing({ count: 3 }, Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: "3" })), "cap_reached");
  refused("count unreadable", await marketing({ countError: true }), "count_failed");
  refused("count missing from the answer", await marketing({ count: null }), "count_failed");
  for (const bad of ["abc", "0", "-5", "2.5"]) {
    const rr = await marketing({}, Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: bad }));
    refused("EMAIL_MARKETING_DAILY_CAP=" + JSON.stringify(bad), rr, "cap_unreadable");
    check("EMAIL_MARKETING_DAILY_CAP=" + JSON.stringify(bad) + ": the count is never read", !rr.b.db.log.some(q => q.opts && q.opts.head));
  }
  refused("contact unreadable", await marketing({ contactError: true }), "lookup_failed");
  refused("contact has no owner", await marketing({ contact: { id: CONTACT, email: "person@example.com", owner_id: null } }), "no_owner");
  refused("no text body", await marketing({}, ENV, { text: "" }), "invalid");
  refused("no HTML body", await marketing({}, ENV, { html: "  " }), "invalid");
  refused("a template name that is not a short lowercase name", await marketing({}, ENV, { template: "Spring News!" }), "invalid");

  /* ── 3. what passes ───────────────────────────────────────────────────── */
  console.log("\n══ 3. what passes ══");
  r = await marketing({ byContact: [bounce("t1", "Transient", "MailboxFull")] });
  check("a temporary bounce alone does not refuse", !r.error && r.b.sent.length === 1, r.error && r.error.message);
  r = await marketing({ count: 2 }, Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: "3" }));
  check("cap minus one sends (cap 3, count 2)", !r.error && r.b.sent.length === 1, r.error && r.error.message);
  r = await marketing({ count: 49 }, Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: " " }));
  check("a blank cap is the default 50: count 49 sends", !r.error && r.b.sent.length === 1, r.error && r.error.message);
  const countQ = r.b.db.log.find(q => q.opts && q.opts.head);
  check("the count is the owner's marketing rows of the last 24 hours",
    countQ && countQ.filters.some(f => f[0] === "like" && f[1] === "template" && f[2] === "marketing:%") &&
    countQ.filters.some(f => f[0] === "eq" && f[1] === "contacts.owner_id" && f[2] === OWNER) &&
    countQ.filters.some(f => f[0] === "gte" && f[1] === "created_at" && Math.abs(Date.now() - 864e5 - Date.parse(f[2])) < 60000),
    countQ && JSON.stringify(countQ.filters));

  r = await marketing({});
  const call = r.b.sent[0] || {};
  check("a successful send: one Resend call, result sent", !r.error && r.b.sent.length === 1 && r.result && r.result.sent === true, r.error && r.error.message);
  check("it goes to the contact's own address", call.to === "Person@Example.com", call.to);
  const ins = r.b.db.log.find(q => q.table === "email_sends" && q.op === "insert");
  check("the email_sends row carries template marketing:spring-news", ins && ins.payload.template === "marketing:spring-news", ins && ins.payload.template);
  const url = "https://bizforceai.net/unsubscribe?token=";
  const m = /https:\/\/bizforceai\.net\/unsubscribe\?token=([A-Za-z0-9_.-]+)/.exec(call.text || "");
  check("the text body carries the unsubscribe link", !!m, call.text);
  check("the HTML body carries the same link", m && call.html.includes('<a href="' + url + m[1] + '"'), call.html);
  check("the link's token verifies to the contact", m && r.b.api.verifyUnsubscribeToken(m[1]) === CONTACT);
  check("the text body carries the postal address exactly", (call.text || "").endsWith("\n" + POSTAL), call.text);
  check("the HTML body carries the postal address, escaped, lines broken",
    (call.html || "").includes("BizForce AI<br>123 Example Street, Suite 4 &amp; 5<br>Springfield, ST 00000"), call.html);
  check("the original bodies come first, unchanged", call.html.startsWith("<p>Hello</p>") && call.text.startsWith("Hello\n\n--\n"));
  check("headers as before: List-Unsubscribe is the same link, and One-Click",
    m && JSON.stringify(call.headers) === JSON.stringify({ "List-Unsubscribe": "<" + url + m[1] + ">", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" }), JSON.stringify(call.headers));
  check("from address unchanged", call.from === "BizForce AI <hello@mail.bizforceai.net>");
  check("consent is checked again by sendEmail on the way out", r.b.db.log.filter(q => q.table === "consent_events").length === 2);
  r = await marketing({ consent: [{ action: "confirmed" }] }, ENV, { contactId: CONTACT, to: "attacker@example.com" });
  check("a caller-supplied `to` is ignored", (r.b.sent[0] || {}).to === "Person@Example.com", (r.b.sent[0] || {}).to);

  /* ── 4. transactional sends, against BEFORE ───────────────────────────── */
  console.log("\n══ 4. transactional sends, byte-identical to " + BEFORE + " ══");
  const TX_ROOT = "this.api = { sendEmail: sendEmail };";
  const cases = [
    ["verification (skipConsentCheck)", { contactId: CONTACT, to: "a@example.com", subject: "Confirm your email for BizForce AI", html: "<p>v</p>", text: "v", template: "email_verification", skipConsentCheck: true }, {}],
    ["password reset (skipConsentCheck)", { contactId: CONTACT, to: "a@example.com", subject: "Reset your BizForce AI password", html: "<p>r</p>", text: "r", template: "password_reset", skipConsentCheck: true }, {}],
    ["consent-checked, granted", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { consent: [{ action: "granted" }] }],
    ["consent-checked, revoked", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { consent: [{ action: "revoked" }] }],
    ["consent-checked, lookup fails", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "x" }, { consentError: true }],
    ["no contactId", { to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, {}],
    ["ledger insert fails", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { insertError: true }],
    ["provider error", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "x", skipConsentCheck: true }, { providerError: true }],
    ["bounced and complained history present (must not matter)", { contactId: CONTACT, to: "a@example.com", subject: "s", html: "h", text: "t", template: "password_reset", skipConsentCheck: true }, { byContact: [bounce("b9", "Permanent")], count: 999 }]
  ];
  for (const envName of ["MAIL_POSTAL_ADDRESS unset", "MAIL_POSTAL_ADDRESS set, cap malformed"]) {
    const env = envName.startsWith("MAIL_POSTAL_ADDRESS unset") ? {} : { MAIL_POSTAL_ADDRESS: POSTAL, EMAIL_MARKETING_DAILY_CAP: "abc" };
    for (const [name, opts, p] of cases) {
      const before = build(OLD, TX_ROOT, p, env), after = build(SRC, TX_ROOT, p, env);
      const rb = await before.api.sendEmail(JSON.parse(JSON.stringify(opts)));
      const ra = await after.api.sendEmail(JSON.parse(JSON.stringify(opts)));
      const same = JSON.stringify([rb, before.sent, before.db.log]) === JSON.stringify([ra, after.sent, after.db.log]);
      check(name + " [" + envName + "]: result, Resend call and database traffic identical", same,
        JSON.stringify([ra, after.sent.length, after.db.log.map(q => q.table + ":" + q.op)]) + " vs " + JSON.stringify([rb, before.sent.length, before.db.log.map(q => q.table + ":" + q.op)]));
    }
  }

  /* ── 5. the webhook keeps the bounce type ─────────────────────────────── */
  console.log("\n══ 5. the webhook ══");
  const SECRET = "whsec_" + Buffer.from("check-marketing-email-secret-32b").toString("base64");
  async function deliver(src, event, env) {
    const b = build(src, webhookRoute(src), { webhookRow: { id: "row-7", contact_id: CONTACT, to_email: "person@example.com", status: "sent" } },
      env === undefined ? { RESEND_WEBHOOK_SECRET: SECRET } : env);
    const body = JSON.stringify(event);
    const id = "msg_" + crypto.randomBytes(6).toString("hex");
    const ts = new Date();
    const sig = new Webhook(SECRET).sign(id, ts, body);
    const headers = { "svix-id": id, "svix-timestamp": String(Math.floor(ts.getTime() / 1000)), "svix-signature": sig };
    const res = { code: 200, body: null, status(c) { this.code = c; return this; }, type() { return this; }, send(x) { this.body = x; return this; }, json(x) { this.body = x; return this; } };
    await b.handler({ get: h => headers[h.toLowerCase()], body: Buffer.from(body), ip: "127.0.0.1" }, res);
    return { b, res, update: b.db.log.find(q => q.table === "email_sends" && q.op === "update") };
  }
  const api = build(SRC, ROOT, GOOD, ENV).api;
  const ev = (bounceObj) => ({ type: "email.bounced", created_at: "2026-10-09T00:00:00Z", data: { email_id: "re_123", to: ["person@example.com"], bounce: bounceObj } });
  let w = await deliver(SRC, ev({ message: "Mailbox does not exist", subType: "General", type: "Permanent" }));
  check("a Permanent bounce is stored with its type", w.update && w.update.payload.status === "bounced" &&
    w.update.payload.error_message === "[bounce type=Permanent subtype=General] Mailbox does not exist", w.update && JSON.stringify(w.update.payload));
  check("…and reads back as permanent", api.emailBounceTypeOf(w.update && w.update.payload.error_message) === "permanent");
  w = await deliver(SRC, ev({ message: "Mailbox full", subType: "MailboxFull", type: "Transient" }));
  check("a Transient bounce is stored with its type and reads back as temporary",
    w.update && w.update.payload.error_message === "[bounce type=Transient subtype=MailboxFull] Mailbox full" &&
    api.emailBounceTypeOf(w.update.payload.error_message) === "temporary", w.update && JSON.stringify(w.update.payload));
  w = await deliver(SRC, ev({ message: "something" }));
  check("a bounce with no type is stored with an empty type and reads back as unknown",
    w.update && w.update.payload.error_message === "[bounce type= subtype=] something" && api.emailBounceTypeOf(w.update.payload.error_message) === "unknown",
    w.update && JSON.stringify(w.update.payload));
  w = await deliver(SRC, ev({ message: "x", subType: "a] [bounce type=Transient", type: "Permanent] x" }));
  check("a payload cannot forge the bracket", w.update && api.emailBounceTypeOf(w.update.payload.error_message) === "unknown" &&
    !/\] \[/.test(w.update.payload.error_message.slice(0, 60)), w.update && w.update.payload.error_message);
  w = await deliver(SRC, { type: "email.bounced", data: { email_id: "re_123" } });
  check("a bounce with no bounce object still stores a bracket that reads as unknown",
    w.update && api.emailBounceTypeOf(w.update.payload.error_message) === "unknown", w.update && JSON.stringify(w.update.payload));
  const complaint = { type: "email.complained", created_at: "2026-10-09T00:00:00Z", data: { email_id: "re_123", to: ["person@example.com"] } };
  const wa = await deliver(SRC, complaint), wb = await deliver(OLD, complaint);
  check("a complaint is handled exactly as at " + BEFORE + " (status, revocation)",
    JSON.stringify(wa.b.db.log.map(q => [q.table, q.op, q.payload])) === JSON.stringify(wb.b.db.log.map(q => [q.table, q.op, q.payload])) && wa.res.code === 200,
    JSON.stringify(wa.b.db.log.map(q => [q.table, q.op, q.payload])));
  w = await deliver(SRC, ev({ message: "m", type: "Permanent" }), {});
  check("RESEND_WEBHOOK_SECRET unset: 403 and no database work", w.res.code === 403 && w.b.db.log.length === 0, w.res.code + " " + w.b.db.log.length);
  const wo = await deliver(OLD, ev({ message: "Mailbox does not exist", subType: "General", type: "Permanent" }));
  check("(at " + BEFORE + " the type was lost: error_message was the message alone)", wo.update && wo.update.payload.error_message === "Mailbox does not exist");

  /* ── the wiring ───────────────────────────────────────────────────────── */
  console.log("\n══ 6. the wiring ══");
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
  // Send approved sequences, one due step at a time: defined once, one caller, named.
  const callers = sendMarketingEmailCallers(SRC);
  check("sendMarketingEmail is defined once and called only by runEmailSequencePass",
    (SRC.match(/^async function sendMarketingEmail\(/gm) || []).length === 1 && JSON.stringify(callers) === JSON.stringify(["runEmailSequencePass"]), JSON.stringify(callers));
  const sendSites = (SRC.match(/\.emails\.send\(/g) || []).length;
  check("server.js still calls Resend in exactly one place (sendEmail)", sendSites === 1, sendSites);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
