"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCardLeads — Card upgrades C2 (migration 172, Nov 6 2026): an opt-in
   lead form on a digital card, with consent recorded, spam defences that need
   no third party, per-card caps, the owner's Leads list and 12-month
   retention. Nothing about a visitor's device is stored.

   server.js's lead routes, the card routes they touch and their helpers are
   lifted and run in a vm against an in-memory database, a stubbed plan
   lookup and a fixed clock. lib/cardLeads.js, lib/cardPage.js and
   lib/legalPages.js run for real, compiled from their (possibly mutated)
   text. card-view.html and the editor's Leads list run in jsdom. Every socket
   and DNS lookup is a tripwire.

   WHAT THIS PROVES
     A. The switch: lead_form_on is a boolean on POST and PUT, off by default.
     B. The public card: lead_form false with no token when off; true with
        form_token and form_issued_at, and Cache-Control no-store, when on.
     K. The token: HMAC-SHA256 over "card-lead|<id>|<issued at>", keyed by
        HKDF of JWT_SECRET with the label bizforce-card-lead-form-v1, never
        the raw secret; 3 seconds to 2 hours, both edges; this card only;
        compared with crypto.timingSafeEqual.
     P. The honeypot: answered exactly as a success, nothing stored or sent.
     V. Validation and its messages; control characters stripped.
     C. Consent: required, and its sentence built on the server.
     L. The caps: 5 an hour and 20 a day, at the exact edges.
     D. The dedupe: same email or phone in 24 hours, answered as a success.
     N. Nothing about the visitor stored or logged; no Set-Cookie.
     O. The notice: at most one an hour, with no lead details.
     W. The owner routes: ownership, paging, statuses, delete.
     U. The purge: 12 months, at the edge; its claim and its cron.
     F. The card page's form: hidden unless on, the honeypot hidden, the
        lines word for word, server messages as text.
     E. The editor's Leads list: textContent, links through telHref and
        mailtoHref, Delete asks first.
     S. The generated shell is in sync with card-view.html.
     G. The legal sentences in source and in the built pages.
     R. The migration as run, its patterns, and the registries.
     Z. Zero network.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module"), net = require("net"), dns = require("dns"), crypto = require("crypto");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkCardLeads: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkCardLeads: no network"); };

// A spy on the constant-time comparison: the lib calls it through the shared crypto module.
const realTimingSafeEqual = crypto.timingSafeEqual;
let timingSafeCalls = 0;
crypto.timingSafeEqual = function (a, b) { timingSafeCalls++; return realTimingSafeEqual(a, b); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const BS = String.fromCharCode(92);

const SV = "server.js", CL = "lib/cardLeads.js", CP = "lib/cardPage.js", GEN = "lib/cardShell.generated.js", LP_FILE = "lib/legalPages.js", MIG = "supabase/migrations/172_card_leads.sql";
const CV = "fe:card-view.html", DC = "fe:digital-cards.html";

const MUTATIONS = {
  // a card whose owner left the form off takes a lead
  "form-when-off": [[SV, "    if (!leadCard || !leadOwnerPublic || leadCard.lead_form_on !== true) return res.status(404).json({ error: cardLeads.MESSAGES.notFound });",
    "    if (!leadCard || !leadOwnerPublic) return res.status(404).json({ error: cardLeads.MESSAGES.notFound });"]],
  // a lapsed owner's card takes a lead
  "form-for-lapsed": [[SV, "leadOwnerPublic = leadCard ? (await ownerPagePublic(leadCard.user_id)) === true : false;", "leadOwnerPublic = !!leadCard;"]],
  // an owner lookup that throws lets the lead in
  "lookup-throw-accepted": [[SV, "} catch (ownerErr) { leadOwnerPublic = false; }", "} catch (ownerErr) { leadOwnerPublic = true; }"]],
  // a filled honeypot is stored
  "honeypot-stored": [[SV, "    if (cardLeads.honeypotFilled(leadBody)) return res.status(200).json(leadSuccess);\n", ""]],
  // a filled honeypot is answered differently from a success
  "honeypot-distinguishable": [[SV, "    if (cardLeads.honeypotFilled(leadBody)) return res.status(200).json(leadSuccess);", "    if (cardLeads.honeypotFilled(leadBody)) return res.status(202).json({ ok: true });"]],
  // the form token is not checked
  "token-unchecked": [[SV, "    if (!cardLeads.checkFormToken(leadCard.id,", "    if (false && !cardLeads.checkFormToken(leadCard.id,"]],
  // a form sent in under 3 seconds is accepted
  "token-too-fast-accepted": [[CL, "  if (!(age >= FORM_MIN_AGE_MS && age <= FORM_MAX_AGE_MS)) return false;", "  if (!(age <= FORM_MAX_AGE_MS)) return false;"]],
  // a form older than 2 hours is accepted
  "token-expired-accepted": [[CL, "  if (!(age >= FORM_MIN_AGE_MS && age <= FORM_MAX_AGE_MS)) return false;", "  if (!(age >= FORM_MIN_AGE_MS)) return false;"]],
  // one card's token works on another card
  "token-other-card": [[CL, ".update(\"card-lead|\" + cardId + \"|\" + issuedAt)", ".update(\"card-lead|\" + issuedAt)"]],
  // the token is compared with ===
  "token-compare-not-timing-safe": [[CL, "  return crypto.timingSafeEqual(got, want);", "  return got.toString(\"utf8\") === want.toString(\"utf8\");"]],
  // the raw secret keys the HMAC
  "raw-secret-key": [[CL, "  return Buffer.from(crypto.hkdfSync(\"sha256\", Buffer.from(secret, \"utf8\"), Buffer.alloc(0), Buffer.from(FORM_KEY_INFO, \"utf8\"), 32));",
    "  return Buffer.from(secret, \"utf8\");"]],
  // a lead without the consent box is stored
  "consent-optional": [[CL, "  if (b.consent !== true) return { error: MESSAGES.consent };\n", ""]],
  // the consent sentence is taken from the request
  "consent-text-from-client": [[SV, "      consent_text: cardLeads.consentSentence(leadCard.full_name), status: \"new\",",
    "      consent_text: String(leadBody.consent_text || cardLeads.consentSentence(leadCard.full_name)), status: \"new\","]],
  // a lead with neither email nor phone is stored
  "contactless-accepted": [[CL, "  if (!email && !phone) return { error: MESSAGES.contact };\n", ""]],
  // any email text is stored
  "email-unvalidated": [[CL, "  if (email && (email.length > EMAIL_MAX || !EMAIL_RE.test(email))) return { error: MESSAGES.email };\n", ""]],
  // a message of any length is stored
  "message-uncapped": [[CL, "  if (m.value.length > MESSAGE_MAX) return { error: MESSAGES.message };\n", ""]],
  // no hourly cap
  "hour-cap-missing": [[CL, "  return hour >= HOUR_CAP || day >= DAY_CAP;", "  return day >= DAY_CAP;"]],
  // no daily cap
  "day-cap-missing": [[CL, "  return hour >= HOUR_CAP || day >= DAY_CAP;", "  return hour >= HOUR_CAP;"]],
  // the caps let one more through
  "cap-off-by-one": [[CL, "  return hour >= HOUR_CAP || day >= DAY_CAP;", "  return hour > HOUR_CAP || day > DAY_CAP;"]],
  // the same person is stored twice
  "dedupe-missing": [[SV, "    if (cardLeads.isDuplicate(recentLeads.data || [], checked.lead, leadNowMs)) return res.status(200).json(leadSuccess);\n", ""]],
  // the visitor's address is stored
  "ip-stored": [[SV, "      card_id: leadCard.id, user_id: leadCard.user_id,\n", "      card_id: leadCard.id, user_id: leadCard.user_id, ip: req.ip,\n"]],
  // the visitor's User-Agent is stored
  "ua-stored": [[SV, "      card_id: leadCard.id, user_id: leadCard.user_id,\n", "      card_id: leadCard.id, user_id: leadCard.user_id, user_agent: req.headers[\"user-agent\"],\n"]],
  // a notice for every lead
  "notice-every-lead": [[SV, "    if (!cardLeads.noticeDue(last && last.created_at, nowMs)) return;\n", ""]],
  // the notice carries the lead's details
  "notice-has-details": [[SV, "    await noticeCardLead(leadCard.user_id, leadNowMs);", "    await noticeCardLead(leadCard.user_id, leadNowMs, checked.lead);"],
    [SV, "      message: cardLeads.MESSAGES.noticeBody,", "      message: cardLeads.MESSAGES.noticeBody + (arguments[2] ? \" \" + arguments[2].name + \" \" + (arguments[2].email || arguments[2].phone) : \"\"),"]],
  // a member reads another member's leads
  "foreign-lead-visible": [[SV, "const leadsOwned = await supabase.from(\"digital_cards\").select(\"id\").eq(\"user_id\", req.user.id).eq(\"id\", leadsCardId).maybeSingle();",
    "const leadsOwned = await supabase.from(\"digital_cards\").select(\"id\").eq(\"id\", leadsCardId).maybeSingle();"],
    [SV, "      .eq(\"user_id\", req.user.id).eq(\"card_id\", leadsOwned.data.id);", "      .eq(\"card_id\", leadsOwned.data.id);"]],
  // a member deletes another member's lead
  "foreign-lead-deleted": [[SV, ".delete().eq(\"id\", leadId).eq(\"user_id\", req.user.id).select(\"id\");", ".delete().eq(\"id\", leadId).select(\"id\");"]],
  // the daily purge is not run
  "purge-missing": [[SV, "      cardLeads.cardLeadsPurgeTick(supabase).catch(function (err) {", "      Promise.resolve().catch(function (err) {"]],
  // the purge deletes leads younger than 12 months
  "purge-too-young": [[CL, "  d.setUTCMonth(d.getUTCMonth() - RETENTION_MONTHS);", "  d.setUTCMonth(d.getUTCMonth() - RETENTION_MONTHS + 1);"]],
  // the editor parses a lead's name as HTML
  "lead-unescaped": [[DC, "  who.textContent = String(lead.name || \"\");", "  who.innerHTML = String(lead.name || \"\");"]],
  // the honeypot is shown to people
  "honeypot-visible": [[CV, ".cv-lead-hp{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}", ".cv-lead-hp{}"]],
  // the Privacy Policy loses the card leads sentence
  "privacy-sentence-removed": [[LP_FILE, "      CARD_LEADS_PRIVACY_SENTENCE,\n", ""]],
  // ── earned by the code ──
  // the Terms lose the card leads sentence
  "terms-sentence-removed": [[LP_FILE, "    p(CARD_LEADS_TERMS_SENTENCE),\n", ""]],
  // a card with its form on may be cached
  "no-store-missing": [[SV, "  if (row && row.lead_form_on === true) res.set(\"Cache-Control\", \"no-store\");", "  if (false) res.set(\"Cache-Control\", \"no-store\");"]],
  // a token on a card whose form is off
  "token-when-off": [[SV, "  const form = row.lead_form_on === true ? cardLeads.issueFormToken(", "  const form = true ? cardLeads.issueFormToken("]],
  // the lead route is not rate-limited
  "lead-limiter-missing": [[SV, "app.post(\"/api/cards/lead\", cardLeadLimiter, async function", "app.post(\"/api/cards/lead\", async function"]],
  // the switch takes anything
  "switch-not-boolean": [[SV, "    if (typeof body.lead_form_on !== \"boolean\") return { error: \"Letting visitors leave their details is true or false.\" };\n", ""]],
  // control characters reach the database
  "control-chars-kept": [[CL, ".replace(/[" + BS + "u0000-" + BS + "u0009" + BS + "u000B-" + BS + "u001F" + BS + "u007F]/g, \"\")", ""]],
  // a page shows more than 50 leads
  "leads-page-unbounded": [[SV, "    const page = (leadRows.data || []).slice(0, cardLeads.LIST_PAGE);", "    const page = (leadRows.data || []);"]],
  // a lead may be given any status
  "status-any": [[SV, "    if (cardLeads.OWNER_STATUSES.indexOf(status) === -1) return res.status(400)", "    if (typeof status !== \"string\") return res.status(400)"]],
  // the editor builds its own mailto link
  "editor-links-raw": [[DC, "    e.appendChild(cardLeadLink(String(lead.email), window.bfCard.mailtoHref(lead.email)));", "    e.appendChild(cardLeadLink(String(lead.email), \"mailto:\" + lead.email));"]],
  // Delete does not ask first
  "delete-without-confirm": [[DC, "  if (!window.confirm(\"Delete this lead? This cannot be undone.\")) return;\n", ""]],
  // the card page parses a server message as HTML
  "page-message-unescaped": [[CV, "      status.textContent = d && typeof d.error === \"string\" ? d.error : ", "      status.innerHTML = d && typeof d.error === \"string\" ? d.error : "]],
  // the card page shows the form when it is off
  "page-form-when-off": [[CV, "  if (!c || c.lead_form !== true || !c.form_token || !c.form_issued_at) return;", "  if (!c) return;"]],
  // the card page never sends the honeypot
  "honeypot-not-sent": [[CV, "      website: document.getElementById(\"cvLeadWebsite\").value", "      website: \"\""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const ALL = {};
[SV, CL, CP, GEN, "lib/supportLinks.js", "lib/scrollbars.js", LP_FILE, "lib/legal.js", "lib/yourData.js", "lib/backup.js", "lib/schemaCheck.js", MIG,
  "scripts/buildCardShell.js", "README.md"].forEach(f => { ALL[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
["card-view.html", "digital-cards.html", "scripts/bf-card.js", "_headers", "privacy.html", "terms.html"].forEach(f => {
  const p = path.join(FRONTEND, f);
  ALL["fe:" + f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) ALL[file] = s.replaceOnce(ALL[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const SRC = ALL[SV];
const fe = f => ALL["fe:" + f];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;

/* ── the libs, compiled from the (possibly mutated) text ─────────────────── */
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const LIB_CACHE = {};
function loadLib(rel) {
  if (LIB_CACHE[rel]) return LIB_CACHE[rel].exports;
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  LIB_CACHE[rel] = m;
  m.require = function (req) {
    if (req.indexOf("./") === 0 || req.indexOf("../") === 0) {
      const target = path.relative(REPO, path.join(path.dirname(file), req)).split(path.sep).join("/").replace(/(\.js)?$/, ".js");
      if (ALL[target] !== undefined) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
let CLL = null, LP = null, YD = null, BK = null, SCH = null, BUILD = null, LIB_ERROR = null;
try {
  CLL = loadLib(CL); loadLib(CP); LP = loadLib(LP_FILE); YD = loadLib("lib/yourData.js"); BK = loadLib("lib/backup.js");
  SCH = loadLib("lib/schemaCheck.js"); BUILD = loadLib("scripts/buildCardShell.js");
} catch (e) { LIB_ERROR = e; }

/* ── the clock and the secret ────────────────────────────────────────────── */
const T0 = Date.parse("2026-11-06T15:00:00.000Z");
const CLOCK = { now: T0 };
const SECRET = "checkCardLeads-fixture-secret-not-a-real-one";
const LABEL = "bizforce-card-lead-form-v1";
const iso = ms => new Date(ms).toISOString();
const HOUR = 3600000, DAY = 24 * HOUR;

/* ── an in-memory database ───────────────────────────────────────────────── */
let idSeq = 1;
const nextId = () => "00000000-0000-4000-8000-" + String(100000000000 + (idSeq++));
function project(rows, cols) {
  if (!cols || cols === "*") return rows.map(r => JSON.parse(JSON.stringify(r)));
  const names = cols.split(",").map(c => c.trim());
  return rows.map(r => { const o = {}; names.forEach(n => { o[n] = r[n] === undefined ? null : JSON.parse(JSON.stringify(r[n])); }); return o; });
}
const CARD_DEFAULTS = () => ({ slug: null, show_email: true, show_phone: true, show_photo: true, discoverable: false, lead_form_on: false, media_layout: {}, video_url: null,
  bg_image_url: null, still_image_url: null, audio_url: null, holographic_style: false });
function orFilter(expr) {
  // the claim's form only: "<col>.is.null,<col>.neq.<value>"
  const parts = String(expr).split(",").map(p => p.split("."));
  return r => parts.some(p => (p[1] === "is" && p[2] === "null" && (r[p[0]] === null || r[p[0]] === undefined)) || (p[1] === "neq" && r[p[0]] !== p.slice(2).join(".")));
}
function makeDb(seed) {
  const t = JSON.parse(JSON.stringify(seed));
  const db = { t, reads: [], writes: [] };
  db.from = function (table) {
    const st = { op: "select", cols: null, ret: null, filters: [], orders: [], limit: null, row: null };
    function run() {
      db.reads.push(table + ":" + st.op);
      if (!t[table]) return Promise.resolve({ data: null, error: { code: "42P01", message: "relation " + table + " does not exist" } });
      if (st.op === "insert") {
        const incoming = (Array.isArray(st.row) ? st.row : [st.row]);
        if (table === "job_runs" && incoming.some(r => t.job_runs.some(x => x.job_name === r.job_name))) return Promise.resolve({ data: null, error: { code: "23505", message: "duplicate" } });
        const rows = incoming.map(r => Object.assign(table === "digital_cards" ? CARD_DEFAULTS() : {}, { id: nextId() }, JSON.parse(JSON.stringify(r))));
        t[table].push(...rows);
        db.writes.push({ table, op: "insert", row: JSON.parse(JSON.stringify(st.row)) });
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      let rows = t[table].filter(r => st.filters.every(f => f(r)));
      if (st.op === "update") {
        rows.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(st.row))));
        if (rows.length) db.writes.push({ table, op: "update", row: JSON.parse(JSON.stringify(st.row)) });
        return Promise.resolve({ data: project(rows, st.ret || "*"), error: null });
      }
      if (st.op === "delete") {
        t[table] = t[table].filter(r => rows.indexOf(r) === -1);
        if (rows.length) db.writes.push({ table, op: "delete", n: rows.length });
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      rows = rows.slice().sort((x, y) => { for (const [c, asc] of st.orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
      if (st.limit != null) rows = rows.slice(0, st.limit);
      return Promise.resolve({ data: project(rows, st.cols), error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.ret = c || "*"; return q; },
      insert(r) { st.op = "insert"; st.row = r; return q; },
      update(p) { st.op = "update"; st.row = p; return q; },
      delete() { st.op = "delete"; return q; },
      eq(c, v) { st.filters.push(r => r[c] === v); return q; },
      neq(c, v) { st.filters.push(r => r[c] !== v); return q; },
      gte(c, v) { st.filters.push(r => r[c] >= v); return q; },
      lt(c, v) { st.filters.push(r => r[c] < v); return q; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return q; },
      or(expr) { st.filters.push(orFilter(expr)); return q; },
      not(c, op, v) { st.filters.push(r => op === "is" && v === null ? r[c] !== null && r[c] !== undefined : true); return q; },
      order(c, o) { st.orders.push([c, !o || o.ascending !== false]); return q; },
      limit(n) { st.limit = n; return q; },
      maybeSingle() { return run().then(r => r.error ? r : r.data.length > 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0] || null, error: null }); },
      single() { return run().then(r => r.error ? r : r.data.length !== 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0], error: null }); },
      then(ok, bad) { return run().then(ok, bad); }
    };
    return q;
  };
  db.rpc = async function () { return { data: null, error: null }; };
  return db;
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const OWNER = "0a0a0a0a-0000-4000-8000-000000000001", OTHER = "0b0b0b0b-0000-4000-8000-000000000002", LAPSED = "0c0c0c0c-0000-4000-8000-000000000003";
const CID = { jane: "c0000000-0000-4000-8000-000000000001", off: "c0000000-0000-4000-8000-000000000002", lapsed: "c0000000-0000-4000-8000-000000000003",
  other: "c0000000-0000-4000-8000-000000000004", token: "c0000000-0000-4000-8000-000000000005" };
const TOK = { jane: "a".repeat(32), off: "b".repeat(32), lapsed: "c".repeat(32), other: "d".repeat(32), token: "0123456789abcdef0123456789abcdef" };
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
function card(key, owner, extra) {
  return Object.assign(CARD_DEFAULTS(), { id: CID[key], user_id: owner, share_token: TOK[key], full_name: "Card " + key, job_title: "", company: "",
    email: key + "+bftest@example.com", phone: "", website: "", theme: "dark", created_at: "2026-11-01T10:00:00.000Z", updated_at: "2026-11-01T10:00:00.000Z" }, extra || {});
}
function seed() {
  return {
    digital_cards: [
      card("jane", OWNER, { slug: "jane-doe", full_name: "Jane Doe", lead_form_on: true }),
      card("off", OWNER, { slug: "form-off", lead_form_on: false }),
      card("lapsed", LAPSED, { slug: "lapsed-card", lead_form_on: true }),
      card("other", OTHER, { slug: "other-card", full_name: "Olu Other", lead_form_on: true }),
      card("token", OWNER, { slug: null, full_name: "", lead_form_on: true })
    ],
    bf_profiles: [],
    member_support: [],
    card_leads: [],
    notifications: [],
    job_runs: []
  };
}

/* ── server.js, lifted ───────────────────────────────────────────────────── */
function routeText(sig) {
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) !== -1) return null;
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function", start)));
  return SRC.slice(start, end) + ");";
}
const R = {
  lead: routeText('app.post("/api/cards/lead",'),
  list: routeText('app.get("/api/digital-cards/:id/leads",'),
  patch: routeText('app.patch("/api/card-leads/:id",'),
  del: routeText('app.delete("/api/card-leads/:id",'),
  share: routeText('app.get("/api/cards/share/:token",'),
  slug: routeText('app.get("/api/cards/slug/:slug",'),
  create: routeText('app.post("/api/digital-cards",'),
  edit: routeText('app.put("/api/digital-cards/:id",')
};
const STUB = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "getUserPlan", "rateLimit", "express", "nowIso",
  "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error", "Set", "Map", "URL", "Buffer", "arguments"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUB.has(name)) continue;
    const def = s.definitionOf(SRC, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUB.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
const LOGS = [];
let CUR = makeDb(seed());
const ROUTES = {};
const LIMITERS = [];
const PLAN = { [OWNER]: true, [OTHER]: true, [LAPSED]: false };
const CTX = {
  supabase: { from: t => CUR.from(t), rpc: (fn, args) => CUR.rpc(fn, args), storage: { from: () => ({ remove: async () => ({ data: null, error: null }) }) } },
  console: { log() { LOGS.push([].slice.call(arguments).join(" ")); }, warn() { LOGS.push([].slice.call(arguments).join(" ")); }, error() { LOGS.push([].slice.call(arguments).join(" ")); } },
  process: { env: { SUPABASE_URL: "https://proj.supabase.co", JWT_SECRET: SECRET } },
  require: function (p) {
    if (p.indexOf("./") === 0) { const rel = p.slice(2).replace(/(\.js)?$/, ".js"); if (ALL[rel] !== undefined) return loadLib(rel); return realRequire(p); }
    return realRequire(p);
  },
  requireAuth: function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: "Authentication required" }); next(); },
  getUserPlan: async function (id) { return PLAN[id] ? { active: true, plan: "all_access" } : { active: false, plan: null, inactive_reason: "no_subscription" }; },
  rateLimit: function (opts) {
    const counts = {};
    const f = function limiter(req, res, next) {
      const k = req.ip || "none";
      counts[k] = (counts[k] || 0) + 1;
      if (counts[k] > opts.max) return res.status(429).json(opts.message || { error: "limited" });
      next();
    };
    f.opts = opts; f.reset = () => { Object.keys(counts).forEach(k => delete counts[k]); };
    LIMITERS.push(f);
    return f;
  },
  express: { text: function (opts) { const f = function textParser(req, res, next) { next(); }; f.opts = opts; return f; } },
  nowIso: () => iso(CLOCK.now),
  URL, URLSearchParams, Buffer,
  app: {}
};
["get", "post", "put", "patch", "delete", "use"].forEach(v => { CTX.app[v] = function (p) { ROUTES[v + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
let LIFT_ERROR = null;
try {
  vm.createContext(CTX);
  vm.runInContext(closure(Object.values(R).join("\n\n")), CTX);
} catch (e) { LIFT_ERROR = e; }
const resetLimits = () => LIMITERS.forEach(l => l.reset());

function mkRes() {
  return {
    statusCode: 200, body: undefined, text: undefined, headers: {}, ended: false, cookies: [],
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); this.ended = true; return this; },
    send(t) { this.text = String(t); this.ended = true; return this; },
    end() { this.ended = true; return this; },
    set(k, v) { if (k && typeof k === "object") Object.keys(k).forEach(n => { this.headers[n.toLowerCase()] = k[n]; }); else this.headers[String(k).toLowerCase()] = v; return this; },
    setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
    cookie(n, v) { this.cookies.push(n + "=" + v); this.headers["set-cookie"] = n + "=" + v; return this; },
    type(v) { this.headers["content-type"] = v; return this; }
  };
}
async function hit(key, o) {
  o = o || {};
  const fns = ROUTES[key];
  if (!fns) return { status: 0, error: "no route " + key };
  const headers = Object.assign({ "user-agent": BROWSER_UA }, o.headers || {});
  const req = { method: key.split(" ")[0].toUpperCase(), user: o.user ? { id: o.user, role: "user" } : undefined, body: o.body === undefined ? {} : o.body,
    params: o.params || {}, query: o.query || {}, headers, ip: o.ip || "203.0.113.7" };
  const res = mkRes();
  let err = null;
  for (let i = 0; i < fns.length; i++) {
    let advanced = false;
    await fns[i](req, res, e => { if (e) err = e; else advanced = true; });
    if (err || !advanced || res.ended) break;
  }
  return { status: res.statusCode, body: res.body, headers: res.headers, cookies: res.cookies, err: err && (err.message || String(err)) };
}
const names = key => (ROUTES[key] || []).map(f => f.name);
/* A token as the card's API would have issued it, ageMs before now. */
function tokenFor(cardId, ageMs) {
  const at = iso(CLOCK.now - (ageMs === undefined ? 10000 : ageMs));
  return CLL.issueFormToken(cardId, at, SECRET);
}
let emailSeq = 0;
function leadBody(cardKey, extra) {
  const tk = tokenFor(CID[cardKey]);
  return Object.assign({ ref: cardKey === "token" ? TOK.token : seed().digital_cards.find(c => c.id === CID[cardKey]).slug, name: "Visitor " + (++emailSeq),
    email: "visitor" + emailSeq + "+bftest@example.com", phone: "", message: "Hello", consent: true, form_token: tk.form_token, form_issued_at: tk.form_issued_at, website: "" }, extra || {});
}
const lead = (body, o) => hit("post /api/cards/lead", Object.assign({ body }, o || {}));
const leadsOf = cardId => CUR.t.card_leads.filter(r => r.card_id === cardId);
const SUCCESS_JANE = { ok: true, message: "Sent. Jane will see your details." };

/* ── jsdom ───────────────────────────────────────────────────────────────── */
let JSDOM = null, VirtualConsole = null;
try { const jd = realRequire("jsdom"); JSDOM = jd.JSDOM; VirtualConsole = jd.VirtualConsole; } catch (e) { JSDOM = null; }
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle(n) { for (let i = 0; i < (n || 12); i++) await tick(); }
const stripScripts = html => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
function inlineMain(html) {
  const all = [...String(html).matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  return all.find(t => t.indexOf("var API_URL") !== -1) || "";
}
function fnOf(text, nm) { const a = text.indexOf("function " + nm + "("); if (a < 0) return ""; return text.slice(text.lastIndexOf("\n", a) + 1, s.braceMatch(text, text.indexOf("{", a))); }
function cardView(opts) {
  const vc = new VirtualConsole();
  const dom = new JSDOM(stripScripts(fe("card-view.html")), { url: opts.url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  const w = dom.window, log = { fetches: [], errors: [] };
  w.QRCode = { toCanvas(canvas, text, o, cb) { if (cb) cb(null); } };
  Object.defineProperty(w.navigator, "sendBeacon", { value: function () { return true; }, configurable: true, writable: true });
  w.fetch = function (url, init) {
    log.fetches.push({ url: String(url), init: init || null });
    let p;
    if (/\/api\/cards\/(slug|share)\//.test(String(url))) p = Promise.resolve({ ok: true, json: async () => ({ card: opts.card, support_links: [] }) });
    else if (/\/api\/cards\/lead$/.test(String(url))) { const a = opts.leadAnswer || { status: 200, body: SUCCESS_JANE }; p = Promise.resolve({ ok: a.status < 300, status: a.status, json: async () => a.body }); }
    else p = Promise.resolve({ ok: false, json: async () => ({}) });
    p.catch(() => {});
    return p;
  };
  try { w.eval(fe("scripts/bf-card.js")); w.eval(inlineMain(fe("card-view.html"))); } catch (e) { log.errors.push(e.message); }
  return { dom, w, doc: w.document, log };
}

/* ── the migration as run ────────────────────────────────────────────────── */
const EMAIL_SQL = "^[^" + BS + "s@]+@[^" + BS + "s@]+" + BS + ".[^" + BS + "s@]+$";
const PHONE_SQL = "^[0-9+() .-]{3,40}$";
const SQL_AS_RUN = [
  "ALTER TABLE public.digital_cards",
  "  ADD COLUMN IF NOT EXISTS lead_form_on boolean NOT NULL DEFAULT false;",
  "",
  "CREATE TABLE public.card_leads (",
  "  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),",
  "  card_id uuid NOT NULL REFERENCES public.digital_cards(id) ON DELETE CASCADE,",
  "  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,",
  "  name text NOT NULL,",
  "  email text,",
  "  phone text,",
  "  message text NOT NULL DEFAULT '',",
  "  consent_text text NOT NULL,",
  "  status text NOT NULL DEFAULT 'new',",
  "  created_at timestamptz NOT NULL DEFAULT now(),",
  "  CONSTRAINT card_leads_name_check CHECK (char_length(name) BETWEEN 1 AND 120),",
  "  CONSTRAINT card_leads_email_check CHECK (email IS NULL OR (char_length(email) <= 254 AND email ~ '" + EMAIL_SQL + "')),",
  "  CONSTRAINT card_leads_phone_check CHECK (phone IS NULL OR phone ~ '" + PHONE_SQL + "'),",
  "  CONSTRAINT card_leads_message_check CHECK (char_length(message) <= 1000),",
  "  CONSTRAINT card_leads_consent_check CHECK (char_length(consent_text) BETWEEN 10 AND 300),",
  "  CONSTRAINT card_leads_status_check CHECK (status IN ('new', 'read', 'archived')),",
  "  CONSTRAINT card_leads_contactable_check CHECK (email IS NOT NULL OR phone IS NOT NULL)",
  ");",
  "",
  "CREATE INDEX card_leads_user_created_idx ON public.card_leads (user_id, created_at DESC);",
  "CREATE INDEX card_leads_card_created_idx ON public.card_leads (card_id, created_at DESC);",
  "",
  "ALTER TABLE public.card_leads ENABLE ROW LEVEL SECURITY;",
  "REVOKE ALL ON public.card_leads FROM anon, authenticated;",
  ""
].join("\n");
const HEADER = "-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.";

(async function main() {
  console.log("\n══ R0. the routes, lifted ══");
  check("R0. lib/cardLeads.js and the card, legal, data, backup and schema libs load", !LIB_ERROR, LIB_ERROR && LIB_ERROR.stack);
  check("R0. the lead routes, the card routes they touch and their helpers were lifted from server.js and run", !LIFT_ERROR && Object.values(R).every(Boolean),
    LIFT_ERROR ? LIFT_ERROR.stack : Object.keys(R).filter(k => !R[k]).join(", "));
  if (LIB_ERROR || LIFT_ERROR) { console.log("\nCHECKS FAILED: the harness could not start"); process.exit(1); }

  /* ════ A. the switch ════ */
  console.log("\n══ A. the switch ══");
  CUR = makeDb(seed()); CLOCK.now = T0;
  const a1 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.off }, body: { lead_form_on: "yes" } });
  const a2 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.off }, body: { lead_form_on: 1 } });
  const offBefore = CUR.t.digital_cards.find(r => r.id === CID.off).lead_form_on;
  const a3 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.off }, body: { lead_form_on: true } });
  const a4 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.off }, body: { lead_form_on: false } });
  check("A1. PUT: lead_form_on is a boolean; \"yes\" or 1 is a 400 and changes nothing; true and false are saved",
    a1.status === 400 && a2.status === 400 && offBefore === false && a3.status === 200 && a4.status === 200 && CUR.t.digital_cards.find(r => r.id === CID.off).lead_form_on === false &&
    /true or false/.test((a1.body || {}).error || ""), J([a1.status, a2.status, a3.status, a4.status]));
  const p1 = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "New" } });
  const p2 = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "New two", lead_form_on: true } });
  const p3 = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "New three", lead_form_on: "true" } });
  const inserts = CUR.writes.filter(w => w.table === "digital_cards" && w.op === "insert");
  check("A2. POST: a new card has the form off unless sent true; a non-boolean is a 400", p1.status === 201 && p1.body.card.lead_form_on === false &&
    !("lead_form_on" in inserts[0].row) && p2.status === 201 && p2.body.card.lead_form_on === true && p3.status === 400, J([p1.status, p2.status, p3.status]));

  /* ════ B. the public card ════ */
  console.log("\n══ B. the public card's answer ══");
  CUR = makeDb(seed()); CLOCK.now = T0;
  const bOff = await hit("get /api/cards/slug/:slug", { params: { slug: "form-off" } });
  const bOffTok = await hit("get /api/cards/share/:token", { params: { token: TOK.off } });
  check("B1. a card with its form off: lead_form false, no form_token or form_issued_at, and no Cache-Control set (by slug and token)",
    [bOff, bOffTok].every(r => r.status === 200 && r.body.card.lead_form === false && !("form_token" in r.body.card) && !("form_issued_at" in r.body.card) && !("cache-control" in r.headers)),
    J([bOff.body, bOffTok.headers]));
  const bOn = await hit("get /api/cards/slug/:slug", { params: { slug: "jane-doe" } });
  const bOnTok = await hit("get /api/cards/share/:token", { params: { token: TOK.jane } });
  check("B2. with the form on: lead_form true, form_token and form_issued_at (now), and Cache-Control no-store (by slug and token)",
    [bOn, bOnTok].every(r => r.status === 200 && r.body.card.lead_form === true && /^[A-Za-z0-9_-]{43}$/.test(r.body.card.form_token || "") &&
      r.body.card.form_issued_at === iso(T0) && r.headers["cache-control"] === "no-store"), J([bOn.body && bOn.body.card, bOn.headers]));
  const keysOff = Object.keys(bOff.body.card).sort(), keysOn = Object.keys(bOn.body.card).sort();
  check("B3. nothing else about the card's output changes: the on answer is the off answer's keys plus form_token and form_issued_at",
    J(keysOn) === J(keysOff.concat(["form_issued_at", "form_token"]).sort()) && keysOff.indexOf("lead_form") !== -1 && keysOff.indexOf("user_id") === -1 && keysOff.indexOf("id") === -1, J([keysOff, keysOn]));
  const lapsedApi = await hit("get /api/cards/slug/:slug", { params: { slug: "lapsed-card" } });
  check("B4. a lapsed owner's card is still a 404 with no token", lapsedApi.status === 404 && J(lapsedApi.body).indexOf("form_token") === -1);
  delete CTX.process.env.JWT_SECRET;
  const noSecret = await hit("get /api/cards/slug/:slug", { params: { slug: "jane-doe" } });
  CTX.process.env.JWT_SECRET = SECRET;
  check("B5. without a server secret no token can be made, so no form is offered (lead_form false)", noSecret.status === 200 && noSecret.body.card.lead_form === false && !("form_token" in noSecret.body.card));

  /* ════ K. the token ════ */
  console.log("\n══ K. the form token ══");
  const wantKey = Buffer.from(crypto.hkdfSync("sha256", Buffer.from(SECRET, "utf8"), Buffer.alloc(0), Buffer.from(LABEL, "utf8"), 32));
  const wantTok = crypto.createHmac("sha256", wantKey).update("card-lead|" + CID.jane + "|" + iso(T0)).digest("base64url");
  const rawTok = crypto.createHmac("sha256", Buffer.from(SECRET, "utf8")).update("card-lead|" + CID.jane + "|" + iso(T0)).digest("base64url");
  check("K1. form_token is HMAC-SHA256 over \"card-lead|<card id>|<form_issued_at>\" keyed by HKDF-SHA256 of JWT_SECRET with the label " + LABEL,
    bOn.body.card.form_token === wantTok && CLL.FORM_KEY_INFO === LABEL && CLL.FORM_SECRET_ENV === "JWT_SECRET", bOn.body.card.form_token === rawTok ? "keyed by the raw secret" : "");
  check("K2. the raw secret never keys it: the key differs from the secret's bytes and the token from an HMAC by the raw secret",
    bOn.body.card.form_token !== rawTok && !CLL.formKey(SECRET).equals(Buffer.from(SECRET, "utf8")) && CLL.formKey("") === null && CLL.formKey(undefined) === null);
  const ck = (age, cardId, tok) => { const t = CLL.issueFormToken(CID.jane, iso(T0 - age), SECRET); return CLL.checkFormToken(cardId || CID.jane, tok || t.form_token, t.form_issued_at, T0, SECRET); };
  check("K3. accepted from exactly 3 seconds to exactly 2 hours; refused at 2.999 seconds, 2 hours and 1 ms, and from the future",
    !ck(2999) && ck(3000) && ck(3001) && ck(HOUR) && ck(2 * HOUR) && !ck(2 * HOUR + 1) && !ck(-5000), J([ck(2999), ck(3000), ck(2 * HOUR), ck(2 * HOUR + 1)]));
  const t10 = CLL.issueFormToken(CID.jane, iso(T0 - 10000), SECRET);
  const flip = t10.form_token.slice(0, -1) + (t10.form_token.slice(-1) === "A" ? "B" : "A");
  check("K4. refused for another card, a changed token, a changed time, a shortened token, another secret, or a time not in ISO form",
    !CLL.checkFormToken(CID.other, t10.form_token, t10.form_issued_at, T0, SECRET) && !CLL.checkFormToken(CID.jane, flip, t10.form_issued_at, T0, SECRET) &&
    !CLL.checkFormToken(CID.jane, t10.form_token, iso(T0 - 9000), T0, SECRET) && !CLL.checkFormToken(CID.jane, t10.form_token.slice(0, 20), t10.form_issued_at, T0, SECRET) &&
    !CLL.checkFormToken(CID.jane, t10.form_token, t10.form_issued_at, T0, SECRET + "x") && !CLL.checkFormToken(CID.jane, t10.form_token, String(T0 - 10000), T0, SECRET) &&
    CLL.checkFormToken(CID.jane, t10.form_token, t10.form_issued_at, T0, SECRET));
  timingSafeCalls = 0;
  const okNow = CLL.checkFormToken(CID.jane, t10.form_token, t10.form_issued_at, T0, SECRET), badNow = CLL.checkFormToken(CID.jane, flip, t10.form_issued_at, T0, SECRET);
  check("K5. the signature is compared with crypto.timingSafeEqual (both a match and a mismatch of equal length go through it)", okNow && !badNow && timingSafeCalls === 2, timingSafeCalls);
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  const fast = await lead(leadBody("jane", (() => { const t = tokenFor(CID.jane, 2000); return { form_token: t.form_token, form_issued_at: t.form_issued_at }; })()));
  const old = await lead(leadBody("jane", (() => { const t = tokenFor(CID.jane, 2 * HOUR + 1000); return { form_token: t.form_token, form_issued_at: t.form_issued_at }; })()));
  const foreignTok = await lead(leadBody("jane", (() => { const t = tokenFor(CID.other); return { form_token: t.form_token, form_issued_at: t.form_issued_at }; })()));
  const noTok = await lead(leadBody("jane", { form_token: undefined, form_issued_at: undefined }));
  check("K6. the route: too fast, expired, another card's token or none: 400 \"Please take a moment and try again.\", nothing stored",
    [fast, old, foreignTok, noTok].every(r => r.status === 400 && r.body.error === "Please take a moment and try again.") && CUR.t.card_leads.length === 0, J([fast, old, foreignTok, noTok].map(r => r.status)));
  const good = await lead(leadBody("jane"));
  check("K7. the route: a token from 10 seconds ago is accepted: 200 and one lead", good.status === 200 && J(good.body) === J(SUCCESS_JANE) && CUR.t.card_leads.length === 1, J(good));

  /* ════ card and owner ════ */
  console.log("\n══ the card and its owner ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  const offLead = await lead(leadBody("off"));
  const lapsedLead = await lead(leadBody("lapsed"));
  const unknown = await lead(leadBody("jane", { ref: "no-such-card" }));
  const badRef = await lead(leadBody("jane", { ref: "../x" }));
  const realOPP = CTX.ownerPagePublic;
  CTX.ownerPagePublic = async () => { throw new Error("plan lookup down"); };
  const thrown = await lead(leadBody("jane"));
  CTX.ownerPagePublic = realOPP;
  check("O1. the form off, a lapsed owner, an unknown or malformed card, an owner lookup that throws: 404 \"Card not found\", nothing stored, no notice",
    [offLead, lapsedLead, unknown, badRef, thrown].every(r => r.status === 404 && r.body.error === "Card not found") && CUR.t.card_leads.length === 0 && CUR.t.notifications.length === 0,
    J([offLead, lapsedLead, unknown, badRef, thrown].map(r => r.status)));
  const byToken = await lead(leadBody("token"));
  check("O2. a card without a short link takes a lead by its share token; with no name the answer says \"They\"",
    byToken.status === 200 && J(byToken.body) === J({ ok: true, message: "Sent. They will see your details." }) && leadsOf(CID.token).length === 1, J(byToken));
  const limiter = (ROUTES["post /api/cards/lead"] || []).find(f => f.name === "limiter");
  check("O3. the lead route is limited to 20 per 10 minutes, keyed by IP (the default key), and needs no account",
    !!limiter && limiter.opts.max === 20 && limiter.opts.windowMs === 600000 && !limiter.opts.keyGenerator && names("post /api/cards/lead").indexOf("requireAuth") === -1, J(limiter && limiter.opts));
  resetLimits();
  const burst = [];
  for (let i = 0; i < 21; i++) burst.push((await lead({ ref: "form-off" }, { ip: "198.51.100.9" })).status);
  check("O4. the 21st request from one address in the window is refused with 429", burst.slice(0, 20).every(x => x === 404) && burst[20] === 429, burst.slice(18).join(","));

  /* ════ P. the honeypot ════ */
  console.log("\n══ P. the honeypot ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits(); LOGS.length = 0;
  const realOne = await lead(leadBody("jane"));
  const before = { leads: CUR.t.card_leads.length, notes: CUR.t.notifications.length, writes: CUR.writes.length };
  const hp1 = await lead(leadBody("jane", { website: "https://spam.example" }));
  const hp2 = await lead(leadBody("jane", { website: "x", form_token: "bad", consent: false, email: "", phone: "" }));
  const hp3 = await lead(leadBody("jane", { website: { a: 1 } }));
  check("P1. a filled honeypot is answered exactly as a success: the same status, body and headers",
    [hp1, hp2, hp3].every(r => r.status === realOne.status && J(r.body) === J(realOne.body) && J(r.headers) === J(realOne.headers)), J([realOne, hp1, hp2].map(r => [r.status, r.body])));
  check("P2. ...and nothing is stored and no one is notified", CUR.t.card_leads.length === before.leads && CUR.t.notifications.length === before.notes && CUR.writes.length === before.writes,
    J([CUR.t.card_leads.length, CUR.t.notifications.length]));
  check("P3. honeypotFilled: empty, blank, missing or null is not filled; any text or value is",
    !CLL.honeypotFilled({}) && !CLL.honeypotFilled({ website: "" }) && !CLL.honeypotFilled({ website: "   " }) && !CLL.honeypotFilled({ website: null }) &&
    CLL.honeypotFilled({ website: "a" }) && CLL.honeypotFilled({ website: 0 }) && CLL.honeypotFilled({ website: [] }));

  /* ════ V. validation ════ */
  console.log("\n══ V. validation and its messages ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  const cases = [
    [{ name: "" }, "Leave your name, up to 120 characters."], [{ name: "   " }, "Leave your name, up to 120 characters."], [{ name: "n".repeat(121) }, "Leave your name, up to 120 characters."],
    [{ name: 5 }, "Leave your name, up to 120 characters."],
    [{ email: "not-an-email" }, "That email address doesn't look right."], [{ email: "a@b" }, "That email address doesn't look right."], [{ email: "a b@c.de" }, "That email address doesn't look right."],
    [{ email: "x".repeat(250) + "@a.co" }, "That email address doesn't look right."], [{ email: ["a@b.co"] }, "That email address doesn't look right."],
    [{ phone: "12" }, "That phone number doesn't look right."], [{ phone: "call me" }, "That phone number doesn't look right."], [{ phone: "1".repeat(41) }, "That phone number doesn't look right."],
    [{ email: "", phone: "" }, "Leave an email or a phone number so they can reach you."], [{ email: null, phone: undefined }, "Leave an email or a phone number so they can reach you."],
    [{ message: "m".repeat(1001) }, "Keep the message to 1,000 characters."],
    [{ consent: false }, "Tick the box to send your details."], [{ consent: "true" }, "Tick the box to send your details."], [{ consent: 1 }, "Tick the box to send your details."],
    [{ consent: undefined }, "Tick the box to send your details."]
  ];
  const vbad = [];
  for (const [extra, want] of cases) {
    const r = await lead(leadBody("jane", extra));
    if (r.status !== 400 || r.body.error !== want) vbad.push(J(extra).slice(0, 60) + " -> " + r.status + " " + J(r.body));
  }
  check("V1. each bad field is a 400 with its own message, and nothing is stored (" + cases.length + " cases)", vbad.length === 0 && CUR.t.card_leads.length === 0, vbad.slice(0, 4).join(" | "));
  const edge = await lead(leadBody("jane", { name: "n".repeat(120), message: "m".repeat(1000), email: "", phone: "+1 (555) 010-2030" }));
  check("V2. the edges are accepted: a 120-character name, a 1,000-character message, a phone alone", edge.status === 200 && leadsOf(CID.jane).length === 1 &&
    leadsOf(CID.jane)[0].name.length === 120 && leadsOf(CID.jane)[0].message.length === 1000 && leadsOf(CID.jane)[0].email === null && leadsOf(CID.jane)[0].phone === "+1 (555) 010-2030", J(edge));
  CUR = makeDb(seed()); resetLimits();
  const ctl = [0, 7, 8, 9, 11, 12, 27, 31, 127].map(c => String.fromCharCode(c)).join("");
  const dirty = await lead(leadBody("jane", { name: "  Ann" + ctl + "\n  Lee  ", email: "  Ann.Lee+BFTEST@Example.COM ", phone: "", message: "line one\r\nline two" + ctl + "\rend" }));
  const st = leadsOf(CID.jane)[0] || {};
  check("V3. control characters other than newlines are stripped; the name is one line; the email trimmed and lower-cased; CR LF becomes a newline",
    dirty.status === 200 && st.name === "Ann Lee" && st.email === "ann.lee+bftest@example.com" && st.message === "line one\nline two\nend", J(st));
  check("V4. EMAIL_RE and PHONE_RE are migration 172's own patterns", CLL.EMAIL_RE.source === EMAIL_SQL && CLL.PHONE_RE.source === PHONE_SQL &&
    ALL[MIG].indexOf("email ~ '" + CLL.EMAIL_RE.source + "'") !== -1 && ALL[MIG].indexOf("phone ~ '" + CLL.PHONE_RE.source + "'") !== -1, CLL.EMAIL_RE.source);

  /* ════ C. consent ════ */
  console.log("\n══ C. consent ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  await lead(leadBody("jane", { consent_text: "I agree to anything at all, signed the visitor" }));
  check("C1. the stored consent_text is built on the server from the card's name, and a consent_text in the request is ignored",
    (leadsOf(CID.jane)[0] || {}).consent_text === "I agree that Jane Doe may contact me about this message.", J(leadsOf(CID.jane)[0]));
  const longName = "N".repeat(400), cs = CLL.consentSentence(longName);
  check("C2. a long name is cut so the sentence is at most 300 characters; no name gives \"the owner of this card\"",
    cs.length === 300 && /^I agree that N+ may contact me about this message\.$/.test(cs) && CLL.consentSentence("  ") === "I agree that the owner of this card may contact me about this message." &&
    CLL.consentSentence("A" + String.fromCharCode(7) + "  B") === "I agree that A B may contact me about this message." && CLL.consentSentence("x").length >= 10, cs.length);

  /* ════ L. caps ════ */
  console.log("\n══ L. the per-card caps ══");
  async function capRun(rows) {
    CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
    rows.forEach((age, i) => CUR.t.card_leads.push({ id: nextId(), card_id: CID.jane, user_id: OWNER, name: "Old " + i, email: "old" + i + "+bftest@example.com", phone: null,
      message: "", consent_text: "x".repeat(20), status: "new", created_at: iso(T0 - age) }));
    const r = await lead(leadBody("jane"));
    return { status: r.status, body: r.body, n: leadsOf(CID.jane).length - rows.length };
  }
  const h4 = await capRun([1, 2, 3, HOUR]), h5 = await capRun([1, 2, 3, 4, HOUR]);
  check("L1. the hour: with 4 leads in the last hour (one exactly an hour old) the 5th is stored; with 5 the next is a 429 with the message",
    h4.status === 200 && h4.n === 1 && h5.status === 429 && h5.body.error === "This card isn't taking more messages right now. Try again later." && h5.n === 0, J([h4, h5]));
  const dayRows = n => Array.from({ length: n }, (x, i) => HOUR + 60000 + i * 60000);
  const d19 = await capRun(dayRows(19)), d20 = await capRun(dayRows(19).concat([DAY])), dOut = await capRun(dayRows(19).concat([DAY + 1]));
  check("L2. the day: with 19 leads in 24 hours the 20th is stored; with 20 (one exactly 24 hours old) the next is a 429; one older than 24 hours does not count",
    d19.status === 200 && d19.n === 1 && d20.status === 429 && d20.n === 0 && dOut.status === 200 && dOut.n === 1, J([d19.status, d20.status, dOut.status]));
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  for (let i = 0; i < 5; i++) await lead(leadBody("other"));
  const otherCard = await lead(leadBody("jane"));
  check("L3. the caps are per card: another card's five do not stop this one", otherCard.status === 200 && leadsOf(CID.other).length === 5 && leadsOf(CID.jane).length === 1);

  /* ════ D. dedupe ════ */
  console.log("\n══ D. the dedupe ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  const first = await lead(leadBody("jane", { email: "same+bftest@example.com", phone: "" }));
  CLOCK.now = T0 + 23 * HOUR;
  const again = await lead(leadBody("jane", { email: "SAME+bftest@example.com", phone: "", message: "second" }));
  const viaPhone1 = await lead(leadBody("jane", { email: "", phone: "+1 555 010 2030" }));
  const viaPhone2 = await lead(leadBody("jane", { email: "", phone: "+1 (555) 010-2030" }));
  check("D1. the same email (in any case), or the same phone (in any format), on the same card within 24 hours: answered as a success, nothing new stored",
    first.status === 200 && J(again.body) === J(first.body) && again.status === 200 && viaPhone1.status === 200 && J(viaPhone2.body) === J(first.body) &&
    leadsOf(CID.jane).length === 2 && !leadsOf(CID.jane).some(r => r.message === "second"), J(leadsOf(CID.jane).map(r => [r.email, r.phone])));
  CLOCK.now = T0 + 24 * HOUR + 1000;
  const later = await lead(leadBody("jane", { email: "same+bftest@example.com", phone: "" }));
  const elsewhere = await lead(leadBody("other", { email: "same+bftest@example.com", phone: "" }));
  check("D2. after 24 hours, or on another card, the same email is stored again", later.status === 200 && elsewhere.status === 200 && leadsOf(CID.jane).length === 3 && leadsOf(CID.other).length === 1);

  /* ════ N. nothing about the visitor ════ */
  console.log("\n══ N. nothing about the visitor ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits(); LOGS.length = 0;
  const VISITOR = { ip: "192.0.2.211", headers: { "user-agent": "Mozilla/5.0 LeadVisitorMarker-91", referer: "https://referrer-marker.example/x", cookie: "session=cookie-marker" } };
  const nv = await lead(leadBody("jane"), VISITOR);
  const insert = CUR.writes.find(w => w.table === "card_leads" && w.op === "insert");
  check("N1. a lead row holds exactly the card, the owner, the name, email, phone, message, consent sentence, status and time",
    nv.status === 200 && !!insert && J(Object.keys(insert.row).sort()) === J(["card_id", "consent_text", "created_at", "email", "message", "name", "phone", "status", "user_id"]) &&
    insert.row.user_id === OWNER && insert.row.status === "new" && insert.row.created_at === iso(T0), J(insert && insert.row));
  const stored = J(CUR.t) + J(CUR.writes) + J(LOGS);
  const markers = ["192.0.2.211", "LeadVisitorMarker-91", "referrer-marker", "cookie-marker"];
  check("N2. the visitor's address, User-Agent, referrer and cookie are nowhere in the database or the log", markers.every(m => stored.indexOf(m) === -1), markers.filter(m => stored.indexOf(m) !== -1).join(","));
  check("N3. no Set-Cookie on a lead, a refusal or the card's answer", [nv, offLead, bOn].every(r => !("set-cookie" in r.headers) && (!r.cookies || r.cookies.length === 0)));
  const leadCode = R.lead + "\n" + (s.definitionOf(SRC, "noticeCardLead") || "");
  check("N4. the lead route never reads req.ip, the User-Agent, the referrer or cookies", !/req\.ip|user-agent|referer|referrer|req\.cookies|cookie\(/i.test(leadCode) && leadCode.length > 1000);
  check("N5. the answer to a lead is never cached", nv.headers["cache-control"] === "no-store" && hp1.headers["cache-control"] === "no-store");

  /* ════ O. the notice ════ */
  console.log("\n══ O. the owner's notice ══");
  CUR = makeDb(seed()); CLOCK.now = T0; resetLimits();
  await lead(leadBody("jane", { name: "Marker Person", email: "marker+bftest@example.com", message: "secret-message-marker" }));
  const n1 = CUR.t.notifications.slice();
  check("O5. the first lead: one in-app notice of type card_lead with the decided title and words, and no lead details",
    n1.length === 1 && n1[0].user_id === OWNER && n1[0].type === "card_lead" && n1[0].title === "New lead on your digital card" &&
    n1[0].message === "Someone left their details on your card. Open Digital Cards to see your leads." && n1[0].read === false &&
    !/Marker Person|marker\+bftest|secret-message-marker/.test(J(n1)), J(n1));
  CLOCK.now = T0 + 59 * 60000;
  await lead(leadBody("jane"));
  await lead(leadBody("token"));
  check("O6. more leads within the hour, on any of the member's cards: no second notice", CUR.t.notifications.length === 1, CUR.t.notifications.length);
  CLOCK.now = T0 + HOUR;
  await lead(leadBody("jane"));
  await lead(leadBody("other"));
  check("O7. an hour after the last notice, the next lead gives one more; another member gets their own",
    CUR.t.notifications.filter(n => n.user_id === OWNER).length === 2 && CUR.t.notifications.filter(n => n.user_id === OTHER).length === 1, J(CUR.t.notifications.map(n => n.user_id + " " + n.created_at)));
  check("O8. noticeDue: none before, or the latest an hour or more ago", CLL.noticeDue(undefined, T0) && CLL.noticeDue(iso(T0 - HOUR), T0) && !CLL.noticeDue(iso(T0 - HOUR + 1), T0));

  /* ════ W. the owner routes ════ */
  console.log("\n══ W. the owner's routes ══");
  CUR = makeDb(seed()); CLOCK.now = T0;
  for (let i = 0; i < 51; i++) CUR.t.card_leads.push({ id: nextId(), card_id: CID.jane, user_id: OWNER, name: "Lead " + i, email: "l" + i + "+bftest@example.com", phone: null,
    message: "m" + i, consent_text: "I agree that Jane Doe may contact me about this message.", status: "new", created_at: iso(T0 - (51 - i) * 60000) });
  const foreignLead = { id: nextId(), card_id: CID.other, user_id: OTHER, name: "Theirs", email: "theirs+bftest@example.com", phone: null, message: "", consent_text: "x".repeat(20), status: "new", created_at: iso(T0) };
  CUR.t.card_leads.push(foreignLead);
  const pg1 = await hit("get /api/digital-cards/:id/leads", { user: OWNER, params: { id: CID.jane } });
  const pg2 = pg1.body && pg1.body.next_before ? await hit("get /api/digital-cards/:id/leads", { user: OWNER, params: { id: CID.jane }, query: { before: pg1.body.next_before } }) : { body: {} };
  check("W1. the owner's leads: 50 newest first, then the 51st with ?before=, then no more",
    pg1.status === 200 && pg1.body.leads.length === 50 && pg1.body.leads[0].name === "Lead 50" && pg1.body.leads[49].name === "Lead 1" && pg1.body.next_before === pg1.body.leads[49].created_at &&
    pg2.status === 200 && pg2.body.leads.length === 1 && pg2.body.leads[0].name === "Lead 0" && pg2.body.next_before === null, J([pg1.body && pg1.body.leads && pg1.body.leads.length, pg1.body && pg1.body.next_before, pg2.body]));
  check("W2. each lead is exactly id, name, email, phone, message, consent_text, status and created_at; nothing of another member's",
    J(Object.keys(pg1.body.leads[0]).sort()) === J(["consent_text", "created_at", "email", "id", "message", "name", "phone", "status"]) &&
    J(pg1.body).indexOf("Theirs") === -1 && pg1.headers["cache-control"] === "no-store");
  const wForeign = await hit("get /api/digital-cards/:id/leads", { user: OTHER, params: { id: CID.jane } });
  const wAnon = await hit("get /api/digital-cards/:id/leads", { params: { id: CID.jane } });
  const wBad = await hit("get /api/digital-cards/:id/leads", { user: OWNER, params: { id: "nope" } });
  const wBefore = await hit("get /api/digital-cards/:id/leads", { user: OWNER, params: { id: CID.jane }, query: { before: "yesterday-ish" } });
  check("W3. another member's card is a 404 with nothing of it; signed out a 401; a malformed id a 404; a bad before a 400",
    wForeign.status === 404 && J(wForeign.body).indexOf("Lead") === -1 && wAnon.status === 401 && wBad.status === 404 && wBefore.status === 400, J([wForeign.status, wAnon.status, wBad.status, wBefore.status]));
  check("W4. the owner routes need an account and no subscription", ["get /api/digital-cards/:id/leads", "patch /api/card-leads/:id", "delete /api/card-leads/:id"].every(k => J(names(k)) === J(["requireAuth", ""]) || (names(k)[0] === "requireAuth" && names(k).length === 2)),
    J(["get /api/digital-cards/:id/leads", "patch /api/card-leads/:id", "delete /api/card-leads/:id"].map(names)));
  const mine = CUR.t.card_leads.find(r => r.name === "Lead 10");
  const pr = await hit("patch /api/card-leads/:id", { user: OWNER, params: { id: mine.id }, body: { status: "read" } });
  const pa = await hit("patch /api/card-leads/:id", { user: OWNER, params: { id: mine.id }, body: { status: "archived" } });
  const pn = await hit("patch /api/card-leads/:id", { user: OWNER, params: { id: mine.id }, body: { status: "new" } });
  const px = await hit("patch /api/card-leads/:id", { user: OWNER, params: { id: mine.id }, body: { status: "deleted" } });
  const pf = await hit("patch /api/card-leads/:id", { user: OWNER, params: { id: foreignLead.id }, body: { status: "read" } });
  check("W5. PATCH: read and archived only (new or anything else is a 400); another member's lead is a 404 and unchanged",
    pr.status === 200 && pa.status === 200 && J(pa.body) === J({ lead: { id: mine.id, status: "archived" } }) && pn.status === 400 && px.status === 400 &&
    mine.status === "archived" && pf.status === 404 && foreignLead.status === "new", J([pr.status, pa.status, pn.status, px.status, pf.status]));
  const df = await hit("delete /api/card-leads/:id", { user: OWNER, params: { id: foreignLead.id } });
  const dm = await hit("delete /api/card-leads/:id", { user: OWNER, params: { id: mine.id } });
  const dAgain = await hit("delete /api/card-leads/:id", { user: OWNER, params: { id: mine.id } });
  check("W6. DELETE: the owner's own lead is gone; another member's is a 404 and kept; deleting twice is a 404",
    df.status === 404 && CUR.t.card_leads.some(r => r.id === foreignLead.id) && dm.status === 200 && !CUR.t.card_leads.some(r => r.id === mine.id) && dAgain.status === 404,
    J([df.status, dm.status, dAgain.status]));

  /* ════ U. the purge ════ */
  console.log("\n══ U. the 12-month purge ══");
  const cutoff = CLL.retentionCutoff(T0);
  check("U1. the cutoff is 12 calendar months before now", cutoff === "2025-11-06T15:00:00.000Z", cutoff);
  const pdb = makeDb({ card_leads: [
    { id: "old-1ms", card_id: CID.jane, user_id: OWNER, created_at: iso(Date.parse(cutoff) - 1) },
    { id: "at-cutoff", card_id: CID.jane, user_id: OWNER, created_at: cutoff },
    { id: "eleven-months", card_id: CID.jane, user_id: OWNER, created_at: "2025-12-06T15:00:00.000Z" },
    { id: "two-years", card_id: CID.jane, user_id: OWNER, created_at: "2024-11-01T00:00:00.000Z" },
    { id: "today", card_id: CID.jane, user_id: OWNER, created_at: iso(T0) }], job_runs: [] });
  const quiet = console.log; console.log = function () {};
  let tick1, tick2, tick3, afterFirst = [];
  try {
    tick1 = await CLL.cardLeadsPurgeTick(pdb, T0);
    afterFirst = pdb.t.card_leads.map(r => r.id).sort();
    tick2 = await CLL.cardLeadsPurgeTick(pdb, T0 + 1000);
    tick3 = await CLL.cardLeadsPurgeTick(pdb, T0 + DAY);
  } finally { console.log = quiet; }
  check("U2. the pass deletes leads older than 12 months, even by 1 ms, and keeps one exactly 12 months old and anything younger",
    tick1.claimed === true && tick1.summary.rows_deleted === 2 && J(afterFirst) === J(["at-cutoff", "eleven-months", "today"]), J(afterFirst));
  check("U3. it is claimed once a UTC day through job_runs.card_leads_purge: a second run that day does nothing, the next day runs",
    tick2.claimed === false && tick3.claimed === true && pdb.t.job_runs.length === 1 && pdb.t.job_runs[0].job_name === "card_leads_purge" && CLL.PURGE_JOB_NAME === "card_leads_purge");
  const cronAt = SRC.indexOf("    cron.schedule(\"45 4 * * *\", function () {\n      cardLeads.cardLeadsPurgeTick(supabase).catch(function (err) {");
  const guardAt = SRC.lastIndexOf("  if (require.main === module) {\n", cronAt);
  const between = cronAt > 0 && guardAt > 0 ? SRC.slice(guardAt, cronAt) : "";
  /* NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE the UTC timezone had to be within 400 characters of the
     cron line. AFTER the same callback then runs the oauth_states purge (lib/microsoftAuth.js oauthStatesPurgeTick,
     its own job_runs row; checkMailboxOutlook), so the callback is longer: the timezone must close THIS schedule call,
     the first "}, {" after the cron line, with no other cron.schedule in between, and no flag anywhere in it. */
  const cronCall = cronAt > 0 ? SRC.slice(cronAt, SRC.indexOf("    });\n", SRC.indexOf("}, {\n      timezone:", cronAt)) + 8) : "";
  check("U4. server.js runs it at 04:45 UTC daily, only when server.js is the program, and no flag turns it off",
    cronAt > 0 && guardAt > 0 && between === "  if (require.main === module) {\n" && !/ENABLE_/.test(between) && !/ENABLE_/.test(cronCall) &&
    /\}, \{\n      timezone: "UTC"\n    \}\);\n$/.test(cronCall) && cronCall.indexOf("cron.schedule(", 10) === -1 && cronCall.length < 900, between);
  check("U5. the README's job table lists it", /\| `cardLeadsPurgeTick`: card leads older than 12 months \| cron `45 4 \* \* \*`, UTC, claimed `card_leads_purge` \|/.test(ALL["README.md"]));

  /* ════ F. the card page ════ */
  console.log("\n══ F. the card page's form ══");
  if (JSDOM) {
    const CARD = { full_name: "Jane Doe", job_title: "", company: "", email: "", phone: "", website: "", theme: "dark", public_url: "https://bizforceai.net/c/jane-doe",
      photo_url: null, media_layout: {}, lead_form: true, form_token: wantTok, form_issued_at: iso(T0) };
    const vOff = cardView({ url: "https://bizforceai.net/c/jane-doe", card: Object.assign({}, CARD, { lead_form: false, form_token: undefined, form_issued_at: undefined }) });
    await settle();
    check("F1. with lead_form false, the \"Leave your details\" button stays hidden and the form closed", vOff.log.errors.length === 0 &&
      vOff.doc.getElementById("cvLeadBtn").hidden === true && vOff.doc.getElementById("cvLead").hidden === true, vOff.log.errors.join("; "));
    vOff.w.close();
    const v = cardView({ url: "https://bizforceai.net/c/jane-doe", card: CARD });
    await settle();
    const d = v.doc, btn = d.getElementById("cvLeadBtn");
    check("F2. with lead_form true, the button shows, and opens the form", btn.hidden === false && btn.textContent === "Leave your details" &&
      (btn.click(), d.getElementById("cvLead").hidden === false) && btn.getAttribute("aria-expanded") === "true");
    const BF = v.w.bfCard;
    const nameVectors = ["Jane Doe", "", "  ", "N".repeat(400), "A" + String.fromCharCode(7) + "  B", "Ren" + String.fromCharCode(0xe9) + " O'Brien <b>", "x"];
    check("F3. the consent label is the server's sentence for the card's name (the same rule in bf-card.js, " + nameVectors.length + " names)",
      d.getElementById("cvLeadConsentText").textContent === "I agree that Jane Doe may contact me about this message." &&
      nameVectors.every(n => BF.consentSentence(n) === CLL.consentSentence(n) && BF.leadName(n) === CLL.publicName(n)), nameVectors.filter(n => BF.consentSentence(n) !== CLL.consentSentence(n)).join("|"));
    const note = d.getElementById("cvLeadPrivacy").parentNode;
    check("F4. under the form, word for word, with a link to the Privacy Policy",
      d.getElementById("cvLeadPrivacy").textContent === "Your details go only to Jane Doe. BizForce keeps them for up to 12 months and records nothing about your device." &&
      note.querySelector("a").getAttribute("href") === "/privacy.html");
    const hp = d.getElementById("cvLeadWebsite"), hpWrap = hp.parentNode;
    const css = (/<style>[\s\S]*?<\/style>/.exec(fe("card-view.html")) || [""])[0];
    check("F5. the honeypot \"website\": off-screen, aria-hidden, tabindex -1, autocomplete off, inside the form",
      hp.getAttribute("name") === "website" && hp.getAttribute("tabindex") === "-1" && hp.getAttribute("autocomplete") === "off" && hpWrap.getAttribute("aria-hidden") === "true" &&
      hpWrap.className === "cv-lead-hp" && css.indexOf(".cv-lead-hp{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}") !== -1 &&
      d.getElementById("cvLeadForm").contains(hp));
    d.getElementById("cvLeadName").value = "Pat Visitor";
    d.getElementById("cvLeadEmail").value = "pat+bftest@example.com";
    d.getElementById("cvLeadMessage").value = "Hi";
    d.getElementById("cvLeadConsent").checked = true;
    hp.value = "bot-was-here";
    d.getElementById("cvLeadForm").dispatchEvent(new v.w.Event("submit", { bubbles: true, cancelable: true }));
    await settle();
    const sent = v.log.fetches.filter(f => /\/api\/cards\/lead$/.test(f.url));
    const sb = sent.length === 1 ? JSON.parse(sent[0].init.body) : {};
    check("F6. Send posts the name, email, phone, message, consent, the card's token and the honeypot, to the API, without credentials",
      sent.length === 1 && sent[0].url === "https://dynamic-prosperity-production-5382.up.railway.app/api/cards/lead" && sent[0].init.method === "POST" && sent[0].init.credentials === "omit" &&
      J(Object.keys(sb)) === J(["ref", "name", "email", "phone", "message", "consent", "form_token", "form_issued_at", "website"]) && sb.ref === "jane-doe" && sb.consent === true &&
      sb.form_token === wantTok && sb.form_issued_at === iso(T0) && sb.website === "bot-was-here", J(sb));
    check("F7. the server's success message is shown as it came, and the form is closed for more", d.getElementById("cvLeadStatus").textContent === SUCCESS_JANE.message &&
      d.getElementById("cvLeadSend").disabled === true && d.getElementById("cvLeadName").disabled === true);
    v.w.close();
    const hostile = "<img src=x id=pwnLead> Tick the box";
    const v2 = cardView({ url: "https://bizforceai.net/card/" + TOK.token, card: CARD, leadAnswer: { status: 400, body: { error: hostile } } });
    await settle();
    v2.doc.getElementById("cvLeadForm").dispatchEvent(new v2.w.Event("submit", { bubbles: true, cancelable: true }));
    await settle();
    check("F8. a server refusal is shown as text, never parsed, and Send works again",
      v2.doc.getElementById("cvLeadStatus").textContent === hostile && !v2.doc.getElementById("pwnLead") && v2.doc.getElementById("cvLeadSend").disabled === false &&
      JSON.parse(v2.log.fetches.find(f => /\/api\/cards\/lead$/.test(f.url)).init.body).ref === TOK.token);
    v2.w.close();
    const pageCode = fnOf(inlineMain(fe("card-view.html")), "renderCardLead");
    check("F9. the card page's form code writes with textContent only", pageCode.length > 500 && !/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(pageCode));
  } else check("F1. jsdom is installed", false);

  /* ════ E. the editor ════ */
  console.log("\n══ E. the editor's Leads list ══");
  const ed = fe("digital-cards.html");
  const section = (/<section id="cardLeads"[\s\S]*?<\/section>/.exec(ed) || [""])[0];
  check("E1. under the visits panel: \"Leads\", the switch \"Let visitors leave their details\", and the line word for word",
    ed.indexOf("</section>\n      <section id=\"cardLeads\"") !== -1 && section.indexOf(">Leads</h2>") !== -1 &&
    /<input type="checkbox" id="fLeadForm"> Let visitors leave their details<\/label>/.test(section) &&
    section.indexOf(">Leads are kept for 12 months, then deleted. Contact people only about what they asked.</p>") !== -1);
  check("E2. the switch is sent with the save and filled from the card", /body\.lead_form_on = document\.getElementById\("fLeadForm"\)\.checked;/.test(ed) &&
    /document\.getElementById\("fLeadForm"\)\.checked = data\.cards\[0\]\.lead_form_on === true;/.test(ed) && /document\.getElementById\("fLeadForm"\)\.checked = saved\.lead_form_on === true;/.test(ed));
  const edCode = ["cardLeadButton", "cardLeadLink", "renderCardLead", "loadCardLeads", "setCardLeadStatus", "deleteCardLead"].map(n => fnOf(ed, n)).join("\n");
  check("E3. the list's code writes with textContent and createElement only", edCode.length > 2000 && !/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(edCode));
  if (JSDOM) {
    const dom = new JSDOM("<!DOCTYPE html><body>" + section + "</body>", { runScripts: "outside-only" });
    const w = dom.window, asked = [];
    let confirmAnswer = false;
    w.confirm = () => confirmAnswer;
    const LEADS = [
      { id: "l1", name: "<img src=x id=pwnName>", email: "ann+bftest@example.com", phone: "+1 (555) 010-2030", message: "<b>hi</b>\nthere", consent_text: "I agree that Jane Doe may contact me about this message.", status: "new", created_at: iso(T0) },
      { id: "l2", name: "Bo", email: "not an email", phone: null, message: "", consent_text: "I agree that Jane Doe may contact me about this message.", status: "archived", created_at: iso(T0 - HOUR) }
    ];
    w.fetch = async (u, init) => { asked.push({ u: String(u), method: (init && init.method) || "GET", body: init && init.body, auth: init && init.headers && init.headers.Authorization });
      return { ok: true, status: 200, json: async () => ({ leads: LEADS, next_before: null }) }; };
    w.eval(fe("scripts/bf-card.js"));
    w.eval("var API_URL = 'https://api.example'; var token = 'tok'; var activeCardId = '" + CID.jane + "'; var cardLeadsBefore = null; function showToast() {}\n" + edCode);
    await w.loadCardLeads(); await settle();
    const items = w.document.querySelectorAll("#cardLeadsList li");
    const li0 = items[0], li1 = items[1];
    check("E4. in jsdom: each lead's name, message and consent sentence are text; a hostile name is not parsed",
      items.length === 2 && li0.querySelector("strong").textContent === LEADS[0].name && !w.document.getElementById("pwnName") &&
      li0.querySelector("p").textContent === "<b>hi</b>\nthere" && li0.textContent.indexOf("They agreed: I agree that Jane Doe may contact me about this message.") !== -1, items.length);
    const links = [...li0.querySelectorAll("a")].map(a => a.getAttribute("href"));
    check("E5. the email is a mailto link and the phone a tel link, both from bf-card.js; an email it refuses is plain text",
      J(links) === J([w.bfCard.mailtoHref(LEADS[0].email), w.bfCard.telHref(LEADS[0].phone)]) && links[0] === "mailto:ann+bftest@example.com" && links[1] === "tel:+15550102030" &&
      li1.querySelectorAll("a").length === 0 && li1.textContent.indexOf("not an email") !== -1, J(links));
    const btns = el => [...el.querySelectorAll("button")].map(b => b.textContent);
    check("E6. a new lead offers Mark read, Archive and Delete; an archived one only Delete", J(btns(li0)) === J(["Mark read", "Archive", "Delete"]) && J(btns(li1)) === J(["Delete"]));
    asked.length = 0;
    [...li0.querySelectorAll("button")].find(b => b.textContent === "Mark read").click(); await settle();
    const patchCall = asked.find(a => a.method === "PATCH");
    check("E7. Mark read sends PATCH { status: read } for that lead, as the owner", !!patchCall && patchCall.u === "https://api.example/api/card-leads/l1" && J(JSON.parse(patchCall.body)) === J({ status: "read" }) && patchCall.auth === "Bearer tok");
    asked.length = 0; confirmAnswer = false;
    [...w.document.querySelectorAll("#cardLeadsList li")[0].querySelectorAll("button")].find(b => b.textContent === "Delete").click(); await settle();
    const noDelete = !asked.some(a => a.method === "DELETE");
    confirmAnswer = true;
    [...w.document.querySelectorAll("#cardLeadsList li")[0].querySelectorAll("button")].find(b => b.textContent === "Delete").click(); await settle();
    const delCall = asked.find(a => a.method === "DELETE");
    check("E8. Delete asks first: refused, nothing is sent; agreed, DELETE for that lead", noDelete && !!delCall && delCall.u === "https://api.example/api/card-leads/l1");
    w.close();
  }

  /* ════ S. the shell ════ */
  console.log("\n══ S. the card page shell ══");
  check("S1. lib/cardShell.generated.js is exactly what scripts/buildCardShell.js makes from today's card-view.html and _headers (the --check rule)",
    BUILD.generate(fe("card-view.html"), fe("_headers")) === ALL[GEN]);

  /* ════ G. legal ════ */
  console.log("\n══ G. the Privacy Policy and the Terms ══");
  const PRIV = "If you turn on the lead form on a card, visitors can leave their name, an email or phone number and a message for you; BizForce stores what they send and the consent sentence they agreed to, records nothing about their device, and deletes each lead after 12 months, when you delete it, or with the card or your account.";
  const TERMS = "If you collect leads with your card, contact people only about what they asked, and delete their details if they ask you to.";
  check("G1. CARD_LEADS_PRIVACY_SENTENCE and CARD_LEADS_TERMS_SENTENCE are word for word", LP.CARD_LEADS_PRIVACY_SENTENCE === PRIV && LP.CARD_LEADS_TERMS_SENTENCE === TERMS);
  const built = LP.buildLegalPages();
  const escH = t => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const after = (h, a, b) => { const i = h.indexOf(escH(a)), j = h.indexOf(escH(b)); return i !== -1 && j > i && j - i - escH(a).length < 20; };
  // NAMED (Nov 6 2026, Google Wallet): BEFORE directly after the card visits sentence. AFTER the Google Wallet sentence sits
  // between them (it follows the visits sentence, checkGoogleWallet), so this one is directly after that.
  check("G2. the Privacy Policy carries it directly after the Google Wallet sentence, which follows the card visits sentence, as built and on disk",
    after(built["privacy.html"], LP.CARD_WALLET_PRIVACY_SENTENCE, PRIV) && after(fe("privacy.html") || "", LP.CARD_WALLET_PRIVACY_SENTENCE, PRIV) &&
    after(built["privacy.html"], LP.CARD_VISITS_PRIVACY_SENTENCE, LP.CARD_WALLET_PRIVACY_SENTENCE));
  check("G3. the Terms carry theirs directly after the media sentence, as built and on disk",
    after(built["terms.html"], LP.MEDIA_TERMS_SENTENCE, TERMS) && after(fe("terms.html") || "", LP.MEDIA_TERMS_SENTENCE, TERMS));

  /* ════ R. migration and registries ════ */
  console.log("\n══ R. migration 172 and the registries ══");
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED BEFORE → AFTER (Nov 6 2026, Outlook sign-in, migration 173): BEFORE 172 was the highest. AFTER
  // 173_mailbox_microsoft.sql is, and checkMailboxOutlook R1 holds that; 172_card_leads.sql is still the only migration numbered 172.
  // NAMED BEFORE → AFTER (Nov 6 2026, Google Wallet, migration 174): BEFORE 173 was the highest. AFTER 174_card_wallet_count.sql
  // is, held by checkGoogleWallet R1; above 172 only 173_mailbox_microsoft.sql and 174_card_wallet_count.sql are allowed, by name.
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE 174 was the highest. AFTER 175_store_changes.sql is, held by
  // checkStoreChanges R1, and is allowed above 172 by name too.
  check("R1. 172_card_leads.sql is the only migration numbered 172; the highest is 175 (checkStoreChanges R1), 171 the last before it",
    migFiles.filter(f => /^172_/.test(f)).length === 1 && migFiles.indexOf("172_card_leads.sql") !== -1 && migFiles.every(f => f === "173_mailbox_microsoft.sql" || f === "174_card_wallet_count.sql" || f === "175_store_changes.sql" || /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): 176 is allowed too; "the highest" is checkShopifyConnect R1's. */ f === "176_shopify_oauth.sql" || /* NAMED (Nov 7 2026, YouTube uploads, migration 177): 177 is allowed too; "the highest" is checkYoutubeUploads R1's. */ f === "177_youtube_uploads.sql" || /* NAMED (Nov 7 2026, TikTok posting, migration 178): 178 is allowed too; "the highest" is checkTiktokPosting R1's. */ f === "178_tiktok_posting.sql" || /* NAMED (Nov 7 2026, Instagram posting, migration 179): 179 is allowed too; "the highest" is checkInstagramPosting R1's. */ f === "179_instagram_posting.sql" || /* NAMED (Nov 7 2026, Facebook Pages posting, migration 180): 180 is allowed too; "the highest" is checkFacebookPages R1's. */ f === "180_facebook_pages.sql" || /* NAMED (Nov 8 2026, Etsy store connection, migration 181): 181 is allowed too; "the highest" is checkEtsyConnect R1's. */ f === "181_etsy_store.sql" || /* NAMED (Nov 8 2026, Amazon store connection, migration 182): 182 is allowed too; "the highest" is checkAmazonConnect R1's. */ f === "182_amazon_store.sql" || /* NAMED (Nov 11 2026, orbit stage 2, migration 183): it adds 183_weekly_goal_and_order_status.sql too; "the highest" is checkOrbitStage2 R1's. */ f === "183_weekly_goal_and_order_status.sql" || Number(f.split("_")[0]) <= 172) && migFiles.some(f => /^171_/.test(f)));
  check("R2. its header says the owner applied it by hand on Nov 6, 2026, and the rest is the SQL as run, exactly", ALL[MIG] === HEADER + "\n\n" + SQL_AS_RUN, ALL[MIG].length + " vs " + (HEADER.length + 2 + SQL_AS_RUN.length));
  check("R3. the table is RLS-on with anon and authenticated revoked, and its leads go with the card and with the account",
    /ALTER TABLE public\.card_leads ENABLE ROW LEVEL SECURITY;/.test(ALL[MIG]) && /REVOKE ALL ON public\.card_leads FROM anon, authenticated;/.test(ALL[MIG]) &&
    /card_id uuid NOT NULL REFERENCES public\.digital_cards\(id\) ON DELETE CASCADE/.test(ALL[MIG]) && /user_id uuid NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(ALL[MIG]));
  check("R4. SCHEMA_TABLES names card_leads as 172's", (SCH.SCHEMA_TABLES || []).some(e => e[0] === "card_leads" && e[1] === "172_card_leads.sql"));
  const crmClass = (BK.BACKUP_TABLES || []).indexOf("crm_customers") !== -1;
  check("R5. the backup includes card_leads, as it does crm_customers, after digital_cards", crmClass && BK.BACKUP_TABLES.indexOf("card_leads") > BK.BACKUP_TABLES.indexOf("digital_cards") &&
    !(BK.EXCLUDED_TABLES || {}).card_leads && !(BK.SKIPPED_TABLES || {}).card_leads);
  const yd = (YD.DATA || []).filter(e => e.table === "card_leads");
  check("R6. Your data: one entry in contacts, \"Leads from your digital cards\", owned by user_id, deleted, and in DELETE_ORDER before digital_cards",
    yd.length === 1 && yd[0].group === "contacts" && /^Leads from your digital cards/.test(yd[0].what) && J(yd[0].owner) === J(["user_id"]) && yd[0].onDelete === "delete" &&
    YD.DELETE_ORDER.filter(t => t === "card_leads").length === 1 && YD.DELETE_ORDER.indexOf("card_leads") < YD.DELETE_ORDER.indexOf("digital_cards"), J(yd));

  console.log("\n══ Z. zero network ══");
  check("Z1. no socket was opened and no name was looked up", NETWORK.length === 0, NETWORK.join(","));

  console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : "CHECKS FAILED: " + failures + " of " + (passes + failures)));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  the check itself crashed: " + (e && e.stack)); console.log("\nCHECKS FAILED: crashed"); process.exit(1); });
