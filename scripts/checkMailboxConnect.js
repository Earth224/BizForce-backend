"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMailboxConnect — a member connects their OWN mailbox with an app
   password and reads the inbox on request, READ ONLY (Email connection,
   Build A, migration 169, Nov 5 2026). Nothing is stored, marked or sent.

   server.js's five /api/mailbox/* routes and recordMailboxSession are lifted
   and run in a vm against an in-memory Supabase that enforces migration 169's
   CHECKs. lib/memberEmail.js runs for real (its text, possibly mutated), and
   so does lib/guardedFetch.js's resolvePublicHost: only its DNS resolver is a
   stand-in. postal-mime parses every message for real. ImapFlow and
   nodemailer are stand-ins that record every option they are given and every
   method called on them; the IMAP commands they would send are written by
   ImapFlow 2.9.1's OWN command builders (commands/select.js and
   commands/fetch.js), run against a recording connection, so "EXAMINE" and
   "BODY.PEEK[]" are what the real library puts on the wire. Nothing leaves the
   machine: every socket and DNS lookup is a tripwire, and no model is called.

   WHAT THIS PROVES
     P. Migration 169: the 19 columns in order, the 13 CHECKs, RLS on with no
        policy, the header; the code's host and address patterns equal the
        SQL's; M2: 169 is the highest migration and used once.
     N. What a member types: the four presets win over typed names; "other"
        needs both names and SMTP 465 or 587; IP literals, localhost, single
        labels, port 25 and 143 are refused; the app password's shape.
     O. The options: IMAP 993 implicit TLS only; SMTP 465 implicit or 587 with
        STARTTLS required; the vetted address as host and the real name as
        servername; certificate checks on, TLS 1.2 at least; no logging; the
        timeouts.
     LIB. The library facts the design leans on, read from node_modules: the
        exact versions; EXAMINE for readOnly and BODY.PEEK[] for source (run);
        nodemailer's requireTLS, servername and no-second-lookup lines.
     A. Connect: the middleware and limiters; sealed BEFORE either check (no
        key, no request); stored only after the IMAP login AND the SMTP auth
        check; the secret never in a response, a log or the database in the
        clear; one row per member.
     V. A refused password, a refused SMTP login, a throttle, no answer, a
        private address and a mixed name each store nothing; one attempt each;
        classify by codes and properties, never message text.
     R. Reading: nothing on the status read; the list (30 newest, the cursor,
        no body asked for); one message as plain text (PEEK, HTML converted,
        attachments listed and never returned, 2 MB refused before the source
        is asked for, 100,000 characters at most); only the allowed client
        methods, no flag, move, copy, expunge or append; the only writes are
        the connection's own stamps; every message still unread.
     E. Errors: a refused password marks needs_reconnect with ONE notice; a
        throttle backs off 15 minutes with no connection; no retry; an
        unreadable secret; not connected.
     D. Status and disconnect, only the caller's row.
     X. Export, backup, deletion and the schema list.
     S. No send code: nothing in the module or the routes sends mail.
     J. The page in jsdom: nothing loads on open, the password field cleared
        whatever the answer, every word set as text, the offline line; the
        dashboard and Email agent links.
     L. Privacy and Terms, word for word, and the third-party line.
     G. The guide tip.
     Z. Zero network.

   MUTATE=<name> edits the source in memory (nothing on disk changes).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly
   once is an ERROR, never counted as caught.

   Test secrets only: every app password below is made up, and is never
   printed (safe() masks each one in any detail a FAIL line shows).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const Module = require("module");
const s = require("./_shared");

/* ── the network tripwire, before anything can open a socket ──────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMailboxConnect: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMailboxConnect: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the app password is stored as typed (hex-encoded, so it even passes 169's hex CHECK)
  "plaintext-secret-stored": [["SRC", "          secret_ciphertext: sealedSecret.ciphertext,\n",
    "          secret_ciphertext: Buffer.from(String(form.app_password)).toString(\"hex\"),\n"]],
  // the app password comes back in the connect response
  "secret-in-response": [["SRC", "      return res.json(me.statusOf(stored.data));\n",
    "      return res.json(Object.assign(me.statusOf(stored.data), { app_password: form.app_password }));\n"]],
  // the app password is written to the server log
  "secret-logged": [["SRC", "      var checked = await me.verifyConnection(asked.settings, appPassword.value);\n",
    "      console.log(\"[mailbox/connect] checking \" + asked.settings.email_address + \" with \" + appPassword.value);\n" +
    "      var checked = await me.verifyConnection(asked.settings, appPassword.value);\n"]],
  // IMAP on 143 (plaintext or STARTTLS) is accepted
  "imap-port-143-allowed": [
    ["ME", "  if (settings.imap_port !== IMAP_PORT) throw new MailboxError(\"unreachable\", \"imap_port\");\n",
      "  if (settings.imap_port !== IMAP_PORT && settings.imap_port !== 143) throw new MailboxError(\"unreachable\", \"imap_port\");\n"],
    ["ME", "    port: IMAP_PORT,\n    secure: true,\n", "    port: settings.imap_port,\n    secure: settings.imap_port === IMAP_PORT,\n"],
    ["ME", "  if (!settings || normalizeHost(settings.imap_host) !== settings.imap_host || settings.imap_port !== IMAP_PORT ||\n",
      "  if (!settings || normalizeHost(settings.imap_host) !== settings.imap_host || (settings.imap_port !== IMAP_PORT && settings.imap_port !== 143) ||\n"]],
  // SMTP on 25 is accepted
  "smtp-port-25-allowed": [["ME", "const SMTP_PORTS = Object.freeze([465, 587]);\n", "const SMTP_PORTS = Object.freeze([465, 587, 25]);\n"]],
  // 587 without STARTTLS required (it would fall back to plaintext)
  "starttls-not-required": [["ME", "    requireTLS: port === 587,\n", "    requireTLS: false,\n"]],
  // certificates are not checked
  "tls-unverified": [["ME", "  return { servername: host, rejectUnauthorized: true, minVersion: \"TLSv1.2\" };\n",
    "  return { servername: host, rejectUnauthorized: false, minVersion: \"TLSv1.2\" };\n"]],
  // the IMAP connection carries no servername, so the certificate is checked against nothing
  "servername-missing": [["ME", "    servername: settings.imap_host,\n    tls: tlsFor(settings.imap_host),\n",
    "    tls: { rejectUnauthorized: true, minVersion: \"TLSv1.2\" },\n"]],
  // the library is handed the name, and resolves it again itself (the rebinding gap)
  "hostname-not-pinned": [["ME", "    host: address,\n    port: IMAP_PORT,\n", "    host: settings.imap_host,\n    port: IMAP_PORT,\n"]],
  // a name that resolves to a private address is connected to
  "private-address-allowed": [["GF", "        const verdict = isBlockedAddress(a.address);\n", "        const verdict = null;\n"]],
  // INBOX opened with SELECT (read-write)
  "mailbox-opened-writable": [["ME", "    var opened = await client.mailboxOpen(\"INBOX\", { readOnly: true });\n",
    "    var opened = await client.mailboxOpen(\"INBOX\", { readOnly: false });\n"]],
  // the body fetched with a raw BODY[] command, which marks the message read
  "body-without-peek": [["ME", "  var full = await client.fetchOne(String(uid), { uid: true, source: true }, { uid: true });\n",
    "  var full = await client.exec(\"UID FETCH\", [{ type: \"SEQUENCE\", value: String(uid) }, [{ type: \"ATOM\", value: \"BODY\", section: [] }]]);\n"]],
  // the listed messages are saved as a run
  "message-stored": [["SRC", "      await recordMailboxSession(req.user.id, box.email_address, listed);\n",
    "      if (listed.ok) await supabase.from(\"ai_tasks\").insert({ user_id: req.user.id, agent_type: \"email\", task_type: \"email/inbox\", status: \"completed\", output: listed.value });\n" +
    "      await recordMailboxSession(req.user.id, box.email_address, listed);\n"]],
  // a message over 2 MB is opened
  "oversize-opened": [
    ["ME", "  if (typeof meta.size !== \"number\" || meta.size > OPEN_MAX_BYTES) throw new MailboxError(\"too_large\", \"over_limit\");\n",
      "  if (typeof meta.size !== \"number\") throw new MailboxError(\"too_large\", \"over_limit\");\n"],
    ["ME", "  if (full.source.length > OPEN_MAX_BYTES) throw new MailboxError(\"too_large\", \"over_limit\");\n", ""]],
  // an HTML-only message is returned as its HTML
  "html-returned": [["ME", "(typeof email.html === \"string\" ? htmlToText(email.html) : \"\")", "(typeof email.html === \"string\" ? email.html : \"\")"]],
  // the attachment's bytes are returned
  "attachment-downloaded": [["ME", "size: byteLength(a && a.content) };\n",
    "size: byteLength(a && a.content), content: Buffer.from(a.content).toString(\"base64\") };\n"]],
  // the text is not capped
  "text-uncapped": [["ME", "  if (truncated) text = text.slice(0, TEXT_MAX);\n", "  if (false) text = text.slice(0, TEXT_MAX);\n"]],
  // a refused login is tried again
  "retry-on-auth-fail": [["ME", "      await client.connect();\n      loggedIn = true;\n    } finally {\n",
    "      try { await client.connect(); } catch (first) { client = new ImapFlow(imapOptions(settings, imapAddress, typed)); await client.connect(); }\n      loggedIn = true;\n    } finally {\n"]],
  // the needs_reconnect mark is not conditional, so every failure notifies again
  "notice-every-failure": [["SRC", "      .from(\"member_email_connections\")\n      .update(Object.assign({ status: \"needs_reconnect\" }, errorPatch))\n      .eq(\"user_id\", userId)\n      .eq(\"status\", \"connected\")\n",
    "      .from(\"member_email_connections\")\n      .update(Object.assign({ status: \"needs_reconnect\" }, errorPatch))\n      .eq(\"user_id\", userId)\n"]],
  // the inbox list is open to a member without a subscription
  "unsubscribed-can-read": [["SRC", "app.get(\"/api/mailbox/inbox\", requireAuth, requireActiveSubscription, mailboxReadHourLimiter, mailboxReadDayLimiter,",
    "app.get(\"/api/mailbox/inbox\", requireAuth, mailboxReadHourLimiter, mailboxReadDayLimiter,"]],
  // the export reads every column of the connection
  "export-leaks-secret": [["YD", "    owner: [\"user_id\"], key: \"provider\", select: \"provider, email_address, created_at\", onDelete: \"delete\" },\n",
    "    owner: [\"user_id\"], key: \"provider\", onDelete: \"delete\" },\n"]],
  // the SMTP auth check is skipped
  "smtp-not-verified": [["ME", "      await transport.verify();\n", "      void transport;\n"]],
  // the IMAP login is skipped
  "imap-not-verified": [["ME", "      await client.connect();\n      loggedIn = true;\n    } finally {\n", "      loggedIn = false;\n    } finally {\n"]],
  // ImapFlow logs (its logs carry the server's replies and the sign-in name)
  "library-logging-on": [["ME", "    logger: false,\n    emitLogs: false,\n", "    logger: console,\n    emitLogs: true,\n"]],
  // the Privacy page loses the mailbox sentence
  "privacy-sentence-removed": [["FE:privacy.html", "If you connect your mailbox, BizForce stores your email address", "BizForce stores your email address"]],
  // the page writes a server or message word as markup
  "innerHTML-on-page": [["FE:scripts/mailbox.js", "    if (text !== undefined && text !== null) n.textContent = String(text);\n",
    "    if (text !== undefined && text !== null) n.innerHTML = String(text);\n"]],
  // added: opening a message marks it read
  "marks-seen": [["ME", "  full = null;\n", "  full = null;\n  await client.messageFlagsAdd(String(uid), [\"\\\\Seen\"], { uid: true });\n"]],
  // added: connecting sends a test mail (Build B's job, and not this build's)
  "sends-mail": [["ME", "      await transport.verify();\n",
    "      await transport.verify();\n      await transport.sendMail({ from: settings.email_address, to: settings.email_address, subject: \"Connected\", text: \"BizForce is connected.\" });\n"]],
  // added: the 15-minute back-off is not honoured
  "backoff-ignored": [["ME", "  if (held) return { ok: false, reason: \"rate_limited\", code: \"backoff\", resumes_at: new Date(held).toISOString() };\n",
    "  if (false) return { ok: false, reason: \"rate_limited\", code: \"backoff\", resumes_at: new Date(held).toISOString() };\n"]],
  // added: disconnect deletes other members' rows
  "disconnect-any-row": [["SRC", "      .from(\"member_email_connections\")\n      .delete()\n      .eq(\"user_id\", req.user.id)\n",
    "      .from(\"member_email_connections\")\n      .delete()\n      .neq(\"user_id\", \"\")\n"]],
  // added: subjects are not capped
  "subject-uncapped": [["ME", "      subject: cleanLine(env.subject, SUBJECT_MAX),\n", "      subject: cleanLine(env.subject, 100000),\n"]],
  // added: the list asks for every message's source
  "list-fetches-body": [["ME", "{ uid: true, flags: true, envelope: true, size: true, internalDate: true }", "{ uid: true, flags: true, envelope: true, size: true, internalDate: true, source: true }"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let failures = 0, passes = 0;
const lf = t => t.replace(/\r\n/g, "\n");
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const J = JSON.stringify;

/* ── test secrets: made up, never printed ─────────────────────────────────── */
const PW = {
  alice: "abcd efgh ijkl mnop",
  bob: "bobTestAppPassword-0001",
  carol: "carolTestAppPassword-02",
  wrong: "wrongTestAppPassword-99",
  dave: "daveTestAppPassword-003",
  gina: "ginaTestAppPassword-004",
  frank: "frankTestAppPassword-05",
  rita: "ritaTestAppPassword-006",
  tom: "tomTestAppPassword-0007",
  uma: "umaTestAppPassword-0008",
  vic: "vicTestAppPassword-0009"
};
const SECRET_FORMS = [];
Object.keys(PW).forEach(k => { const v = PW[k]; SECRET_FORMS.push(v, Buffer.from(v).toString("hex"), Buffer.from(v).toString("base64")); });
const safe = x => { let t = typeof x === "string" ? x : J(x); SECRET_FORMS.forEach(f => { t = t.split(f).join("[secret]"); }); return t; };
const noSecretIn = text => SECRET_FORMS.every(f => String(text).indexOf(f) === -1);
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + safe(String(detail)).slice(0, 300) + "]" : "")); }
}

/* ── the sources, mutated in memory ───────────────────────────────────────── */
const SOURCES = {
  SRC: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  ME: lf(fs.readFileSync(path.join(REPO, "lib/memberEmail.js"), "utf8")),
  GF: lf(fs.readFileSync(path.join(REPO, "lib/guardedFetch.js"), "utf8")),
  YD: lf(fs.readFileSync(path.join(REPO, "lib/yourData.js"), "utf8"))
};
const FE_FILES = ["mailbox.html", "scripts/mailbox.js", "scripts/termaximus-guide.js", "privacy.html", "terms.html", "dashboard.html", "email-agent.html"];
FE_FILES.forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
const MIGRATION = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/169_member_email_connections.sql"), "utf8"));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];

/* A lib file compiled from its (possibly mutated) text, requiring its own siblings from disk. */
function loadLib(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
const TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.ENCRYPTION_SECRET = TEST_KEY;
const CRYPTO = require(path.join(REPO, "lib/apiKeyCrypto.js"));
const GF = loadLib("lib/guardedFetch.js", SOURCES.GF);
const ME = loadLib("lib/memberEmail.js", SOURCES.ME);
const YDATA = loadLib("lib/yourData.js", SOURCES.YD);
const LP = require(path.join(REPO, "lib/legalPages.js"));
const BACKUP = require(path.join(REPO, "lib/backup.js"));
let JSDOM = null;
try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }

/* ── ImapFlow's own command builders, run against a recording connection ──── */
const IMAP_DIR = path.join(REPO, "node_modules/imapflow/dist/cjs");
const FETCH_CMD = require(path.join(IMAP_DIR, "commands/fetch.js"));
const SELECT_CMD = require(path.join(IMAP_DIR, "commands/select.js"));
function wireConn(wire, state) {
  return {
    states: { NOT_AUTHENTICATED: 1, AUTHENTICATED: 2, SELECTED: 3, LOGOUT: 4 }, state: state,
    mailbox: { path: "INBOX", uidValidity: BigInt(1) },
    capabilities: new Map(), enabled: new Set(), log: { debug() {}, warn() {}, info() {}, error() {}, trace() {} },
    createNoMailboxError() { return new Error("no mailbox"); },
    async exec(command, attributes) {
      wire.push(command + " " + J(attributes, (k, v) => typeof v === "bigint" ? String(v) : v));
      return { next() {}, response: { attributes: [] } };
    },
    folders: new Map([["INBOX", { path: "INBOX", delimiter: "/" }]]), emit() {}, async run() { return []; },
    namespace: { delimiter: "/", prefix: "" }
  };
}
async function wireOf(builder, args, state) {
  const wire = [];
  try { await builder.apply(null, [wireConn(wire, state)].concat(args)); } catch (e) { wire.push("BUILDER ERROR " + e.message); }
  return wire;
}
// A FETCH line that reads a body without PEEK (BODY[...], BINARY[...], RFC822, RFC822.TEXT) would mark it read.
const NON_PEEK = /"value":"(BODY|BINARY|RFC822|RFC822\.TEXT)"/;
const BODY_ASKED = /"value":"(BODY|BINARY)(\.PEEK)?"|"value":"RFC822(\.TEXT)?"/;
const WRITE_COMMANDS = /^(UID )?(STORE|COPY|MOVE|EXPUNGE)\b|^(APPEND|DELETE|RENAME|CREATE|SELECT)\b/;

/* ── the stub mail servers ────────────────────────────────────────────────── */
const STUB = {
  names: {
    "imap.gmail.com": ["142.250.1.10"], "smtp.gmail.com": ["142.250.1.20"],
    "imap.fastmail.com": ["103.168.172.10"], "smtp.fastmail.com": ["103.168.172.20"],
    "imap.kiln.example": ["93.184.216.34"], "smtp.kiln.example": ["93.184.216.35"],
    "imap.private.example": ["10.0.0.5"], "imap.mixed.example": ["93.184.216.40", "192.168.1.9"]
  },
  boxes: {}, smtpUsers: {}, imapMode: {}, smtpMode: {},
  clients: [], transports: [], wire: [], resolved: [],
  everClients: [], everTransports: []   // never reset: every client and transport the whole run made
};
function errOf(props) { const e = new Error("stub failure"); Object.assign(e, props); return e; }
function fakeResolve(hostname, options, cb) {
  STUB.resolved.push(hostname);
  const list = STUB.names[hostname];
  if (!list) { const e = new Error("getaddrinfo ENOTFOUND"); e.code = "ENOTFOUND"; return cb(e); }
  return cb(null, list.map(a => ({ address: a, family: 4 })));
}
const GFX = GF.createGuardedFetch({ resolve: fakeResolve, request: function () { NETWORK.push("request"); throw new Error("no network"); } });

const ALLOWED_CLIENT_CALLS = ["connect", "mailboxOpen", "search", "fetch", "fetchOne", "logout", "close"];
function pick(m, q) {
  const out = { uid: m.uid, seq: m.uid };
  if (q.flags) out.flags = new Set(m.flags);
  if (q.envelope) out.envelope = { from: clone(m.from), subject: m.subject, date: new Date(m.date) };
  if (q.size) out.size = m.size;
  if (q.internalDate) out.internalDate = new Date(m.date);
  if (q.source) out.source = m.source;
  return out;
}
function noteWire(rec, lines) {
  lines.forEach(l => {
    STUB.wire.push(l); rec.wire.push(l);
    // a server marks a message read when its body is fetched without PEEK
    if (/FETCH/.test(l) && NON_PEEK.test(l) && rec.box) {
      const uids = ((/"type":"SEQUENCE","value":"([^"]+)"/.exec(l) || [])[1] || "").split(",").map(Number);
      rec.box.messages.forEach(m => { if (uids.indexOf(m.uid) !== -1 && m.flags.indexOf("\\Seen") === -1) m.flags.push("\\Seen"); });
    }
  });
}
function FakeImapFlow(options) {
  const rec = { options: options, calls: [], wire: [], box: null };
  STUB.clients.push(rec); STUB.everClients.push(rec);
  const host = options.servername;
  const impl = {
    async connect() {
      rec.calls.push("connect");
      const mode = STUB.imapMode[host];
      if (mode === "down") throw errOf({ code: "ECONNREFUSED" });
      if (mode === "throttle") throw errOf({ code: "ETHROTTLE" });
      if (mode === "limit") throw errOf({ serverResponseCode: "LIMIT" });
      const auth = options.auth || {};
      const box = STUB.boxes[host + " " + auth.user];
      if (!box || box.password !== auth.pass) throw errOf({ authenticationFailed: true, serverResponseCode: "AUTHENTICATIONFAILED", message: "Invalid credentials (Failure)" });
      rec.box = box;
    },
    async mailboxOpen(p, o) {
      rec.calls.push("mailboxOpen");
      noteWire(rec, await wireOf(SELECT_CMD, [p, o || {}], 2));
      rec.opened = { path: p, opts: clone(o || {}) };
      return { path: p, readOnly: !!(o && o.readOnly), exists: rec.box ? rec.box.messages.length : 0 };
    },
    async search(q, o) {
      rec.calls.push("search");
      rec.searches = (rec.searches || []).concat([J([q, o])]);
      const all = rec.box.messages.map(m => m.uid);
      if (q && q.all) return all;
      const m = /^1:(\d+)$/.exec(String(q && q.uid || ""));
      return m ? all.filter(u => u <= Number(m[1])) : [];
    },
    fetch(range, q, o) {
      rec.calls.push("fetch");
      rec.fetchQueries = (rec.fetchQueries || []).concat([J(q)]);
      return (async function* () {
        noteWire(rec, await wireOf(FETCH_CMD, [range, q, o], 3));
        const uids = String(range).split(",").map(Number);
        for (const m of rec.box.messages) if (uids.indexOf(m.uid) !== -1) yield pick(m, q);
      })();
    },
    async fetchOne(range, q, o) {
      rec.calls.push("fetchOne");
      rec.fetchQueries = (rec.fetchQueries || []).concat([J(q)]);
      noteWire(rec, await wireOf(FETCH_CMD, [range, q, o], 3));
      const m = rec.box.messages.find(x => String(x.uid) === String(range));
      return m ? pick(m, q) : false;
    },
    async exec(command, attributes) {
      rec.calls.push("exec");
      noteWire(rec, [command + " " + J(attributes)]);
      const uid = Number(((attributes || [])[0] || {}).value);
      const m = rec.box && rec.box.messages.find(x => x.uid === uid);
      return m ? { uid: uid, source: m.source } : {};
    },
    async logout() { rec.calls.push("logout"); },
    close() { rec.calls.push("close"); }
  };
  return new Proxy(impl, {
    get(t, prop) {
      if (prop in t) return t[prop];
      if (typeof prop === "symbol" || prop === "then") return undefined;
      return function () {
        rec.calls.push("unexpected:" + String(prop));
        if (/flag/i.test(String(prop)) && rec.box) {
          const uid = Number(arguments[0]);
          rec.box.messages.forEach(m => { if (m.uid === uid && m.flags.indexOf("\\Seen") === -1) m.flags.push("\\Seen"); });
        }
        return Promise.resolve(true);
      };
    }
  });
}
function fakeCreateTransport(options) {
  const rec = { options: options, calls: [] };
  STUB.transports.push(rec); STUB.everTransports.push(rec);
  const host = options.servername;
  const impl = {
    async verify() {
      rec.calls.push("verify");
      const mode = STUB.smtpMode[host];
      if (mode === "down") throw errOf({ code: "ECONNECTION" });
      if (mode === "throttle") throw errOf({ code: "EAUTH", responseCode: 421 });
      const auth = options.auth || {};
      if (STUB.smtpUsers[host + " " + auth.user] !== auth.pass) throw errOf({ code: "EAUTH", responseCode: 535, message: "Username and Password not accepted" });
      return true;
    },
    close() { rec.calls.push("close"); },
    async sendMail() { rec.calls.push("sendMail"); return { messageId: "x" }; }
  };
  return new Proxy(impl, {
    get(t, prop) {
      if (prop in t) return t[prop];
      if (typeof prop === "symbol" || prop === "then") return undefined;
      return function () { rec.calls.push("unexpected:" + String(prop)); return Promise.resolve(true); };
    }
  });
}
const CLOCK = { now: Date.parse("2026-11-05T12:00:00.000Z") };
ME.deps.ImapFlow = () => FakeImapFlow;
ME.deps.createTransport = fakeCreateTransport;
ME.deps.resolvePublicHost = host => GFX.resolvePublicHost(host);
ME.deps.now = () => CLOCK.now;
function resetStubCounters() { STUB.clients = []; STUB.transports = []; STUB.wire = []; STUB.resolved = []; }

/* ── the messages (every address on the +bftest pattern) ─────────────────── */
const ATTACH_MARK = "BFTEST-ATTACHMENT-BYTES-0123456789-do-not-return";
const ATTACH_B64 = Buffer.from(ATTACH_MARK).toString("base64");
const HOSTILE = "<img src=x onerror=alert(1)>";
const CRLF = "\r\n";
function rawMail(headers, body) { return Buffer.from(headers.join(CRLF) + CRLF + CRLF + body); }
const HEAD = (subject, extra) => ["From: Ann Lee <ann+bftest@example.com>", "To: Alice <alice+bftest@example.com>", "Cc: Cy <cy+bftest@example.com>",
  "Subject: " + subject, "Date: Wed, 04 Nov 2026 10:00:00 +0000", "Message-ID: <" + subject.length + "@example.com>", "MIME-Version: 1.0"].concat(extra || []);
const LONG_TEXT = "glaze ".repeat(25000);   // 150,000 characters
const MSG = {
  plain: rawMail(HEAD("Kiln schedule", ["Content-Type: text/plain; charset=utf-8"]), "The kiln fires Saturday at 9." + CRLF),
  html: rawMail(HEAD("Glaze notes", ["Content-Type: text/html; charset=utf-8"]),
    "<html><head><title>T</title><style>p{color:red}</style></head><body><p>Fire &amp; glaze</p><script>steal()</script><div>Line two &lt;3</div></body></html>"),
  attach: rawMail(HEAD("Invoice attached", ["Content-Type: multipart/mixed; boundary=\"b1\""]),
    "--b1" + CRLF + "Content-Type: text/plain; charset=utf-8" + CRLF + CRLF + "See the invoice." + CRLF +
    "--b1" + CRLF + "Content-Type: application/pdf; name=\"invoice.pdf\"" + CRLF + "Content-Disposition: attachment; filename=\"invoice.pdf\"" + CRLF +
    "Content-Transfer-Encoding: base64" + CRLF + CRLF + ATTACH_B64 + CRLF + "--b1--" + CRLF),
  long: rawMail(HEAD("Long letter", ["Content-Type: text/plain; charset=utf-8"]), LONG_TEXT)
};
const BIG = 3 * 1024 * 1024;
function aliceMessages() {
  const list = [];
  for (let uid = 1; uid <= 40; uid++) {
    let m = { uid: uid, from: [{ name: "Filler " + uid, address: "filler" + uid + "+bftest@example.com" }], subject: "Note " + uid,
      date: new Date(Date.parse("2026-10-01T00:00:00Z") + uid * 3600000).toISOString(), flags: uid % 2 ? [] : ["\\Seen"], source: null, size: 0 };
    if (uid === 40) m = Object.assign(m, { from: [{ name: "Ann Lee", address: "ann+bftest@example.com" }], subject: "Kiln schedule", flags: [], source: MSG.plain });
    if (uid === 39) m = Object.assign(m, { subject: "Glaze notes", flags: [], source: MSG.html });
    if (uid === 38) m = Object.assign(m, { subject: "Invoice attached", flags: [], source: MSG.attach });
    if (uid === 37) m = Object.assign(m, { subject: "Long letter", flags: [], source: MSG.long });
    if (uid === 36) m = Object.assign(m, { subject: "Big photos", flags: [], source: Buffer.alloc(64, 65), size: BIG });
    if (uid === 35) m = Object.assign(m, { subject: "S".repeat(350) + "\u0007end", flags: [] });
    if (!m.source) m.source = rawMail(HEAD(m.subject.slice(0, 50), ["Content-Type: text/plain; charset=utf-8"]), "Filler body " + uid + CRLF);
    if (!m.size) m.size = m.source.length;
    list.push(m);
  }
  return list;
}

/* ── the fake database, with migration 169's CHECKs ──────────────────────── */
const SQL_BODY = (/CREATE TABLE public\.member_email_connections \(([\s\S]*?)\n\);/.exec(MIGRATION) || ["", ""])[1];
const HOST_SQL = (/imap_host ~ '([^']+)'/.exec(SQL_BODY) || [])[1];
const SMTP_HOST_SQL = (/smtp_host ~ '([^']+)'/.exec(SQL_BODY) || [])[1];
const EMAIL_SQL = (/email_address ~ '([^']+)'/.exec(SQL_BODY) || [])[1];
function violates(table, row) {
  if (table !== "member_email_connections") return null;
  const len = v => String(v == null ? "" : v).length;
  if (["gmail", "yahoo", "icloud", "fastmail", "other"].indexOf(row.provider) === -1) return "member_email_connections_provider_check";
  if (len(row.email_address) > 254 || !new RegExp(EMAIL_SQL).test(String(row.email_address))) return "member_email_connections_email_check";
  if (len(row.username) < 1 || len(row.username) > 254) return "member_email_connections_username_check";
  if (len(row.imap_host) < 4 || len(row.imap_host) > 253 || !new RegExp(HOST_SQL).test(String(row.imap_host))) return "member_email_connections_imap_host_check";
  if (row.imap_port !== 993) return "member_email_connections_imap_port_check";
  if (len(row.smtp_host) < 4 || len(row.smtp_host) > 253 || !new RegExp(SMTP_HOST_SQL).test(String(row.smtp_host))) return "member_email_connections_smtp_host_check";
  if ([465, 587].indexOf(row.smtp_port) === -1) return "member_email_connections_smtp_port_check";
  if (row.auth_kind !== "app_password") return "member_email_connections_auth_kind_check";
  if (!/^[0-9a-f]+$/.test(String(row.secret_ciphertext))) return "member_email_connections_ciphertext_check";
  if (!/^[0-9a-f]{24}$/.test(String(row.secret_iv))) return "member_email_connections_iv_check";
  if (!/^[0-9a-f]{32}$/.test(String(row.secret_auth_tag))) return "member_email_connections_auth_tag_check";
  if (["connected", "needs_reconnect", "disconnected"].indexOf(row.status) === -1) return "member_email_connections_status_check";
  if (row.last_error_code != null && len(row.last_error_code) > 60) return "member_email_connections_error_code_check";
  return null;
}
const DEFAULTS = {
  member_email_connections: () => ({ imap_port: 993, smtp_port: 465, auth_kind: "app_password", status: "connected", last_ok_at: null, last_error_at: null,
    last_error_code: null, created_at: "2026-11-05T09:00:00.000Z", updated_at: "2026-11-05T09:00:00.000Z" }),
  notifications: () => ({ read: false, created_at: "2026-11-05T12:00:00.000Z" })
};
function fakeDb(seed) {
  const db = { tables: {}, log: [], seq: 0 };
  Object.keys(seed || {}).forEach(t => { db.tables[t] = seed[t].map(clone); });
  const rows = t => db.tables[t] || (db.tables[t] = []);
  function project(row, cols) {
    if (!cols || cols.trim() === "*") return clone(row);
    const out = {};
    cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c] === undefined ? null : row[c]; });
    return out;
  }
  const keep = (q, r) => q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "neq" ? r[f[1]] !== f[2] : true);
  function finish(q, list) {
    const cols = q.op === "select" ? q.cols : q.retCols;
    const data = (q.op === "select" || q.returning) ? list.map(r => project(r, cols)) : null;
    if (q.single === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: (data ? data.length : 0) + " rows" } };
    if (q.single === "maybe") return data && data.length > 1 ? { data: null, error: { message: "more than one row" } } : { data: data ? data[0] || null : null, error: null };
    return { data: data, error: null };
  }
  function insertOne(table, payload) {
    const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++db.seq).padStart(12, "0") }, DEFAULTS[table] ? DEFAULTS[table]() : {}, clone(payload));
    const bad = violates(table, row);
    if (bad) return { error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } };
    if (table === "member_email_connections" && rows(table).some(r => r.user_id === row.user_id)) return { error: { code: "23505", message: "duplicate key" } };
    rows(table).push(row);
    return { row };
  }
  function answer(q) {
    db.log.push(clone({ table: q.table, op: q.op, payload: q.payload, filters: q.filters }));
    if (q.op === "insert") {
      const made = [];
      for (const p of [].concat(q.payload)) { const r = insertOne(q.table, p); if (r.error) return Promise.resolve({ data: null, error: r.error }); made.push(r.row); }
      return Promise.resolve(finish(q, made));
    }
    if (q.op === "upsert") {
      const keys = String((q.opts && q.opts.onConflict) || "id").split(",");
      const found = rows(q.table).find(r => keys.every(k => r[k] === q.payload[k]));
      if (found) {
        const bad = violates(q.table, Object.assign({}, found, clone(q.payload)));
        if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } });
        Object.assign(found, clone(q.payload));
        return Promise.resolve(finish(q, [found]));
      }
      const r = insertOne(q.table, q.payload);
      if (r.error) return Promise.resolve({ data: null, error: r.error });
      return Promise.resolve(finish(q, [r.row]));
    }
    const hits = rows(q.table).filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) { const bad = violates(q.table, Object.assign({}, r, q.payload)); if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } }); }
      hits.forEach(r => Object.assign(r, clone(q.payload)));
      return Promise.resolve(finish(q, hits));
    }
    if (q.op === "delete") {
      db.tables[q.table] = rows(q.table).filter(r => hits.indexOf(r) === -1);
      return Promise.resolve(finish(q, hits));
    }
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", cols: "*", retCols: "*", payload: null, opts: null, filters: [], single: false, returning: false };
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols || "*"; else { q.returning = true; q.retCols = cols || "*"; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p, o) { q.op = "upsert"; q.payload = p; q.opts = o; return b; },
      delete() { q.op = "delete"; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      neq(c, v) { q.filters.push(["neq", c, v]); return b; },
      order() { return b; }, limit() { return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    return b;
  }
  db.client = { from };
  db.rows = rows;
  db.writes = () => db.log.filter(q => q.op !== "select");
  return db;
}

/* ── server.js, lifted ────────────────────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
const FN_AT = new Map(), DECL_AT = new Map();
{
  let m;
  const fre = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm;
  while ((m = fre.exec(SRC))) if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index);
  const dre = /^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm;
  while ((m = dre.exec(SRC))) {
    const at = m.index;
    if (!DECL_AT.has(m[1]) && !SPANS.some(([x, y]) => at > x && at < y)) DECL_AT.set(m[1], { index: at, length: m[0].length });
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
  const d = DECL_AT.get(name);
  if (!d) return null;
  const brk = /;\n/g; brk.lastIndex = d.index + d.length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(d.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "rateLimit", "anthropic", "Anthropic"]);
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closureParts(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return have;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  if (SRC.indexOf(sig, start + 1) !== -1) throw new Error(method.toUpperCase() + " " + route + " is defined twice");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const R = {
  connect: ["post", "/api/mailbox/connect"], status: ["get", "/api/mailbox/status"], disconnect: ["post", "/api/mailbox/disconnect"],
  inbox: ["get", "/api/mailbox/inbox"], open: ["get", "/api/mailbox/inbox/:uid"]
};
const API_ROOT = "\n\nthis.api = { recordMailboxSession: recordMailboxSession };";
let LIFTED, ROUTE_TEXT;
try {
  ROUTE_TEXT = Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n");
  const root = ROUTE_TEXT + API_ROOT;
  LIFTED = [...closureParts(root).values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}
// The mailbox block of server.js, start to end, for the no-send and no-store reads.
const BLOCK_START = SRC.indexOf("// ── Mailbox: a member's own inbox, read only (migration 169)");
const BLOCK = BLOCK_START === -1 ? "" : SRC.slice(BLOCK_START, SRC.indexOf("// ── SEO Agent: Social Search", BLOCK_START));

const ALICE = "aaaaaaaa-0000-4000-8000-000000000001", BOB = "bbbbbbbb-0000-4000-8000-000000000002", CAROL = "cccccccc-0000-4000-8000-000000000003",
  DAVE = "dddddddd-0000-4000-8000-000000000004", GINA = "eeeeeeee-0000-4000-8000-000000000005", FRANK = "ffffffff-0000-4000-8000-000000000006",
  RITA = "abababab-0000-4000-8000-000000000007", TOM = "cdcdcdcd-0000-4000-8000-000000000008", UMA = "efefefef-0000-4000-8000-000000000009",
  VIC = "a1a1a1a1-0000-4000-8000-000000000010", NOBODY = "b2b2b2b2-0000-4000-8000-000000000011";
const ADDR = { alice: "alice+bftest@example.com", bob: "bob+bftest@example.com", carol: "carol+bftest@example.com", dave: "dave+bftest@example.com",
  gina: "gina+bftest@example.com", frank: "frank+bftest@example.com", rita: "rita+bftest@example.com", tom: "tom+bftest@example.com",
  uma: "uma+bftest@example.com", vic: "vic+bftest@example.com" };
function seedServers() {
  STUB.boxes = {
    ["imap.gmail.com " + ADDR.alice]: { password: PW.alice, messages: aliceMessages() },
    ["imap.kiln.example bob-signin"]: { password: PW.bob, messages: aliceMessages().slice(0, 2) },
    ["imap.gmail.com " + ADDR.carol]: { password: PW.carol, messages: [] },
    ["imap.gmail.com " + ADDR.dave]: { password: PW.dave, messages: [] },
    ["imap.fastmail.com " + ADDR.gina]: { password: PW.gina, messages: [] },
    ["imap.gmail.com " + ADDR.rita]: { password: PW.rita, messages: aliceMessages().slice(0, 3) },
    ["imap.fastmail.com " + ADDR.tom]: { password: PW.tom, messages: aliceMessages().slice(0, 3) },
    ["imap.gmail.com " + ADDR.uma]: { password: PW.uma, messages: aliceMessages().slice(0, 3) },
    ["imap.gmail.com " + ADDR.vic]: { password: PW.vic, messages: aliceMessages().slice(0, 3) }
  };
  STUB.smtpUsers = {
    ["smtp.gmail.com " + ADDR.alice]: PW.alice, ["smtp.kiln.example bob-signin"]: PW.bob, ["smtp.gmail.com " + ADDR.carol]: PW.carol,
    ["smtp.fastmail.com " + ADDR.gina]: PW.gina, ["smtp.gmail.com " + ADDR.rita]: PW.rita, ["smtp.fastmail.com " + ADDR.tom]: PW.tom,
    ["smtp.gmail.com " + ADDR.uma]: PW.uma, ["smtp.gmail.com " + ADDR.vic]: PW.vic, ["smtp.kiln.example " + ADDR.frank]: PW.frank
  };
  STUB.imapMode = {}; STUB.smtpMode = {};
}

const LOGS = [];
function build() {
  const db = fakeDb({ users: [ALICE, BOB, CAROL, DAVE, GINA, FRANK, RITA, TOM, UMA, VIC, NOBODY].map(id => ({ id: id, role: "user" })),
    member_email_connections: [], notifications: [], ai_tasks: [] });
  const limiters = [];
  const logTo = function () { LOGS.push([].slice.call(arguments).map(a => typeof a === "string" ? a : J(a)).join(" ")); };
  const ctx = {
    supabase: db.client, Date, JSON, Math, Promise, Number, Object, Array, String, Buffer, RegExp, Error, TypeError, Set, Map,
    nowIso: () => new Date(CLOCK.now).toISOString(),
    process: { env: {} },
    require: p => p === "./lib/memberEmail" ? ME : p === "./lib/apiKeyCrypto" ? CRYPTO : require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: async (u) => { NETWORK.push("fetch " + u); throw new Error("no network"); },
    console: { log: logTo, error: logTo, warn: logTo, info: logTo },
    setImmediate, setTimeout, clearTimeout,
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {},
    rateLimit: function (o) { limiters.push(o); const f = function limiter() {}; f.__opts = o; return f; }
  };
  const routes = {};
  const mount = method => function (p) { routes[method + " " + p] = { handler: arguments[arguments.length - 1], middleware: [].slice.call(arguments, 1, -1) }; };
  ctx.app = { post: mount("post"), put: mount("put"), get: mount("get") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function hit(key, user, opts) {
    opts = opts || {};
    const [method, route] = R[key];
    const res = { code: 200, body: null, headers: {}, status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; },
      set(k, v) { this.headers[String(k).toLowerCase()] = v; return this; } };
    await routes[method + " " + route].handler({ user: { id: user, role: "user" }, body: opts.body || {}, params: opts.params || {}, query: opts.query || {} }, res,
      e => { res.error = e; res.code = 500; res.body = { error: "internal" }; });
    return res;
  }
  return { db, ctx, routes, hit, limiters };
}
const connOf = (b, user) => b.db.rows("member_email_connections").find(r => r.user_id === user);
const gmail = (addr, pw, extra) => ({ body: Object.assign({ provider: "gmail", email_address: addr, app_password: pw }, extra || {}) });
const tick = () => new Promise(r => setImmediate(r));

(async function main() {
  seedServers();

  /* ── P. the migration ───────────────────────────────────────────────────── */
  console.log("\n══ P. migration 169 ══");
  const sql = MIGRATION.replace(/--[^\n]*/g, "");
  const COLUMNS = ["id", "user_id", "provider", "email_address", "username", "imap_host", "imap_port", "smtp_host", "smtp_port", "auth_kind",
    "secret_ciphertext", "secret_iv", "secret_auth_tag", "status", "last_ok_at", "last_error_at", "last_error_code", "created_at", "updated_at"];
  const declared = SQL_BODY.split("\n").map(l => (/^  ([a-z_]+) (uuid|text|integer|boolean|timestamptz)\b/.exec(l) || [])[1]).filter(Boolean);
  check("P1. member_email_connections has exactly the 19 columns, in order", J(declared) === J(COLUMNS), declared.join(","));
  check("P2. one row per member (user_id UNIQUE, cascading); 993 and 465 by default; status connected; auth_kind app_password",
    /user_id uuid NOT NULL UNIQUE REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(SQL_BODY) && /imap_port integer NOT NULL DEFAULT 993/.test(SQL_BODY) &&
    /smtp_port integer NOT NULL DEFAULT 465/.test(SQL_BODY) && /status text NOT NULL DEFAULT 'connected'/.test(SQL_BODY) && /auth_kind text NOT NULL DEFAULT 'app_password'/.test(SQL_BODY));
  const constraints = (SQL_BODY.match(/^  CONSTRAINT [a-z_]+ CHECK /gm) || []).length;
  check("P3. 13 CHECK constraints: provider, address, sign-in name, both hosts, IMAP 993 only, SMTP 465 or 587, auth kind, hex secret, iv and tag, status, error code",
    constraints === 13 && /CHECK \(imap_port = 993\)/.test(SQL_BODY) && /CHECK \(smtp_port IN \(465, 587\)\)/.test(SQL_BODY) &&
    /CHECK \(provider IN \('gmail', 'yahoo', 'icloud', 'fastmail', 'other'\)\)/.test(SQL_BODY) && /CHECK \(auth_kind IN \('app_password'\)\)/.test(SQL_BODY) &&
    /secret_ciphertext ~ '\^\[0-9a-f\]\+\$'/.test(SQL_BODY) && /secret_iv ~ '\^\[0-9a-f\]\{24\}\$'/.test(SQL_BODY) && /secret_auth_tag ~ '\^\[0-9a-f\]\{32\}\$'/.test(SQL_BODY) &&
    /CHECK \(status IN \('connected', 'needs_reconnect', 'disconnected'\)\)/.test(SQL_BODY) && /char_length\(last_error_code\) <= 60/.test(SQL_BODY), constraints);
  check("P4. an app password (it has spaces and letters past f) cannot be stored as typed", !/^[0-9a-f]+$/.test(PW.alice) && violates("member_email_connections",
    { provider: "gmail", email_address: ADDR.alice, username: ADDR.alice, imap_host: "imap.gmail.com", imap_port: 993, smtp_host: "smtp.gmail.com", smtp_port: 465,
      auth_kind: "app_password", secret_ciphertext: PW.alice, secret_iv: "0".repeat(24), secret_auth_tag: "0".repeat(32), status: "connected" }) === "member_email_connections_ciphertext_check");
  check("P5. RLS is enabled and no policy is created", /ALTER TABLE public\.member_email_connections ENABLE ROW LEVEL SECURITY;/.test(sql) && !/CREATE POLICY/i.test(sql));
  check("P6. lib/memberEmail.js's host and address patterns equal the SQL's, character for character (both hosts share one)",
    HOST_SQL === ME.HOST_RE.source && SMTP_HOST_SQL === ME.HOST_RE.source && EMAIL_SQL === ME.EMAIL_RE.source, [HOST_SQL, ME.HOST_RE.source].join(" | "));
  check("P7. the header says the owner applied it by hand on Nov 5, 2026",
    MIGRATION.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 5, 2026. This file is the text as run.") !== -1);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE "the highest" with every migration at most 169. AFTER 169 is
  // still the only one numbered 169, and every migration but 170_member_email_replies.sql is at most 169; "the highest" is checkMailboxReply M2's.
  // NAMED (Nov 6 2026, card upgrades C1, migration 171): BEFORE every migration but 170 at most 169. AFTER 171_card_counts.sql
  // too; "the highest" is checkCardUpgrades R1's.
  // NAMED (Nov 6 2026, card upgrades C2, migration 172): BEFORE 171_card_counts.sql was the last allowed above 169. AFTER
  // 172_card_leads.sql too; "the highest" is checkCardLeads R1's.
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE 172_card_leads.sql was the last allowed above 169. AFTER
  // 173_mailbox_microsoft.sql too; "the highest" is checkMailboxOutlook R1's.
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE 173_mailbox_microsoft.sql was the last allowed above 169. AFTER
  // 174_card_wallet_count.sql too; "the highest" is checkGoogleWallet R1's.
  // NAMED (Nov 6 2026, store changes, migration 175): 175_store_changes.sql is allowed too; "the highest" is checkStoreChanges R1's.
  check("M2. 169_member_email_connections.sql is the only migration numbered 169, and every other migration but 170_member_email_replies.sql, 171_card_counts.sql, 172_card_leads.sql, 173_mailbox_microsoft.sql and 174_card_wallet_count.sql is at most 169",
    migFiles.filter(f => /^169_/.test(f)).length === 1 && migFiles.indexOf("169_member_email_connections.sql") !== -1 &&
    migFiles.every(f => f === "170_member_email_replies.sql" || f === "171_card_counts.sql" || f === "172_card_leads.sql" || f === "173_mailbox_microsoft.sql" || f === "174_card_wallet_count.sql" || f === "175_store_changes.sql" || /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): 176 is allowed too; "the highest" is checkShopifyConnect R1's. */ f === "176_shopify_oauth.sql" || /* NAMED (Nov 7 2026, YouTube uploads, migration 177): 177 is allowed too; "the highest" is checkYoutubeUploads R1's. */ f === "177_youtube_uploads.sql" || /* NAMED (Nov 7 2026, TikTok posting, migration 178): 178 is allowed too; "the highest" is checkTiktokPosting R1's. */ f === "178_tiktok_posting.sql" || /* NAMED (Nov 7 2026, Instagram posting, migration 179): 179 is allowed too; "the highest" is checkInstagramPosting R1's. */ f === "179_instagram_posting.sql" || Number(f.split("_")[0]) <= 169) && migFiles.some(f => /^168_/.test(f)), migFiles.slice(-2).join(","));

  /* ── N. what a member types ─────────────────────────────────────────────── */
  console.log("\n══ N. what a member types ══");
  const set = b => ME.settingsFrom(b);
  const g = set({ provider: "gmail", email_address: " " + ADDR.alice + " ", imap_host: "imap.evil.example", smtp_host: "smtp.evil.example", smtp_port: 25 });
  check("N1. a named provider's preset wins over typed server names and ports; the sign-in name defaults to the address",
    g.ok && J(g.settings) === J({ provider: "gmail", email_address: ADDR.alice, username: ADDR.alice, imap_host: "imap.gmail.com", imap_port: 993, smtp_host: "smtp.gmail.com", smtp_port: 465 }), J(g));
  const PRESETS = { gmail: ["imap.gmail.com", "smtp.gmail.com", 465], yahoo: ["imap.mail.yahoo.com", "smtp.mail.yahoo.com", 465],
    icloud: ["imap.mail.me.com", "smtp.mail.me.com", 587], fastmail: ["imap.fastmail.com", "smtp.fastmail.com", 465] };
  /* NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE "Outlook is not offered", held by ME.OUTLOOK_LINE ("Sign in with
     Microsoft is coming"). AFTER Outlook is offered only through Sign in with Microsoft (checkMailboxOutlook): the app-password
     providers are still exactly these five, and an app-password connect for outlook is still refused, now pointing to the sign-in. */
  check("N2. the four presets are the architect's: Gmail, Yahoo 465, iCloud 587, Fastmail 465, and Other; Outlook is not an app-password provider",
    Object.keys(PRESETS).every(p => J([ME.PROVIDERS[p].imap_host, ME.PROVIDERS[p].smtp_host, ME.PROVIDERS[p].smtp_port]) === J(PRESETS[p])) &&
    J(ME.PROVIDER_IDS) === J(["gmail", "yahoo", "icloud", "fastmail", "other"]) && !set({ provider: "outlook", email_address: ADDR.alice }).ok &&
    set({ provider: "outlook", email_address: ADDR.alice }).error === ME.MESSAGES.outlookSignIn && ME.OUTLOOK_LINE === undefined);
  const o = set({ provider: "other", email_address: ADDR.bob, username: "bob-signin", imap_host: "IMAP.Kiln.Example.", smtp_host: "smtp.kiln.example", smtp_port: "587" });
  check("N3. Other: both names lowercased (one trailing dot dropped), port 587 taken, the typed sign-in name kept",
    o.ok && o.settings.imap_host === "imap.kiln.example" && o.settings.smtp_port === 587 && o.settings.username === "bob-signin", J(o));
  const refusedOther = [
    [{ smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"], [{ imap_host: "imap.kiln.example", smtp_port: 465 }, "smtp_host"],
    [{ imap_host: "imap.kiln.example", smtp_host: "smtp.kiln.example", smtp_port: 25 }, "smtp_port"],
    [{ imap_host: "imap.kiln.example", smtp_host: "smtp.kiln.example", smtp_port: 2525 }, "smtp_port"],
    [{ imap_host: "imap.kiln.example", smtp_host: "smtp.kiln.example" }, "smtp_port"],
    [{ imap_host: "127.0.0.1", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "[::1]", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "localhost", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "mail.localhost", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "mailserver", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "imap.kiln.example:993", smtp_host: "smtp.kiln.example", smtp_port: 465 }, "imap_host"],
    [{ imap_host: "imap.kiln.example", smtp_host: "10.0.0.5", smtp_port: 465 }, "smtp_host"]
  ].filter(([extra, code]) => { const r = set(Object.assign({ provider: "other", email_address: ADDR.bob }, extra)); return r.ok || r.code !== code; });
  check("N4. Other refuses a missing name, SMTP 25 or any port but 465 and 587, IP literals, localhost, a single label and a name with a port",
    refusedOther.length === 0, J(refusedOther));
  check("N5. a bad address and a multi-line sign-in name are refused; every refusal says nothing was saved",
    !set({ provider: "gmail", email_address: "not-an-address" }).ok && !set({ provider: "gmail", email_address: ADDR.alice, username: "a\nb" }).ok &&
    ["provider", "email", "username", "password", "imapHost", "smtpHost", "smtpPort"].every(k => /Nothing was saved\.$/.test(ME.MESSAGES[k])));
  check("N6. the app password: trimmed, 1 to 256 characters on one line; Gmail's inner spaces kept",
    ME.checkAppPassword("  " + PW.alice + " ").value === PW.alice && !ME.checkAppPassword("").ok && !ME.checkAppPassword("x".repeat(257)).ok &&
    !ME.checkAppPassword("ab\ncd").ok && !ME.checkAppPassword(12345).ok);

  /* ── O. the connection options ──────────────────────────────────────────── */
  console.log("\n══ O. the connection options ══");
  const st465 = Object.assign({}, g.settings), st587 = Object.assign({}, o.settings);
  const io = ME.imapOptions(st465, "142.250.1.10", "s");
  check("O1. IMAP: the vetted address as host, port 993, implicit TLS, the real name as servername", io.host === "142.250.1.10" && io.port === 993 && io.secure === true &&
    io.servername === "imap.gmail.com", J(Object.assign({}, io, { auth: "…" })));
  check("O2. IMAP TLS: servername, rejectUnauthorized true, TLS 1.2 at least", J(io.tls) === J({ servername: "imap.gmail.com", rejectUnauthorized: true, minVersion: "TLSv1.2" }));
  check("O3. IMAP: no logging (logger false, emitLogs false), no IDLE, timeouts 15 s, 15 s and 30 s, literals at most 2 MB",
    io.logger === false && io.emitLogs === false && io.disableAutoIdle === true && io.connectionTimeout === 15000 && io.greetingTimeout === 15000 &&
    io.socketTimeout === 30000 && io.maxLiteralSize === 2 * 1024 * 1024);
  let threw143 = false; try { ME.imapOptions(Object.assign({}, st465, { imap_port: 143 }), "142.250.1.10", "s"); } catch (e) { threw143 = e.kind === "unreachable"; }
  check("O4. IMAP on any port but 993 is refused before a client exists", threw143 && ME.IMAP_PORT === 993);
  const so465 = ME.smtpOptions(st465, "142.250.1.20", "s"), so587 = ME.smtpOptions(st587, "93.184.216.35", "s");
  check("O5. SMTP 465: implicit TLS; 587: STARTTLS required; never ignoreTLS or opportunistic TLS",
    so465.secure === true && so465.requireTLS === false && so587.secure === false && so587.requireTLS === true &&
    [so465, so587].every(x => x.ignoreTLS === false && x.opportunisticTLS === false), J([so465.secure, so465.requireTLS, so587.secure, so587.requireTLS]));
  check("O6. SMTP: the vetted address as host, the real name as servername and in TLS, certificates checked",
    so465.host === "142.250.1.20" && so465.servername === "smtp.gmail.com" && J(so465.tls) === J(ME.tlsFor("smtp.gmail.com")) &&
    so587.host === "93.184.216.35" && so587.servername === "smtp.kiln.example" && so587.tls.rejectUnauthorized === true);
  check("O7. SMTP: no pool, no logging (logger, debug and transactionLog false), the same timeouts",
    [so465, so587].every(x => x.pool === false && x.logger === false && x.debug === false && x.transactionLog === false &&
      x.connectionTimeout === 15000 && x.greetingTimeout === 15000 && x.socketTimeout === 30000));
  let threw25 = false; try { ME.smtpOptions(Object.assign({}, st465, { smtp_port: 25 }), "1.1.1.1", "s"); } catch (e) { threw25 = e.kind === "unreachable"; }
  check("O8. SMTP on 25 (or any port but 465 and 587) is refused before a transport exists", threw25 && J(ME.SMTP_PORTS) === J([465, 587]));

  /* ── LIB. what the libraries do with those options ─────────────────────── */
  console.log("\n══ LIB. the library facts, read from node_modules ══");
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, "package.json"), "utf8"));
  const ver = n => JSON.parse(fs.readFileSync(path.join(REPO, "node_modules", n, "package.json"), "utf8")).version;
  check("LIB1. package.json pins imapflow 2.9.1, nodemailer 10.2.1 and postal-mime 2.7.5 exactly, and those are installed",
    pkg.dependencies.imapflow === "2.9.1" && pkg.dependencies.nodemailer === "10.2.1" && pkg.dependencies["postal-mime"] === "2.7.5" &&
    ver("imapflow") === "2.9.1" && ver("nodemailer") === "10.2.1" && ver("postal-mime") === "2.7.5");
  const ex = await wireOf(SELECT_CMD, ["INBOX", { readOnly: true }], 2), se = await wireOf(SELECT_CMD, ["INBOX", {}], 2);
  check("LIB2. ImapFlow's own SELECT builder sends EXAMINE for readOnly (and SELECT without it)", ex.length === 1 && /^EXAMINE /.test(ex[0]) && se.length === 1 && /^SELECT /.test(se[0]), ex.concat(se).join(" | "));
  const pk = await wireOf(FETCH_CMD, ["5", { uid: true, source: true }, { uid: true }], 3);
  check("LIB3. ImapFlow's own FETCH builder asks for a message's source as BODY.PEEK[] (never BODY[], which marks it read)",
    pk.length === 1 && /^UID FETCH /.test(pk[0]) && /"value":"BODY\.PEEK","section":\[\]/.test(pk[0]) && !NON_PEEK.test(pk[0]), pk.join(" | "));
  const IF = lf(fs.readFileSync(path.join(IMAP_DIR, "imap-flow.js"), "utf8"));
  const SC = lf(fs.readFileSync(path.join(REPO, "node_modules/nodemailer/dist/cjs/smtp-connection/index.js"), "utf8"));
  const SH = lf(fs.readFileSync(path.join(REPO, "node_modules/nodemailer/dist/cjs/shared/index.js"), "utf8"));
  check("LIB4. both libraries take servername from the option (else none for an IP host), so the vetted IP never becomes the certificate name",
    IF.indexOf("this.servername = this.options.servername ? this.options.servername : !(0, tools_js_1.isIpLiteral)(this.host) ? this.host : false;") !== -1 &&
    SC.indexOf("this.servername = this.options.servername ? this.options.servername : !node_net_1.default.isIP(this.host) ? this.host : false;") !== -1);
  check("LIB5. nodemailer: requireTLS overrides ignoreTLS and opportunisticTLS, and forces STARTTLS",
    SC.indexOf("if (this.options.requireTLS && (this.options.ignoreTLS || this.options.opportunisticTLS)) {") !== -1 &&
    SC.indexOf("if (!this.secure && !this.options.ignoreTLS && (/[ -]STARTTLS\\b/im.test(str) || this.options.requireTLS)) {") !== -1);
  check("LIB6. nodemailer does not look an IP host up again (resolveHostname returns it as it is)",
    SH.indexOf("    if (!options.host || node_net_1.default.isIP(options.host)) {\n        // nothing to do here") !== -1);

  /* ── A. connect ─────────────────────────────────────────────────────────── */
  console.log("\n══ A. connect ══");
  const b = build();
  const mw = key => (b.routes[R[key][0] + " " + R[key][1]] || { middleware: [] }).middleware;
  const names = key => mw(key).map(f => f.__opts ? "limiter" : f.name);
  check("A1. connect, the list and a message need a subscription; status and disconnect only a sign-in",
    J(names("connect")) === J(["requireAuth", "requireActiveSubscription", "limiter"]) && J(names("inbox")) === J(["requireAuth", "requireActiveSubscription", "limiter", "limiter"]) &&
    J(names("open")) === J(["requireAuth", "requireActiveSubscription", "limiter", "limiter"]) && J(names("status")) === J(["requireAuth"]) && J(names("disconnect")) === J(["requireAuth"]),
    J(Object.keys(R).map(k => k + ":" + names(k).join("+"))));
  const lim = (key, i) => mw(key)[i] && mw(key)[i].__opts;
  const key = (o2) => o2 && o2.keyGenerator({ user: { id: "u1" } });
  check("A2. the limiters, per account: connect 5 an hour; the list 30 an hour and 200 a day; a message 60 an hour and 300 a day",
    lim("connect", 2).max === 5 && lim("connect", 2).windowMs === 3600000 && key(lim("connect", 2)) === "mailbox-connect:u1" &&
    lim("inbox", 2).max === 30 && lim("inbox", 2).windowMs === 3600000 && lim("inbox", 3).max === 200 && lim("inbox", 3).windowMs === 86400000 && key(lim("inbox", 2)) === "mailbox-read:u1" &&
    lim("open", 2).max === 60 && lim("open", 3).max === 300 && key(lim("open", 3)) === "mailbox-open:u1");

  resetStubCounters();
  const ra = await b.hit("connect", ALICE, gmail(ADDR.alice, PW.alice, { imap_host: "imap.evil.example" }));
  const rowA = connOf(b, ALICE);
  check("A3. Alice connects Gmail: 200 with exactly connected, provider, email_address, status and since",
    ra.code === 200 && J(Object.keys(ra.body).sort()) === J(["connected", "email_address", "provider", "since", "status"]) && ra.body.connected === true &&
    ra.body.provider === "gmail" && ra.body.email_address === ADDR.alice, safe(J([ra.code, ra.body])));
  check("A4. the row: the preset's names, 993, 465, the address as sign-in name, app_password",
    !!rowA && rowA.provider === "gmail" && rowA.imap_host === "imap.gmail.com" && rowA.smtp_host === "smtp.gmail.com" && rowA.imap_port === 993 &&
    rowA.smtp_port === 465 && rowA.username === ADDR.alice && rowA.auth_kind === "app_password" && rowA.status === "connected");
  let opened = null; try { opened = rowA && CRYPTO.decrypt({ ciphertext: rowA.secret_ciphertext, iv: rowA.secret_iv, authTag: rowA.secret_auth_tag }); } catch (e) { opened = null; }
  check("A5. the stored secret is AES-256-GCM sealed: it opens with the key to the app password, and the row holds it in no other form",
    opened === PW.alice && noSecretIn(J(rowA)));
  const ic = STUB.clients[0] || { options: {}, calls: [] }, tc = STUB.transports[0] || { options: {}, calls: [] };
  check("A6. the IMAP check: one client, given the vetted address (never the typed name) and the real servername; connect, then logout",
    STUB.clients.length === 1 && ic.options.host === "142.250.1.10" && ic.options.servername === "imap.gmail.com" && ic.options.port === 993 &&
    ic.options.secure === true && ic.options.tls && ic.options.tls.rejectUnauthorized === true && J(ic.calls) === J(["connect", "logout"]), J(ic.calls));
  check("A7. the SMTP check: one transport on the vetted address, 465, certificates checked; verify once, then close; nothing sent",
    STUB.transports.length === 1 && tc.options.host === "142.250.1.20" && tc.options.servername === "smtp.gmail.com" && tc.options.port === 465 &&
    tc.options.secure === true && tc.options.tls && tc.options.tls.rejectUnauthorized === true && J(tc.calls) === J(["verify", "close"]), J(tc.calls));
  check("A8. both names were resolved through resolvePublicHost, once each", J(STUB.resolved) === J(["imap.gmail.com", "smtp.gmail.com"]), J(STUB.resolved));
  check("A9. the app password is in no response, no log line and no table in the clear (or hex, or base64)",
    noSecretIn(J(ra.body)) && noSecretIn(LOGS.join("\n")) && noSecretIn(J(b.db.tables)));
  const firstCipher = rowA && rowA.secret_ciphertext;
  const ra2 = await b.hit("connect", ALICE, gmail(ADDR.alice, PW.alice));
  check("A10. connecting again keeps one row per member, freshly sealed", ra2.code === 200 && b.db.rows("member_email_connections").filter(r => r.user_id === ALICE).length === 1 &&
    connOf(b, ALICE).secret_ciphertext !== firstCipher);
  resetStubCounters();
  const rb = await b.hit("connect", BOB, { body: { provider: "other", email_address: ADDR.bob, username: "bob-signin", imap_host: "imap.kiln.example", smtp_host: "smtp.kiln.example", smtp_port: 587, app_password: PW.bob } });
  const tb = STUB.transports[0] || { options: {} };
  check("A11. Bob's own server on 587: STARTTLS required, not implicit TLS; the typed sign-in name used for both",
    rb.code === 200 && tb.options.port === 587 && tb.options.requireTLS === true && tb.options.secure === false && tb.options.auth.user === "bob-signin" &&
    (STUB.clients[0] || { options: { auth: {} } }).options.auth.user === "bob-signin" && connOf(b, BOB).smtp_port === 587, safe(J([rb.code, rb.body])));
  resetStubCounters();
  delete process.env.ENCRYPTION_SECRET;
  const rk = await b.hit("connect", UMA, gmail(ADDR.uma, PW.uma));
  process.env.ENCRYPTION_SECRET = TEST_KEY;
  check("A12. with no encryption key: 503 no_encryption_key, and no name resolved, no client, no transport, nothing stored",
    rk.code === 503 && rk.body.code === "no_encryption_key" && STUB.resolved.length === 0 && STUB.clients.length === 0 && STUB.transports.length === 0 && !connOf(b, UMA));
  resetStubCounters();
  const bad = [];
  for (const body of [{ provider: "outlook", email_address: ADDR.uma, app_password: PW.uma }, { provider: "gmail", email_address: "nope", app_password: PW.uma },
    { provider: "gmail", email_address: ADDR.uma, app_password: "" }, { provider: "other", email_address: ADDR.uma, app_password: PW.uma, imap_host: "imap.kiln.example", smtp_host: "smtp.kiln.example", smtp_port: 25 }]) {
    const r = await b.hit("connect", UMA, { body: body });
    if (r.code !== 400 || r.body.saved !== false) bad.push(r.code);
  }
  check("A13. a refused form answers 400 with saved false, before any name is resolved or any client exists",
    bad.length === 0 && STUB.resolved.length === 0 && STUB.clients.length === 0 && STUB.transports.length === 0 && !connOf(b, UMA), J(bad));

  /* ── V. refusals at connect ─────────────────────────────────────────────── */
  console.log("\n══ V. refusals at connect: nothing stored, one attempt each ══");
  resetStubCounters();
  const rc = await b.hit("connect", CAROL, gmail(ADDR.carol, PW.wrong));
  check("V1. a password the IMAP server refuses: 422 rejected, nothing stored, ONE login attempt, SMTP never tried",
    rc.code === 422 && rc.body.code === "rejected" && rc.body.error === ME.MESSAGES.rejected && !connOf(b, CAROL) &&
    STUB.clients.length === 1 && STUB.clients[0].calls.filter(c => c === "connect").length === 1 && STUB.transports.length === 0, J([rc.code, STUB.clients.length, STUB.transports.length]));
  resetStubCounters();
  const rd = await b.hit("connect", DAVE, gmail(ADDR.dave, PW.dave));
  check("V2. IMAP accepts but the SMTP server refuses: 422 rejected, nothing stored; IMAP logged out, verify tried once",
    rd.code === 422 && rd.body.code === "rejected" && !connOf(b, DAVE) && J((STUB.clients[0] || {}).calls) === J(["connect", "logout"]) &&
    STUB.transports.length === 1 && J(STUB.transports[0].calls) === J(["verify", "close"]), J([rd.code, STUB.transports.length]));
  resetStubCounters(); STUB.imapMode["imap.fastmail.com"] = "throttle";
  const rg = await b.hit("connect", GINA, { body: { provider: "fastmail", email_address: ADDR.gina, app_password: PW.gina } });
  STUB.imapMode = {};
  check("V3. a throttling server: 502 with the slow-down words, nothing stored", rg.code === 502 && rg.body.code === "rate_limited" && rg.body.error === ME.MESSAGES.rateLimited && !connOf(b, GINA));
  resetStubCounters(); STUB.smtpMode["smtp.fastmail.com"] = "down";
  const rg2 = await b.hit("connect", GINA, { body: { provider: "fastmail", email_address: ADDR.gina, app_password: PW.gina } });
  STUB.smtpMode = {};
  check("V4. an SMTP server that does not answer: 502 unreachable, nothing stored", rg2.code === 502 && rg2.body.code === "unreachable" && rg2.body.error === ME.MESSAGES.unreachable && !connOf(b, GINA));
  resetStubCounters();
  const rf = await b.hit("connect", FRANK, { body: { provider: "other", email_address: ADDR.frank, imap_host: "imap.private.example", smtp_host: "smtp.kiln.example", smtp_port: 465, app_password: PW.frank } });
  check("V5. a name that resolves to a private address: 502 unreachable, no client is ever made, nothing stored",
    rf.code === 502 && rf.body.code === "unreachable" && STUB.clients.length === 0 && STUB.transports.length === 0 && !connOf(b, FRANK), J([rf.code, STUB.clients.map(c => c.options.host)]));
  resetStubCounters();
  const rm = await b.hit("connect", FRANK, { body: { provider: "other", email_address: ADDR.frank, imap_host: "imap.mixed.example", smtp_host: "smtp.kiln.example", smtp_port: 465, app_password: PW.frank } });
  check("V6. a name with one public and one private address is refused the same way", rm.code === 502 && STUB.clients.length === 0 && !connOf(b, FRANK));
  check("V7. no refusal at connect wrote anything, logged the password, or answered with it",
    b.db.writes().filter(w => w.table === "member_email_connections" && [CAROL, DAVE, GINA, FRANK, UMA].indexOf(w.payload && w.payload.user_id) !== -1).length === 0 &&
    noSecretIn(LOGS.join("\n")) && [rc, rd, rg, rg2, rf, rm].every(r => noSecretIn(J(r.body))));
  const C = ME.classify;
  const table = [
    [errOf({ authenticationFailed: true }), "rejected", "imap_auth"], [errOf({ serverResponseCode: "AUTHENTICATIONFAILED" }), "rejected", "imap_auth"],
    [errOf({ serverResponseCode: "AUTHORIZATIONFAILED" }), "rejected", "imap_auth"], [errOf({ code: "ETHROTTLE" }), "rate_limited", "imap_throttled"],
    [errOf({ serverResponseCode: "LIMIT" }), "rate_limited", "imap_throttled"], [errOf({ code: "EAUTH", responseCode: 535 }), "rejected", "smtp_auth"],
    [errOf({ code: "EAUTH", responseCode: 421 }), "rate_limited", "smtp_421"], [errOf({ code: "EAUTH", responseCode: 454 }), "rate_limited", "smtp_454"],
    [errOf({ code: "ECONNREFUSED" }), "unreachable", "ECONNREFUSED"], [errOf({ code: "CONNECT_TIMEOUT" }), "unreachable", "CONNECT_TIMEOUT"],
    [errOf({ message: "Invalid credentials: authentication failed, wrong password" }), "unreachable", "error"],
    [errOf({ code: "a b;c" }), "unreachable", "error"], [null, "unreachable", "unknown"]
  ].filter(([e, kind, code]) => { const v = C(e); return v.kind !== kind || v.code !== code; });
  check("V8. classify reads codes and properties only: a message that says \"authentication failed\" with no code is unreachable, never rejected",
    table.length === 0, J(table.map(t => C(t[0]))));

  /* ── R. reading, on request only ────────────────────────────────────────── */
  console.log("\n══ R. reading, read-only, on request only ══");
  resetStubCounters();
  const logAt = b.db.log.length;
  const rs = await b.hit("status", ALICE);
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE these five keys only. AFTER outlook_available too (true or false:
  // whether Sign in with Microsoft is set up on the server); an app-password row adds nothing else (account_type is outlook rows').
  check("R1. status: provider, address, status, since and outlook_available only; no secret, sign-in name or server names; no connection made",
    rs.code === 200 && J(Object.keys(rs.body).sort()) === J(["connected", "email_address", "outlook_available", "provider", "since", "status"]) &&
    typeof rs.body.outlook_available === "boolean" && STUB.clients.length === 0 &&
    !/imap|smtp|secret|username/.test(J(rs.body)));
  const r1 = await b.hit("inbox", ALICE);
  const list = (r1.body && r1.body.messages) || [];
  check("R2. the list: the newest 30 by UID, newest first, with the cursor to the next page",
    r1.code === 200 && list.length === 30 && list[0].uid === 40 && list[29].uid === 11 && r1.body.next_before === 11, J([r1.code, list.length, r1.body && r1.body.next_before]));
  check("R3. each entry is exactly uid, from (name and address), subject, date, seen and size",
    list.every(m => J(Object.keys(m).sort()) === J(["date", "from", "seen", "size", "subject", "uid"]) && J(Object.keys(m.from).sort()) === J(["address", "name"])) &&
    list[0].from.address === "ann+bftest@example.com" && list[0].seen === false && list.find(m => m.uid === 34).seen === true && typeof list[0].size === "number");
  const s35 = list.find(m => m.uid === 35);
  check("R4. a subject is capped at 300 characters, control characters made spaces", !!s35 && s35.subject.length === 300 && !/[\u0000-\u001f]/.test(s35.subject), s35 && s35.subject.length);
  const lc = STUB.clients[0] || { calls: [], wire: [], fetchQueries: [] };
  check("R5. one connection: connect, EXAMINE INBOX (never SELECT), search, fetch, logout",
    STUB.clients.length === 1 && J(lc.calls) === J(["connect", "mailboxOpen", "search", "fetch", "logout"]) && lc.wire.length >= 2 && /^EXAMINE /.test(lc.wire[0]) &&
    !lc.wire.some(l => /^SELECT /.test(l)) && J(lc.opened && lc.opened.opts) === J({ readOnly: true }), J(lc.calls) + " " + lc.wire.join(" | "));
  check("R6. the list asks for flags, envelope, size and date only: no body, no source, on the wire or in the query",
    lc.wire.filter(l => /FETCH/.test(l)).every(l => !BODY_ASKED.test(l)) && (lc.fetchQueries || []).every(q => !/source|bodyParts|bodyStructure/.test(q)), (lc.fetchQueries || []).join(" "));
  check("R7. both read routes answer with Cache-Control no-store", r1.headers["cache-control"] === "no-store");
  const r2 = await b.hit("inbox", ALICE, { query: { before: "11" } });
  check("R8. Show older: before=11 lists 10 down to 1, and the cursor ends", r2.code === 200 && r2.body.messages.length === 10 && r2.body.messages[0].uid === 10 &&
    r2.body.messages[9].uid === 1 && r2.body.next_before === null, J([r2.code, r2.body && r2.body.next_before]));
  resetStubCounters();
  const badBefore = [];
  for (const v of ["abc", "0", "-3", "1.5", "99999999999", "4294967296"]) { const r = await b.hit("inbox", ALICE, { query: { before: v } }); if (r.code !== 400) badBefore.push(v + ":" + r.code); }
  check("R9. a before that is not a 32-bit message number is 400, with no connection", badBefore.length === 0 && STUB.clients.length === 0, badBefore.join(","));

  resetStubCounters();
  const o40 = await b.hit("open", ALICE, { params: { uid: "40" } });
  const m40 = (o40.body && o40.body.message) || {};
  check("R10. a plain message: uid, from, to, cc, subject, date, text, truncated, attachments; and nothing else (no html, no source, no headers)",
    o40.code === 200 && J(Object.keys(m40).sort()) === J(["attachments", "cc", "date", "from", "subject", "text", "to", "truncated", "uid"]) &&
    m40.text.trim() === "The kiln fires Saturday at 9." && m40.from.address === "ann+bftest@example.com" && m40.to[0].address === ADDR.alice &&
    m40.cc[0].address === "cy+bftest@example.com" && m40.subject === "Kiln schedule" && m40.date === "2026-11-04T10:00:00.000Z" && m40.truncated === false,
    safe(J([o40.code, Object.keys(m40)])));
  const oc = STUB.clients[0] || { calls: [], wire: [] };
  const fetchLines = oc.wire.filter(l => /FETCH/.test(l));
  check("R11. opening: EXAMINE, then the size alone, then the source as BODY.PEEK[]; one connection, logged out",
    J(oc.calls) === J(["connect", "mailboxOpen", "fetchOne", "fetchOne", "logout"]) && /^EXAMINE /.test(oc.wire[0]) && fetchLines.length === 2 &&
    /RFC822\.SIZE/.test(fetchLines[0]) && !BODY_ASKED.test(fetchLines[0]) && /"value":"BODY\.PEEK"/.test(fetchLines[1]) && fetchLines.every(l => !NON_PEEK.test(l)), oc.wire.join(" | "));
  check("R12. the message is still unread on the server", STUB.boxes["imap.gmail.com " + ADDR.alice].messages.find(m => m.uid === 40).flags.indexOf("\\Seen") === -1);
  check("R13. the source was fetched only through fetchOne (no raw command)", oc.calls.indexOf("exec") === -1 && oc.calls.every(c => ALLOWED_CLIENT_CALLS.indexOf(c) !== -1), J(oc.calls));
  const o39 = await b.hit("open", ALICE, { params: { uid: "39" } });
  const t39 = (o39.body && o39.body.message && o39.body.message.text) || "";
  check("R14. an HTML-only message comes back as plain text: no tag, no script or style, the entities decoded",
    o39.code === 200 && t39 === "Fire & glaze\nLine two <3" && !/<[a-z/!]/i.test(t39) && t39.indexOf("steal") === -1 && t39.indexOf("color") === -1, J(t39.slice(0, 120)));
  const o38 = await b.hit("open", ALICE, { params: { uid: "38" } });
  const a38 = (o38.body && o38.body.message && o38.body.message.attachments) || [];
  check("R15. an attachment is listed by name, type and size, and only those", o38.code === 200 && a38.length === 1 && J(Object.keys(a38[0]).sort()) === J(["name", "size", "type"]) &&
    a38[0].name === "invoice.pdf" && a38[0].type === "application/pdf" && a38[0].size === Buffer.byteLength(ATTACH_MARK), J(a38));
  check("R16. its bytes are never returned (neither raw nor base64)", J(o38.body).indexOf(ATTACH_MARK) === -1 && J(o38.body).indexOf(ATTACH_B64) === -1);
  const o37 = await b.hit("open", ALICE, { params: { uid: "37" } });
  check("R17. text is capped at 100,000 characters, and says so", o37.code === 200 && o37.body.message.text.length === 100000 && o37.body.message.truncated === true,
    o37.body && o37.body.message && o37.body.message.text.length);
  resetStubCounters();
  const o36 = await b.hit("open", ALICE, { params: { uid: "36" } });
  const bc = STUB.clients[0] || { wire: [], calls: [] };
  check("R18. a message over 2 MB: 413 \"This message is too large to open here.\", and its source is never asked for",
    o36.code === 413 && o36.body.error === "This message is too large to open here." && o36.body.code === "too_large" &&
    bc.wire.filter(l => /FETCH/.test(l)).length === 1 && !bc.wire.some(l => BODY_ASKED.test(l)), J([o36.code, o36.body && o36.body.error]) + " " + bc.wire.join(" | "));
  const o99 = await b.hit("open", ALICE, { params: { uid: "99" } });
  const oBad = await b.hit("open", ALICE, { params: { uid: "x1" } });
  check("R19. a message that is not there is 404; a uid that is not a number is 400", o99.code === 404 && o99.body.error === ME.MESSAGES.notFound && oBad.code === 400);
  const allCalls = [].concat.apply([], STUB.clients.map(c => c.calls));
  check("R20. across every read: only connect, EXAMINE, search, fetch, fetchOne and logout; no flag, move, copy, delete or raw command",
    allCalls.every(c => ALLOWED_CLIENT_CALLS.indexOf(c) !== -1) && STUB.wire.every(l => !WRITE_COMMANDS.test(l)), allCalls.filter(c => ALLOWED_CLIENT_CALLS.indexOf(c) === -1).join(","));
  const readWrites = b.db.log.slice(logAt).filter(q => q.op !== "select");
  const STAMPS = ["last_ok_at", "updated_at", "last_error_at", "last_error_code"];
  check("R21. the only writes a read makes are the connection's own stamps (last_ok_at, updated_at): no message, header or attachment in any table",
    readWrites.length > 0 && readWrites.every(w => w.table === "member_email_connections" && w.op === "update" && Object.keys(w.payload).every(k => STAMPS.indexOf(k) !== -1)) &&
    ["Kiln schedule", "kiln fires", "Fire & glaze", "invoice.pdf", ATTACH_B64, "Glaze notes"].every(t => J(b.db.tables).indexOf(t) === -1),
    J(readWrites.map(w => w.table + " " + w.op + " " + Object.keys(w.payload || {}).join("+"))));
  check("R22. nothing a message holds reaches a log line", ["Kiln schedule", "kiln fires", "Fire & glaze", "invoice.pdf", "ann+bftest"].every(t => LOGS.join("\n").indexOf(t) === -1));
  check("R23. every message that was unread before is still unread", STUB.boxes["imap.gmail.com " + ADDR.alice].messages.every((m, i) => J(m.flags) === J(aliceMessages()[i].flags)));
  check("R24. no read sent mail or made a transport", STUB.transports.length === 0);

  /* ── E. errors while reading ────────────────────────────────────────────── */
  console.log("\n══ E. errors while reading ══");
  const rr = await b.hit("connect", RITA, gmail(ADDR.rita, PW.rita));
  STUB.boxes["imap.gmail.com " + ADDR.rita].password = "revoked-by-the-member";
  resetStubCounters();
  const e1 = await b.hit("inbox", RITA);
  const ritaNotes = () => b.db.rows("notifications").filter(n => n.user_id === RITA);
  const RECONNECT = "Your mailbox stopped accepting the app password saved for " + ADDR.rita + ", so BizForce can't read it. Make a new app password and connect again.";
  check("E1. a revoked app password: 422 needs_reconnect with the reconnect words; the row is needs_reconnect",
    rr.code === 200 && e1.code === 422 && e1.body.code === "needs_reconnect" && e1.body.error === RECONNECT && connOf(b, RITA).status === "needs_reconnect", J([rr.code, e1.code, e1.body]));
  check("E2. ONE notice: email_reconnect, \"Reconnect your mailbox\"", ritaNotes().length === 1 && ritaNotes()[0].type === "email_reconnect" &&
    ritaNotes()[0].title === "Reconnect your mailbox" && ritaNotes()[0].message === RECONNECT);
  check("E3. no retry: one client, one login attempt", STUB.clients.length === 1 && J(STUB.clients[0].calls) === J(["connect", "close"]), J(STUB.clients.map(c => c.calls)));
  resetStubCounters();
  const e4 = await b.hit("inbox", RITA);
  check("E4. the next read is refused 409 needs_reconnect without connecting, and raises no second notice",
    e4.code === 409 && e4.body.code === "needs_reconnect" && STUB.clients.length === 0 && ritaNotes().length === 1);
  connOf(b, RITA).status = "connected";
  await b.ctx.api.recordMailboxSession(RITA, ADDR.rita, { ok: false, reason: "session_failed", code: "imap_auth" });
  await b.ctx.api.recordMailboxSession(RITA, ADDR.rita, { ok: false, reason: "session_failed", code: "imap_auth" });
  check("E5. two refusals in a row raise exactly one notice (the mark is conditional on status connected)", ritaNotes().length === 2, ritaNotes().length);
  await b.hit("connect", TOM, { body: { provider: "fastmail", email_address: ADDR.tom, app_password: PW.tom } });
  STUB.imapMode["imap.fastmail.com"] = "throttle";
  resetStubCounters();
  const e6 = await b.hit("inbox", TOM);
  STUB.imapMode = {};
  const resumes = new Date(CLOCK.now + 15 * 60 * 1000).toISOString();
  check("E6. a throttle while reading: 429 with the slow-down words and the time it ends, 15 minutes on", e6.code === 429 && e6.body.code === "rate_limited" &&
    e6.body.error === ME.MESSAGES.rateLimited && e6.body.resumes_at === resumes && connOf(b, TOM).status === "connected", J([e6.code, e6.body]));
  resetStubCounters();
  CLOCK.now += 14 * 60 * 1000;
  const e7 = await b.hit("inbox", TOM);
  check("E7. within the 15 minutes the next read makes no connection at all", e7.code === 429 && STUB.clients.length === 0 && STUB.resolved.length === 0, J([e7.code, STUB.clients.length]));
  CLOCK.now += 61 * 1000;
  resetStubCounters();
  const e8 = await b.hit("inbox", TOM);
  check("E8. after 15 minutes it connects again", e8.code === 200 && STUB.clients.length === 1, J([e8.code, STUB.clients.length]));
  await b.hit("connect", VIC, gmail(ADDR.vic, PW.vic));
  connOf(b, VIC).secret_auth_tag = "0".repeat(32);
  resetStubCounters();
  const e9 = await b.hit("inbox", VIC);
  check("E9. a secret that will not open is treated as a refused password (needs_reconnect), with no connection", e9.code === 422 && e9.body.code === "needs_reconnect" &&
    STUB.clients.length === 0 && connOf(b, VIC).status === "needs_reconnect");
  const e10 = await b.hit("inbox", NOBODY), e11 = await b.hit("open", NOBODY, { params: { uid: "4" } });
  check("E10. not connected: 404 not_connected on both reads", e10.code === 404 && e10.body.code === "not_connected" && e11.code === 404 && e11.body.code === "not_connected");
  check("E11. no error path logged the password or a message", noSecretIn(LOGS.join("\n")) && LOGS.join("\n").indexOf("Kiln schedule") === -1);

  /* ── D. status and disconnect ───────────────────────────────────────────── */
  console.log("\n══ D. status and disconnect ══");
  const before = b.db.rows("member_email_connections").length;
  const d1 = await b.hit("disconnect", BOB);
  check("D1. disconnect deletes only the caller's row and says how to cancel the app password itself",
    d1.code === 200 && d1.body.removed === true && !connOf(b, BOB) && b.db.rows("member_email_connections").length === before - 1 && !!connOf(b, ALICE) &&
    d1.body.note === "Disconnected. To cancel the app password itself, remove it in your email provider's security settings." && d1.body.connected === false);
  const d2 = await b.hit("disconnect", BOB), d3 = await b.hit("status", BOB);
  check("D2. disconnecting again removes nothing; status then says not connected", d2.code === 200 && d2.body.removed === false && d3.code === 200 && d3.body.connected === false && d3.body.provider === null);

  /* ── X. export, backup, deletion, the schema list ───────────────────────── */
  console.log("\n══ X. export, backup, deletion ══");
  const entry = (YDATA.DATA || []).find(e => e.table === "member_email_connections") || {};
  check("X1. Your data exports the provider, the address and the date only (group account, key provider, deleted with the account)",
    entry.select === "provider, email_address, created_at" && entry.group === "account" && entry.key === "provider" && entry.onDelete === "delete" &&
    J(entry.owner) === J(["user_id"]) && !/secret|username|host|port/.test(String(entry.select)), J(entry));
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE "Your mailbox app password: stored encrypted; ...". AFTER
  // "Your mailbox app password or Microsoft access: stored encrypted; ..." (the brief's words), the rest unchanged.
  check("X2. the never-exported list names the app password and the Microsoft access", (YDATA.NEVER_EXPORTED || []).indexOf("Your mailbox app password or Microsoft access: stored encrypted; the export shows only the provider, the address and the date you connected.") !== -1);
  check("X3. account deletion removes the row (FINAL_DELETES)", (YDATA.FINAL_DELETES || []).indexOf("member_email_connections") !== -1);
  check("X4. backups leave the table out, with the reason", BACKUP.EXCLUDED_TABLES.member_email_connections === "members' mailbox app passwords (encrypted); members connect again");
  check("X5. the schema list names the table as migration 169's", lf(fs.readFileSync(path.join(REPO, "lib/schemaCheck.js"), "utf8")).indexOf('["member_email_connections", "169_member_email_connections.sql"]') !== -1);

  /* ── S. no send code ────────────────────────────────────────────────────── */
  console.log("\n══ S. read only: no send code in this build ══");
  const MEcode = uncommented(SOURCES.ME), BLcode = uncommented(BLOCK);
  check("S1. the server's mailbox block was read", BLOCK.length > 5000 && BLOCK.indexOf("app.get(\"/api/mailbox/inbox/:uid\"") !== -1, BLOCK.length);
  /* NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE S2 and S3 read all of lib/memberEmail.js, which had no
     send code. AFTER Build B's sendReply sends one approved reply (checkMailboxReply holds it); S2 and S3 read the module
     with sendReply set aside, and S2b holds sendReply to exactly one sendMail and no other method that writes. */
  /* NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE sendReply was one function. AFTER it is three, side by
     side: sendReply (the checks and the one-retry rule), sendWithToken (an oauth row's token) and sendOnce (the one
     transport and its one sendMail). The three are set aside together, and S2b reads the three together. */
  const SEND_AT = MEcode.indexOf("async function sendReply(");
  const ONCE_AT = MEcode.indexOf("async function sendOnce(");
  const SEND_END = SEND_AT === -1 || ONCE_AT < SEND_AT ? -1 : s.braceMatch(MEcode, MEcode.indexOf(") {", ONCE_AT) + 2);
  const sendReplyCode = SEND_END === -1 ? "" : MEcode.slice(SEND_AT, SEND_END + 1);
  const MEread = SEND_END === -1 ? MEcode : MEcode.slice(0, SEND_AT) + MEcode.slice(SEND_END + 1);
  check("S2. neither lib/memberEmail.js (sendReply aside) nor the mailbox routes call sendMail, send, append or a flag, move, copy or delete method",
    ![MEread, BLcode].some(t => /\.sendMail\(|\.send\(|\.append\(|messageFlags(Add|Set|Remove)\(|messageMove\(|messageCopy\(|messageDelete\(|mailboxDelete\(/.test(t)));
  check("S2b. sendReply calls sendMail exactly once and nothing that writes to a mailbox",
    sendReplyCode.length > 200 && (sendReplyCode.match(/\.sendMail\(/g) || []).length === 1 &&
    !/\.send\(|\.append\(|messageFlags(Add|Set|Remove)\(|messageMove\(|messageCopy\(|messageDelete\(|mailboxDelete\(/.test(sendReplyCode), sendReplyCode.length);
  check("S3. outside sendReply, the only nodemailer call is verify(), which connects, logs in and quits", (MEread.match(/transport\.[a-zA-Z]+\(/g) || []).every(c => c === "transport.verify(" || c === "transport.close("));
  check("S4. during every check above, no transport sent mail and no client called an unexpected method",
    STUB.everClients.length > 10 && STUB.everTransports.length > 5 && STUB.everTransports.every(t => t.calls.every(c => c === "verify" || c === "close")) &&
    STUB.everClients.every(c => c.calls.every(x => ALLOWED_CLIENT_CALLS.indexOf(x) !== -1)), J([STUB.everClients.length, STUB.everTransports.length]));

  /* ── J. the page ────────────────────────────────────────────────────────── */
  console.log("\n══ J. mailbox.html and scripts/mailbox.js ══");
  const page = FE("mailbox.html"), js = FE("scripts/mailbox.js");
  const PRIV_LINE = "BizForce reads your inbox only when you ask, never stores your messages, and never marks them read or changes anything in your mailbox.";
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE the third line was "Outlook.com no longer allows app passwords.
  // Sign in with Microsoft is coming." AFTER that line is gone (it is no longer true) and the page says the sign-in line instead.
  check("J1. the page says the lines word for word: read on request, attachments not downloaded, and the Microsoft sign-in line; the old Outlook line is gone",
    page.indexOf(PRIV_LINE) !== -1 && page.indexOf("Attachments are listed but not downloaded.") !== -1 &&
    page.indexOf("Sign in with Microsoft is coming.") === -1 && page.indexOf("You sign in on Microsoft's own page. BizForce never sees your Microsoft password.") !== -1 &&
    js.indexOf("var OFFLINE = \"Your inbox loads when you are back online.\";") !== -1);
  check("J2. the page loads bf-theme.js first, its own script, the guide and the legal footer; title \"Your Inbox\"",
    page.indexOf("<head>\n<script src=\"/scripts/bf-theme.js\"></script>") !== -1 && page.indexOf('<script src="/scripts/mailbox.js"></script>') !== -1 &&
    page.indexOf('<script src="/scripts/termaximus-guide.js"></script>') !== -1 && page.indexOf("/scripts/bf-legal-footer.js") !== -1 && /<h1 class="hero-title">Your Inbox<\/h1>/.test(page));
  const noComments = t => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/<!--[\s\S]*?-->/g, "").replace(/^\s*\/\/.*$/gm, "");
  check("J3. no innerHTML, outerHTML, insertAdjacentHTML or document.write in the page or its script", [page, js].every(t => !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(noComments(t))));
  check("J4. the help lines are the server's presets', word for word", Object.keys(PRESETS).concat(["other"]).every(p => js.indexOf(ME.PROVIDERS[p].help.replace(ME.HELP_SUFFIX, "")) !== -1) &&
    js.indexOf("var HELP_SUFFIX = \"" + ME.HELP_SUFFIX + "\";") !== -1);
  check("J5. the password field is type password with autocomplete off", /<input type="password" id="mbPassword" maxlength="256" autocomplete="off"\/>/.test(page));
  if (!JSDOM) check("J6. jsdom loads", false, "jsdom is not installed");
  else {
    const stripScripts = h => h.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
    const settle = async () => { for (let i = 0; i < 25; i++) await tick(); };
    async function mailboxPage(answers, offline) {
      const dom = new JSDOM(stripScripts(page), { url: "https://bizforceai.net/mailbox.html", runScripts: "outside-only" });
      const w = dom.window, log = { fetches: [] };
      w.localStorage.setItem("bf_token", "tok");
      if (offline) Object.defineProperty(w.navigator, "onLine", { configurable: true, get: () => false });
      w.fetch = function (u, init) {
        const m = (init && init.method) || "GET";
        log.fetches.push({ url: String(u), method: m, body: init && init.body });
        const a = answers.find(x => x.test(String(u), m)) || { status: 404, body: {} };
        return Promise.resolve({ ok: (a.status || 200) < 400, status: a.status || 200, json: () => Promise.resolve(JSON.parse(J(a.body))) });
      };
      w.eval(js);
      await settle();
      return { w, doc: w.document, log };
    }
    const STATUS_ON = { connected: true, provider: "gmail", email_address: ADDR.alice, status: "connected", since: "2026-11-05T09:00:00.000Z" };
    const STATUS_OFF = { connected: false, provider: null, email_address: null, status: null, since: null };
    const ans = (re, method, body, status) => ({ test: (u, m) => re.test(u) && (!method || m === method), body: body, status: status });
    const LISTED = { messages: [{ uid: 7, from: { name: HOSTILE, address: "x+bftest@example.com" }, subject: HOSTILE, date: "2026-11-04T10:00:00.000Z", seen: false, size: 100 }], next_before: 3 };
    const OPENED = { message: { uid: 7, from: { name: "Ann", address: "ann+bftest@example.com" }, to: [], cc: [], subject: HOSTILE, date: "2026-11-04T10:00:00.000Z",
      text: "Hello " + HOSTILE, truncated: false, attachments: [{ name: HOSTILE + ".pdf", type: "application/pdf", size: 2048 }] } };
    const P1 = await mailboxPage([ans(/\/api\/mailbox\/status$/, "GET", STATUS_ON), ans(/\/api\/mailbox\/inbox\/7$/, "GET", OPENED), ans(/\/api\/mailbox\/inbox(\?|$)/, "GET", LISTED)]);
    check("J6. on open the page reads only the connection's status; nothing loads from the inbox until asked",
      P1.log.fetches.length === 1 && /\/api\/mailbox\/status$/.test(P1.log.fetches[0].url) && P1.doc.getElementById("mbList").children.length === 0 &&
      P1.doc.getElementById("mbInbox").hidden === true && P1.doc.getElementById("mbConnected").hidden === false, J(P1.log.fetches.map(f => f.url)));
    P1.doc.getElementById("mbShowBtn").click(); await settle();
    const rows = Array.from(P1.doc.querySelectorAll(".mb-row"));
    check("J7. \"Show my inbox\" lists the messages; a hostile sender and subject are text, never markup; unread rows are marked",
      rows.length === 1 && rows[0].querySelector(".mb-subject").textContent === HOSTILE && P1.doc.querySelectorAll("img").length === 0 &&
      rows[0].classList.contains("unread") && P1.doc.getElementById("mbOlderBtn").hidden === false, rows.length);
    rows[0].click(); await settle();
    check("J8. a row opens the message: its text and attachments as text, in the message view",
      P1.doc.getElementById("mbMessage").hidden === false && P1.doc.getElementById("mbMsgText").textContent === "Hello " + HOSTILE &&
      P1.doc.getElementById("mbMsgSubject").textContent === HOSTILE && P1.doc.getElementById("mbMsgAttach").textContent.indexOf(HOSTILE + ".pdf") !== -1 &&
      P1.doc.querySelectorAll("img").length === 0 && P1.log.fetches.some(f => /\/api\/mailbox\/inbox\/7$/.test(f.url)));
    P1.doc.getElementById("mbOlderBtn").hidden = false;
    P1.doc.getElementById("mbBackBtn").click(); P1.doc.getElementById("mbOlderBtn").click(); await settle();
    check("J9. \"Show older\" asks for the page before the cursor", P1.log.fetches.some(f => /\/api\/mailbox\/inbox\?before=3$/.test(f.url)), J(P1.log.fetches.map(f => f.url)));
    const P2 = await mailboxPage([ans(/\/api\/mailbox\/status$/, "GET", STATUS_OFF), ans(/\/api\/mailbox\/connect$/, "POST", { error: ME.MESSAGES.rejected, code: "rejected", saved: false }, 422)]);
    const pwField = P2.doc.getElementById("mbPassword");
    P2.doc.getElementById("mbEmail").value = ADDR.alice; pwField.value = PW.alice;
    P2.doc.getElementById("mbConnectBtn").click(); await settle();
    const sent = P2.log.fetches.find(f => f.method === "POST");
    check("J10. a refused connect: the password field is cleared and the server's words shown",
      P2.doc.getElementById("mbConnect").hidden === false && pwField.value === "" && P2.doc.getElementById("mbStatus").textContent === ME.MESSAGES.rejected &&
      !!sent && J(Object.keys(JSON.parse(sent.body)).sort()) === J(["app_password", "email_address", "provider", "username"]));
    const P3 = await mailboxPage([ans(/\/api\/mailbox\/status$/, "GET", STATUS_OFF), ans(/\/api\/mailbox\/connect$/, "POST", STATUS_ON)]);
    P3.doc.getElementById("mbProvider").value = "other"; P3.doc.getElementById("mbProvider").dispatchEvent(new P3.w.Event("change"));
    const otherShown = P3.doc.getElementById("mbOtherFields").hidden === false;
    P3.doc.getElementById("mbProvider").value = "gmail"; P3.doc.getElementById("mbProvider").dispatchEvent(new P3.w.Event("change"));
    P3.doc.getElementById("mbEmail").value = ADDR.alice; P3.doc.getElementById("mbPassword").value = PW.alice;
    P3.doc.getElementById("mbConnectBtn").click(); await settle();
    check("J11. an accepted connect: the password field is cleared too, and the connected card shows; Other shows the server fields",
      otherShown && P3.doc.getElementById("mbPassword").value === "" && P3.doc.getElementById("mbConnected").hidden === false &&
      P3.doc.getElementById("mbConnectedTitle").textContent === "Gmail: " + ADDR.alice && P3.doc.getElementById("mbHelp").textContent === ME.PROVIDERS.gmail.help);
    const P4 = await mailboxPage([ans(/\/api\/mailbox\/status$/, "GET", Object.assign({}, STATUS_ON, { connected: false, status: "needs_reconnect" }))]);
    check("J12. needs_reconnect: the reconnect words, no Show my inbox, the connect form with the address filled in",
      P4.doc.getElementById("mbConnectedNote").textContent === "Your mailbox stopped accepting the app password saved for " + ADDR.alice + ", so BizForce can't read it. Make a new app password and connect again." &&
      P4.doc.getElementById("mbShowBtn").hidden === true && P4.doc.getElementById("mbConnect").hidden === false && P4.doc.getElementById("mbEmail").value === ADDR.alice);
    const P5 = await mailboxPage([ans(/./, null, STATUS_ON)], true);
    check("J13. offline: \"Your inbox loads when you are back online.\", and nothing is fetched",
      P5.doc.getElementById("mbStatus").textContent === "Your inbox loads when you are back online." && P5.log.fetches.length === 0);
  }
  check("J14. the dashboard has a Your Inbox card, and the Email agent page links the page",
    /data-card="mailbox" onclick="window\.location\.href='mailbox\.html'"/.test(FE("dashboard.html")) && FE("dashboard.html").indexOf(">Open Your Inbox</a>") !== -1 &&
    FE("email-agent.html").indexOf('<a class="action-btn action-btn--ghost" href="mailbox.html">Your Inbox</a>') !== -1);

  /* ── L. privacy and terms ───────────────────────────────────────────────── */
  console.log("\n══ L. Privacy and Terms ══");
  /* NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE "to check the connection and to read your inbox when you open it in
     BizForce". AFTER "to check the connection, to read your inbox when you open it in BizForce, and to send the replies you approve",
     as Build B decides; the reply sentences that follow it are checkMailboxReply's. */
  /* NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE the sentence below as it stood. AFTER exactly two
     replacements, as the brief decides and nothing else: "the app password you made for BizForce, encrypted" names the
     access Microsoft grants too, and "cancel the app password with your email provider" adds removing BizForce from the
     Microsoft account. The words before each replacement are kept here, so any other change still fails L1. */
  const PRIVACY_169 = "If you connect your mailbox, BizForce stores your email address, your mail server names and the app password you made for BizForce, encrypted; it is used only to check the connection, to read your inbox when you open it in BizForce, and to send the replies you approve. Your messages are read each time you ask and are not stored, BizForce never marks them read or changes anything in your mailbox, and attachments are listed but not downloaded. You can disconnect at any time, you can also cancel the app password with your email provider, and it is deleted with your account.";
  const PRIVACY = PRIVACY_169
    .replace("the app password you made for BizForce, encrypted", "the app password you made for BizForce or, if you sign in with Microsoft, the access Microsoft grants BizForce, encrypted")
    .replace("you can also cancel the app password with your email provider", "you can also cancel the app password with your email provider or remove BizForce from your Microsoft account");
  const TERMS = "If you connect a mailbox, you confirm it is yours or that you are allowed to connect it.";
  check("L1. lib/legalPages.js holds both sentences word for word", LP.MAILBOX_PRIVACY_SENTENCE === PRIVACY && LP.MAILBOX_TERMS_SENTENCE === TERMS);
  const priv = FE("privacy.html"), terms = FE("terms.html");
  check("L2. privacy.html says it once, right after the social images sentence", priv.split(PRIVACY).length === 2 &&
    priv.indexOf(LP.SOCIAL_MEDIA_PRIVACY_SENTENCE) !== -1 && priv.indexOf(LP.SOCIAL_MEDIA_PRIVACY_SENTENCE) < priv.indexOf(PRIVACY));
  check("L3. terms.html says the Terms sentence once, after the Mastodon one", terms.split(TERMS).length === 2 &&
    terms.indexOf("If you connect your own Mastodon account, you are responsible") !== -1 && terms.indexOf("If you connect your own Mastodon account, you are responsible") < terms.indexOf(TERMS));
  check("L4. the services list names the member's own email provider", (YDATA.THIRD_PARTIES || []).some(t => t.name === "your own email provider") &&
    priv.indexOf("your own email provider") !== -1);

  /* ── G. the guide ───────────────────────────────────────────────────────── */
  console.log("\n══ G. the guide ══");
  const GUIDE = FE("scripts/termaximus-guide.js");
  const gi = GUIDE.indexOf("    \"mailbox.html\": [\n"), ge = GUIDE.indexOf("\n    ],", gi);
  const tips = gi === -1 ? [] : (GUIDE.slice(gi, ge).match(/^      "(?:[^"\\]|\\.)*"/gm) || []).map(t => JSON.parse(t.trim()));
  check("G1. mailbox.html has its own four tips: Connect, Show my inbox and Show older, unread and not stored, Disconnect",
    tips.length === 4 && /\\"Connect\\"|"Connect"/.test(J(tips[0])) && tips[1].indexOf("\"Show my inbox\"") !== -1 && tips[1].indexOf("\"Show older\"") !== -1 &&
    /unread/.test(tips[2]) && /no copy/.test(tips[2]) && tips[3].indexOf("\"Disconnect\"") !== -1, J(tips));

  /* ── Z. zero network ────────────────────────────────────────────────────── */
  console.log("\n══ Z. zero network ══");
  check("Z. no socket, DNS lookup or fetch was attempted", NETWORK.length === 0, NETWORK.join(", "));

  console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : "CHECKS FAILED: " + failures + " of " + (passes + failures)));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  the check crashed: " + safe(String(e && e.stack || e))); process.exit(1); });
