"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMailboxOutlook — Sign in with Microsoft for Your Inbox (migration 173,
   Nov 6 2026): OAuth 2.0 authorization code with PKCE (S256), a single-use
   state stored only as its hash, both tokens sealed before any mail server is
   asked anything, a compare-and-set refresh, and the same read and reply
   rules as an app password.

   No request leaves the machine, and nothing here calls Microsoft. The token
   endpoint is a fake behind lib/guardedFetch.js guardedJsonRequest's REAL
   form mode (its request function is swapped for one that answers in memory,
   after asking the fetcher's own guarded lookup where to go, so every address
   rule still runs). ImapFlow and nodemailer are fakes that record every
   option; DNS is a stub; the database is a fake that enforces migration
   173's CHECKs (and 169's); the clock is fixed; a tripwire fails any socket
   or DNS lookup.

   SECTIONS
     A. lib/microsoftAuth.js: the constants, the state and verifier, the S256
        vectors, the authorize URL parameters exactly, the finish shapes.
     B. the token endpoint: the exchange and refresh form bodies, the refusals
        (no refresh token, a missing mail scope), invalid_grant, a 500.
     C. the ID token: aud, exp and tid, the address, personal and work.
     D. lib/memberEmail.js: the OAuth options for ImapFlow and nodemailer,
        getAccessToken (fresh, near expiry, the CAS winner and loser,
        single-flight, a forced refresh), the one-retry rule, and the
        app-password path unchanged.
     E. the routes: 503 until configured, start, finish (the state hashed,
        single-use, 10 minutes, this member only, one message for every
        failure; the tokens sealed before IMAP; the upsert against the
        kind_shape CHECK; the work-account message), status, disconnect, a
        read with an outlook row (refresh through the CAS, needs_reconnect only
        per decision 7), the CAS itself, and nothing secret in any answer or log.
     F. the oauth_states purge, and the 04:45 cron.
     G. the page: the picker, the button, the lines word for word, the return
        with replaceState always, the error messages, textContent only.
     H. legal and yourData, README, registries, the migration.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const crypto = require("crypto");
const { EventEmitter } = require("events");
const { PassThrough } = require("stream");
const Module = require("module");
const s = require("./_shared");

/* ── the network tripwire, before anything can open a socket ──────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMailboxOutlook: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMailboxOutlook: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the state is stored as it is, not as its sha256
  "state-stored-raw": [["SRC", "        state_hash:          ms.stateHash(state),\n", "        state_hash:          state,\n"]],
  // a consumed state can be used again
  "state-reusable": [["SRC", "        .eq(\"purpose\", ms.PURPOSE)\n        .is(\"consumed_at\", null)\n", "        .eq(\"purpose\", ms.PURPOSE)\n"]],
  // another member's state is accepted
  "state-other-member": [["SRC", "        .eq(\"state_hash\", ms.stateHash(shape.state))\n        .eq(\"user_id\", req.user.id)\n", "        .eq(\"state_hash\", ms.stateHash(shape.state))\n"]],
  // an expired state is accepted
  "state-expiry-unchecked": [["SRC", "        .gt(\"expires_at\", consumedAt)\n", ""]],
  // a failed consume says why
  "consume-reason-leaked": [["SRC", "      if (!spent) {\n        return res.status(400).json({ error: ms.MESSAGES.stateInvalid, code: \"state_invalid\", saved: false });\n      }\n",
    "      if (!spent) {\n        var why = await supabase.from(\"oauth_states\").select(\"consumed_at, expires_at, user_id\").eq(\"state_hash\", ms.stateHash(shape.state)).maybeSingle();\n" +
    "        return res.status(400).json({ error: ms.MESSAGES.stateInvalid, code: !why.data ? \"state_unknown\" : why.data.consumed_at ? \"state_used\" : why.data.user_id !== req.user.id ? \"state_other\" : \"state_expired\", saved: false });\n      }\n"]],
  // PKCE plain instead of S256
  "pkce-plain": [["MS", "function challengeFor(verifier) { return base64url(crypto.createHash(\"sha256\").update(String(verifier), \"ascii\").digest()); }",
    "function challengeFor(verifier) { return String(verifier); }"],
    ["MS", "  q.append(\"code_challenge_method\", \"S256\");\n", "  q.append(\"code_challenge_method\", \"plain\");\n"]],
  // the verifier is stored readable (hex passes the CHECK)
  "verifier-unsealed": [["SRC", "        verifier_ciphertext: sealedVerifier.ciphertext,\n", "        verifier_ciphertext: Buffer.from(verifier).toString(\"hex\"),\n"]],
  // the authorization code is logged
  "code-logged": [["SRC", "      var shape = ms.finishShape(req.body);\n", "      var shape = ms.finishShape(req.body);\n      console.log(\"[mailbox/microsoft/finish] code\", shape.code);\n"]],
  // the tokens are logged
  "token-logged": [["SRC", "      var accessExpiresAt = new Date(", "      console.log(\"[mailbox/microsoft/finish] tokens\", grant.accessToken, grant.refreshToken);\n      var accessExpiresAt = new Date("]],
  // a token goes back in the answer
  "token-in-response": [["SRC", "      return res.json(Object.assign(me.statusOf(saved.data), { outlook_available: true }));\n",
    "      return res.json(Object.assign(me.statusOf(saved.data), { outlook_available: true, refresh_token: crypt.decrypt({ ciphertext: sealedRefresh.ciphertext, iv: sealedRefresh.iv, authTag: sealedRefresh.authTag }) }));\n"]],
  // nodemailer is handed refresh and client fields, so it could fetch a token itself
  "nodemailer-refresh-fields": [["ME", "  if (isOauthSecret(secret)) return { type: \"OAuth2\", user: user, accessToken: secret.accessToken };\n",
    "  if (isOauthSecret(secret)) return { type: \"OAuth2\", user: user, accessToken: secret.accessToken, refreshToken: \"r\", clientId: \"c\", clientSecret: \"s\", accessUrl: MS.TOKEN_URL };\n"]],
  // nodemailer is handed a provisionCallback
  "nodemailer-provision-fetch": [["ME", "  if (isOauthSecret(secret)) return { type: \"OAuth2\", user: user, accessToken: secret.accessToken };\n",
    "  if (isOauthSecret(secret)) return { type: \"OAuth2\", user: user, accessToken: secret.accessToken, provisionCallback: function (u, r, cb) { cb(null, secret.accessToken); } };\n"]],
  // the access token goes to ImapFlow as a password
  "imap-pass-for-oauth": [["ME", "  if (isOauthSecret(secret)) return { user: user, accessToken: secret.accessToken };\n", "  if (isOauthSecret(secret)) return { user: user, pass: secret.accessToken };\n"]],
  // IMAP is asked before the tokens are sealed
  "unsealed-before-verify": [["SRC", "      // Sealed first: both tokens are encrypted before any mail server is asked anything.\n",
    "      await me.verifyConnection({ provider: \"outlook\", email_address: who.email, username: who.email, imap_host: hosts.imap_host, imap_port: hosts.imap_port, smtp_host: hosts.smtp_host, smtp_port: hosts.smtp_port }, { kind: \"oauth\", accessToken: grant.accessToken });\n"]],
  "aud-unchecked": [["MS", "  if (claims.aud !== clientId) throw new MicrosoftError(\"id_token\", \"aud\");\n", ""]],
  "exp-unchecked": [["MS", "  if (typeof claims.exp !== \"number\" || !(claims.exp * 1000 > nowMs)) throw new MicrosoftError(\"id_token\", \"exp\");\n", ""]],
  "tid-account-swapped": [["MS", "  return tid === PERSONAL_TID ? \"personal\" : \"work\";", "  return tid === PERSONAL_TID ? \"work\" : \"personal\";"]],
  "scope-unchecked": [["MS", "  if (!grantsMail(j.scope)) throw new MicrosoftError(\"no_mail_access\", \"scope_missing\");\n", ""]],
  "missing-refresh-accepted": [["MS", "  if (typeof j.refresh_token !== \"string\" || !j.refresh_token) throw new MicrosoftError(\"no_mail_access\", \"no_refresh_token\");\n", ""]],
  // the refresh write is not conditional on the token_version read
  "cas-missing": [["SRC", "        .eq(\"token_version\", row.token_version)\n", ""]],
  // the loser of a refresh race writes its own tokens anyway
  "loser-writes": [["ME", "  // Lost the race: nothing more is written. The winner's token is the one to use.\n",
    "  var again = await access.reread(row);\n  await access.cas(again, update);\n"]],
  "refresh-every-request": [["ME", "  if (!force && isFinite(expires) && expires - deps.now() > REFRESH_MARGIN_MS) {\n", "  if (false) {\n"]],
  "retry-twice": [["ME", "  if (outcome.refused && outcome.oauth && !outcome.refreshedNow) outcome = await imapSession(row, settings, access, fn, true);\n",
    "  for (var tries = 0; outcome.refused && outcome.oauth && tries < 2; tries++) outcome = await imapSession(row, settings, access, fn, true);\n"]],
  // a refused token that was not refreshed marks needs_reconnect without the one forced refresh
  "reconnect-on-expiry": [["ME", "  if (outcome.refused && outcome.oauth && !outcome.refreshedNow) outcome = await imapSession(row, settings, access, fn, true);\n", ""]],
  "invalid-grant-ignored": [["ME", "    if (err && err.kind === \"invalid_grant\") throw new MailboxError(\"rejected\", \"invalid_grant\");\n", ""]],
  "unconfigured-not-503": [["SRC", "      if (!config) {\n        return res.status(503).json({ error: ms.MESSAGES.notConfigured, code: \"not_configured\" });\n      }\n",
    "      if (!config) config = { clientId: \"\", clientSecret: \"\" };\n"]],
  "replacestate-skipped": [["FE:scripts/mailbox.js", "      stripQuery();\n      state.busy = false;\n", "      state.busy = false;\n"]],
  "form-mislabelled": [["GF", "    if (formEncoded) headers[\"Content-Type\"] = \"application/x-www-form-urlencoded\";\n", ""]],
  // an app password goes to ImapFlow as an access token
  "app-password-path-changed": [["ME", "  if (typeof secret !== \"string\") throw new MailboxError(\"unreachable\", \"secret_shape\");\n  return { user: user, pass: secret };\n}\n/* nodemailer's OAuth2",
    "  if (typeof secret !== \"string\") throw new MailboxError(\"unreachable\", \"secret_shape\");\n  return { user: user, accessToken: secret };\n}\n/* nodemailer's OAuth2"]],
  "privacy-sentence-unchanged": [["LP", "BizForce \" +\n  \"or, if you sign in with Microsoft, the access Microsoft grants BizForce, encrypted;", "BizForce, \" +\n  \"encrypted;"]],
  "innerHTML-on-page": [["FE:scripts/mailbox.js", "    if (text !== undefined && text !== null) n.textContent = String(text);\n", "    if (text !== undefined && text !== null) n.innerHTML = String(text);\n"]],
  // earned: disconnect leaves the member's sign-in states
  "disconnect-keeps-states": [["SRC", "    var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);\n", "    var statesDropped = { error: null };\n"]],
  // earned: the purge keeps states for a month
  "purge-keeps-old": [["MS", "    var removed = await supabase.from(\"oauth_states\").delete().lt(\"created_at\", cutoff).select(\"id\");\n",
    "    var removed = await supabase.from(\"oauth_states\").delete().lt(\"created_at\", new Date(startedMs - 30 * STATES_RETENTION_MS).toISOString()).select(\"id\");\n"]],
  // earned: status says Outlook sign-in is available when it is not set up
  "status-always-available": [["SRC", "      outlook_available: require(\"./lib/microsoftAuth\").configured() !== null\n", "      outlook_available: true\n"]],
  // earned: a refreshed refresh token is stored readable
  "refresh-unsealed": [["ME", "  var sealedRefresh = access.encrypt(grant.refreshToken);\n",
    "  var sealedRefresh = { ciphertext: Buffer.from(grant.refreshToken).toString(\"hex\"), iv: \"0\".repeat(24), authTag: \"0\".repeat(32) };\n"]],
  // earned: the work-account refusal is given the personal wording
  "org-message-lost": [["SRC", "error: who.accountType === \"work\" ? ms.MESSAGES.orgBlocked : ms.MESSAGES.personalRefused", "error: ms.MESSAGES.personalRefused"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
const lf = t => t.replace(/\r\n/g, "\n");
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const J = JSON.stringify;
const tick = () => new Promise(r => setImmediate(r));

/* ── secrets the run makes up: never printed ─────────────────────────────── */
const SECRET_FORMS = [];
function secret(v) {
  [v, Buffer.from(v).toString("hex"), Buffer.from(v).toString("base64")].forEach(f => { if (SECRET_FORMS.indexOf(f) === -1) SECRET_FORMS.push(f); });
  return v;
}
const safe = x => { let t = typeof x === "string" ? x : J(x); SECRET_FORMS.forEach(f => { t = t.split(f).join("[secret]"); }); return t; };
const holdsSecret = text => SECRET_FORMS.some(f => String(text).indexOf(f) !== -1);
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + safe(String(detail)).slice(0, 300) + "]" : "")); }
}

/* ── the sources, mutated in memory ───────────────────────────────────────── */
const SOURCES = {
  SRC: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  ME: lf(fs.readFileSync(path.join(REPO, "lib/memberEmail.js"), "utf8")),
  MS: lf(fs.readFileSync(path.join(REPO, "lib/microsoftAuth.js"), "utf8")),
  GF: lf(fs.readFileSync(path.join(REPO, "lib/guardedFetch.js"), "utf8")),
  LP: lf(fs.readFileSync(path.join(REPO, "lib/legalPages.js"), "utf8"))
};
const FE_FILES = ["mailbox.html", "scripts/mailbox.js", "scripts/termaximus-guide.js", "privacy.html"];
FE_FILES.forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];
const MIG_PATH = path.join(REPO, "supabase/migrations/173_mailbox_microsoft.sql");
const MIGRATION = lf(fs.readFileSync(MIG_PATH, "utf8"));

/* A lib file compiled from its (possibly mutated) text and put in require's
   cache, so a sibling that requires it gets this copy. */
function loadLib(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  require.cache[file] = m;
  m._compile(text, file);
  m.loaded = true;
  return m.exports;
}
const TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.ENCRYPTION_SECRET = TEST_KEY;
delete process.env.MS_CLIENT_ID;
delete process.env.MS_CLIENT_SECRET;
const CRYPTO = require(path.join(REPO, "lib/apiKeyCrypto.js"));
const GF = loadLib("lib/guardedFetch.js", SOURCES.GF);
const MS = loadLib("lib/microsoftAuth.js", SOURCES.MS);
const ME = loadLib("lib/memberEmail.js", SOURCES.ME);
const LP = loadLib("lib/legalPages.js", SOURCES.LP);
const YDATA = require(path.join(REPO, "lib/yourData.js"));
const BACKUP = require(path.join(REPO, "lib/backup.js"));
const SCHEMA = require(path.join(REPO, "lib/schemaCheck.js"));
let JSDOM = null, VirtualConsole = null;
try { ({ JSDOM, VirtualConsole } = require("jsdom")); } catch (e) { JSDOM = null; }

const CLIENT_ID = "bftest-client-0000-4000-8000-000000000001";
const CLIENT_SECRET = secret("bftest-client-secret-do-not-print-0001");
function configure(on) {
  if (on) { process.env.MS_CLIENT_ID = CLIENT_ID; process.env.MS_CLIENT_SECRET = CLIENT_SECRET; }
  else { delete process.env.MS_CLIENT_ID; delete process.env.MS_CLIENT_SECRET; }
}

/* ── the clock, and the random bytes ──────────────────────────────────────── */
const CLOCK = { now: Date.parse("2026-11-06T12:00:00.000Z") };
const iso = ms => new Date(ms).toISOString();
let RANDOM_N = 0;
const MINTED = { states: [], verifiers: [] };
MS.deps.randomBytes = function (n) {
  RANDOM_N++;
  return crypto.createHash("sha256").update("bftest-random-" + RANDOM_N).digest().subarray(0, n);
};
MS.deps.now = () => CLOCK.now;
ME.deps.now = () => CLOCK.now;
const b64url = buf => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/* ── stub DNS and the fake token endpoint behind the real form mode ─────── */
const NAMES = {
  "login.microsoftonline.com": ["20.190.160.10"],
  "outlook.office365.com": ["52.96.0.10"], "smtp-mail.outlook.com": ["52.96.0.20"], "smtp.office365.com": ["52.96.0.30"],
  "imap.gmail.com": ["142.250.1.10"], "smtp.gmail.com": ["142.250.1.20"]
};
const RESOLVED = [];
function fakeResolve(hostname, options, cb) {
  RESOLVED.push(hostname);
  const list = NAMES[hostname];
  if (!list) { const e = new Error("getaddrinfo ENOTFOUND"); e.code = "ENOTFOUND"; return cb(e); }
  return cb(null, list.map(a => ({ address: a, family: 4 })));
}
const TOKEN = { calls: [], mode: "ok", scope: MS.IMAP_SCOPE + " " + MS.SMTP_SCOPE + " openid profile email offline_access", n: 0, claims: null };
function idTokenFor(claims) {
  const part = o => b64url(Buffer.from(J(o)));
  return secret(part({ alg: "RS256", typ: "JWT" }) + "." + part(claims) + ".bftest-signature-not-checked");
}
function mint() {
  TOKEN.n++;
  return { access: secret("bftest-access-token-" + TOKEN.n + "-0123456789abcdef"), refresh: secret("bftest-refresh-token-" + TOKEN.n + "-fedcba9876543210") };
}
function tokenAnswer(form) {
  if (TOKEN.mode === "invalid_grant") return { status: 400, json: { error: "invalid_grant", error_description: "AADSTS70008: expired" } };
  if (TOKEN.mode === "500") return { status: 500, json: { error: "server_error" } };
  const t = mint();
  const body = { token_type: "Bearer", scope: TOKEN.scope, expires_in: 3600, access_token: t.access, refresh_token: t.refresh };
  if (TOKEN.mode === "no_refresh") delete body.refresh_token;
  if (TOKEN.mode === "no_smtp") body.scope = MS.IMAP_SCOPE + " openid offline_access";
  if (TOKEN.claims) body.id_token = idTokenFor(TOKEN.claims);
  TOKEN.lastIssued = t;
  if (TOKEN.autoAccept) { MAIL.imapAccepted.add(t.access); MAIL.smtpAccepted.add(t.access); }
  return { status: 200, json: body };
}
function fakeRequest(options) {
  const req = new EventEmitter();
  req.destroy = function () {};
  req.end = function (payload) {
    setImmediate(function () {
      options.lookup(options.hostname, { all: true }, function (err, addresses) {
        if (err) return req.emit("error", err);
        const body = payload ? Buffer.from(payload).toString("utf8") : "";
        const call = { host: options.hostname, port: options.port, protocol: options.protocol, path: options.path, method: options.method,
          headers: Object.assign({}, options.headers), body: body, address: addresses[0].address };
        TOKEN.calls.push(call);
        const ans = tokenAnswer(new URLSearchParams(body));
        const res = new PassThrough();
        res.statusCode = ans.status;
        res.headers = { "content-type": "application/json; charset=utf-8" };
        req.emit("response", res);
        res.end(J(ans.json));
      });
    });
  };
  return req;
}
const GFX = GF.createGuardedFetch({ resolve: fakeResolve, request: fakeRequest });
MS.deps.request = (u, o) => GFX.json(u, o);

/* ── fake ImapFlow and nodemailer ─────────────────────────────────────────── */
const ORDER = [];
const MAIL = { imapAccepted: new Set(), smtpAccepted: new Set(), passwords: {}, clients: [], transports: [], sent: [] };
function errOf(props) { const e = new Error("stub failure"); Object.assign(e, props); return e; }
function authOk(set, auth, host) {
  if (!auth) return false;
  if (auth.accessToken !== undefined) return set.has(auth.accessToken);
  return auth.pass !== undefined && MAIL.passwords[host + " " + auth.user] === auth.pass;
}
function FakeImapFlow(options) {
  const rec = { options: options, calls: [] };
  MAIL.clients.push(rec);
  return {
    async connect() { rec.calls.push("connect"); ORDER.push("imap"); if (!authOk(MAIL.imapAccepted, options.auth, options.servername)) throw errOf({ authenticationFailed: true, serverResponseCode: "AUTHENTICATIONFAILED" }); },
    async mailboxOpen(p, o) { rec.calls.push("mailboxOpen"); return { path: p, readOnly: !!(o && o.readOnly), exists: 0 }; },
    async search() { rec.calls.push("search"); return []; },
    fetch() { rec.calls.push("fetch"); return (async function* () {})(); },
    async logout() { rec.calls.push("logout"); },
    close() { rec.calls.push("close"); }
  };
}
function fakeCreateTransport(options) {
  const rec = { options: options, calls: [] };
  MAIL.transports.push(rec);
  return {
    async verify() { rec.calls.push("verify"); ORDER.push("smtp"); if (!authOk(MAIL.smtpAccepted, options.auth, options.servername)) throw errOf({ code: "EAUTH", responseCode: 535 }); return true; },
    async sendMail(m) { rec.calls.push("sendMail"); if (!authOk(MAIL.smtpAccepted, options.auth, options.servername)) throw errOf({ code: "EAUTH", responseCode: 535 }); MAIL.sent.push(m.messageId); return { messageId: m.messageId }; },
    close() { rec.calls.push("close"); }
  };
}
ME.deps.ImapFlow = () => FakeImapFlow;
ME.deps.createTransport = fakeCreateTransport;
ME.deps.resolvePublicHost = host => GFX.resolvePublicHost(host);
function resetMail() { MAIL.clients = []; MAIL.transports = []; MAIL.sent = []; ORDER.length = 0; }

/* ── the fake database, with migration 173's CHECKs (and 169's) ──────────── */
const pat = (re) => { const m = re.exec(MIGRATION); return m ? new RegExp(m[1]) : null; };
const RE173 = {
  accessCipher: pat(/access_ciphertext IS NULL OR access_ciphertext ~ '([^']+)'/), accessIv: pat(/access_iv IS NULL OR access_iv ~ '([^']+)'/),
  accessTag: pat(/access_auth_tag IS NULL OR access_auth_tag ~ '([^']+)'/), hash: pat(/state_hash ~ '([^']+)'/),
  vCipher: pat(/verifier_ciphertext ~ '([^']+)'/), vIv: pat(/verifier_iv ~ '([^']+)'/), vTag: pat(/verifier_auth_tag ~ '([^']+)'/)
};
const EMAIL_169 = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function violates(table, row) {
  if (table === "member_email_connections") {
    if (["gmail", "yahoo", "icloud", "fastmail", "other", "outlook"].indexOf(row.provider) === -1) return "provider_check";
    if (["app_password", "oauth_microsoft"].indexOf(row.auth_kind) === -1) return "auth_kind_check";
    if (!EMAIL_169.test(String(row.email_address))) return "email_check";
    if (row.imap_port !== 993) return "imap_port_check";
    if ([465, 587].indexOf(row.smtp_port) === -1) return "smtp_port_check";
    if (!/^[0-9a-f]+$/.test(String(row.secret_ciphertext)) || !/^[0-9a-f]{24}$/.test(String(row.secret_iv)) || !/^[0-9a-f]{32}$/.test(String(row.secret_auth_tag))) return "secret_checks";
    if (row.access_ciphertext != null && !RE173.accessCipher.test(row.access_ciphertext)) return "access_ciphertext_check";
    if (row.access_iv != null && !RE173.accessIv.test(row.access_iv)) return "access_iv_check";
    if (row.access_auth_tag != null && !RE173.accessTag.test(row.access_auth_tag)) return "access_tag_check";
    if (!Number.isInteger(row.token_version) || row.token_version < 0) return "token_version_check";
    const nul = k => row[k] === null || row[k] === undefined;
    const appShape = row.auth_kind === "app_password" && row.provider !== "outlook" && ["access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at", "account_type"].every(nul);
    const msShape = row.auth_kind === "oauth_microsoft" && row.provider === "outlook" && ["access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at"].every(k => !nul(k)) &&
      ["personal", "work"].indexOf(row.account_type) !== -1;
    if (!appShape && !msShape) return "kind_shape_check";
    if (["connected", "needs_reconnect", "disconnected"].indexOf(row.status) === -1) return "status_check";
    return null;
  }
  if (table === "oauth_states") {
    if (row.purpose !== "mailbox_microsoft") return "oauth_states_purpose_check";
    if (!RE173.hash.test(String(row.state_hash))) return "oauth_states_hash_check";
    if (!RE173.vCipher.test(String(row.verifier_ciphertext))) return "oauth_states_ciphertext_check";
    if (!RE173.vIv.test(String(row.verifier_iv))) return "oauth_states_iv_check";
    if (!RE173.vTag.test(String(row.verifier_auth_tag))) return "oauth_states_tag_check";
    const e = Date.parse(row.expires_at), c = Date.parse(row.created_at);
    if (!(e > c && e <= c + 15 * 60 * 1000)) return "oauth_states_expiry_check";
    return null;
  }
  return null;
}
const DEFAULTS = {
  member_email_connections: () => ({ token_version: 0, access_ciphertext: null, access_iv: null, access_auth_tag: null, access_expires_at: null, account_type: null,
    status: "connected", last_ok_at: null, last_error_at: null, last_error_code: null, created_at: iso(CLOCK.now), updated_at: iso(CLOCK.now) }),
  oauth_states: () => ({ consumed_at: null, created_at: iso(CLOCK.now) }),
  notifications: () => ({ read: false, created_at: iso(CLOCK.now) }),
  job_runs: () => ({})
};
function fakeDb(seed) {
  const db = { tables: {}, log: [], seq: 0 };
  Object.keys(seed || {}).forEach(t => { db.tables[t] = seed[t].map(clone); });
  const rows = t => db.tables[t] || (db.tables[t] = []);
  const cmp = (a, b) => { const x = Date.parse(a), y = Date.parse(b); return isFinite(x) && isFinite(y) ? x - y : (a < b ? -1 : a > b ? 1 : 0); };
  const keep = (q, r) => q.filters.every(f => {
    if (f[0] === "eq") return r[f[1]] === f[2];
    if (f[0] === "neq") return r[f[1]] !== f[2];
    if (f[0] === "is") return f[2] === null ? (r[f[1]] === null || r[f[1]] === undefined) : r[f[1]] === f[2];
    if (f[0] === "gt") return r[f[1]] != null && cmp(r[f[1]], f[2]) > 0;
    if (f[0] === "lt") return r[f[1]] != null && cmp(r[f[1]], f[2]) < 0;
    if (f[0] === "or") return String(f[1]).split(",").some(c => { const p = c.split("."); return p[1] === "is" && p[2] === "null" ? r[p[0]] == null : p[1] === "neq" ? r[p[0]] !== p.slice(2).join(".") : false; });
    return true;
  });
  function project(row, cols) {
    if (!cols || cols.trim() === "*") return clone(row);
    const out = {};
    cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c] === undefined ? null : row[c]; });
    return out;
  }
  function finish(q, list) {
    const cols = q.op === "select" ? q.cols : q.retCols;
    const data = (q.op === "select" || q.returning) ? list.map(r => project(r, cols)) : null;
    if (q.single === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116" } };
    if (q.single === "maybe") return data && data.length > 1 ? { data: null, error: { code: "PGRST116" } } : { data: data ? data[0] || null : null, error: null };
    return { data: data, error: null };
  }
  function insertOne(table, payload) {
    const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++db.seq).padStart(12, "0") }, DEFAULTS[table] ? DEFAULTS[table]() : {}, clone(payload));
    const bad = violates(table, row);
    if (bad) return { error: { code: "23514", message: bad } };
    if (table === "member_email_connections" && rows(table).some(r => r.user_id === row.user_id)) return { error: { code: "23505" } };
    if (table === "oauth_states" && rows(table).some(r => r.state_hash === row.state_hash)) return { error: { code: "23505" } };
    if (table === "job_runs" && rows(table).some(r => r.job_name === row.job_name)) return { error: { code: "23505" } };
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
      is(c, v) { q.filters.push(["is", c, v]); return b; },
      gt(c, v) { q.filters.push(["gt", c, v]); return b; },
      lt(c, v) { q.filters.push(["lt", c, v]); return b; },
      or(v) { q.filters.push(["or", v]); return b; },
      order() { return b; }, limit() { return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    return b;
  }
  db.client = { from };
  db.rows = rows;
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
  "requireAuth", "requireActiveSubscription", "rateLimit", "anthropic", "Anthropic", "Date"]);
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
  start: ["post", "/api/mailbox/microsoft/start"], finish: ["post", "/api/mailbox/microsoft/finish"],
  connect: ["post", "/api/mailbox/connect"], status: ["get", "/api/mailbox/status"], disconnect: ["post", "/api/mailbox/disconnect"],
  inbox: ["get", "/api/mailbox/inbox"]
};
const API_ROOT = "\n\nthis.api = { recordMailboxSession: recordMailboxSession, mailboxAccess: mailboxAccess, mailboxRedirectUri: mailboxRedirectUri };";
let LIFTED, ROUTE_TEXT;
try {
  ROUTE_TEXT = Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n");
  const root = ROUTE_TEXT + API_ROOT;
  LIFTED = [...closureParts(root).values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

const ALICE = "aaaaaaaa-0000-4000-8000-000000000001", BOB = "bbbbbbbb-0000-4000-8000-000000000002", CAROL = "cccccccc-0000-4000-8000-000000000003",
  DAVE = "dddddddd-0000-4000-8000-000000000004", ERIN = "eeeeeeee-0000-4000-8000-000000000005", FRAN = "ffffffff-0000-4000-8000-000000000006";
const ADDR = { alice: "alice+bftest@outlook.example.com", work: "wanda+bftest@contoso.example.com", gmail: "alice+bftest@example.com" };
const WORK_TID = "72f988bf-86f1-41af-91ab-2d7cd011db47";
const claimsFor = (over) => Object.assign({ aud: CLIENT_ID, iss: "https://login.microsoftonline.com/" + MS.PERSONAL_TID + "/v2.0", tid: MS.PERSONAL_TID,
  exp: Math.floor(CLOCK.now / 1000) + 3600, iat: Math.floor(CLOCK.now / 1000), preferred_username: "Alice+BFTest@Outlook.Example.com", name: "Alice" }, over || {});

const LOGS = [];
function FakeDate() {
  const a = [].slice.call(arguments);
  return a.length ? new (Function.prototype.bind.apply(Date, [null].concat(a)))() : new Date(CLOCK.now);
}
FakeDate.now = () => CLOCK.now;
FakeDate.parse = Date.parse;
FakeDate.UTC = Date.UTC;
FakeDate.prototype = Date.prototype;
const CRYPTO_REC = {
  encrypt: function (plain) { ORDER.push("encrypt:" + String(plain)); return CRYPTO.encrypt(plain); },
  decrypt: CRYPTO.decrypt
};
function build(seed) {
  const db = fakeDb(Object.assign({ users: [ALICE, BOB, CAROL, DAVE, ERIN, FRAN].map(id => ({ id: id })), member_email_connections: [], oauth_states: [],
    notifications: [], job_runs: [] }, seed || {}));
  const limiters = [];
  const logTo = function () { LOGS.push([].slice.call(arguments).map(a => typeof a === "string" ? a : J(a)).join(" ")); };
  const ctx = {
    supabase: db.client, Date: FakeDate, JSON, Math, Promise, Number, Object, Array, String, Buffer, RegExp, Error, TypeError, Set, Map, URL, URLSearchParams,
    nowIso: () => iso(CLOCK.now),
    process: { env: {} },
    require: p => p === "./lib/memberEmail" ? ME : p === "./lib/microsoftAuth" ? MS : p === "./lib/apiKeyCrypto" ? CRYPTO_REC : require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
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
  return { db, ctx, routes, hit, limiters, api: ctx.api };
}
const connOf = (b, user) => b.db.rows("member_email_connections").find(r => r.user_id === user);
const statesOf = (b, user) => b.db.rows("oauth_states").filter(r => r.user_id === user);
const open = sealed => CRYPTO.decrypt(sealed);
function sealedRow(prefix, plain) { const e = CRYPTO.encrypt(plain); const o = {}; o[prefix + "_ciphertext"] = e.ciphertext; o[prefix + "_iv"] = e.iv; o[prefix + "_auth_tag"] = e.authTag; return o; }
function outlookRow(user, opts) {
  opts = opts || {};
  const hosts = MS.hostsFor(opts.accountType || "personal");
  return Object.assign({ id: opts.id || "11111111-0000-4000-8000-" + user.slice(-12), user_id: user, provider: "outlook", auth_kind: "oauth_microsoft",
    email_address: opts.address || ADDR.alice, username: opts.address || ADDR.alice, imap_host: hosts.imap_host, imap_port: 993, smtp_host: hosts.smtp_host, smtp_port: 587,
    access_expires_at: iso(opts.expiresAt !== undefined ? opts.expiresAt : CLOCK.now + 50 * 60 * 1000), token_version: opts.version || 0, account_type: opts.accountType || "personal",
    status: opts.status || "connected", created_at: iso(CLOCK.now - 86400000), updated_at: iso(CLOCK.now - 86400000), last_ok_at: null, last_error_at: null, last_error_code: null },
    sealedRow("secret", opts.refresh), sealedRow("access", opts.access));
}
function stateParts(url) {
  const u = new URL(url);
  return { base: u.origin + u.pathname, entries: [...u.searchParams.entries()], q: u.searchParams };
}

(async function main() {
  /* ════ A. lib/microsoftAuth.js ════ */
  console.log("\n══ A. lib/microsoftAuth.js: constants, state, verifier, S256, the authorize URL ══");
  check("A1. the endpoints, the scope and the personal tenant are the brief's, exactly",
    MS.AUTHORIZE_URL === "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" && MS.TOKEN_URL === "https://login.microsoftonline.com/common/oauth2/v2.0/token" &&
    MS.SCOPE === "offline_access openid email profile https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send" &&
    MS.PERSONAL_TID === "9188040d-6c67-4c5b-b112-36a304b66dad");
  check("A2. the hosts: IMAP outlook.office365.com:993 for both; SMTP smtp-mail.outlook.com:587 personal, smtp.office365.com:587 work",
    J(MS.hostsFor("personal")) === J({ imap_host: "outlook.office365.com", imap_port: 993, smtp_host: "smtp-mail.outlook.com", smtp_port: 587 }) &&
    J(MS.hostsFor("work")) === J({ imap_host: "outlook.office365.com", imap_port: 993, smtp_host: "smtp.office365.com", smtp_port: 587 }));
  const rnBefore = RANDOM_N;
  const st = MS.newState(), vf = MS.newVerifier();
  const expectState = b64url(crypto.createHash("sha256").update("bftest-random-" + (rnBefore + 1)).digest().subarray(0, 32));
  check("A3. the state and the verifier are 32 random bytes each, base64url, 43 characters",
    st === expectState && /^[A-Za-z0-9_-]{43}$/.test(st) && /^[A-Za-z0-9_-]{43}$/.test(vf) && st !== vf && RANDOM_N === rnBefore + 2);
  check("A4. S256 matches RFC 7636's own vector, and a state is stored as its sha256 hex",
    MS.challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") === "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" &&
    MS.stateHash("abc") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && /^[0-9a-f]{64}$/.test(MS.stateHash(st)));
  const au = stateParts(MS.authorizeUrl(CLIENT_ID, "https://bizforceai.net/mailbox.html", st, MS.challengeFor(vf)));
  check("A5. the authorize URL: the common endpoint and exactly these nine parameters, in order",
    au.base === MS.AUTHORIZE_URL && J(au.entries) === J([["client_id", CLIENT_ID], ["response_type", "code"], ["redirect_uri", "https://bizforceai.net/mailbox.html"],
      ["response_mode", "query"], ["scope", MS.SCOPE], ["state", st], ["code_challenge", MS.challengeFor(vf)], ["code_challenge_method", "S256"], ["prompt", "select_account"]]), J(au.entries));
  check("A6. finish shapes: a code of at most 4096 characters, a state of exactly 43 base64url characters",
    MS.finishShape({ code: "c".repeat(4096), state: st }).ok === true && MS.finishShape({ code: "c".repeat(4097), state: st }).ok === false &&
    MS.finishShape({ code: "", state: st }).ok === false && MS.finishShape({ code: "a b", state: st }).ok === false &&
    MS.finishShape({ code: "c", state: st.slice(1) }).ok === false && MS.finishShape({ code: "c", state: st.slice(1) + "+" }).ok === false && MS.finishShape({ code: "c" }).ok === false);
  check("A7. configured() needs both env vars", (configure(false), MS.configured() === null) && (process.env.MS_CLIENT_ID = CLIENT_ID, MS.configured() === null) &&
    (configure(true), J(MS.configured()) === J({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET })));
  configure(false);

  /* ════ B. the token endpoint ════ */
  console.log("\n══ B. the token endpoint, through guardedJsonRequest's form mode ══");
  const CFG = { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET };
  const code1 = secret("bftest-auth-code-0001-abcdefghijklmnop");
  TOKEN.mode = "ok"; TOKEN.claims = claimsFor(); TOKEN.calls = [];
  const g1 = await MS.exchangeCode(CFG, code1, vf, "https://bizforceai.net/mailbox.html");
  const c1 = TOKEN.calls[0] || { headers: {} };
  const f1 = new URLSearchParams(c1.body || "");
  check("B1. the exchange is one https POST to the token endpoint's host on 443, to the vetted address, under application/x-www-form-urlencoded",
    TOKEN.calls.length === 1 && c1.method === "POST" && c1.host === "login.microsoftonline.com" && c1.port === 443 && c1.protocol === "https:" &&
    c1.path === "/common/oauth2/v2.0/token" && c1.address === "20.190.160.10" && c1.headers["Content-Type"] === "application/x-www-form-urlencoded", J([c1.method, c1.host, c1.headers["Content-Type"]]));
  check("B2. its form body is exactly client_id, client_secret, grant_type, code, redirect_uri, code_verifier and scope",
    J([...f1.keys()]) === J(["client_id", "client_secret", "grant_type", "code", "redirect_uri", "code_verifier", "scope"]) &&
    f1.get("client_id") === CLIENT_ID && f1.get("client_secret") === CLIENT_SECRET && f1.get("grant_type") === "authorization_code" && f1.get("code") === code1 &&
    f1.get("redirect_uri") === "https://bizforceai.net/mailbox.html" && f1.get("code_verifier") === vf && f1.get("scope") === MS.SCOPE, J([...f1.keys()]));
  check("B3. the grant gives the access token, the refresh token, expires_in and the ID token, nothing else",
    J(Object.keys(g1).sort()) === J(["accessToken", "expiresIn", "idToken", "refreshToken"]) && g1.accessToken === TOKEN.lastIssued.access && g1.refreshToken === TOKEN.lastIssued.refresh && g1.expiresIn === 3600);
  const rt1 = secret("bftest-refresh-in-0001");
  TOKEN.calls = [];
  await MS.refreshTokens(CFG, rt1, "https://bizforceai.net/mailbox.html");
  const f2 = new URLSearchParams((TOKEN.calls[0] || {}).body || "");
  check("B4. a refresh is a form POST of client_id, client_secret, grant_type refresh_token, the refresh token, redirect_uri and scope",
    J([...f2.keys()]) === J(["client_id", "client_secret", "grant_type", "refresh_token", "redirect_uri", "scope"]) && f2.get("grant_type") === "refresh_token" &&
    f2.get("refresh_token") === rt1 && f2.get("scope") === MS.SCOPE && (TOKEN.calls[0] || { headers: {} }).headers["Content-Type"] === "application/x-www-form-urlencoded");
  const refusal = async (mode) => { TOKEN.mode = mode; try { await MS.exchangeCode(CFG, code1, vf, "https://bizforceai.net/mailbox.html"); return "accepted"; } catch (e) { return e.kind + "/" + e.code; } finally { TOKEN.mode = "ok"; } };
  const noRefresh = await refusal("no_refresh"), noSmtp = await refusal("no_smtp"), badGrant = await refusal("invalid_grant"), five = await refusal("500");
  check("B5. no refresh token, or a scope without SMTP.Send, is no_mail_access; the message is the brief's",
    noRefresh === "no_mail_access/no_refresh_token" && noSmtp === "no_mail_access/scope_missing" &&
    MS.MESSAGES.noMailAccess === "Microsoft didn't grant mail access. Sign in again and approve both permissions.", J([noRefresh, noSmtp]));
  check("B6. invalid_grant is its own kind; any other non-2xx is unreachable", badGrant === "invalid_grant/invalid_grant" && five === "unreachable/token_status_500", J([badGrant, five]));
  check("B7. the granted scope must hold both mail permissions", MS.grantsMail(MS.IMAP_SCOPE + " " + MS.SMTP_SCOPE) && MS.grantsMail("imap.accessasuser.all smtp.send") &&
    !MS.grantsMail(MS.IMAP_SCOPE) && !MS.grantsMail(MS.SMTP_SCOPE + " openid") && !MS.grantsMail(undefined));
  const errText = [noRefresh, noSmtp, badGrant, five].join(" ");
  check("B8. a token-endpoint error carries a kind and a code only: no token, code, verifier or secret", !holdsSecret(errText) && errText.indexOf(vf) === -1);

  /* ════ C. the ID token ════ */
  console.log("\n══ C. the ID token: aud, exp, tid, the address, the account type ══");
  const read = (claims) => { try { return MS.readIdToken(idTokenFor(claims), CLIENT_ID, CLOCK.now); } catch (e) { return { error: e.kind + "/" + e.code }; } };
  check("C1. a personal account: the address is preferred_username, lowercased; account_type personal",
    J(read(claimsFor())) === J({ email: "alice+bftest@outlook.example.com", accountType: "personal" }), J(read(claimsFor())));
  check("C2. any other tid is work; email is used when preferred_username is missing",
    J(read(claimsFor({ tid: WORK_TID, preferred_username: undefined, email: "Wanda+BFTest@Contoso.Example.com" }))) === J({ email: ADDR.work, accountType: "work" }));
  check("C3. aud must be this client id", read(claimsFor({ aud: "someone-else" })).error === "id_token/aud");
  check("C4. exp must be in the future (an expired one, and one ending now, are refused)",
    read(claimsFor({ exp: Math.floor(CLOCK.now / 1000) - 1 })).error === "id_token/exp" && read(claimsFor({ exp: Math.floor(CLOCK.now / 1000) })).error === "id_token/exp" &&
    read(claimsFor({ exp: "9999999999" })).error === "id_token/exp");
  check("C5. tid must be present", read(claimsFor({ tid: undefined })).error === "id_token/tid" && read(claimsFor({ tid: "" })).error === "id_token/tid");
  check("C6. the address must match 169's pattern", read(claimsFor({ preferred_username: "not an address" })).error === "id_token/email" &&
    read(claimsFor({ preferred_username: undefined, email: undefined })).error === "id_token/email");
  check("C7. a malformed token is refused", (() => { try { MS.readIdToken("a.b", CLIENT_ID, CLOCK.now); return false; } catch (e) { return e.kind === "id_token"; } })() &&
    (() => { try { MS.readIdToken(null, CLIENT_ID, CLOCK.now); return false; } catch (e) { return e.kind === "id_token"; } })());
  check("C8. the source says the signature is not checked, and why", /signature is NOT checked here/.test(SOURCES.MS) && /straight from the token endpoint/.test(SOURCES.MS));

  /* ════ D. lib/memberEmail.js ════ */
  console.log("\n══ D. lib/memberEmail.js: the OAuth options, getAccessToken, the one-retry rule ══");
  const msSettings = { provider: "outlook", email_address: ADDR.alice, username: ADDR.alice, imap_host: "outlook.office365.com", imap_port: 993, smtp_host: "smtp-mail.outlook.com", smtp_port: 587 };
  const tokX = secret("bftest-access-literal-0001");
  const io = ME.imapOptions(msSettings, "52.96.0.10", { kind: "oauth", accessToken: tokX });
  const so = ME.smtpOptions(msSettings, "52.96.0.20", { kind: "oauth", accessToken: tokX });
  check("D1. ImapFlow gets { user, accessToken } and no password, on the vetted address with the real name for TLS",
    J(io.auth) === J({ user: ADDR.alice, accessToken: tokX }) && io.host === "52.96.0.10" && io.servername === "outlook.office365.com" && io.tls.rejectUnauthorized === true && io.secure === true, J(Object.keys(io.auth)));
  check("D2. nodemailer gets { type: OAuth2, user, accessToken } and NO refreshToken, clientId, clientSecret, accessUrl, serviceClient, privateKey, expires or provisionCallback",
    J(so.auth) === J({ type: "OAuth2", user: ADDR.alice, accessToken: tokX }) && so.requireTLS === true && so.secure === false && so.port === 587 && so.servername === "smtp-mail.outlook.com", J(Object.keys(so.auth)));
  const realNodemailer = require("nodemailer").createTransport(so);
  check("D3. the real nodemailer, given those options, holds no way to fetch a token (no provisionCallback, no refresh token, no token URL)",
    !!realNodemailer && J(Object.keys(so.auth).filter(k => ["refreshToken", "clientId", "clientSecret", "accessUrl", "serviceClient", "privateKey", "expires", "provisionCallback"].indexOf(k) !== -1)) === "[]");
  try { realNodemailer.close(); } catch (e) { /* not open */ }
  const pwSettings = { provider: "gmail", email_address: ADDR.gmail, username: ADDR.gmail, imap_host: "imap.gmail.com", imap_port: 993, smtp_host: "smtp.gmail.com", smtp_port: 465 };
  const pw = secret("bftest app pass word");
  check("D4. the app-password path is unchanged: { user, pass } for both libraries",
    J(ME.imapOptions(pwSettings, "142.250.1.10", pw).auth) === J({ user: ADDR.gmail, pass: pw }) && J(ME.smtpOptions(pwSettings, "142.250.1.20", pw).auth) === J({ user: ADDR.gmail, pass: pw }));
  check("D5. anything else is refused before a library sees it", (() => { try { ME.imapOptions(msSettings, "52.96.0.10", { kind: "oauth" }); return false; } catch (e) { return e.kind === "unreachable"; } })());

  // getAccessToken with an in-memory access object
  function access(opts) {
    opts = opts || {};
    const a = { refreshCalls: 0, casCalls: 0, rereads: 0, updates: [], decrypt: CRYPTO.decrypt, encrypt: CRYPTO.encrypt,
      refresh: async function (rt) {
        a.refreshCalls++; a.lastRefreshToken = rt;
        await tick();
        if (opts.refreshError) throw opts.refreshError;
        const t = mint(); a.issued = t;
        if (opts.accept !== false) { MAIL.imapAccepted.add(t.access); MAIL.smtpAccepted.add(t.access); }
        return { accessToken: t.access, refreshToken: t.refresh, expiresIn: 3600, idToken: null };
      },
      cas: async function (row, update) { a.casCalls++; a.updates.push({ version: row.token_version, update: update }); return opts.lose ? false : true; },
      reread: async function () { a.rereads++; return opts.winner || null; } };
    return a;
  }
  const accFresh = secret("bftest-access-fresh-0001"), refA = secret("bftest-refresh-a-0001");
  MAIL.imapAccepted.add(accFresh); MAIL.smtpAccepted.add(accFresh);
  let acc = access();
  let got = await ME.getAccessToken(outlookRow(ALICE, { access: accFresh, refresh: refA }), acc);
  check("D6. a token more than 5 minutes from expiry is used as stored: no refresh", got.auth.accessToken === accFresh && got.refreshedNow === false && acc.refreshCalls === 0 && ME.REFRESH_MARGIN_MS === 5 * 60 * 1000);
  acc = access();
  const nearRow = outlookRow(BOB, { access: secret("bftest-access-near-0001"), refresh: refA, expiresAt: CLOCK.now + 4 * 60 * 1000, version: 3 });
  got = await ME.getAccessToken(nearRow, acc);
  const up = (acc.updates[0] || {}).update || {};
  check("D7. within 5 minutes: one refresh with the stored refresh token, written by one CAS from version 3 to 4",
    acc.refreshCalls === 1 && acc.lastRefreshToken === refA && acc.casCalls === 1 && acc.updates[0].version === 3 && up.token_version === 4 && got.refreshedNow === true && got.auth.accessToken === acc.issued.access);
  check("D8. both new tokens are sealed in the update, and access_expires_at is now + expires_in - 60 s",
    open({ ciphertext: up.access_ciphertext, iv: up.access_iv, authTag: up.access_auth_tag }) === acc.issued.access &&
    open({ ciphertext: up.secret_ciphertext, iv: up.secret_iv, authTag: up.secret_auth_tag }) === acc.issued.refresh &&
    up.access_expires_at === iso(CLOCK.now + 3600 * 1000 - 60 * 1000) && !holdsSecret(J([up.access_ciphertext, up.secret_ciphertext])), up.access_expires_at);
  const winnerAccess = secret("bftest-access-winner-0001");
  MAIL.imapAccepted.add(winnerAccess);
  acc = access({ lose: true, winner: outlookRow(CAROL, { access: winnerAccess, refresh: secret("bftest-refresh-winner-0001"), version: 1 }) });
  got = await ME.getAccessToken(outlookRow(CAROL, { access: secret("bftest-access-old-0001"), refresh: refA, expiresAt: CLOCK.now - 1000 }), acc);
  check("D9. the loser of the race writes nothing more, reads the row again and uses the winner's token",
    acc.casCalls === 1 && acc.rereads === 1 && got.auth.accessToken === winnerAccess && got.refreshedNow === true, J([acc.casCalls, acc.rereads]));
  acc = access();
  const sfRow = outlookRow(DAVE, { access: secret("bftest-access-sf-0001"), refresh: refA, expiresAt: CLOCK.now });
  const both = await Promise.all([ME.getAccessToken(sfRow, acc), ME.getAccessToken(sfRow, acc)]);
  check("D10. two requests for one member at once share one refresh (single-flight)", acc.refreshCalls === 1 && both[0].auth.accessToken === both[1].auth.accessToken);
  acc = access();
  got = await ME.getAccessToken(outlookRow(ERIN, { access: accFresh, refresh: refA }), acc, { force: true });
  check("D11. force refreshes even a fresh token", acc.refreshCalls === 1 && got.refreshedNow === true);
  let ig;
  try { await ME.getAccessToken(outlookRow(ERIN, { access: accFresh, refresh: refA, expiresAt: CLOCK.now }), access({ refreshError: new MS.MicrosoftError("invalid_grant", "invalid_grant") })); }
  catch (e) { ig = e.kind + "/" + e.code; }
  check("D12. invalid_grant from the refresh is rejected/invalid_grant (what marks needs_reconnect)", ig === "rejected/invalid_grant", ig);

  // the one-retry rule through withImap
  const list = c => ME.listInbox(c, null);
  const staleTok = secret("bftest-access-stale-0001");   // refused by the server, not near expiry
  resetMail();
  acc = access();
  let out = await ME.withImap(outlookRow(FRAN, { access: staleTok, refresh: refA }), acc, list);
  check("D13. a refused token that was not refreshed: one forced refresh, one retry, and the read succeeds",
    out.ok === true && acc.refreshCalls === 1 && MAIL.clients.length === 2 && MAIL.clients[1].options.auth.accessToken === acc.issued.access, J([out.ok, out.reason, acc.refreshCalls, MAIL.clients.length]));
  resetMail();
  acc = access({ accept: false });
  out = await ME.withImap(outlookRow(FRAN, { access: staleTok, refresh: refA }), acc, list);
  check("D14. refused again after the forced refresh: session_failed, with exactly one refresh and two sessions (no second retry)",
    out.ok === false && out.reason === "session_failed" && acc.refreshCalls === 1 && MAIL.clients.length === 2, J([out.reason, acc.refreshCalls, MAIL.clients.length]));
  resetMail();
  acc = access({ accept: false });
  out = await ME.withImap(outlookRow(FRAN, { access: staleTok, refresh: refA, expiresAt: CLOCK.now + 60000 }), acc, list);
  check("D15. a token refreshed in this request and refused: session_failed at once, no forced refresh", out.reason === "session_failed" && acc.refreshCalls === 1 && MAIL.clients.length === 1,
    J([out.reason, acc.refreshCalls, MAIL.clients.length]));
  resetMail();
  out = await ME.withImap(outlookRow(FRAN, { access: staleTok, refresh: refA, expiresAt: CLOCK.now }), access({ refreshError: new MS.MicrosoftError("invalid_grant", "invalid_grant") }), list);
  check("D16. invalid_grant: session_failed, and no mail server is asked", out.reason === "session_failed" && out.code === "invalid_grant" && MAIL.clients.length === 0, J(out));
  resetMail();
  out = await ME.withImap(outlookRow(FRAN, { access: staleTok, refresh: refA, expiresAt: CLOCK.now }), access({ refreshError: new MS.MicrosoftError("unreachable", "token_status_500") }), list);
  check("D17. the token endpoint down: call_failed, not session_failed (nothing marks needs_reconnect)", out.reason === "call_failed" && MAIL.clients.length === 0, J(out));
  resetMail();
  MAIL.passwords["imap.gmail.com " + ADDR.gmail] = pw;
  const pwRow = Object.assign({ id: "22222222-0000-4000-8000-000000000001", user_id: ALICE, provider: "gmail", auth_kind: "app_password", email_address: ADDR.gmail, username: ADDR.gmail,
    imap_host: "imap.gmail.com", imap_port: 993, smtp_host: "smtp.gmail.com", smtp_port: 465, status: "connected" }, sealedRow("secret", pw));
  out = await ME.withImap(pwRow, CRYPTO.decrypt, list);
  const outBad = await ME.withImap(Object.assign({}, pwRow, sealedRow("secret", secret("bftest wrong pass"))), CRYPTO.decrypt, list);
  check("D18. the app-password path is unchanged: decrypt alone works, a refused password is session_failed with no retry",
    out.ok === true && outBad.reason === "session_failed" && MAIL.clients.length === 2 && J(MAIL.clients[0].options.auth) === J({ user: ADDR.gmail, pass: pw }), J([out.ok, outBad.reason, MAIL.clients.length]));

  // the one-retry rule through sendReply
  const msg = { from: ADDR.alice, to: "pat+bftest@example.com", subject: "Re: hi", text: "Thanks", inReplyTo: "<a@example.com>", references: "<a@example.com>", messageId: "<bftest-1@outlook.example.com>" };
  resetMail();
  acc = access();
  let sent = await ME.sendReply(outlookRow(FRAN, { access: staleTok, refresh: refA }), { smtp_host: "smtp-mail.outlook.com", smtp_port: 587, username: ADDR.alice }, acc, msg);
  check("D19. a reply with a refused, not-refreshed token: one forced refresh and one more try, the same Message-ID, sent once",
    sent.ok === true && acc.refreshCalls === 1 && MAIL.transports.length === 2 && J(MAIL.sent) === J([msg.messageId]) && J(MAIL.transports[1].options.auth) === J({ type: "OAuth2", user: ADDR.alice, accessToken: acc.issued.access }), J([sent, acc.refreshCalls]));
  resetMail();
  acc = access({ accept: false });
  sent = await ME.sendReply(outlookRow(FRAN, { access: staleTok, refresh: refA }), { smtp_host: "smtp-mail.outlook.com", smtp_port: 587, username: ADDR.alice }, acc, msg);
  check("D20. refused after the forced refresh: rejected, two tries, nothing sent", sent.ok === false && sent.kind === "rejected" && MAIL.transports.length === 2 && MAIL.sent.length === 0 && acc.refreshCalls === 1);
  resetMail();
  MAIL.passwords["smtp.gmail.com " + ADDR.gmail] = pw;
  sent = await ME.sendReply(pwRow, { smtp_host: "smtp.gmail.com", smtp_port: 465, username: ADDR.gmail }, secret("bftest wrong pass"), Object.assign({}, msg, { from: ADDR.gmail }));
  check("D21. an app-password reply is still tried once, no retry", sent.ok === false && sent.kind === "rejected" && MAIL.transports.length === 1);
  check("D22. OUTLOOK_LINE is gone; outlook is a provider with no password, and not an app-password provider",
    ME.OUTLOOK_LINE === undefined && ME.PROVIDERS.outlook && ME.PROVIDERS.outlook.sign_in === "microsoft" && ME.PROVIDER_IDS.indexOf("outlook") === -1 &&
    ME.settingsFrom({ provider: "outlook", email_address: ADDR.alice }).error === ME.MESSAGES.outlookSignIn);
  check("D23. the Outlook reconnect wording is the brief's", ME.reconnectText({ auth_kind: "oauth_microsoft", email_address: ADDR.alice }) ===
    "Microsoft stopped accepting BizForce's access to " + ADDR.alice + ", so BizForce can't read it. Sign in with Microsoft again." &&
    ME.reconnectText({ auth_kind: "app_password", email_address: ADDR.gmail }) === "Your mailbox stopped accepting the app password saved for " + ADDR.gmail + ", so BizForce can't read it. Make a new app password and connect again.");

  /* ════ E. the routes ════ */
  console.log("\n══ E. the routes ══");
  configure(false);
  let b = build();
  let r = await b.hit("start", ALICE);
  let rf = await b.hit("finish", ALICE, { body: { code: "x", state: st } });
  let rs = await b.hit("status", ALICE);
  check("E1. not configured: start and finish answer 503 \"Outlook sign-in isn't set up yet.\"; status says outlook_available false; nothing stored, nothing asked",
    r.code === 503 && r.body.error === "Outlook sign-in isn't set up yet." && rf.code === 503 && rf.body.error === "Outlook sign-in isn't set up yet." &&
    rs.code === 200 && rs.body.outlook_available === false && b.db.rows("oauth_states").length === 0, J([r.code, rf.code, rs.body]));
  const mw = k => b.routes[R[k][0] + " " + R[k][1]].middleware;
  const msLimiter = (mw("start")[2] || {}).__opts || {};
  check("E2. start and finish: requireAuth, requireActiveSubscription, then one limiter keyed mailbox-ms:<id>, 10 an hour",
    ["start", "finish"].every(k => mw(k).length === 3 && mw(k)[0].name === "requireAuth" && mw(k)[1].name === "requireActiveSubscription" && mw(k)[2] === mw("start")[2]) &&
    msLimiter.max === 10 && msLimiter.windowMs === 3600000 && msLimiter.keyGenerator({ user: { id: ALICE } }) === "mailbox-ms:" + ALICE);
  configure(true);
  rs = await b.hit("status", ALICE);
  check("E3. configured: status says outlook_available true", rs.body.outlook_available === true);

  // start
  b = build({ oauth_states: [
    { id: "s-old-a", user_id: ALICE, purpose: "mailbox_microsoft", state_hash: "a".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
      created_at: iso(CLOCK.now - 2 * 86400000), expires_at: iso(CLOCK.now - 2 * 86400000 + 600000), consumed_at: null },
    { id: "s-new-a", user_id: ALICE, purpose: "mailbox_microsoft", state_hash: "b".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
      created_at: iso(CLOCK.now - 3600000), expires_at: iso(CLOCK.now - 3000000), consumed_at: iso(CLOCK.now - 3500000) },
    { id: "s-old-b", user_id: BOB, purpose: "mailbox_microsoft", state_hash: "c".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
      created_at: iso(CLOCK.now - 2 * 86400000), expires_at: iso(CLOCK.now - 2 * 86400000 + 600000), consumed_at: null }] });
  ORDER.length = 0;
  r = await b.hit("start", ALICE);
  const url = r.body && r.body.authorize_url;
  const sp = url ? stateParts(url) : { q: new URLSearchParams() };
  const stA = sp.q.get("state") || "";
  const rowA = statesOf(b, ALICE).find(x => x.id !== "s-new-a") || {};
  let verA = null;
  try { verA = open({ ciphertext: rowA.verifier_ciphertext, iv: rowA.verifier_iv, authTag: rowA.verifier_auth_tag }); } catch (e) { verA = null; }
  if (verA) secret(verA);
  check("E4. start answers { authorize_url } only: Microsoft's URL with this client, the redirect to /mailbox.html and S256",
    r.code === 200 && J(Object.keys(r.body)) === J(["authorize_url"]) && sp.base === MS.AUTHORIZE_URL && sp.q.get("client_id") === CLIENT_ID &&
    sp.q.get("redirect_uri") === "https://bizforceai.net/mailbox.html" && sp.q.get("code_challenge_method") === "S256" && r.headers["cache-control"] === "no-store", J([r.code, r.body && Object.keys(r.body)]));
  check("E5. the state row holds the state's sha256, never the state itself",
    rowA.state_hash === MS.stateHash(stA) && /^[A-Za-z0-9_-]{43}$/.test(stA) && J(b.db.rows("oauth_states")).indexOf(stA) === -1, rowA.state_hash);
  check("E6. the verifier is sealed: it decrypts to the verifier whose S256 is the URL's challenge, and its readable forms are stored nowhere",
    !!verA && MS.challengeFor(verA) === sp.q.get("code_challenge") && [verA, Buffer.from(verA || "").toString("hex"), Buffer.from(verA || "").toString("base64")].every(f => J(b.db.rows("oauth_states")).indexOf(f) === -1));
  check("E7. it lives 10 minutes, for this member, purpose mailbox_microsoft", rowA.expires_at === iso(CLOCK.now + 10 * 60 * 1000) && rowA.created_at === iso(CLOCK.now) &&
    rowA.user_id === ALICE && rowA.purpose === "mailbox_microsoft" && rowA.consumed_at === null);
  check("E8. start tidies this member's rows older than a day, and no one else's", J(b.db.rows("oauth_states").map(x => x.id).filter(x => /^s-/.test(x)).sort()) === J(["s-new-a", "s-old-b"]));

  // finish: the state
  const codeA = secret("bftest-auth-code-alice-0002");
  const finish = (user, code, state) => b.hit("finish", user, { body: { code: code, state: state } });
  const sameRefusal = x => x.code === 400 && J(x.body) === J({ error: "That sign-in link has expired or was already used. Start again.", code: "state_invalid", saved: false });
  TOKEN.calls = [];
  const otherMember = await finish(BOB, codeA, stA);
  const unknown = await finish(ALICE, codeA, MS.newState());
  check("E9. another member's state, or one never issued: the same 400, word for word, and the code is never sent anywhere",
    sameRefusal(otherMember) && sameRefusal(unknown) && TOKEN.calls.length === 0 && rowA.consumed_at === null, J([otherMember.body, unknown.body]));
  const bad = await b.hit("finish", ALICE, { body: { code: codeA, state: "short" } });
  check("E10. a malformed state or code is 400 before anything is read", bad.code === 400 && bad.body.code === "bad_request");
  // a second start for the expiry case
  r = await b.hit("start", ALICE);
  const stExp = stateParts(r.body.authorize_url).q.get("state");
  CLOCK.now += 10 * 60 * 1000 + 1;
  const expired = await finish(ALICE, codeA, stExp);
  CLOCK.now -= 10 * 60 * 1000 + 1;
  check("E11. a state past its 10 minutes: the same 400, and nothing sent to Microsoft", sameRefusal(expired) && TOKEN.calls.length === 0, J(expired.body));

  // finish: success, personal
  TOKEN.mode = "ok"; TOKEN.claims = claimsFor(); TOKEN.calls = [];
  // every token the fake endpoint issues is accepted by the fake mail servers unless a test says otherwise
  TOKEN.autoAccept = true;
  ORDER.length = 0; resetMail();
  const ok = await finish(ALICE, codeA, stA);
  const conn = connOf(b, ALICE) || {};
  const issued = TOKEN.lastIssued || { access: "?", refresh: "?" };
  const fx = new URLSearchParams((TOKEN.calls[0] || {}).body || "");
  check("E12. finish exchanges the code once, with this state's verifier and the /mailbox.html redirect",
    TOKEN.calls.length === 1 && fx.get("code") === codeA && fx.get("code_verifier") === verA && fx.get("redirect_uri") === "https://bizforceai.net/mailbox.html", J([TOKEN.calls.length, ok.code]));
  check("E13. it answers the status of an Outlook personal mailbox, outlook_available true, and nothing else",
    ok.code === 200 && J(Object.keys(ok.body).sort()) === J(["account_type", "connected", "email_address", "outlook_available", "provider", "since", "status"]) &&
    ok.body.provider === "outlook" && ok.body.account_type === "personal" && ok.body.email_address === ADDR.alice && ok.body.connected === true, J(ok.body));
  check("E14. the row: provider outlook, auth_kind oauth_microsoft, the address as username, the personal hosts, token_version 0, connected, errors cleared",
    conn.provider === "outlook" && conn.auth_kind === "oauth_microsoft" && conn.email_address === ADDR.alice && conn.username === ADDR.alice &&
    conn.imap_host === "outlook.office365.com" && conn.imap_port === 993 && conn.smtp_host === "smtp-mail.outlook.com" && conn.smtp_port === 587 &&
    conn.token_version === 0 && conn.account_type === "personal" && conn.status === "connected" && conn.last_error_code === null && violates("member_email_connections", conn) === null, J(conn).slice(0, 200));
  check("E15. the refresh token is sealed in secret_*, the access token in access_*, expiring now + expires_in - 60 s",
    open({ ciphertext: conn.secret_ciphertext, iv: conn.secret_iv, authTag: conn.secret_auth_tag }) === issued.refresh &&
    open({ ciphertext: conn.access_ciphertext, iv: conn.access_iv, authTag: conn.access_auth_tag }) === issued.access &&
    conn.access_expires_at === iso(CLOCK.now + 3540 * 1000) && !holdsSecret(J(b.db.tables)), conn.access_expires_at);
  const firstMail = ORDER.findIndex(x => x === "imap" || x === "smtp");
  const sealAt = [ORDER.indexOf("encrypt:" + issued.refresh), ORDER.indexOf("encrypt:" + issued.access)];
  check("E16. both tokens are sealed before any IMAP or SMTP call", firstMail > 0 && sealAt.every(i => i !== -1 && i < firstMail) && ORDER.slice(firstMail).indexOf("imap") !== -1,
    J(ORDER.map(x => x.indexOf("encrypt:") === 0 ? "encrypt" : x)));
  check("E17. verifyConnection ran with the access token, pinned: ImapFlow { user, accessToken }, nodemailer OAuth2 with the access token only",
    MAIL.clients.length === 1 && J(MAIL.clients[0].options.auth) === J({ user: ADDR.alice, accessToken: issued.access }) && MAIL.clients[0].options.host === "52.96.0.10" &&
    MAIL.transports.length === 1 && J(MAIL.transports[0].options.auth) === J({ type: "OAuth2", user: ADDR.alice, accessToken: issued.access }) && MAIL.transports[0].options.host === "52.96.0.20");
  const reused = await finish(ALICE, codeA, stA);
  check("E18. the same state again: the same 400, nothing sent", sameRefusal(reused) && TOKEN.calls.length === 1, J(reused.body));

  // finish: refusals
  async function finishWith(mode, claims, opts) {
    opts = opts || {};
    const bb = build(opts.seed);
    const st0 = stateParts((await bb.hit("start", opts.user || BOB)).body.authorize_url).q.get("state");
    TOKEN.mode = mode; TOKEN.claims = claims; TOKEN.calls = [];
    TOKEN.autoAccept = opts.accept !== false;
    resetMail();
    try { return { res: await bb.hit("finish", opts.user || BOB, { body: { code: secret("bftest-code-" + mode + "-" + (++TOKEN.n)), state: st0 } }), b: bb }; }
    finally { TOKEN.mode = "ok"; TOKEN.autoAccept = true; }
  }
  let x = await finishWith("no_refresh", claimsFor());
  check("E19. no refresh token: 422 with the brief's message, nothing stored", x.res.code === 422 && x.res.body.error === MS.MESSAGES.noMailAccess && !connOf(x.b, BOB) && MAIL.clients.length === 0);
  x = await finishWith("no_smtp", claimsFor());
  check("E20. a grant without SMTP.Send: the same 422", x.res.code === 422 && x.res.body.code === "no_mail_access" && !connOf(x.b, BOB));
  x = await finishWith("invalid_grant", claimsFor());
  check("E21. a code Microsoft refuses (invalid_grant): the spent-link 400", sameRefusal(x.res) && !connOf(x.b, BOB), J(x.res.body));
  x = await finishWith("500", claimsFor());
  check("E22. the token endpoint failing: 502, nothing stored", x.res.code === 502 && !connOf(x.b, BOB));
  x = await finishWith("ok", claimsFor({ aud: "another-app" }));
  check("E23. an ID token for another app: 502, nothing stored, no mail server asked", x.res.code === 502 && !connOf(x.b, BOB) && MAIL.clients.length === 0);
  x = await finishWith("ok", claimsFor({ tid: WORK_TID, preferred_username: "Wanda+BFTest@Contoso.Example.com" }));
  const wconn = connOf(x.b, BOB) || {};
  check("E24. a work account: account_type work and the work SMTP host", x.res.code === 200 && wconn.account_type === "work" && wconn.smtp_host === "smtp.office365.com" && wconn.email_address === ADDR.work, J(x.res.body));
  x = await finishWith("ok", claimsFor({ tid: WORK_TID, preferred_username: ADDR.work }), { accept: false });
  check("E25. a work account refused right after a fresh grant: 422 with the administrator message, nothing stored",
    x.res.code === 422 && x.res.body.error === "Your organisation's settings don't let outside apps read or send mail for this mailbox. Ask your administrator to allow IMAP and SMTP sign-in for it." && !connOf(x.b, BOB), J(x.res.body));
  x = await finishWith("ok", claimsFor(), { accept: false });
  check("E26. a personal account refused: 422 with the personal wording, nothing stored", x.res.code === 422 && x.res.body.error === MS.MESSAGES.personalRefused && !connOf(x.b, BOB));

  // status, an app password replacing an outlook row, disconnect
  rs = await b.hit("status", ALICE);
  check("E27. status for an outlook row adds account_type; no token, host or sign-in name",
    rs.body.account_type === "personal" && rs.body.outlook_available === true && !/imap|smtp|username|secret|access_/.test(J(rs.body)) && !holdsSecret(J(rs.body)), J(rs.body));
  MAIL.passwords["imap.gmail.com " + ADDR.gmail] = pw; MAIL.passwords["smtp.gmail.com " + ADDR.gmail] = pw;
  const bSwitch = build({ member_email_connections: [outlookRow(CAROL, { access: accFresh, refresh: refA })] });
  const sw = await bSwitch.hit("connect", CAROL, { body: { provider: "gmail", email_address: ADDR.gmail, app_password: pw } });
  const swRow = connOf(bSwitch, CAROL) || {};
  check("E28. connecting an app password over an outlook row clears every Microsoft column (the kind_shape CHECK holds)",
    sw.code === 200 && swRow.auth_kind === "app_password" && swRow.provider === "gmail" && swRow.access_ciphertext === null && swRow.access_expires_at === null &&
    swRow.account_type === null && swRow.token_version === 0 && violates("member_email_connections", swRow) === null, J([sw.code, sw.body]));
  const bOut = await bSwitch.hit("connect", CAROL, { body: { provider: "outlook", email_address: ADDR.alice, app_password: pw } });
  check("E29. an app-password connect for outlook is refused, pointing to Sign in with Microsoft", bOut.code === 400 && bOut.body.error === ME.MESSAGES.outlookSignIn);
  b.db.rows("oauth_states").push({ id: "s-bob", user_id: BOB, purpose: "mailbox_microsoft", state_hash: "d".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
    created_at: iso(CLOCK.now), expires_at: iso(CLOCK.now + 600000), consumed_at: null });
  TOKEN.calls = [];
  const dc = await b.hit("disconnect", ALICE);
  check("E30. disconnect deletes the row and this member's sign-in states, keeps others', calls no one, and gives the Microsoft note",
    dc.code === 200 && !connOf(b, ALICE) && statesOf(b, ALICE).length === 0 && statesOf(b, BOB).some(x => x.id === "s-bob") && TOKEN.calls.length === 0 &&
    dc.body.note === "Disconnected. To remove BizForce from your Microsoft account too, open your Microsoft account's app permissions and remove BizForce.", J(dc.body));
  const dc2 = await bSwitch.hit("disconnect", CAROL);
  check("E31. an app-password disconnect keeps its own note", dc2.body.note === "Disconnected. To cancel the app password itself, remove it in your email provider's security settings.");

  // a read with an outlook row, through the server's mailboxAccess
  async function readWith(rowOpts, mode, acceptNew) {
    const bb = build({ member_email_connections: [outlookRow(DAVE, rowOpts)] });
    TOKEN.mode = mode; TOKEN.claims = null; TOKEN.calls = [];
    TOKEN.autoAccept = acceptNew !== false;
    resetMail();
    try { return { res: await bb.hit("inbox", DAVE), b: bb, row: connOf(bb, DAVE) }; }
    finally { TOKEN.mode = "ok"; TOKEN.autoAccept = true; }
  }
  let rd = await readWith({ access: accFresh, refresh: refA }, "ok");
  check("E32. a fresh token reads with no call to the token endpoint", rd.res.code === 200 && TOKEN.calls.length === 0 && rd.row.token_version === 0);
  rd = await readWith({ access: secret("bftest-access-near-0002"), refresh: refA, expiresAt: CLOCK.now + 60000 }, "ok");
  check("E33. a token near expiry is refreshed through the token endpoint and written by the CAS (token_version 0 -> 1, both sealed)",
    rd.res.code === 200 && TOKEN.calls.length === 1 && rd.row.token_version === 1 &&
    open({ ciphertext: rd.row.access_ciphertext, iv: rd.row.access_iv, authTag: rd.row.access_auth_tag }) === TOKEN.lastIssued.access &&
    open({ ciphertext: rd.row.secret_ciphertext, iv: rd.row.secret_iv, authTag: rd.row.secret_auth_tag }) === TOKEN.lastIssued.refresh, J([rd.res.code, TOKEN.calls.length, rd.row.token_version]));
  rd = await readWith({ access: staleTok, refresh: refA }, "ok");
  check("E34. a refused stale token: one refresh, the read succeeds, the mailbox stays connected, no notice",
    rd.res.code === 200 && TOKEN.calls.length === 1 && rd.row.status === "connected" && rd.b.db.rows("notifications").length === 0, J([rd.res.code, rd.row.status]));
  rd = await readWith({ access: staleTok, refresh: refA, expiresAt: CLOCK.now }, "invalid_grant");
  const notes = rd.b.db.rows("notifications");
  check("E35. invalid_grant: 422 needs_reconnect, the row marked, one notice with the Microsoft wording",
    rd.res.code === 422 && rd.res.body.code === "needs_reconnect" && rd.res.body.error === ME.reconnectText({ auth_kind: "oauth_microsoft", email_address: ADDR.alice }) &&
    rd.row.status === "needs_reconnect" && notes.length === 1 && notes[0].type === "email_reconnect" && notes[0].message === rd.res.body.error, J([rd.res.code, rd.row.status, notes.length]));
  rd = await readWith({ access: staleTok, refresh: refA, expiresAt: CLOCK.now }, "500");
  check("E36. the token endpoint down: 502, still connected, no notice", rd.res.code === 502 && rd.row.status === "connected" && rd.b.db.rows("notifications").length === 0);
  rd = await readWith({ access: staleTok, refresh: refA, expiresAt: CLOCK.now }, "ok", false);
  check("E37. a fresh token refused: needs_reconnect (decision 7)", rd.res.code === 422 && rd.row.status === "needs_reconnect" && TOKEN.calls.length === 1);

  // the CAS itself
  const bc = build({ member_email_connections: [outlookRow(ERIN, { access: accFresh, refresh: refA, version: 0 })] });
  const readRow = clone(connOf(bc, ERIN));
  connOf(bc, ERIN).token_version = 1;   // another request won
  const won = await bc.api.mailboxAccess().cas(readRow, Object.assign({ token_version: 1 }, sealedRow("access", secret("bftest-access-late-0001"))));
  check("E38. the CAS: an update from a stale token_version writes nothing and says false",
    won === false && connOf(bc, ERIN).access_ciphertext === readRow.access_ciphertext, J(won));
  const won2 = await bc.api.mailboxAccess().cas(clone(connOf(bc, ERIN)), { token_version: 2 });
  check("E39. ... and from the current one writes and says true", won2 === true && connOf(bc, ERIN).token_version === 2);
  check("E40. the redirect is FRONTEND_URL + /mailbox.html", bc.api.mailboxRedirectUri() === "https://bizforceai.net/mailbox.html");

  check("E41. no token, code, verifier, client secret or ID token in any answer or log line", !holdsSecret(LOGS.join("\n")) && !holdsSecret(J(ok.body)) && !holdsSecret(J(r.body || {}).replace(stA, "")),
    LOGS.filter(holdsSecret).slice(0, 1).join(""));
  check("E42. no socket, DNS lookup or fetch left the process", NETWORK.length === 0, NETWORK.join(", "));

  /* ════ F. the oauth_states purge ════ */
  console.log("\n══ F. the oauth_states purge ══");
  const pdb = fakeDb({ job_runs: [], oauth_states: [
    { id: "p-2d", user_id: ALICE, created_at: iso(CLOCK.now - 2 * 86400000) }, { id: "p-25h", user_id: BOB, created_at: iso(CLOCK.now - 25 * 3600000) },
    { id: "p-23h", user_id: ALICE, created_at: iso(CLOCK.now - 23 * 3600000) }, { id: "p-now", user_id: BOB, created_at: iso(CLOCK.now) }] });
  const quiet = console.log; let t1, t2;
  console.log = function () {};
  try { t1 = await MS.oauthStatesPurgeTick(pdb.client, CLOCK.now); t2 = await MS.oauthStatesPurgeTick(pdb.client, CLOCK.now + 1000); } finally { console.log = quiet; }
  check("F1. rows older than a day are deleted, younger ones kept", t1.claimed === true && t1.deleted === 2 && J(pdb.rows("oauth_states").map(x => x.id).sort()) === J(["p-23h", "p-now"]), J(t1));
  check("F2. claimed once a UTC day through its own job_runs row, oauth_states_purge", t2.claimed === false && pdb.rows("job_runs").length === 1 && pdb.rows("job_runs")[0].job_name === "oauth_states_purge");
  const cronAt = SRC.indexOf("    cron.schedule(\"45 4 * * *\", function () {\n");
  const cronBody = cronAt === -1 ? "" : SRC.slice(cronAt, SRC.indexOf("}, {\n      timezone: \"UTC\"", cronAt));
  check("F3. the 04:45 UTC cron runs it after the card leads purge, only when server.js is the program",
    cronBody.indexOf("cardLeads.cardLeadsPurgeTick(supabase)") !== -1 && cronBody.indexOf("require(\"./lib/microsoftAuth\").oauthStatesPurgeTick(supabase)") > cronBody.indexOf("cardLeadsPurgeTick") &&
    SRC.lastIndexOf("  if (require.main === module) {\n", cronAt) > SRC.lastIndexOf("\n  }\n", cronAt));

  /* ════ G. the page ════ */
  console.log("\n══ G. mailbox.html and scripts/mailbox.js ══");
  const page = FE("mailbox.html"), js = FE("scripts/mailbox.js");
  const noComments = t => t.replace(/<!--[\s\S]*?-->/g, "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  const LINE1 = "You sign in on Microsoft's own page. BizForce never sees your Microsoft password.";
  const LINE2 = "Work accounts: some organisations block outside apps from reading mail. If yours does, your administrator can allow it.";
  check("G1. the picker offers \"Outlook, Hotmail or Microsoft 365\"; the two lines are word for word; the old Outlook line is gone",
    page.indexOf("<option value=\"outlook\">Outlook, Hotmail or Microsoft 365</option>") !== -1 && page.indexOf(LINE1) !== -1 && page.indexOf(LINE2) !== -1 &&
    page.indexOf("Sign in with Microsoft is coming") === -1 && page.indexOf("mbOutlookLine") === -1 && js.indexOf("mbOutlookLine") === -1);
  check("G2. no innerHTML, outerHTML, insertAdjacentHTML or document.write in the page or its script", [page, js].every(t => !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(noComments(t))));
  if (!JSDOM) check("G3. jsdom loads", false, "jsdom is not installed");
  else {
    const stripScripts = h => h.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
    const settle = async () => { for (let i = 0; i < 25; i++) await tick(); };
    function pageAt(url, answers) {
      const vc = new VirtualConsole(); const nav = [];
      vc.on("jsdomError", e => { if (/navigation/i.test(String(e && e.message))) nav.push(e.message); });
      const dom = new JSDOM(stripScripts(page), { url: url, runScripts: "outside-only", virtualConsole: vc });
      const w = dom.window, fetches = [];
      w.localStorage.setItem("bf_token", "tok");
      w.fetch = function (u, init) {
        const m = (init && init.method) || "GET";
        fetches.push({ url: String(u), method: m, body: init && init.body });
        const a = answers.find(y => y.test(String(u), m)) || { status: 404, body: {} };
        if (a.reject) return Promise.reject(new Error("offline"));
        return Promise.resolve({ ok: (a.status || 200) < 400, status: a.status || 200, json: () => Promise.resolve(JSON.parse(J(a.body))) });
      };
      w.eval(js);
      return { w, fetches, nav, $: id => w.document.getElementById(id) };
    }
    const statusAns = (avail) => ({ test: u => /\/api\/mailbox\/status$/.test(u), body: { connected: false, provider: null, email_address: null, status: null, since: null, outlook_available: avail } });
    let p = pageAt("https://bizforceai.net/mailbox.html", [statusAns(false)]);
    await settle();
    const pick = (pg, v) => { pg.$("mbProvider").value = v; pg.$("mbProvider").dispatchEvent(new pg.w.Event("change")); };
    pick(p, "outlook");
    check("G3. choosing Outlook hides the address and password fields and the Connect button, and shows the Microsoft block",
      p.$("mbPasswordFields").hidden === true && p.$("mbConnectActions").hidden === true && p.$("mbMicrosoft").hidden === false && p.$("mbOtherFields").hidden === true &&
      p.$("mbMsSignInLine").textContent === LINE1 && p.$("mbMsWorkLine").textContent === LINE2 && p.$("mbMsBtn").textContent === "Sign in with Microsoft");
    check("G4. outlook_available false: the button is disabled and \"Outlook sign-in isn't set up yet.\" shows",
      p.$("mbMsBtn").disabled === true && p.$("mbMsUnavailable").hidden === false && p.$("mbMsUnavailable").textContent === "Outlook sign-in isn't set up yet.");
    pick(p, "gmail");
    check("G5. back to Gmail: the password fields return, the Microsoft block hides", p.$("mbPasswordFields").hidden === false && p.$("mbMicrosoft").hidden === true && p.$("mbConnectActions").hidden === false);
    p = pageAt("https://bizforceai.net/mailbox.html", [statusAns(true),
      { test: (u, m) => /\/api\/mailbox\/microsoft\/start$/.test(u) && m === "POST", body: { authorize_url: MS.AUTHORIZE_URL + "?client_id=x&state=y" } }]);
    await settle(); pick(p, "outlook");
    check("G6. outlook_available true: the button is enabled and the not-set-up line hidden", p.$("mbMsBtn").disabled === false && p.$("mbMsUnavailable").hidden === true);
    p.$("mbMsBtn").click(); await settle();
    check("G7. the button POSTs start, then goes to Microsoft's URL", p.fetches.some(f => /\/microsoft\/start$/.test(f.url) && f.method === "POST") && p.nav.length === 1, J(p.nav));
    p = pageAt("https://bizforceai.net/mailbox.html", [statusAns(true), { test: u => /\/microsoft\/start$/.test(u), body: { authorize_url: "https://login.example.net/phish" } }]);
    await settle(); pick(p, "outlook"); p.$("mbMsBtn").click(); await settle();
    check("G8. an authorize_url that is not Microsoft's is not followed", p.nav.length === 0 && p.$("mbStatus").textContent === "Microsoft sign-in didn't finish. Try again.");
    const RET_STATE = MS.newState();
    const finishAns = (status, body) => ({ test: (u, m) => /\/microsoft\/finish$/.test(u) && m === "POST", status: status, body: body });
    p = pageAt("https://bizforceai.net/mailbox.html?code=bftest-code-page&state=" + RET_STATE + "&session_state=z", [statusAns(true),
      finishAns(400, { error: "That sign-in link has expired or was already used. Start again.", code: "state_invalid" })]);
    await settle();
    const fin = p.fetches.filter(f => /\/microsoft\/finish$/.test(f.url));
    check("G9. back from Microsoft: POST finish with { code, state } only, then the query is stripped even though the answer was a refusal",
      fin.length === 1 && J(JSON.parse(fin[0].body)) === J({ code: "bftest-code-page", state: RET_STATE }) && p.w.location.search === "" && p.w.location.pathname === "/mailbox.html" &&
      p.$("mbStatus").textContent === "That sign-in link has expired or was already used. Start again.", p.w.location.href);
    p = pageAt("https://bizforceai.net/mailbox.html?code=bftest-code-page&state=" + RET_STATE, [statusAns(true), { test: u => /\/microsoft\/finish$/.test(u), reject: true }]);
    await settle();
    check("G10. a finish that fails to arrive still strips the query", p.w.location.search === "" && p.$("mbStatus").textContent === "Microsoft sign-in didn't finish. Try again.", p.w.location.href);
    p = pageAt("https://bizforceai.net/mailbox.html?code=bftest-code-page&state=" + RET_STATE, [statusAns(true),
      finishAns(200, { connected: true, provider: "outlook", email_address: ADDR.alice, status: "connected", since: null, account_type: "personal", outlook_available: true })]);
    await settle();
    check("G11. a finish that succeeds: stripped, and the mailbox shows as Outlook", p.w.location.search === "" && p.$("mbConnected").hidden === false &&
      p.$("mbConnectedTitle").textContent === "Outlook: " + ADDR.alice && p.$("mbStatus").textContent === "Connected.");
    p = pageAt("https://bizforceai.net/mailbox.html?error=access_denied&error_description=" + encodeURIComponent("<b>no</b>") + "&state=" + RET_STATE, [statusAns(true)]);
    await settle();
    check("G12. ?error=access_denied: \"You cancelled the Microsoft sign-in.\", stripped, no finish, and Microsoft's description is never shown",
      p.$("mbStatus").textContent === "You cancelled the Microsoft sign-in." && p.w.location.search === "" && !p.fetches.some(f => /finish/.test(f.url)) && p.w.document.body.textContent.indexOf("<b>no</b>") === -1);
    p = pageAt("https://bizforceai.net/mailbox.html?error=server_error", [statusAns(true)]);
    await settle();
    check("G13. any other ?error: \"Microsoft sign-in didn't finish. Try again.\", stripped", p.$("mbStatus").textContent === "Microsoft sign-in didn't finish. Try again." && p.w.location.search === "");
    const HOSTILE = "<img src=x onerror=alert(1)>";
    p = pageAt("https://bizforceai.net/mailbox.html", [{ test: u => /\/api\/mailbox\/status$/.test(u), body: { connected: false, provider: "outlook", email_address: HOSTILE, status: "needs_reconnect", since: null, account_type: "work", outlook_available: true } }]);
    await settle();
    check("G14. needs_reconnect for Outlook: the Microsoft wording, as text, and the Sign in button offered",
      p.$("mbConnectedNote").textContent === "Microsoft stopped accepting BizForce's access to " + HOSTILE + ", so BizForce can't read it. Sign in with Microsoft again." &&
      !p.w.document.querySelector("#mbConnected img") && p.$("mbMicrosoft").hidden === false && p.$("mbProvider").value === "outlook");
  }

  /* ════ H. legal, yourData, README, registries, the migration ════ */
  console.log("\n══ H. legal, yourData, README, registries, the migration ══");
  const PRIVACY = "If you connect your mailbox, BizForce stores your email address, your mail server names and the app password you made for BizForce or, if you sign in with Microsoft, the access Microsoft grants BizForce, encrypted; it is used only to check the connection, to read your inbox when you open it in BizForce, and to send the replies you approve. Your messages are read each time you ask and are not stored, BizForce never marks them read or changes anything in your mailbox, and attachments are listed but not downloaded. You can disconnect at any time, you can also cancel the app password with your email provider or remove BizForce from your Microsoft account, and it is deleted with your account.";
  check("H1. MAILBOX_PRIVACY_SENTENCE has exactly the two replacements, and privacy.html says it once",
    LP.MAILBOX_PRIVACY_SENTENCE === PRIVACY && FE("privacy.html").split(PRIVACY).length === 2, LP.MAILBOX_PRIVACY_SENTENCE.slice(80, 220));
  check("H2. THIRD_PARTIES names Microsoft, word for word, and the Privacy Policy lists it",
    YDATA.THIRD_PARTIES.some(t => t.name === "Microsoft" && t.for === "signing in to your Outlook or Microsoft 365 mailbox, when you choose Sign in with Microsoft") &&
    FE("privacy.html").indexOf("signing in to your Outlook or Microsoft 365 mailbox, when you choose Sign in with Microsoft") !== -1);
  const ydMail = YDATA.DATA.find(d => d.table === "member_email_connections") || {};
  const ydStates = YDATA.DATA.find(d => d.table === "oauth_states") || {};
  check("H3. yourData names both kinds: the mailbox entry and the never-exported line",
    /app password, or the access Microsoft granted when you signed in with Microsoft, is stored encrypted/.test(ydMail.what || "") &&
    YDATA.NEVER_EXPORTED.indexOf("Your mailbox app password or Microsoft access: stored encrypted; the export shows only the provider, the address and the date you connected.") !== -1);
  check("H4. oauth_states: not exported (\"temporary sign-in states, deleted within a day\"), deleted with the account",
    ydStates.export === false && ydStates.exportWhy === "temporary sign-in states, deleted within a day" && ydStates.onDelete === "delete" && J(ydStates.owner) === J(["user_id"]) &&
    YDATA.FINAL_DELETES.indexOf("oauth_states") !== -1);
  check("H5. backups leave oauth_states out, with the reason", BACKUP.EXCLUDED_TABLES.oauth_states === "one-time sign-in states, deleted within a day");
  check("H6. the schema list names oauth_states as 173's", SCHEMA.SCHEMA_TABLES.some(e => e[0] === "oauth_states" && e[1] === "173_mailbox_microsoft.sql"));
  const README = lf(fs.readFileSync(path.join(REPO, "README.md"), "utf8"));
  const rowOf = n => README.split("\n").find(l => l.indexOf("| `" + n + "` |") === 0) || "";
  const reg = (README.split("## Microsoft app registration")[1] || "").split("\n## ")[0];
  check("H7. README rows for MS_CLIENT_ID and MS_CLIENT_SECRET: only for Outlook sign-in, never committed",
    /Needed only for Sign in with Microsoft/.test(rowOf("MS_CLIENT_ID")) && /never commit it/.test(rowOf("MS_CLIENT_ID")) && /never commit it/.test(rowOf("MS_CLIENT_SECRET")) && /^\| `MS_CLIENT_SECRET` \| none \|/.test(rowOf("MS_CLIENT_SECRET")));
  check("H8. the Microsoft app registration section: account types, Web, the redirect URI exactly, the six permissions, a secret to rotate",
    reg.indexOf("any organisational directory and personal Microsoft accounts") !== -1 && /\*\*Platform:\*\* Web/.test(reg) && reg.indexOf("`https://bizforceai.net/mailbox.html`") !== -1 &&
    ["offline_access", "openid", "email", "profile", "IMAP.AccessAsUser.All", "SMTP.Send"].every(p => reg.indexOf("`" + p + "`") !== -1) && /rotate it before then/.test(reg));
  check("H9. the README job table lists the oauth_states purge", /\| `oauthStatesPurgeTick` \(`lib\/microsoftAuth\.js`\): one-time Microsoft sign-in states older than a day \|/.test(README));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  check("R1. 173_mailbox_microsoft.sql is the only migration numbered 173, and the highest (172 was the last before it)",
    migFiles.filter(f => /^173_/.test(f)).length === 1 && migFiles.indexOf("173_mailbox_microsoft.sql") !== -1 && migFiles.every(f => Number(f.split("_")[0]) <= 173) && migFiles.some(f => /^172_/.test(f)));
  check("R2. its header says the owner applied it by hand on Nov 6, 2026", MIGRATION.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.\n") === 0);
  check("R3. RLS on, anon and authenticated revoked, the state hash unique, the kind_shape CHECK present, and every pattern this check enforces read from it",
    /ALTER TABLE public\.oauth_states ENABLE ROW LEVEL SECURITY;/.test(MIGRATION) && /REVOKE ALL ON public\.oauth_states FROM anon, authenticated;/.test(MIGRATION) &&
    /state_hash text NOT NULL UNIQUE,/.test(MIGRATION) && /member_email_connections_kind_shape_check CHECK \(/.test(MIGRATION) &&
    /expires_at <= created_at \+ interval '15 minutes'/.test(MIGRATION) && Object.keys(RE173).every(k => RE173[k] instanceof RegExp));
  check("R4. the routes are named in checkDormantRoutesDeleted and checkUnsubscribedSurface",
    ["checkDormantRoutesDeleted.js", "checkUnsubscribedSurface.js"].every(f => { const t = fs.readFileSync(path.join(__dirname, f), "utf8"); return t.indexOf("/api/mailbox/microsoft/start") !== -1 && t.indexOf("/api/mailbox/microsoft/finish") !== -1; }));
  check("R5. the reply executor hands an oauth row's access hooks to sendReply, and keeps the app-password decrypt for the rest",
    /var oauthRow = conn\.auth_kind === "oauth_microsoft";/.test(SRC) && /if \(oauthRow\) \{\n    secret = mailboxAccess\(\);\n  \} else \{/.test(SRC));

  console.log(failures ? "\nCHECKS FAILED: " + failures + " of " + (passes + failures) : "\nALL " + passes + " CHECKS PASSED");
  process.exit(failures ? 1 : 0);
})().catch(function (e) {
  console.log("    FAIL  threw: " + safe(String(e && e.stack || e)).slice(0, 600));
  process.exit(1);
});
