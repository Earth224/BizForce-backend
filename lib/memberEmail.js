"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   A member's own mailbox, connected with an app password (migration 169).
   READ ONLY: this module reads the inbox when the member asks and nothing
   else. It sends no mail (Build B, replies, is a later block), stores no
   message anywhere, and never marks, moves, flags or deletes anything.

   CONNECTING. The member picks a provider (PROVIDERS: the server names are
   fixed for the four named ones; "other" types both names and picks SMTP 465
   or 587) and types the address and an app password. verifyConnection runs
   two checks, both of which must pass before server.js stores anything:
     1. IMAP: connect (which logs in) and log out, on 993 with implicit TLS;
     2. SMTP: transporter.verify(), which connects and authenticates and sends
        nothing, on 465 (implicit TLS) or 587 with STARTTLS required.
   Certificate verification is always on and nothing is ever plaintext.

   WHERE THE SOCKETS GO. Every server name goes through lib/guardedFetch.js
   resolvePublicHost first: every address it resolves to must be a public one,
   and the libraries are handed that one vetted address as the host and the
   real name as the TLS servername. The certificate is checked against the
   name; the socket goes only to the vetted address; nodemailer does not
   resolve an IP host again (node_modules/nodemailer/dist/cjs/shared/index.js
   resolveHostname) and ImapFlow hands it straight to tls.connect.

   READING (withImap, listInbox, openMessage). One IMAP connection per request,
   INBOX opened with EXAMINE (readOnly), so the server itself refuses any
   change. The list asks for flags, envelope, size and date only; a message is
   opened only when it is at most OPEN_MAX_BYTES, its source fetched through
   ImapFlow's fetchOne, which always asks for BODY.PEEK[]
   (node_modules/imapflow/dist/cjs/commands/fetch.js setBodyPeek), and parsed
   with postal-mime into plain text only. Attachments are listed by name,
   type and size; their bytes are never returned.

   ERRORS are classified by codes and properties, never by message text
   (classify). The libraries log nothing (logger false, debug false).
   ══════════════════════════════════════════════════════════════════════════ */

const net = require("net");

const HELP_SUFFIX = " Your provider may name these steps slightly differently.";
const PROVIDERS = Object.freeze({
  gmail: Object.freeze({ label: "Gmail", imap_host: "imap.gmail.com", smtp_host: "smtp.gmail.com", smtp_port: 465,
    help: "Google Account, Security, turn on 2-Step Verification, then App passwords." + HELP_SUFFIX }),
  yahoo: Object.freeze({ label: "Yahoo Mail", imap_host: "imap.mail.yahoo.com", smtp_host: "smtp.mail.yahoo.com", smtp_port: 465,
    help: "Account security, then Generate app password." + HELP_SUFFIX }),
  icloud: Object.freeze({ label: "iCloud Mail", imap_host: "imap.mail.me.com", smtp_host: "smtp.mail.me.com", smtp_port: 587,
    help: "appleid.apple.com, Sign-In and Security, then App-Specific Passwords." + HELP_SUFFIX }),
  fastmail: Object.freeze({ label: "Fastmail", imap_host: "imap.fastmail.com", smtp_host: "smtp.fastmail.com", smtp_port: 465,
    help: "Settings, Privacy and Security, then App passwords." + HELP_SUFFIX }),
  other: Object.freeze({ label: "Other", imap_host: null, smtp_host: null, smtp_port: null,
    help: "Your provider's help pages explain how to make an app password." + HELP_SUFFIX })
});
const PROVIDER_IDS = Object.freeze(Object.keys(PROVIDERS));
const OUTLOOK_LINE = "Outlook.com no longer allows app passwords. Sign in with Microsoft is coming.";

const IMAP_PORT = 993;
const SMTP_PORTS = Object.freeze([465, 587]);
const CONNECTION_TIMEOUT_MS = 15 * 1000;
const GREETING_TIMEOUT_MS = 15 * 1000;
const SOCKET_TIMEOUT_MS = 30 * 1000;
const LIST_PAGE = 30;
const SUBJECT_MAX = 300;
const OPEN_MAX_BYTES = 2 * 1024 * 1024;
const TEXT_MAX = 100000;
const BACKOFF_MS = 15 * 60 * 1000;
const UID_MAX = 4294967295;

/* Migration 169's patterns, character for character (checkMailboxConnect holds them equal). */
const HOST_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

const MESSAGES = Object.freeze({
  provider: "Choose your email provider: Gmail, Yahoo Mail, iCloud Mail, Fastmail or Other. Nothing was saved.",
  email: "Type the email address of the mailbox you are connecting. Nothing was saved.",
  username: "The sign-in name must be 1 to 254 characters on one line. Nothing was saved.",
  password: "Paste the app password you made for BizForce. Nothing was saved.",
  imapHost: "Type your provider's IMAP server name, such as imap.example.com. Nothing was saved.",
  smtpHost: "Type your provider's SMTP server name, such as smtp.example.com. Nothing was saved.",
  smtpPort: "Choose SMTP port 465 or 587. Nothing was saved.",
  noSecret: "BizForce cannot store an app password right now (the server's encryption key is missing). Nothing was saved.",
  rejected: "Your email provider did not accept that address and app password. Check both, make a new app password if needed, and try again. Nothing was saved.",
  unreachable: "BizForce could not reach that mail server over a verified secure connection. Check the server names, or try again later. Nothing was saved.",
  rateLimited: "Your email provider asked BizForce to slow down. Try again in 15 minutes.",
  readUnreachable: "BizForce could not reach your mail server just now. Try again later.",
  tooLarge: "This message is too large to open here.",
  notFound: "That message is no longer in your inbox.",
  notConnected: "Connect your mailbox first.",
  uid: "That is not a message number."
});

/* ── what a member types ─────────────────────────────────────────────────── */

/* A mail server name, lowercased, one trailing dot dropped; null unless it is a
   dotted name 169's pattern accepts. No IP literal, no localhost, no single label. */
function normalizeHost(raw) {
  if (typeof raw !== "string") return null;
  var host = raw.trim().toLowerCase();
  if (host.slice(-1) === ".") host = host.slice(0, -1);
  if (host.length < 4 || host.length > 253) return null;
  if (net.isIP(host.replace(/^\[|\]$/g, ""))) return null;
  if (host === "localhost" || host.slice(-10) === ".localhost") return null;
  if (!HOST_RE.test(host)) return null;
  return host;
}

/* { ok: true, value } or { ok: false, code, error }. */
function checkEmailAddress(raw) {
  var value = typeof raw === "string" ? raw.trim() : "";
  if (!value || value.length > 254 || !EMAIL_RE.test(value) || CONTROL_RE.test(value)) return { ok: false, code: "email_format", error: MESSAGES.email };
  return { ok: true, value: value };
}

function checkUsername(raw, fallback) {
  if (raw === undefined || raw === null || (typeof raw === "string" && raw.trim() === "")) return { ok: true, value: fallback };
  var value = typeof raw === "string" ? raw.trim() : "";
  if (!value || value.length > 254 || CONTROL_RE.test(value)) return { ok: false, code: "username_format", error: MESSAGES.username };
  return { ok: true, value: value };
}

/* The app password: ends trimmed, nothing else changed (Gmail's spaces are its own). */
function checkAppPassword(raw) {
  var value = typeof raw === "string" ? raw.trim() : "";
  if (!value || value.length > 256 || CONTROL_RE.test(value)) return { ok: false, code: "password_required", error: MESSAGES.password };
  return { ok: true, value: value };
}

function portOf(raw) {
  var n = typeof raw === "number" ? raw : (typeof raw === "string" && /^\d{1,5}$/.test(raw.trim()) ? Number(raw.trim()) : NaN);
  return Number.isInteger(n) ? n : null;
}

/* The settings a connect body asks for. A named provider's preset wins over
   anything typed; "other" needs both names and port 465 or 587.
   { ok: true, settings } or { ok: false, code, error }. */
function settingsFrom(body) {
  body = body || {};
  var provider = typeof body.provider === "string" ? body.provider.trim().toLowerCase() : "";
  if (PROVIDER_IDS.indexOf(provider) === -1) return { ok: false, code: "provider", error: MESSAGES.provider };
  var email = checkEmailAddress(body.email_address);
  if (!email.ok) return email;
  var user = checkUsername(body.username, email.value);
  if (!user.ok) return user;
  var preset = PROVIDERS[provider];
  var imapHost = preset.imap_host, smtpHost = preset.smtp_host, smtpPort = preset.smtp_port;
  if (provider === "other") {
    imapHost = normalizeHost(body.imap_host);
    if (!imapHost) return { ok: false, code: "imap_host", error: MESSAGES.imapHost };
    smtpHost = normalizeHost(body.smtp_host);
    if (!smtpHost) return { ok: false, code: "smtp_host", error: MESSAGES.smtpHost };
    smtpPort = portOf(body.smtp_port);
    if (SMTP_PORTS.indexOf(smtpPort) === -1) return { ok: false, code: "smtp_port", error: MESSAGES.smtpPort };
  }
  return { ok: true, settings: { provider: provider, email_address: email.value, username: user.value,
    imap_host: imapHost, imap_port: IMAP_PORT, smtp_host: smtpHost, smtp_port: smtpPort } };
}

/* ── the libraries, injectable so the checks never open a socket ─────────── */
const deps = {
  ImapFlow: function () { return require("imapflow").ImapFlow; },
  createTransport: function (options) { return require("nodemailer").createTransport(options); },
  resolvePublicHost: function (host) { return require("./guardedFetch").resolvePublicHost(host); },
  PostalMime: function () { return require("postal-mime").default; },
  now: function () { return Date.now(); }
};

/* A refusal or failure this module names itself. kind: rejected, rate_limited,
   unreachable, too_large or not_found. */
function MailboxError(kind, code) {
  this.name = "MailboxError";
  this.kind = kind;
  this.code = code;
  this.message = "mailbox " + kind + " (" + code + ")";
}
MailboxError.prototype = Object.create(Error.prototype);

/* The TLS options both libraries get: the real name for SNI and the
   certificate check, verification on, TLS 1.2 or later. */
function tlsFor(host) {
  return { servername: host, rejectUnauthorized: true, minVersion: "TLSv1.2" };
}

/* ImapFlow's options: the vetted address as host, implicit TLS on 993 only. */
function imapOptions(settings, address, secret) {
  if (settings.imap_port !== IMAP_PORT) throw new MailboxError("unreachable", "imap_port");
  return {
    host: address,
    port: IMAP_PORT,
    secure: true,
    servername: settings.imap_host,
    tls: tlsFor(settings.imap_host),
    auth: { user: settings.username, pass: secret },
    logger: false,
    emitLogs: false,
    disableAutoIdle: true,
    connectionTimeout: CONNECTION_TIMEOUT_MS,
    greetingTimeout: GREETING_TIMEOUT_MS,
    socketTimeout: SOCKET_TIMEOUT_MS,
    maxLiteralSize: OPEN_MAX_BYTES
  };
}

/* nodemailer's SMTP options: 465 implicit TLS, or 587 with STARTTLS required. */
function smtpOptions(settings, address, secret) {
  var port = settings.smtp_port;
  if (SMTP_PORTS.indexOf(port) === -1) throw new MailboxError("unreachable", "smtp_port");
  return {
    host: address,
    port: port,
    secure: port === 465,
    requireTLS: port === 587,
    ignoreTLS: false,
    opportunisticTLS: false,
    servername: settings.smtp_host,
    tls: tlsFor(settings.smtp_host),
    auth: { user: settings.username, pass: secret },
    pool: false,
    logger: false,
    debug: false,
    transactionLog: false,
    connectionTimeout: CONNECTION_TIMEOUT_MS,
    greetingTimeout: GREETING_TIMEOUT_MS,
    socketTimeout: SOCKET_TIMEOUT_MS
  };
}

/* The one vetted address for a server name, or a MailboxError("unreachable"). */
async function pinHost(host) {
  if (normalizeHost(host) !== host) throw new MailboxError("unreachable", "host_invalid");
  try {
    var vetted = await deps.resolvePublicHost(host);
    if (!vetted || typeof vetted.address !== "string" || !net.isIP(vetted.address)) throw new Error("no address");
    return vetted.address;
  } catch (err) {
    throw new MailboxError("unreachable", "address_refused");
  }
}

/* ── what a failure means ───────────────────────────────────────────────────
   Codes and properties only, never message text:
     rejected      IMAP authenticationFailed, or response code AUTHENTICATIONFAILED
                   or AUTHORIZATIONFAILED; SMTP EAUTH (other than a 421 or 454)
     rate_limited  IMAP ETHROTTLE or response code LIMIT; SMTP 421 or 454
     unreachable   everything else */
const SAFE_CODE_RE = /^[A-Za-z0-9_]{1,40}$/;
function classify(err) {
  if (err instanceof MailboxError) return { kind: err.kind, code: err.code };
  if (!err || typeof err !== "object") return { kind: "unreachable", code: "unknown" };
  var responseCode = typeof err.serverResponseCode === "string" ? err.serverResponseCode.toUpperCase() : "";
  var smtpCode = typeof err.responseCode === "number" ? err.responseCode : null;
  if (err.code === "ETHROTTLE" || responseCode === "LIMIT") return { kind: "rate_limited", code: "imap_throttled" };
  if (smtpCode === 421 || smtpCode === 454) return { kind: "rate_limited", code: "smtp_" + smtpCode };
  if (err.authenticationFailed === true || responseCode === "AUTHENTICATIONFAILED" || responseCode === "AUTHORIZATIONFAILED") {
    return { kind: "rejected", code: "imap_auth" };
  }
  if (err.code === "EAUTH") return { kind: "rejected", code: "smtp_auth" };
  return { kind: "unreachable", code: typeof err.code === "string" && SAFE_CODE_RE.test(err.code) ? err.code : "error" };
}

/* ── A MEMBER'S OWN BACK-OFF ────────────────────────────────────────────────
   In memory, per member, its own Map (Bluesky and Mastodon keep theirs). After
   a throttle, no connection is made for BACKOFF_MS. A success clears it. */
var mailboxBackoffs = new Map();
function backoffUntil(userId, nowMs) {
  if (typeof userId !== "string" || !userId) return 0;
  var until = mailboxBackoffs.get(userId) || 0;
  if (until <= nowMs) {
    if (until) mailboxBackoffs.delete(userId);
    return 0;
  }
  return until;
}
function noteThrottle(userId, nowMs) {
  var until = nowMs + BACKOFF_MS;
  if (typeof userId === "string" && userId) mailboxBackoffs.set(userId, until);
  return until;
}
function clearBackoff(userId) {
  if (typeof userId === "string" && userId) mailboxBackoffs.delete(userId);
}

/* ── connecting ──────────────────────────────────────────────────────────── */

/* Close an ImapFlow client: LOGOUT when it got that far, else drop the socket. */
async function closeImap(client, loggedIn) {
  if (!client) return;
  try {
    if (loggedIn) await client.logout();
    else if (typeof client.close === "function") client.close();
  } catch (err) {
    try { if (typeof client.close === "function") client.close(); } catch (e) { /* already closed */ }
  }
}

/* The two checks with what the member typed, once each, no retry: the IMAP
   login, then the SMTP auth check. { ok: true } or { ok: false, kind, code }.
   Never throws; the secret is never put into a result or a log. */
async function verifyConnection(settings, secret) {
  var typed = secret;
  try {
    var imapAddress = await pinHost(settings.imap_host);
    var smtpAddress = await pinHost(settings.smtp_host);

    var ImapFlow = deps.ImapFlow();
    var client = new ImapFlow(imapOptions(settings, imapAddress, typed));
    var loggedIn = false;
    try {
      await client.connect();
      loggedIn = true;
    } finally {
      await closeImap(client, loggedIn);
    }

    var transport = deps.createTransport(smtpOptions(settings, smtpAddress, typed));
    try {
      await transport.verify();
    } finally {
      try { if (transport && typeof transport.close === "function") transport.close(); } catch (e) { /* closed */ }
    }
    return { ok: true };
  } catch (err) {
    var verdict = classify(err);
    return { ok: false, kind: verdict.kind, code: verdict.code };
  } finally {
    typed = null;
  }
}

/* fn(client) on the member's INBOX, opened read-only, in one IMAP connection.
   `row` is their member_email_connections row; `decrypt` is lib/apiKeyCrypto.js's.
   Resolves { ok: true, value } or { ok: false, reason, code, resumes_at? }:
     session_failed  the server refused the app password, or it could not be
                     decrypted (server.js marks needs_reconnect)
     rate_limited    throttled now or within the last 15 minutes
     too_large       the message is over OPEN_MAX_BYTES
     not_found       no such message
     call_failed     anything else
   No retry. Never throws. */
async function withImap(row, decrypt, fn) {
  var userId = row && row.user_id;
  var held = backoffUntil(userId, deps.now());
  if (held) return { ok: false, reason: "rate_limited", code: "backoff", resumes_at: new Date(held).toISOString() };
  var settings = row ? { imap_host: row.imap_host, imap_port: row.imap_port, username: row.username } : null;
  if (!settings || normalizeHost(settings.imap_host) !== settings.imap_host || settings.imap_port !== IMAP_PORT ||
      typeof settings.username !== "string" || !settings.username) {
    return { ok: false, reason: "call_failed", code: "settings_invalid" };
  }
  var secret;
  try {
    secret = decrypt({ ciphertext: row.secret_ciphertext, iv: row.secret_iv, authTag: row.secret_auth_tag });
  } catch (err) {
    return { ok: false, reason: "session_failed", code: "secret_unreadable" };
  }
  var client = null, loggedIn = false;
  try {
    var address = await pinHost(settings.imap_host);
    var ImapFlow = deps.ImapFlow();
    client = new ImapFlow(imapOptions(settings, address, secret));
    secret = null;
    await client.connect();
    loggedIn = true;
    var opened = await client.mailboxOpen("INBOX", { readOnly: true });
    if (opened && opened.readOnly === false) throw new MailboxError("unreachable", "not_read_only");
    var value = await fn(client);
    clearBackoff(userId);
    return { ok: true, value: value };
  } catch (err) {
    var verdict = classify(err);
    if (verdict.kind === "rejected") return { ok: false, reason: "session_failed", code: verdict.code };
    if (verdict.kind === "rate_limited") {
      var until = noteThrottle(userId, deps.now());
      return { ok: false, reason: "rate_limited", code: verdict.code, resumes_at: new Date(until).toISOString() };
    }
    if (verdict.kind === "too_large" || verdict.kind === "not_found") return { ok: false, reason: verdict.kind, code: verdict.code };
    return { ok: false, reason: "call_failed", code: verdict.code };
  } finally {
    secret = null;
    await closeImap(client, loggedIn);
  }
}

/* ── reading ─────────────────────────────────────────────────────────────── */

function cleanLine(value, max) {
  return String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max);
}
function mailboxOf(a) {
  if (!a || typeof a !== "object") return null;
  return { name: cleanLine(a.name, 200), address: cleanLine(a.address, 254) };
}
/* postal-mime's addresses, groups flattened, as { name, address }. */
function addressList(list) {
  var out = [];
  [].concat(list || []).forEach(function (a) {
    if (a && Array.isArray(a.group)) a.group.forEach(function (m) { var x = mailboxOf(m); if (x) out.push(x); });
    else { var x = mailboxOf(a); if (x) out.push(x); }
  });
  return out.slice(0, 100);
}
function isoDate(value) {
  var t = value instanceof Date ? value.getTime() : Date.parse(String(value || ""));
  return isFinite(t) ? new Date(t).toISOString() : null;
}

/* A uid from a request: a positive whole number within IMAP's 32 bits, or null. */
function uidOf(raw) {
  var s = typeof raw === "number" ? String(raw) : (typeof raw === "string" ? raw.trim() : "");
  if (!/^[1-9][0-9]{0,9}$/.test(s)) return null;
  var n = Number(s);
  return n <= UID_MAX ? n : null;
}

/* The newest LIST_PAGE messages by UID, below `before` when given. Flags,
   envelope, size and date only: no body, no source. next_before is the
   cursor for the next page, or null at the oldest. */
async function listInbox(client, before) {
  if (before === 1) return { messages: [], next_before: null };
  var query = before ? { uid: "1:" + (before - 1) } : { all: true };
  var found = await client.search(query, { uid: true });
  var uids = (Array.isArray(found) ? found : []).filter(function (u) { return Number.isInteger(u) && u > 0 && (!before || u < before); })
    .sort(function (a, b) { return a - b; });
  var page = uids.slice(-LIST_PAGE);
  if (!page.length) return { messages: [], next_before: null };
  var messages = [];
  for await (var msg of client.fetch(page.join(","), { uid: true, flags: true, envelope: true, size: true, internalDate: true }, { uid: true })) {
    var env = msg.envelope || {};
    var from = addressList(env.from)[0] || { name: "", address: "" };
    messages.push({
      uid: msg.uid,
      from: from,
      subject: cleanLine(env.subject, SUBJECT_MAX),
      date: isoDate(env.date) || isoDate(msg.internalDate),
      seen: !!(msg.flags && typeof msg.flags.has === "function" && msg.flags.has("\\Seen")),
      size: typeof msg.size === "number" ? msg.size : null
    });
  }
  messages.sort(function (a, b) { return b.uid - a.uid; });
  return { messages: messages, next_before: page.length < uids.length ? page[0] : null };
}

/* HTML to plain text: scripts, styles and comments dropped, block ends as line
   breaks, every tag removed, then the basic entities decoded (&amp; last, so
   nothing is decoded twice). The result is text and is only ever shown as text. */
var NAMED_ENTITIES = { nbsp: " ", lt: "<", gt: ">", quot: "\"", apos: "'", "#39": "'" };
function htmlToText(html) {
  var s = String(html == null ? "" : html);
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  s = s.replace(/<(script|style|head|title|template|noscript)\b[\s\S]*?<\/\1\s*>/gi, " ");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<\/(p|div|li|tr|h[1-6]|blockquote|table|section|article|header|footer|ul|ol)\s*>/gi, "\n");
  s = s.replace(/<[^>]*>/g, "");
  s = s.replace(/</g, "");
  s = s.replace(/&#(x[0-9a-f]{1,6}|[0-9]{1,7});/gi, function (m, n) {
    var cp = n[0] === "x" || n[0] === "X" ? parseInt(n.slice(1), 16) : parseInt(n, 10);
    if (!isFinite(cp) || cp < 32 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return " ";
    return String.fromCodePoint(cp);
  });
  s = s.replace(/&(nbsp|lt|gt|quot|apos);/gi, function (m, n) { return NAMED_ENTITIES[n.toLowerCase()]; });
  s = s.replace(/&amp;/gi, "&");
  s = s.replace(/[ \t\f\v ]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{3,}/g, "\n\n");
  return s.trim();
}

function byteLength(content) {
  if (content == null) return 0;
  if (typeof content === "string") return Buffer.byteLength(content);
  if (typeof content.byteLength === "number") return content.byteLength;
  return 0;
}

/* One message, as plain text. Refused over OPEN_MAX_BYTES before its source
   is asked for. Headers: from, to, cc, subject, date. Attachments: name, type,
   size. No HTML, no raw source, no attachment bytes. */
async function openMessage(client, uid) {
  var meta = await client.fetchOne(String(uid), { uid: true, size: true }, { uid: true });
  if (!meta || meta.uid !== uid) throw new MailboxError("not_found", "no_message");
  if (typeof meta.size !== "number" || meta.size > OPEN_MAX_BYTES) throw new MailboxError("too_large", "over_limit");
  var full = await client.fetchOne(String(uid), { uid: true, source: true }, { uid: true });
  if (!full || !full.source) throw new MailboxError("not_found", "no_source");
  if (full.source.length > OPEN_MAX_BYTES) throw new MailboxError("too_large", "over_limit");
  var PostalMime = deps.PostalMime();
  var email = await PostalMime.parse(full.source, { attachmentEncoding: "arraybuffer", maxNestingDepth: 50, maxHeadersSize: 256 * 1024 });
  full = null;
  var text = typeof email.text === "string" && email.text.trim() ? email.text : (typeof email.html === "string" ? htmlToText(email.html) : "");
  text = text.replace(/\r\n?/g, "\n");
  var truncated = text.length > TEXT_MAX;
  if (truncated) text = text.slice(0, TEXT_MAX);
  var attachments = (Array.isArray(email.attachments) ? email.attachments : []).slice(0, 100).map(function (a) {
    return { name: cleanLine(a && a.filename, 200) || "unnamed", type: cleanLine(a && a.mimeType, 100) || "application/octet-stream", size: byteLength(a && a.content) };
  });
  return {
    uid: uid,
    from: addressList(email.from)[0] || { name: "", address: "" },
    to: addressList(email.to),
    cc: addressList(email.cc),
    subject: cleanLine(email.subject, SUBJECT_MAX),
    date: isoDate(email.date),
    text: text,
    truncated: truncated,
    attachments: attachments
  };
}

/* What GET /api/mailbox/status answers: never the secret, the sign-in name or the server names. */
function statusOf(row) {
  if (!row) return { connected: false, provider: null, email_address: null, status: null, since: null };
  return {
    connected: row.status === "connected",
    provider: row.provider,
    email_address: row.email_address,
    status: row.status,
    since: row.created_at || null
  };
}

module.exports = {
  PROVIDERS: PROVIDERS,
  PROVIDER_IDS: PROVIDER_IDS,
  HELP_SUFFIX: HELP_SUFFIX,
  OUTLOOK_LINE: OUTLOOK_LINE,
  IMAP_PORT: IMAP_PORT,
  SMTP_PORTS: SMTP_PORTS,
  CONNECTION_TIMEOUT_MS: CONNECTION_TIMEOUT_MS,
  GREETING_TIMEOUT_MS: GREETING_TIMEOUT_MS,
  SOCKET_TIMEOUT_MS: SOCKET_TIMEOUT_MS,
  LIST_PAGE: LIST_PAGE,
  SUBJECT_MAX: SUBJECT_MAX,
  OPEN_MAX_BYTES: OPEN_MAX_BYTES,
  TEXT_MAX: TEXT_MAX,
  BACKOFF_MS: BACKOFF_MS,
  HOST_RE: HOST_RE,
  EMAIL_RE: EMAIL_RE,
  MESSAGES: MESSAGES,
  deps: deps,
  MailboxError: MailboxError,
  normalizeHost: normalizeHost,
  checkEmailAddress: checkEmailAddress,
  checkUsername: checkUsername,
  checkAppPassword: checkAppPassword,
  settingsFrom: settingsFrom,
  tlsFor: tlsFor,
  imapOptions: imapOptions,
  smtpOptions: smtpOptions,
  classify: classify,
  backoffUntil: backoffUntil,
  noteThrottle: noteThrottle,
  clearBackoff: clearBackoff,
  verifyConnection: verifyConnection,
  withImap: withImap,
  uidOf: uidOf,
  listInbox: listInbox,
  htmlToText: htmlToText,
  openMessage: openMessage,
  statusOf: statusOf
};
