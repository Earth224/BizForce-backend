"use strict";

/* THE ONE WAY THIS SERVER FETCHES AN ADDRESS SOMEONE ELSE CHOSE.
   ──────────────────────────────────────────────────────────────
   POST /api/agents/seo/optimize used to hand the user's URL straight to
   fetch(): no timeout, no size cap, twenty redirects followed silently, and no
   look at where the address pointed. It then returned up to 8,000 characters of
   the page to the caller. So any subscriber could point the server at
   http://127.0.0.1, at the Railway private network (*.railway.internal, which
   resolves to fd00::/8 addresses), or at a public URL that redirects to either,
   and read the reply. That is the whole of server-side request forgery, and it
   was one form field away.

   WHAT THIS ENFORCES, on every hop including every redirect:
     - http: and https: only, on ports 80 and 443 only, with no username or
       password in the address;
     - the address actually connected to is a public one (BLOCKED_IPV4 below,
       and for IPv6 global unicast only, minus BLOCKED_IPV6);
     - at most MAX_REDIRECTS redirects;
     - TOTAL_TIMEOUT_MS for the whole thing, DNS and every hop included;
     - MAX_BODY_BYTES of body, counted AFTER decompression, so a small gzip
       that expands to gigabytes stops at the cap;
     - a 2xx answer must be text/html (or application/xhtml+xml), unless the
       caller names other types with options.accept (see below);
     - a 2xx answer that is a bot-check page is refused rather than read as
       the site.

   options.accept, FOR ROBOTS.TXT AND SITEMAPS. A list of media types, such as
   ["text/plain"] or ["application/xml", "text/xml"], that REPLACES the HTML
   rule above for that one call, and changes nothing else: every address, port,
   scheme, credential, redirect, timeout, size and decompression guard is the
   same with it as without it. A type matches on the media type alone,
   case-insensitively, so "Text/Plain; charset=utf-8" is text/plain. HTML is
   read only if it is listed. Without it, the rule is exactly what it was.

   WHAT A CALLER GETS BACK. url is the final URL, status the final response's
   status, and chain every response on the way, in order, as { url, status }:
   each redirect, then the final answer. redirects is the list of URLs each
   redirect pointed to, as before. A reached answer that is not 2xx (a missing
   robots.txt's 404) is RETURNED, never thrown, with ok:false and no body read;
   that was always so. Only a refusal throws, so a blocked or unreachable
   address can never be mistaken for a reached 404. A refusal carries the chain
   up to where it stopped, for the server log; what the caller is told about it
   is publicMessage, unchanged.

   HOW REBINDING IS STOPPED. The check runs inside the `lookup` function handed
   to http.request, and that lookup returns the very addresses it checked. Node
   connects to what lookup returns, so there is no second resolution for a
   hostile DNS server to answer differently: the address checked IS the address
   connected to. Every address the name resolves to must pass, not just the
   first, because Node may try any of them (autoSelectFamily). An IP literal in
   the URL never reaches lookup (Node connects to a literal directly), so
   literals are checked before the request is made. agent:false means no pooled
   socket from an earlier request is reused.

   WHAT A REFUSED ADDRESS TELLS THE CALLER: nothing. A blocked address, a name
   that does not resolve, a refused connection, and a timeout before any
   connection was made all produce the SAME message (UNREACHABLE_MESSAGE),
   and a blocked address is refused before any connection is attempted, so
   nobody can map which internal addresses exist or which ports are open. The
   reason is in the server log, not the response.

   The model of a request here is GET, nothing else, and the body is decoded as
   UTF-8 exactly as fetch's .text() did, so the page a legitimate URL yields is
   the page it yielded before.

   THE JSON MODE, guardedJsonRequest(url, { method, headers, body, form, maxBytes }),
   for an API on a server a member named (a Mastodon server, lib/memberMastodon.js),
   or a fixed one (the Microsoft token endpoint, lib/microsoftAuth.js).
   It is the same request function, not a copy: the same checkUrl, the same
   DNS-pinned lookup, agent:false and the same total timeout. It is stricter:
     - https only, port 443 only;
     - GET or POST only, and only a POST carries a body;
     - an object body is sent as JSON under application/json; a string body
       is sent as its UTF-8 bytes, labelled application/json only when the
       caller set no Content-Type (so a string is NOT a way to send a form;
       use form); a Buffer is a multipart upload sent byte for byte: its
       Content-Type must be set by the caller and start
       "multipart/form-data; boundary=", and it is at most maxUploadBytes,
       1 MB unless asked, up to JSON_MAX_UPLOAD_BYTES_CEILING (12 MB); a
       larger maxUploadBytes is refused, never clamped;
     - form, a plain object whose values are all strings, is a POST body
       encoded with URLSearchParams and always labelled
       application/x-www-form-urlencoded (an OAuth token endpoint). form
       with a body, or form with a caller Content-Type, is a TypeError before
       any lookup, so the label can never disagree with the bytes;
     - no redirect is ever followed: any 3xx is refused as "redirected";
     - JSON_MAX_BODY_BYTES (1 MB) of body after decompression, or maxBytes,
       a whole number up to JSON_MAX_BODY_BYTES_CEILING (8 MB); a larger
       maxBytes is refused, never clamped, and a body over the limit fails
       with the code too_large (the 3 MB HTML cap does not apply here);
     - TOTAL_TIMEOUT_MS in total, or timeoutMs, from 1000 to 30000;
     - a 2xx answer must be application/json, and is parsed.
   A reached non-2xx answer is RETURNED with its json (or null), so the caller
   can tell a refused token from a rate limit. What comes back is only
   { status, json, headers }, and headers holds only retry-after,
   x-ratelimit-reset and x-ratelimit-remaining, or the names in exposeHeaders
   (at most 8 lowercase names, never set-cookie or authorization; the store
   sync, lib/storeSync.js, asks for retry-after, link and x-wp-totalpages).
   An option outside these bounds is a TypeError before any lookup. The request headers (the
   Authorization value above all) are never put into an error, a detail or a
   log line.

   resolvePublicHost(host), FOR CONNECTIONS THAT ARE NOT HTTP (a member's IMAP
   and SMTP servers, lib/memberEmail.js). The same guardedLookup runs once:
   every address the name resolves to must pass, and one of them is returned.
   The caller connects to that address and gives the name only as the TLS
   servername, so the certificate is checked against the name while the socket
   goes nowhere else. An IP literal is refused. */

const http = require("http");
const https = require("https");
const dns = require("dns");
const net = require("net");
const zlib = require("zlib");

const MAX_REDIRECTS = 5;
const TOTAL_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const ALLOWED_PORTS = [80, 443];
const ALLOWED_CONTENT_TYPES = ["text/html", "application/xhtml+xml"];
const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
const JSON_MAX_BODY_BYTES = 1024 * 1024;
const JSON_METHODS = ["GET", "POST"];
const JSON_ANSWER_HEADERS = ["retry-after", "x-ratelimit-reset", "x-ratelimit-remaining"];
// What a caller may change in the JSON mode, and how far. Anything outside these is refused, never clamped.
const JSON_MAX_BODY_BYTES_CEILING = 8 * 1024 * 1024;
// A Buffer body (a multipart upload): at most maxUploadBytes, 1 MB unless the caller asks, never past the ceiling.
const JSON_MAX_UPLOAD_BYTES = 1024 * 1024;
const JSON_MAX_UPLOAD_BYTES_CEILING = 12 * 1024 * 1024;
const JSON_MULTIPART_PREFIX = "multipart/form-data; boundary=";
const JSON_MIN_TIMEOUT_MS = 1000;
const JSON_MAX_TIMEOUT_MS = 30000;
const JSON_MAX_EXPOSED_HEADERS = 8;
const JSON_EXPOSE_NAME = /^[a-z0-9-]{1,64}$/;
const JSON_UNEXPOSABLE_HEADERS = ["set-cookie", "authorization"];
// Request headers a caller may not set in the JSON mode: the request function owns these.
const JSON_RESERVED_HEADERS = ["host", "content-length", "transfer-encoding", "connection", "accept-encoding"];

const UNREACHABLE_MESSAGE = "Could not reach that URL. Check that it is correct and publicly accessible.";

/* Every IPv4 range that is not the public internet. */
const BLOCKED_IPV4 = [
  ["0.0.0.0/8",       "\"this network\" (RFC 1122) — 0.0.0.0 reaches the local host on most systems"],
  ["10.0.0.0/8",      "private (RFC 1918)"],
  ["100.64.0.0/10",   "shared address space / carrier-grade NAT (RFC 6598)"],
  ["127.0.0.0/8",     "loopback"],
  ["169.254.0.0/16",  "link-local, including the cloud metadata address 169.254.169.254"],
  ["172.16.0.0/12",   "private (RFC 1918)"],
  ["192.0.0.0/24",    "IETF protocol assignments (RFC 6890)"],
  ["192.0.2.0/24",    "documentation, TEST-NET-1 (RFC 5737)"],
  ["192.88.99.0/24",  "6to4 relay anycast, deprecated (RFC 7526)"],
  ["192.168.0.0/16",  "private (RFC 1918)"],
  ["198.18.0.0/15",   "benchmarking (RFC 2544)"],
  ["198.51.100.0/24", "documentation, TEST-NET-2 (RFC 5737)"],
  ["203.0.113.0/24",  "documentation, TEST-NET-3 (RFC 5737)"],
  ["224.0.0.0/4",     "multicast"],
  ["240.0.0.0/4",     "reserved, including the broadcast address 255.255.255.255"]
];

/* IPv6 is an ALLOW list: only global unicast, 2000::/3, may be reached, and
   these ranges inside it are carved back out. Everything outside 2000::/3 is
   refused by name in classifyIPv6 — loopback, unique-local (the Railway
   private network), link-local, multicast, NAT64 and the rest. */
const BLOCKED_IPV6 = [
  ["2001::/23",     "IETF protocol assignments, including Teredo 2001::/32 (RFC 6890)"],
  ["2001:db8::/32", "documentation (RFC 3849)"],
  ["2002::/16",     "6to4 — embeds an IPv4 address, which may be a private one (RFC 3056)"],
  ["3fff::/20",     "documentation (RFC 9637)"]
];

class GuardedFetchError extends Error {
  constructor(code, detail, extra) {
    super(code + ": " + detail);
    this.name = "GuardedFetchError";
    this.code = code;
    this.detail = detail;
    this.guardedFetch = true;
    Object.assign(this, extra || {});
  }
}

/* ── address parsing ─────────────────────────────────────────────────────── */

function parseIPv4(text) {
  const parts = String(text).split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function parseIPv6(text) {
  let s = String(text).replace(/^\[|\]$/g, "");
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  if (net.isIPv6(s) === false) return null;

  // A trailing dotted quad (::ffff:127.0.0.1) becomes two hex groups.
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.indexOf(".") !== -1) {
    const v4 = parseIPv4(tail);
    if (v4 === null) return null;
    s = s.slice(0, lastColon + 1) + Math.floor(v4 / 65536).toString(16) + ":" + (v4 % 65536).toString(16);
  }

  const halves = s.split("::");
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const groups = head.concat(new Array(fill).fill("0"), rest);
  if (groups.length !== 8) return null;

  let n = 0n;
  for (const g of groups) n = (n << 16n) + BigInt(parseInt(g || "0", 16));
  return n;
}

function inRange4(n, cidr) {
  const [base, bits] = cidr.split("/");
  const size = 2 ** (32 - Number(bits));
  const start = parseIPv4(base);
  return n >= start && n < start + size;
}

function inRange6(n, cidr) {
  const [base, bits] = cidr.split("/");
  const shift = BigInt(128 - Number(bits));
  return (n >> shift) === (parseIPv6(base) >> shift);
}

function classifyIPv4(text) {
  const n = parseIPv4(text);
  if (n === null) return "not a valid IPv4 address";
  for (const [cidr, name] of BLOCKED_IPV4) {
    if (inRange4(n, cidr)) return cidr + " " + name;
  }
  return null;
}

function classifyIPv6(text) {
  const n = parseIPv6(text);
  if (n === null) return "not a valid IPv6 address";

  // IPv4-mapped (::ffff:a.b.c.d): the connection goes to the IPv4 address, so
  // that is the address judged.
  if (inRange6(n, "::ffff:0:0/96")) {
    const v4 = Number(n & 0xffffffffn);
    const dotted = [24, 16, 8, 0].map(function (s) { return (v4 >>> s) & 255; }).join(".");
    const verdict = classifyIPv4(dotted);
    return verdict === null ? null : "::ffff:0:0/96 IPv4-mapped " + dotted + " — " + verdict;
  }

  if (!inRange6(n, "2000::/3")) {
    if (n === 0n) return "::/128 unspecified";
    if (n === 1n) return "::1/128 loopback";
    if (inRange6(n, "::/96")) return "::/96 IPv4-compatible, deprecated";
    if (inRange6(n, "64:ff9b::/96")) return "64:ff9b::/96 NAT64 — translates to an IPv4 address that is not checked here";
    if (inRange6(n, "64:ff9b:1::/48")) return "64:ff9b:1::/48 local-use NAT64";
    if (inRange6(n, "100::/64")) return "100::/64 discard-only";
    if (inRange6(n, "fc00::/7")) return "fc00::/7 unique local — includes the Railway private network";
    if (inRange6(n, "fe80::/10")) return "fe80::/10 link-local";
    if (inRange6(n, "fec0::/10")) return "fec0::/10 site-local, deprecated";
    if (inRange6(n, "ff00::/8")) return "ff00::/8 multicast";
    return "outside 2000::/3, the only IPv6 range that is public internet";
  }

  for (const [cidr, name] of BLOCKED_IPV6) {
    if (inRange6(n, cidr)) return cidr + " " + name;
  }
  return null;
}

/* null when the address may be connected to; otherwise the range that refused it. */
function isBlockedAddress(address) {
  const kind = net.isIP(String(address).replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  if (kind === 4) return classifyIPv4(address);
  if (kind === 6) return classifyIPv6(address);
  return "not an IP address";
}

/* ── the URL, before anything leaves the machine ─────────────────────────── */

function checkUrl(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    throw new GuardedFetchError("invalid_url", "not a URL: " + String(urlString).slice(0, 200));
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new GuardedFetchError("invalid_url", "scheme " + url.protocol + " is not http or https");
  }
  if (url.username || url.password) {
    throw new GuardedFetchError("invalid_url", "the address carries a username or password");
  }
  const port = url.port ? Number(url.port) : (url.protocol === "https:" ? 443 : 80);
  if (ALLOWED_PORTS.indexOf(port) === -1) {
    throw new GuardedFetchError("invalid_url", "port " + port + " is not 80 or 443");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname) {
    throw new GuardedFetchError("invalid_url", "the address has no host");
  }
  // The WHATWG parser has already turned 2130706433, 0x7f.1 and 0177.0.0.1
  // into 127.0.0.1, so a literal is always in one canonical form here.
  if (net.isIP(hostname)) {
    const verdict = isBlockedAddress(hostname);
    if (verdict) throw new GuardedFetchError("blocked", hostname + " is in " + verdict);
  }
  return { url: url, hostname: hostname, port: port, isHttps: url.protocol === "https:" };
}

/* ── bot-check pages served with a 200 ───────────────────────────────────── */

const CHALLENGE_TITLES = [
  /^just a moment\.*$/i,                         // Cloudflare managed challenge
  /^attention required!? \| cloudflare$/i,       // Cloudflare block page
  /^please wait\.*\s*\|\s*cloudflare$/i,
  /^ddos-guard$/i,
  /^vercel security checkpoint$/i,
  /^checking your browser/i
];

/* The headers are judged on every answer; the <title> only on an HTML one, since
   a robots.txt or a sitemap has no title to be a challenge page by. */
function challengeReason(headers, body, isHtml) {
  if (String(headers["cf-mitigated"] || "").toLowerCase() === "challenge") return "cf-mitigated: challenge header";
  if (headers["x-amzn-waf-action"]) return "x-amzn-waf-action: " + headers["x-amzn-waf-action"] + " header";
  if (!isHtml) return null;
  const m = String(body).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = m ? m[1].replace(/\s+/g, " ").trim() : "";
  for (const re of CHALLENGE_TITLES) {
    if (re.test(title)) return "title \"" + title + "\"";
  }
  return null;
}

/* ── options.accept ──────────────────────────────────────────────────────── */

const MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/* null for the default rule; otherwise the listed media types, lowercased. A
   list that is not a non-empty list of bare media types is a programming
   error, refused before anything is fetched. */
function acceptedTypes(accept) {
  if (accept === undefined || accept === null) return null;
  if (!Array.isArray(accept) || !accept.length) throw new TypeError("guardedFetch: options.accept must be a non-empty array of media types");
  return accept.map(function (t) {
    const type = String(t).trim().toLowerCase();
    if (!MEDIA_TYPE.test(type)) throw new TypeError("guardedFetch: options.accept holds " + JSON.stringify(t) + ", which is not a bare media type");
    return type;
  });
}

/* ── the fetcher ─────────────────────────────────────────────────────────── */

/* deps exist for scripts/checkGuardedFetch.js and nothing else: `resolve`
   stands in for dns.lookup, `dial` for the socket connect (so a test can land
   on a local server). Neither can loosen a check — the lookup that checks is
   the one `dial` is handed, and its answer is what `dial` must connect to.
   `request` stands in for http.request / https.request, for the JSON mode's
   https-only tests: it is handed the same options, the guarded lookup among
   them, and must connect where that lookup says.
   server.js uses guardedFetch, which takes no deps. */
function createGuardedFetch(deps) {
  deps = deps || {};
  const resolve = deps.resolve || dns.lookup;

  function guardedFetch(rawUrl, options) {
    return run(rawUrl, options || {}, null);
  }

  guardedFetch.json = function guardedJsonRequest(rawUrl, opts) {
    opts = opts || {};
    const method = opts.method === undefined ? "GET" : opts.method;
    if (JSON_METHODS.indexOf(method) === -1) {
      return Promise.reject(new TypeError("guardedJsonRequest: method must be GET or POST"));
    }
    let payload = null;
    let formEncoded = false;
    if (opts.form !== undefined && opts.form !== null) {
      if (method !== "POST") return Promise.reject(new TypeError("guardedJsonRequest: only a POST carries a form"));
      if (opts.body !== undefined && opts.body !== null) return Promise.reject(new TypeError("guardedJsonRequest: form and body cannot both be given"));
      if (Object.keys(opts.headers || {}).some(function (n) { return n.toLowerCase() === "content-type"; })) {
        return Promise.reject(new TypeError("guardedJsonRequest: a form sets its own Content-Type; do not pass one"));
      }
      const form = opts.form;
      if (typeof form !== "object" || Array.isArray(form) || Buffer.isBuffer(form) || Object.getPrototypeOf(form) !== Object.prototype) {
        return Promise.reject(new TypeError("guardedJsonRequest: form must be a plain object"));
      }
      const pairs = new URLSearchParams();
      for (const k of Object.keys(form)) {
        if (typeof form[k] !== "string") return Promise.reject(new TypeError("guardedJsonRequest: every form value must be a string"));
        pairs.append(k, form[k]);
      }
      payload = Buffer.from(pairs.toString(), "utf8");
      formEncoded = true;
    } else if (opts.body !== undefined && opts.body !== null) {
      if (method !== "POST") return Promise.reject(new TypeError("guardedJsonRequest: only a POST carries a body"));
      if (Buffer.isBuffer(opts.body)) {
        /* A multipart upload: the caller's bytes as they are, never JSON or
           UTF-8 encoded, under its own Content-Type with a boundary, and at
           most maxUploadBytes (refused above the ceiling, never clamped). */
        const uploadCap = opts.maxUploadBytes === undefined ? JSON_MAX_UPLOAD_BYTES : opts.maxUploadBytes;
        if (typeof uploadCap !== "number" || !Number.isInteger(uploadCap) || uploadCap < 1 || uploadCap > JSON_MAX_UPLOAD_BYTES_CEILING) {
          return Promise.reject(new TypeError("guardedJsonRequest: maxUploadBytes must be a whole number from 1 to " + JSON_MAX_UPLOAD_BYTES_CEILING));
        }
        const typeName = Object.keys(opts.headers || {}).find(function (n) { return n.toLowerCase() === "content-type"; });
        const declared = typeName === undefined ? "" : String(opts.headers[typeName]);
        if (declared.indexOf(JSON_MULTIPART_PREFIX) !== 0 || declared.length === JSON_MULTIPART_PREFIX.length) {
          return Promise.reject(new TypeError("guardedJsonRequest: a Buffer body needs a Content-Type of " + JSON_MULTIPART_PREFIX + "..."));
        }
        if (opts.body.length > uploadCap) {
          return Promise.reject(new TypeError("guardedJsonRequest: the body is " + opts.body.length + " bytes, over maxUploadBytes " + uploadCap));
        }
        payload = opts.body;
      } else {
        payload = Buffer.from(typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body), "utf8");
      }
    }
    const limit = opts.maxBytes === undefined ? JSON_MAX_BODY_BYTES : opts.maxBytes;
    if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > JSON_MAX_BODY_BYTES_CEILING) {
      return Promise.reject(new TypeError("guardedJsonRequest: maxBytes must be a whole number from 1 to " + JSON_MAX_BODY_BYTES_CEILING));
    }
    const timeoutMs = opts.timeoutMs === undefined ? TOTAL_TIMEOUT_MS : opts.timeoutMs;
    if (typeof timeoutMs !== "number" || !Number.isInteger(timeoutMs) || timeoutMs < JSON_MIN_TIMEOUT_MS || timeoutMs > JSON_MAX_TIMEOUT_MS) {
      return Promise.reject(new TypeError("guardedJsonRequest: timeoutMs must be from " + JSON_MIN_TIMEOUT_MS + " to " + JSON_MAX_TIMEOUT_MS));
    }
    const expose = opts.exposeHeaders === undefined ? JSON_ANSWER_HEADERS : opts.exposeHeaders;
    if (!Array.isArray(expose) || expose.length > JSON_MAX_EXPOSED_HEADERS) {
      return Promise.reject(new TypeError("guardedJsonRequest: exposeHeaders must be a list of at most " + JSON_MAX_EXPOSED_HEADERS + " names"));
    }
    for (const n of expose) {
      if (typeof n !== "string" || !JSON_EXPOSE_NAME.test(n) || JSON_UNEXPOSABLE_HEADERS.indexOf(n) !== -1) {
        return Promise.reject(new TypeError("guardedJsonRequest: an exposed header must be a lowercase name, and never set-cookie or authorization"));
      }
    }
    const headers = {
      "User-Agent": "BizForceBot/1.0 (+https://bizforceai.net)",
      "Accept": "application/json",
      "Accept-Encoding": "gzip, deflate, br"
    };
    Object.keys(opts.headers || {}).forEach(function (name) {
      if (JSON_RESERVED_HEADERS.indexOf(String(name).toLowerCase()) === -1) headers[name] = String(opts.headers[name]);
    });
    if (formEncoded) headers["Content-Type"] = "application/x-www-form-urlencoded";
    if (payload) {
      if (!Object.keys(headers).some(function (n) { return n.toLowerCase() === "content-type"; })) headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(payload.length);
    }
    return run(rawUrl, {}, { method: method, headers: headers, payload: payload, limit: limit, timeoutMs: timeoutMs }).then(function (r) {
      let parsed = null;
      if (r.body !== null && r.contentType === "application/json") {
        try { parsed = JSON.parse(r.body); } catch (e) { parsed = undefined; }
      }
      if (r.ok && parsed === undefined) throw new GuardedFetchError("not_json", "a " + r.status + " answer whose body is not JSON");
      const picked = {};
      expose.forEach(function (n) {
        if (r.headers && r.headers[n] !== undefined) picked[n] = String(r.headers[n]);
      });
      return { status: r.status, json: parsed === undefined ? null : parsed, headers: picked };
    });
  };

  /* resolvePublicHost(host): for a connection that is not HTTP (lib/memberEmail.js's
     IMAP and SMTP). The same guardedLookup decides: every address the name resolves
     to must pass isBlockedAddress, and the one handed back is one that passed. The
     caller connects to that address and names the host only as the TLS servername,
     so nothing resolves the name a second time. An IP literal is refused: a host is
     a name. Resolves to { address, family }; rejects with a GuardedFetchError
     ("invalid_url", "dns" or "blocked"). */
  guardedFetch.resolvePublicHost = function resolvePublicHost(host) {
    return new Promise(function (fulfil, reject) {
      const name = typeof host === "string" ? host.trim() : "";
      if (!name) return reject(new GuardedFetchError("invalid_url", "no host"));
      if (net.isIP(name.replace(/^\[|\]$/g, ""))) return reject(new GuardedFetchError("invalid_url", "a host must be a name, not an IP address"));
      guardedLookup(name, { all: true }, function (err, addresses) {
        if (err) {
          if (err.guardedFetch) return reject(err);
          const dnsMiss = err.code === "ENOTFOUND" || err.code === "EAI_AGAIN" || err.code === "ENODATA";
          return reject(new GuardedFetchError(dnsMiss ? "dns" : "network", err.code || err.message || String(err)));
        }
        return fulfil({ address: addresses[0].address, family: addresses[0].family });
      });
    });
  };

  return guardedFetch;

  /* THE CHECK THAT DECIDES WHERE THE SOCKET GOES. One resolution; every
     address it returns must pass; the addresses handed back are the ones
     that passed. Shared by every hop of every fetch and by resolvePublicHost. */
  function guardedLookup(hostname, lookupOptions, callback) {
    resolve(hostname, { all: true, verbatim: true }, function (err, addresses) {
      if (err) return callback(err);
      if (!addresses || !addresses.length) return callback(new GuardedFetchError("dns", hostname + " resolved to nothing"));
      for (const a of addresses) {
        const verdict = isBlockedAddress(a.address);
        if (verdict) {
          return callback(new GuardedFetchError("blocked", hostname + " resolved to " + a.address + ", which is in " + verdict));
        }
      }
      if (lookupOptions && lookupOptions.all) return callback(null, addresses);
      return callback(null, addresses[0].address, addresses[0].family);
    });
  }

  function run(rawUrl, options, json) {
    let accepted;
    try {
      accepted = json ? null : acceptedTypes(options.accept);
    } catch (err) {
      return Promise.reject(err);
    }
    const startedAt = Date.now();
    const redirects = [];
    const chain = [];
    const totalMs = json ? json.timeoutMs : TOTAL_TIMEOUT_MS;

    return new Promise(function (fulfil, reject) {
      let settled = false;
      let currentReq = null;
      let connected = false;

      const timer = setTimeout(function () {
        fail(new GuardedFetchError("timeout", "no complete answer within " + totalMs + " ms", { connected: connected }));
      }, totalMs);

      function fail(err) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (currentReq) currentReq.destroy();
        if (!err.guardedFetch) {
          const dnsMiss = err && (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN" || err.code === "ENODATA");
          err = new GuardedFetchError(dnsMiss ? "dns" : "network", (err && (err.code || err.message)) || String(err));
        }
        err.chain = chain.slice();
        reject(err);
      }

      function succeed(value) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        value.ms = Date.now() - startedAt;
        value.redirects = redirects.slice();
        value.chain = chain.slice();
        fulfil(value);
      }

      function hop(urlString, hopNumber) {
        let target;
        try {
          target = checkUrl(urlString);
        } catch (err) {
          return fail(err);
        }
        if (json && !target.isHttps) {
          return fail(new GuardedFetchError("invalid_url", "the JSON mode is https only"));
        }
        if (json && target.port !== 443) {
          return fail(new GuardedFetchError("invalid_url", "the JSON mode is port 443 only"));
        }
        connected = false;

        const requestOptions = {
          protocol: target.url.protocol,
          hostname: target.hostname,
          port: target.port,
          path: target.url.pathname + target.url.search,
          method: json ? json.method : "GET",
          agent: false,
          lookup: guardedLookup,
          headers: json ? json.headers : {
            "User-Agent": options.userAgent || "BizForceBot/1.0 (+https://bizforceai.net)",
            "Accept": accepted ? accepted.join(",") + ",*/*;q=0.1" : "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br"
          }
        };
        if (deps.dial) {
          // A one-off agent, as agent:false would make, whose sockets come from
          // dial. Node ignores createConnection when an agent is in play.
          const dialAgent = new (target.isHttps ? https : http).Agent({ keepAlive: false });
          dialAgent.createConnection = function (connectOptions, cb) {
            return deps.dial(Object.assign({}, connectOptions, { lookup: requestOptions.lookup }), cb);
          };
          requestOptions.agent = dialAgent;
        }

        let req;
        try {
          req = (deps.request || (target.isHttps ? https : http).request)(requestOptions);
        } catch (err) {
          return fail(err);
        }
        currentReq = req;

        req.on("socket", function (socket) {
          socket.once("connect", function () { connected = true; });
        });
        req.on("error", fail);

        req.on("response", function (res) {
          const status = res.statusCode;
          chain.push({ url: urlString, status: status });

          if (json && status >= 300 && status < 400) {
            res.destroy();
            return fail(new GuardedFetchError("redirected", "answered " + status + "; the JSON mode never follows a redirect"));
          }

          if (REDIRECT_STATUSES.indexOf(status) !== -1 && res.headers.location) {
            res.destroy();
            if (hopNumber >= MAX_REDIRECTS) {
              return fail(new GuardedFetchError("too_many_redirects", "more than " + MAX_REDIRECTS + " redirects"));
            }
            let next;
            try {
              next = new URL(res.headers.location, urlString).href;
            } catch (e) {
              return fail(new GuardedFetchError("invalid_url", "unparseable redirect " + String(res.headers.location).slice(0, 200)));
            }
            redirects.push(next);
            return hop(next, hopNumber + 1);
          }

          const base = { status: status, url: urlString, headers: res.headers };

          const answered2xx = status >= 200 && status < 300;

          // Not a success: nothing in the body is used, so none of it is read.
          // The JSON mode reads it (under the same limits), so a caller can classify it.
          if (!answered2xx && !json) {
            res.destroy();
            return succeed(Object.assign(base, { ok: false, body: null, bytes: 0 }));
          }

          const contentType = String(res.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
          const isHtml = ALLOWED_CONTENT_TYPES.indexOf(contentType) !== -1;
          if (json) {
            if (answered2xx && contentType !== "application/json") {
              res.destroy();
              return fail(new GuardedFetchError("unaccepted_type", "content type " + (contentType || "(none)") + " is not application/json",
                { contentType: contentType, accepted: ["application/json"] }));
            }
          } else if (accepted) {
            if (accepted.indexOf(contentType) === -1) {
              res.destroy();
              return fail(new GuardedFetchError("unaccepted_type", "content type " + (contentType || "(none)") + " is not one of " + accepted.join(", "),
                { contentType: contentType, accepted: accepted.slice() }));
            }
          } else if (!isHtml) {
            res.destroy();
            return fail(new GuardedFetchError("not_html", "content type " + (contentType || "(none)"), { contentType: contentType }));
          }

          const declared = Number(res.headers["content-length"]);
          if (json && isFinite(declared) && declared > json.limit) {
            res.destroy();
            return fail(new GuardedFetchError("too_large", "declared " + declared + " bytes, over the JSON limit of " + json.limit));
          }
          if (!json && isFinite(declared) && declared > MAX_BODY_BYTES) {
            res.destroy();
            return fail(new GuardedFetchError("too_large", "declared " + declared + " bytes"));
          }

          const encoding = String(res.headers["content-encoding"] || "").trim().toLowerCase();
          let stream = res;
          if (encoding === "gzip" || encoding === "x-gzip") stream = res.pipe(zlib.createGunzip());
          else if (encoding === "deflate") stream = res.pipe(zlib.createInflate());
          else if (encoding === "br") stream = res.pipe(zlib.createBrotliDecompress());

          const chunks = [];
          let bytes = 0;
          stream.on("data", function (chunk) {
            bytes += chunk.length;
            if (json && bytes > json.limit) {
              if (stream !== res) stream.destroy();
              return fail(new GuardedFetchError("too_large", "more than " + json.limit + " bytes of JSON body"));
            }
            if (!json && bytes > MAX_BODY_BYTES) {
              if (stream !== res) stream.destroy();
              return fail(new GuardedFetchError("too_large", "more than " + MAX_BODY_BYTES + " bytes of body"));
            }
            chunks.push(chunk);
          });
          stream.on("error", fail);
          res.on("aborted", function () { fail(new GuardedFetchError("network", "the response was cut off")); });
          stream.on("end", function () {
            if (settled) return;
            const body = new TextDecoder("utf-8").decode(Buffer.concat(chunks));
            const challenge = challengeReason(res.headers, body, isHtml);
            if (challenge) return fail(new GuardedFetchError("challenge", challenge));
            succeed(Object.assign(base, { ok: answered2xx, body: body, bytes: bytes, contentType: contentType }));
          });
        });

        req.end(json && json.payload ? json.payload : undefined);
      }

      hop(String(rawUrl || ""), 0);
    });
  }
}

/* What the person who typed the URL is told. Blocked, unresolvable, refused,
   and timed-out-before-connecting are deliberately indistinguishable. */
function publicMessage(err) {
  switch (err && err.code) {
    case "invalid_url":
      return "That address can't be fetched. Only http:// and https:// addresses on the standard ports (80 and 443), without a username or password, are allowed.";
    case "timeout":
      return err.connected ? "That website did not finish responding within 10 seconds." : UNREACHABLE_MESSAGE;
    case "too_large":
      return "That page is larger than 3 MB, so it was not read.";
    case "not_html":
      return "That address returned " + (err.contentType || "no content type") + ", not an HTML page.";
    case "unaccepted_type":
      return "That address returned " + (err.contentType || "no content type") + ", not " + (err.accepted || []).join(" or ") + ".";
    case "challenge":
      return "That website answered with a bot-check page instead of its content, so there was nothing real to read.";
    case "too_many_redirects":
      return "That address redirected more than 5 times.";
    default:
      return UNREACHABLE_MESSAGE;
  }
}

/* For the server log only. */
function logLine(err) {
  return err && err.guardedFetch ? err.code + " — " + err.detail : String((err && err.message) || err);
}

const DEFAULT_FETCH = createGuardedFetch();

/* resolvePublicHost(host, deps): deps.resolve stands in for dns.lookup (the checks). */
function resolvePublicHost(host, deps) {
  return (deps ? createGuardedFetch(deps) : DEFAULT_FETCH).resolvePublicHost(host);
}

module.exports = {
  guardedFetch: DEFAULT_FETCH,
  guardedJsonRequest: DEFAULT_FETCH.json,
  resolvePublicHost: resolvePublicHost,
  createGuardedFetch: createGuardedFetch,
  JSON_MAX_BODY_BYTES: JSON_MAX_BODY_BYTES,
  JSON_MAX_BODY_BYTES_CEILING: JSON_MAX_BODY_BYTES_CEILING,
  JSON_MAX_UPLOAD_BYTES: JSON_MAX_UPLOAD_BYTES,
  JSON_MAX_UPLOAD_BYTES_CEILING: JSON_MAX_UPLOAD_BYTES_CEILING,
  JSON_MULTIPART_PREFIX: JSON_MULTIPART_PREFIX,
  JSON_MIN_TIMEOUT_MS: JSON_MIN_TIMEOUT_MS,
  JSON_MAX_TIMEOUT_MS: JSON_MAX_TIMEOUT_MS,
  isBlockedAddress: isBlockedAddress,
  publicMessage: publicMessage,
  logLine: logLine,
  GuardedFetchError: GuardedFetchError,
  UNREACHABLE_MESSAGE: UNREACHABLE_MESSAGE,
  MAX_REDIRECTS: MAX_REDIRECTS,
  TOTAL_TIMEOUT_MS: TOTAL_TIMEOUT_MS,
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  ALLOWED_PORTS: ALLOWED_PORTS,
  BLOCKED_IPV4: BLOCKED_IPV4,
  BLOCKED_IPV6: BLOCKED_IPV6
};
