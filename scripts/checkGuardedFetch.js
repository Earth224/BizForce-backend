/* ══════════════════════════════════════════════════════════════════════════
   checkGuardedFetch.js — the server fetches only public web pages, and says
   nothing about the ones it refuses.

   WHY THIS EXISTS. POST /api/agents/seo/optimize fetched whatever URL it was
   given and returned the page to the caller: a subscriber could read the
   server's own network. lib/guardedFetch.js is the fix, and every guard in it
   is proved here, each by a test that goes red when that guard is removed.

   WHAT THIS PROVES
     1. ADDRESSES. Every blocked IPv4 range refuses its first, last and a middle
        address; the addresses just outside each edge are allowed unless another
        range claims them. IPv6 allows only 2000::/3, carves out its blocked
        ranges, and judges IPv4-mapped addresses as the IPv4 they map to.
     2. THE URL. Only http/https, only ports 80 and 443, no credentials, and IP
        literals — in every spelling the URL parser accepts — refused before
        any connection.
     3. NAMES. A name resolving to a private address is refused; so is a name
        with ANY private address among several; a public one is fetched.
     4. REBINDING. A resolver that answers public then private is asked once,
        and the socket goes to the public address it checked.
     5. REDIRECTS. A redirect to a private name, a private literal or a bad
        port is refused; 5 redirects are followed, the 6th is refused.
     6. TIMEOUT. A server that never answers, and one that drips its body, are
        both cut off at 10 s in total. A lookup that never answers is too.
     7. SIZE. A declared 4 MB body, a streamed 3 MB + 1, and a 20 MB gzip bomb
        are refused; exactly 3 MB is read; gzip is decoded.
     8. CONTENT TYPE. JSON, PDF and no content type are refused; text/html with
        a charset and application/xhtml+xml are read.
     9. CHALLENGE PAGES served with 200 are refused; a page that merely says
        "just a moment" in its text is not.
    10. NOTHING LEAKS. Blocked, unresolvable, refused and timed-out-before-
        connecting give the caller one identical message.
    11. THE ROUTE. server.js's live POST /api/agents/seo/optimize refuses
        private targets with that message; /api/seo/audit and seo_audit are gone
        from the backend and the frontend.
    12. options.accept (for robots.txt and sitemaps). The default still refuses
        text/plain and XML with the message it always had. The option reads
        only the types it lists, matched on the media type alone and without
        regard to case, and refuses HTML unless HTML is listed. With it set,
        every blocked range is refused again as a literal and as a name, as are
        bad schemes, ports and credentials, redirects to blocked addresses, a
        6th redirect, rebinding, a 4 MB / 3 MB + 1 / gzip-bomb text/plain body
        and a text/plain answer that hangs or drips past 10 s. Challenge
        headers still refuse; a <title> is judged only in HTML. Every result
        carries its chain, every hop in order with its status; a reached 404
        is returned, with or without the option, exactly as before, while a
        blocked address is thrown.
    13. THE JSON MODE (guardedJsonRequest, NAMED Nov 3 2026 for Connect
        Mastodon). https on 443 only; every blocked literal and name refused
        before connecting; one resolution against rebinding; GET or POST only
        (NAMED Nov 7 2026, YouTube uploads: GET, POST or DELETE, see 13b;
        NAMED Nov 8 2026, Etsy store connection: GET, POST, PUT or DELETE,
        a PUT carrying exactly one JSON object, see 13b; NAMED Nov 8 2026,
        Amazon store connection: GET, POST, PUT, PATCH or DELETE, a PATCH
        held to the PUT's rules, see 13b);
        no redirect followed; 1 MB of body after decompression; a 2xx must be
        JSON; a non-2xx is returned with its json; only three answer headers
        come back; the Authorization value is in no error, detail, log line or
        public message; the same 10 s limit; the HTML mode unchanged.
        13i (NAMED Nov 3 2026, store connections): exposeHeaders is at most
        8 lowercase names and never set-cookie or authorization; maxBytes may
        rise to 8 MB and no further (refused, never clamped), and a body over
        it fails as too_large; timeoutMs runs from 1000 to 30000 and is the
        limit used; every default is unchanged.
     15 (NAMED Nov 6 2026, Outlook sign-in). The JSON mode's form option: a
        plain object of strings, sent URL-encoded and always labelled
        application/x-www-form-urlencoded; form with a body, with a caller
        Content-Type, on a GET, or of any other shape is a TypeError before
        any lookup.

   No request leaves the machine. Names resolve through a stub; sockets land on
   a local server through a stub dial that asks the fetcher's OWN lookup where
   to go, exactly as Node does, so a guard that is removed lets a test request
   through and the test sees it arrive.

   MUTATE=<name> removes one guard at compile time (nothing is written to
   lib/guardedFetch.js on disk). MUTATE=all runs every mutation in its own
   process and passes only if every one of them fails.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const path = require("path");
const fs = require("fs");
const http = require("http");
const net = require("net");
const zlib = require("zlib");
const Module = require("module");
const { spawnSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const LIB_PATH = path.join(REPO, "lib", "guardedFetch.js");
const SERVER_PATH = path.join(REPO, "server.js");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

/* ── the mutations ──────────────────────────────────────────────────────── */
const MUTATIONS = {
  "scheme":           [["  if (url.protocol !== \"http:\" && url.protocol !== \"https:\") {", "  if (false) {"]],
  "credentials":      [["  if (url.username || url.password) {", "  if (false) {"]],
  "port":             [["  if (ALLOWED_PORTS.indexOf(port) === -1) {", "  if (false) {"]],
  "literal":          [["  if (net.isIP(hostname)) {\n    const verdict", "  if (false) {\n    const verdict"]],
  "ipv4-ranges":      [["    if (inRange4(n, cidr)) return cidr", "    if (false) return cidr"]],
  "ipv6-allowlist":   [["  if (!inRange6(n, \"2000::/3\")) {", "  if (false) {"]],
  "ipv6-carveouts":   [["    if (inRange6(n, cidr)) return cidr", "    if (false) return cidr"]],
  "mapped":           [["    const verdict = classifyIPv4(dotted);", "    const verdict = null;"]],
  /* NAMED (Nov 5 2026, mailbox connection): BEFORE guardedLookup was declared inside run(), and these two anchors
     carried its 10-space indent. AFTER it is declared once in createGuardedFetch's scope (so resolvePublicHost uses
     the same function, not a copy), with a 6-space indent; the mutations are the same. */
  "all-addresses":    [["      for (const a of addresses) {", "      for (const a of addresses.slice(0, 1)) {"]],
  "rebind":           [["      if (lookupOptions && lookupOptions.all) return callback(null, addresses);\n      return callback(null, addresses[0].address, addresses[0].family);",
                        "      return resolve(hostname, { all: true, verbatim: true }, function (e2, again) {\n        if (lookupOptions && lookupOptions.all) return callback(e2, again);\n        return callback(e2, again[0].address, again[0].family);\n      });"]],
  "redirect-recheck": [["          target = checkUrl(urlString);", "          target = hopNumber === 0 ? checkUrl(urlString) : (function (u) { return { url: u, hostname: u.hostname.replace(/^\\[|\\]$/g, \"\"), port: Number(u.port) || 80, isHttps: u.protocol === \"https:\" }; })(new URL(urlString));"],
                       ["          lookup: guardedLookup,", "          lookup: hopNumber === 0 ? guardedLookup : function (h, o, cb) { resolve(h, { all: true, verbatim: true }, function (e, a) { return o && o.all ? cb(e, a) : cb(e, a[0].address, a[0].family); }); },"]],
  "redirect-limit":   [["            if (hopNumber >= MAX_REDIRECTS) {", "            if (false) {"]],
  "timeout":          [["      const timer = setTimeout(function () {\n", "      const timer = setTimeout(function () {\n        return;\n"]],
  /* NAMED (Nov 3 2026, store connections): BEFORE these two anchors were "if (isFinite(declared) && declared >
     MAX_BODY_BYTES) {" and "if (bytes > MAX_BODY_BYTES) {". AFTER both start "!json && ", because the JSON mode now
     has its own limit of up to 8 MB; the mutations still remove the whole 3 MB HTML-mode check, as before. */
  "size-declared":    [["          if (!json && isFinite(declared) && declared > MAX_BODY_BYTES) {", "          if (false) {"]],
  "size-stream":      [["            if (!json && bytes > MAX_BODY_BYTES) {", "            if (false) {"]],
  "content-type":     [["          } else if (!isHtml) {", "          } else if (false) {"]],
  "challenge":        [["            if (challenge) return fail(", "            if (false) return fail("]],
  "leak-blocked":     [["    default:\n      return UNREACHABLE_MESSAGE;", "    case \"blocked\":\n      return \"That address is private.\";\n    default:\n      return UNREACHABLE_MESSAGE;"]],
  "leak-timeout":     [["      return err.connected ? \"That website did not finish", "      return true ? \"That website did not finish"]],
  // options.accept may change the content-type rule and nothing else
  /* NAMED (Nov 5 2026, mailbox connection): BEFORE the anchor was the verdict line inside guardedLookup, which then
     sat inside run() and could see `accepted`. AFTER guardedLookup is shared by every request and cannot, so the
     mutation skips it at the one place a request picks its lookup, when options.accept is given. Same meaning. */
  "accept-skips-dns": [["          lookup: guardedLookup,", "          lookup: accepted ? function (h, o, cb) { resolve(h, { all: true, verbatim: true }, function (e, a) { return o && o.all ? cb(e, a) : cb(e, a[0].address, a[0].family); }); } : guardedLookup,"]],
  // NAMED (Nov 5 2026, mailbox connection): resolvePublicHost (section 14)
  "resolve-first-only":         [["      guardedLookup(name, { all: true }, function (err, addresses) {", "      resolve(name, { all: true, verbatim: true }, function (err, addresses) { if (!err && addresses && addresses.length && isBlockedAddress(addresses[0].address)) err = new GuardedFetchError(\"blocked\", \"the first address\");"]],
  "resolve-blocked-allowed":    [["      guardedLookup(name, { all: true }, function (err, addresses) {", "      resolve(name, { all: true, verbatim: true }, function (err, addresses) {"]],
  "resolve-ip-literal-allowed": [["      if (net.isIP(name.replace(/^\\[|\\]$/g, \"\"))) return reject(", "      if (false) return reject("]],
  // NAMED (Nov 6 2026, Outlook sign-in): the form option (section 15)
  "form-mislabelled":           [["    if (formEncoded) headers[\"Content-Type\"] = \"application/x-www-form-urlencoded\";\n", ""]],
  "form-with-body-allowed":     [["      if (opts.body !== undefined && opts.body !== null) return Promise.reject(new TypeError(\"guardedJsonRequest: form and body cannot both be given\"));\n", ""]],
  "form-content-type-override": [["        return Promise.reject(new TypeError(\"guardedJsonRequest: a form sets its own Content-Type; do not pass one\"));\n", ""]],
  "accept-skips-url": [["          target = checkUrl(urlString);", "          target = accepted ? (function (u) { return { url: u, hostname: u.hostname.replace(/^\\[|\\]$/g, \"\"), port: Number(u.port) || 80, isHttps: u.protocol === \"https:\" }; })(new URL(urlString)) : checkUrl(urlString);"]],
  "accept-ignored":   [["            if (accepted.indexOf(contentType) === -1) {", "            if (!isHtml) {"]],
  "accept-anything":  [["            if (accepted.indexOf(contentType) === -1) {", "            if (false) {"]],
  "title-non-html":   [["  if (!isHtml) return null;\n", ""]],
  "chain-drop-hop":   [["          chain.push({ url: urlString, status: status });", "          if (hopNumber !== 1) chain.push({ url: urlString, status: status });"]],
  // NAMED (Nov 3 2026, Connect Mastodon): the JSON mode, guardedJsonRequest (section 13)
  "json-redirect-followed": [["          if (json && status >= 300 && status < 400) {", "          if (false) {"]],
  "json-http-allowed":      [["        if (json && !target.isHttps) {", "        if (false) {"]],
  "json-port-allowed":      [["        if (json && target.port !== 443) {", "        if (false) {"]],
  "json-size-unbounded":    [["          if (json && isFinite(declared) && declared > json.limit) {", "          if (false) {"],
                             ["            if (json && bytes > json.limit) {", "            if (false) {"]],
  "json-dns-unchecked":     [["          lookup: guardedLookup,", "          lookup: json ? function (h, o, cb) { resolve(h, { all: true, verbatim: true }, function (e, a) { return o && o.all ? cb(e, a) : cb(e, a[0].address, a[0].family); }); } : guardedLookup,"]],
  "json-auth-logged":       [["        req.on(\"error\", fail);", "        req.on(\"error\", function (e) { fail(new GuardedFetchError(\"network\", (e && e.code) + \" sending \" + JSON.stringify(requestOptions.headers))); });"]],
  // NAMED (Nov 8 2026, Amazon store connection): PATCH is allowed now; this is caught by "patch", HEAD and OPTIONS (section 13b)
  "json-method-unrestricted": [["    if (JSON_METHODS.indexOf(method) === -1) {", "    if (false) {"]],
  // NAMED (Nov 8 2026, Amazon store connection): a PATCH that skips the PUT's one-JSON-object rule (section 13b)
  "patch-body-unchecked":   [["    } else if (method === \"PUT\" || method === \"PATCH\") {", "    } else if (method === \"PUT\") {"]],
  // NAMED (Nov 8 2026, Etsy store connection): a PUT that takes any body, or none (section 13b)
  "put-body-unchecked":     [["      if (putBody === undefined || putBody === null || typeof putBody !== \"object\" || Array.isArray(putBody) || Buffer.isBuffer(putBody) ||", "      if (false &&"]],
  // NAMED (Nov 3 2026, store connections): what a caller may raise in the JSON mode, and how far (section 13i)
  "expose-set-cookie":      [["const JSON_UNEXPOSABLE_HEADERS = [\"set-cookie\", \"authorization\"];", "const JSON_UNEXPOSABLE_HEADERS = [\"authorization\"];"]],
  "expose-unbounded":       [["    if (!Array.isArray(expose) || expose.length > JSON_MAX_EXPOSED_HEADERS) {", "    if (!Array.isArray(expose)) {"]],
  "maxbytes-over-ceiling":  [["    if (typeof limit !== \"number\" || !Number.isInteger(limit) || limit < 1 || limit > JSON_MAX_BODY_BYTES_CEILING) {", "    if (typeof limit !== \"number\" || !Number.isInteger(limit) || limit < 1) {"]],
  "timeout-unbounded":      [["timeoutMs < JSON_MIN_TIMEOUT_MS || timeoutMs > JSON_MAX_TIMEOUT_MS) {", "false) {"]],
  "too-large-indistinct":   [["return fail(new GuardedFetchError(\"too_large\", \"more than \" + json.limit + \" bytes of JSON body\"));", "return fail(new GuardedFetchError(\"network\", \"more than \" + json.limit + \" bytes of JSON body\"));"],
                             ["return fail(new GuardedFetchError(\"too_large\", \"declared \" + declared + \" bytes, over the JSON limit of \" + json.limit));", "return fail(new GuardedFetchError(\"network\", \"declared \" + declared + \" bytes, over the JSON limit of \" + json.limit));"]]
};
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  const realCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(LIB_PATH)) {
      content = content.replace(/\r\n/g, "\n");
      for (const [from, to] of edits) {
        content = MUT.replaceOnce(content, from, to, MUTATE);
      }
      console.log("\n!! MUTATION: " + MUTATE);
    }
    return realCompile.call(this, content, filename);
  };
}

const lib = require(LIB_PATH);

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── the local server every allowed socket lands on ─────────────────────── */
const hits = {};
const THREE_MB = 3 * 1024 * 1024;
/* Large bodies go out in 64 KB writes. One res.end() of 3 MB on Windows loopback
   intermittently stalls about 2 KB short and then resets — plain http.get sees
   it too, with no fetcher involved — which would read as a timeout here. */
function pump(res, body) {
  let off = 0;
  (function more() {
    while (off < body.length) {
      const ok = res.write(body.subarray(off, off + 65536));
      off += 65536;
      if (!ok) return res.once("drain", more);
    }
    res.end();
  })();
}
function page(title, extra) { return "<!doctype html><html><head><title>" + title + "</title></head><body><h1>" + title + "</h1>" + (extra || "") + "</body></html>"; }
const ROUTES = {
  "/":              function (req, res) { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(page("Home")); },
  "/landing":       function (req, res) { res.writeHead(200, { "Content-Type": "text/html" }); res.end(page("Landing")); },
  "/r/private":     function (req, res) { res.writeHead(302, { Location: "http://internal.test/landing" }); res.end(); },
  "/r/literal":     function (req, res) { res.writeHead(301, { Location: "http://127.0.0.1/landing" }); res.end(); },
  "/r/metadata":    function (req, res) { res.writeHead(307, { Location: "http://169.254.169.254/landing" }); res.end(); },
  "/r/port":        function (req, res) { res.writeHead(302, { Location: "http://public.test:8080/landing" }); res.end(); },
  "/r/relative":    function (req, res) { res.writeHead(302, { Location: "/landing" }); res.end(); },
  "/r/relative-404": function (req, res) { res.writeHead(302, { Location: "/missing" }); res.end(); },
  "/hang":          function () { /* never answers */ },
  "/drip":          function (req, res) {
    res.writeHead(200, { "Content-Type": "text/html" });
    const t = setInterval(function () { if (res.writableEnded || res.destroyed) return clearInterval(t); res.write("x"); }, 300);
    res.on("close", function () { clearInterval(t); });
  },
  "/big-declared":  function (req, res) { res.writeHead(200, { "Content-Type": "text/html", "Content-Length": String(4 * 1024 * 1024) }); res.write("<html>"); },
  "/big-stream":    function (req, res) { res.writeHead(200, { "Content-Type": "text/html" }); pump(res, Buffer.alloc(THREE_MB + 1, 97)); },
  "/exact":         function (req, res) { const head = "<html><head><title>Exact</title></head><body>"; res.writeHead(200, { "Content-Type": "text/html" }); pump(res, Buffer.from(head + "a".repeat(THREE_MB - head.length))); },
  "/bomb":          function (req, res) { res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(Buffer.alloc(20 * 1024 * 1024, 32))); },
  "/gzip":          function (req, res) { res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(page("Zipped ünïcode"))); },
  "/json":          function (req, res) { res.writeHead(200, { "Content-Type": "application/json" }); res.end("{\"a\":1}"); },
  "/pdf":           function (req, res) { res.writeHead(200, { "Content-Type": "application/pdf" }); res.end("%PDF-1.4"); },
  "/none":          function (req, res) { res.writeHead(200); res.end(page("No type")); },
  "/xhtml":         function (req, res) { res.writeHead(200, { "Content-Type": "application/xhtml+xml" }); res.end(page("XHTML")); },
  "/cf-header":     function (req, res) { res.writeHead(200, { "Content-Type": "text/html", "cf-mitigated": "challenge" }); res.end(page("Shop")); },
  "/cf-title":      function (req, res) { res.writeHead(200, { "Content-Type": "text/html" }); res.end(page("Just a moment...")); },
  "/aws-waf":       function (req, res) { res.writeHead(200, { "Content-Type": "text/html", "x-amzn-waf-action": "challenge" }); res.end(page("Shop")); },
  "/says-moment":   function (req, res) { res.writeHead(200, { "Content-Type": "text/html" }); res.end(page("Bakery", "<p>Just a moment, the oven is hot.</p>")); },
  "/missing":       function (req, res) { res.writeHead(404, { "Content-Type": "text/html" }); res.end(page("Not found")); },
  // for options.accept (section 12)
  "/robots.txt":    function (req, res) { res.writeHead(200, { "Content-Type": "text/plain" }); res.end(ROBOTS); },
  "/robots-cased":  function (req, res) { res.writeHead(200, { "Content-Type": "Text/Plain; charset=utf-8" }); res.end(ROBOTS); },
  "/sitemap.xml":   function (req, res) { res.writeHead(200, { "Content-Type": "application/xml" }); res.end(SITEMAP); },
  "/sitemap-tx":    function (req, res) { res.writeHead(200, { "Content-Type": "text/xml; charset=UTF-8" }); res.end(SITEMAP); },
  "/r/robots-private": function (req, res) { res.writeHead(302, { Location: "http://internal.test/robots.txt" }); res.end(); },
  "/r/robots-literal": function (req, res) { res.writeHead(301, { Location: "http://127.0.0.1/robots.txt" }); res.end(); },
  "/r/robots-meta": function (req, res) { res.writeHead(308, { Location: "http://metadata.test/robots.txt" }); res.end(); },
  "/r/robots-port": function (req, res) { res.writeHead(302, { Location: "http://public.test:8080/robots.txt" }); res.end(); },
  "/mix/1":         function (req, res) { res.writeHead(301, { Location: "/mix/2" }); res.end(); },
  "/mix/2":         function (req, res) { res.writeHead(308, { Location: "http://public6.test/mix/3" }); res.end(); },
  "/mix/3":         function (req, res) { res.writeHead(307, { Location: "/robots.txt" }); res.end(); },
  "/plain-hang":    function (req, res) { res.writeHead(200, { "Content-Type": "text/plain" }); res.flushHeaders(); },
  "/plain-drip":    function (req, res) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    const t = setInterval(function () { if (res.writableEnded || res.destroyed) return clearInterval(t); res.write("x"); }, 300);
    res.on("close", function () { clearInterval(t); });
  },
  "/plain-declared": function (req, res) { res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(4 * 1024 * 1024) }); res.write("User-agent"); },
  "/plain-stream":  function (req, res) { res.writeHead(200, { "Content-Type": "text/plain" }); pump(res, Buffer.alloc(THREE_MB + 1, 97)); },
  "/plain-exact":   function (req, res) { res.writeHead(200, { "Content-Type": "text/plain" }); pump(res, Buffer.alloc(THREE_MB, 97)); },
  "/plain-bomb":    function (req, res) { res.writeHead(200, { "Content-Type": "text/plain", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(Buffer.alloc(20 * 1024 * 1024, 32))); },
  "/plain-gzip":    function (req, res) { res.writeHead(200, { "Content-Type": "text/plain", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(ROBOTS)); },
  "/plain-cf":      function (req, res) { res.writeHead(200, { "Content-Type": "text/plain", "cf-mitigated": "challenge" }); res.end(ROBOTS); },
  "/plain-aws":     function (req, res) { res.writeHead(200, { "Content-Type": "text/plain", "x-amzn-waf-action": "captcha" }); res.end(ROBOTS); },
  "/plain-moment":  function (req, res) { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("# <title>Just a moment...</title>\n" + ROBOTS); }
};
const ROBOTS = "User-agent: *\nDisallow: /private/\nSitemap: https://public.test/sitemap.xml\n";
const SITEMAP = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://public.test/</loc></url></urlset>\n";
// for the JSON mode (section 13)
const ONE_MB = 1024 * 1024;
function sendJson(res, status, value, extraHeaders) {
  res.writeHead(status, Object.assign({ "Content-Type": "application/json; charset=utf-8" }, extraHeaders || {}));
  res.end(JSON.stringify(value));
}
Object.assign(ROUTES, {
  "/j/ok":           function (req, res) { sendJson(res, 200, { id: "109", username: "alice" }); },
  "/j/302":          function (req, res) { res.writeHead(302, { Location: "/j/ok" }); res.end(); },
  "/j/301":          function (req, res) { res.writeHead(301, { Location: "https://public.test/j/ok" }); res.end(); },
  "/j/307":          function (req, res) { res.writeHead(307, { Location: "/j/ok" }); res.end(); },
  "/j/308":          function (req, res) { res.writeHead(308, { Location: "/j/ok" }); res.end(); },
  "/j/300":          function (req, res) { res.writeHead(300, { "Content-Type": "application/json" }); res.end("{}"); },
  "/j/big-declared": function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(2 * ONE_MB) }); res.write("{"); },
  "/j/big-stream":   function (req, res) { res.writeHead(200, { "Content-Type": "application/json" }); pump(res, Buffer.from("\"" + "a".repeat(ONE_MB - 1) + "\"")); },
  "/j/exact":        function (req, res) { res.writeHead(200, { "Content-Type": "application/json" }); pump(res, Buffer.from("\"" + "a".repeat(ONE_MB - 2) + "\"")); },
  "/j/small":        function (req, res) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ pad: "a".repeat(5000) })); },
  "/j/bomb":         function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(Buffer.from("\"" + " ".repeat(8 * ONE_MB) + "\""))); },
  "/j/gzip":         function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(JSON.stringify({ zipped: true }))); },
  "/j/html":         function (req, res) { res.writeHead(200, { "Content-Type": "text/html" }); res.end(page("Not an API")); },
  "/j/notjson":      function (req, res) { res.writeHead(200, { "Content-Type": "application/json" }); res.end("nope"); },
  "/j/401":          function (req, res) { sendJson(res, 401, { error: "The access token is invalid" }); },
  "/j/429":          function (req, res) { sendJson(res, 429, { error: "Too many requests" }, { "Retry-After": "120", "X-RateLimit-Reset": "2026-11-03T20:00:00.000Z", "X-RateLimit-Remaining": "0", "Set-Cookie": "s=1" }); },
  "/j/500-html":     function (req, res) { res.writeHead(500, { "Content-Type": "text/html" }); res.end(page("Error")); },
  "/j/hang":         function () { /* never answers */ },
  // NAMED (Nov 3 2026, store connections): the options a caller may raise, up to their ceilings (section 13i)
  // gzipped, so the decompressed size is what is counted and Windows loopback never carries megabytes (see pump)
  "/j/five-mb":      function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(Buffer.from("\"" + "a".repeat(5 * ONE_MB) + "\""))); },
  "/j/over-ceiling": function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip" }); res.end(zlib.gzipSync(Buffer.from("\"" + "a".repeat(8 * ONE_MB - 1) + "\""))); },
  "/j/declared-9mb": function (req, res) { res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(9 * ONE_MB) }); res.write("{"); },
  "/j/paged":        function (req, res) { sendJson(res, 200, [{ id: 1 }], { "Link": "<https://public.test/j/paged?page=2>; rel=\"next\"", "X-WP-TotalPages": "3", "Retry-After": "1", "Set-Cookie": "s=1", "X-Other": "x" }); },
  // NAMED (Nov 7 2026, YouTube uploads): a 2xx with no body at all, as videos.delete and the revoke answer (section 13b)
  "/j/empty204":     function (req, res) { res.writeHead(204); res.end(); },
  "/j/echo":         function (req, res) {
    const chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { sendJson(res, 200, { method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") }); });
  }
});
for (let i = 1; i <= 6; i++) {
  ROUTES["/chain/" + i] = (function (n) { return function (req, res) { res.writeHead(302, { Location: n > 1 ? "/chain/" + (n - 1) : "/landing" }); res.end(); }; })(i);
}
const server = http.createServer(function (req, res) {
  const p = req.url.split("?")[0];
  hits[p] = (hits[p] || 0) + 1;
  (ROUTES[p] || ROUTES["/missing"])(req, res);
});

/* ── the stubs ─────────────────────────────────────────────────────────── */
const PUBLIC_V4 = "93.184.216.34";
const NAMES = {
  "public.test":     [{ address: PUBLIC_V4, family: 4 }],
  "public6.test":    [{ address: "2606:2800:220:1::1", family: 6 }],
  "internal.test":   [{ address: "10.0.0.5", family: 4 }],
  "loop.test":       [{ address: "127.0.0.1", family: 4 }],
  "metadata.test":   [{ address: "169.254.169.254", family: 4 }],
  "railway.test":    [{ address: "fd12:3456:789a::5", family: 6 }],
  "mixed.test":      [{ address: PUBLIC_V4, family: 4 }, { address: "10.0.0.5", family: 4 }],
  "refused.test":    [{ address: PUBLIC_V4, family: 4 }]
};
let resolverCalls = {};
let rebindCalls = 0;
function resolve(hostname, options, cb) {
  resolverCalls[hostname] = (resolverCalls[hostname] || 0) + 1;
  if (hostname === "rebind.test") {
    rebindCalls++;
    return cb(null, [{ address: rebindCalls === 1 ? PUBLIC_V4 : "127.0.0.1", family: 4 }]);
  }
  if (hostname === "silent.test") return;  // never answers
  if (NAMES[hostname]) return cb(null, NAMES[hostname]);
  const e = new Error("getaddrinfo ENOTFOUND " + hostname); e.code = "ENOTFOUND"; return cb(e);
}
let dialed = [];
let closedPort = 0;
function dial(options) {
  const host = String(options.host || options.hostname || "").replace(/^\[|\]$/g, "");
  const port = host === "refused.test" ? closedPort : server.address().port;
  if (net.isIP(host)) {
    dialed.push({ host: host, address: host });
    return net.connect({ host: "127.0.0.1", port: port });
  }
  // net.connect calls this exactly where it would call the fetcher's lookup;
  // the fetcher's answer is recorded, then the socket is pointed here instead.
  return net.connect({ host: host, port: port, lookup: function (h, o, cb) {
    options.lookup(h, o, function (err, addresses) {
      if (err) return cb(err);
      dialed.push({ host: host, address: Array.isArray(addresses) ? addresses[0].address : addresses });
      return o && o.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    });
  } });
}
const fetchStub = lib.createGuardedFetch({ resolve: resolve, dial: dial });

/* The JSON mode is https on 443 only, so its requests cannot land on the plain
   local server through dial. `request` stands in for https.request instead: it
   records the options it was handed and connects to the local server over
   plain http, asking the fetcher's OWN lookup where to go first, exactly as
   Node would. A guard that is removed lets a request through to the server. */
let jsonSeen = [];
function jsonRequest(options) {
  jsonSeen.push({ protocol: options.protocol, port: options.port, method: options.method, path: options.path, agent: options.agent,
    hostname: options.hostname, headers: Object.assign({}, options.headers) });
  const host = String(options.hostname || "").replace(/^\[|\]$/g, "");
  const port = host === "refused.test" ? closedPort : server.address().port;
  const base = { host: "127.0.0.1", port: port, path: options.path, method: options.method, headers: options.headers, agent: false };
  if (net.isIP(host)) {
    dialed.push({ host: host, address: host });
    return http.request(base);
  }
  return http.request(Object.assign(base, { host: host, lookup: function (h, o, cb) {
    options.lookup(h, o, function (err, addresses) {
      if (err) return cb(err);
      dialed.push({ host: host, address: Array.isArray(addresses) ? addresses[0].address : addresses });
      return o && o.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    });
  } }));
}
const jsonStub = lib.createGuardedFetch({ resolve: resolve, request: jsonRequest }).json;
async function attemptJson(url, opts) {
  const t0 = Date.now();
  try {
    return { ok: true, value: await jsonStub(url, opts), ms: Date.now() - t0 };
  } catch (err) {
    return { ok: false, err: err, ms: Date.now() - t0 };
  }
}

async function attempt(url, fetcher, extra) {
  const t0 = Date.now();
  try {
    const r = await (fetcher || fetchStub)(url, Object.assign({ userAgent: "checkGuardedFetch" }, extra || {}));
    return { ok: true, value: r, ms: Date.now() - t0 };
  } catch (err) {
    return { ok: false, err: err, ms: Date.now() - t0 };
  }
}
function code(a) { return a.ok ? "fetched " + a.value.status : (a.err && a.err.code) || String(a.err); }
function withWatchdog(promise, ms) {
  return Promise.race([promise, new Promise(function (r) { setTimeout(function () { r({ ok: false, err: { code: "WATCHDOG — still running after " + ms + " ms" }, ms: ms }); }, ms); })]);
}

/* ── 1. addresses ──────────────────────────────────────────────────────── */
function int2ip(n) { return [24, 16, 8, 0].map(function (s) { return Math.floor(n / 2 ** s) % 256; }).join("."); }
function ip2int(ip) { return ip.split(".").reduce(function (a, p) { return a * 256 + Number(p); }, 0); }
function sectionAddresses() {
  console.log("\n══ 1. addresses ══");
  const EXPECTED_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"];
  check("BLOCKED_IPV4 is exactly the 15 named ranges", JSON.stringify(lib.BLOCKED_IPV4.map(function (r) { return r[0]; })) === JSON.stringify(EXPECTED_V4));
  for (const cidr of EXPECTED_V4) {
    const [base, bits] = cidr.split("/");
    const start = ip2int(base), size = 2 ** (32 - Number(bits));
    const inside = [start, start + Math.floor(size / 2), start + size - 1].map(int2ip);
    const blocked = inside.filter(function (ip) { return lib.isBlockedAddress(ip); });
    check(cidr + " refuses " + inside.join(", "), blocked.length === 3, "refused " + blocked.join(","));
  }
  const ALLOWED_V4 = ["1.1.1.1", "8.8.8.8", PUBLIC_V4, "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.0",
    "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0", "223.255.255.255"];
  const wronglyBlocked = ALLOWED_V4.filter(function (ip) { return lib.isBlockedAddress(ip); });
  check("public IPv4 addresses just outside the edges are allowed (" + ALLOWED_V4.length + ")", wronglyBlocked.length === 0, wronglyBlocked.join(","));

  const BLOCKED_V6 = {
    "::": "unspecified", "::1": "loopback", "::7f00:1": "IPv4-compatible", "64:ff9b::7f00:1": "NAT64", "64:ff9b:1::1": "local NAT64",
    "100::1": "discard", "fc00::1": "unique local", "fd12:3456:789a::5": "unique local (Railway private network)", "fe80::1": "link-local",
    "fe80::1%eth0": "link-local with zone", "fec0::1": "site-local", "ff02::1": "multicast", "2001::1": "Teredo", "2001:1ff::1": "IETF assignments end",
    "2001:db8::1": "documentation", "2002:7f00:1::1": "6to4", "3fff::1": "documentation (RFC 9637)", "1fff:ffff::1": "below 2000::/3", "4000::1": "above 2000::/3",
    "::ffff:127.0.0.1": "IPv4-mapped loopback", "::ffff:7f00:1": "IPv4-mapped loopback, hex", "::ffff:10.1.2.3": "IPv4-mapped private", "::ffff:169.254.169.254": "IPv4-mapped metadata"
  };
  for (const ip of Object.keys(BLOCKED_V6)) {
    check("IPv6 " + ip + " refused (" + BLOCKED_V6[ip] + ")", !!lib.isBlockedAddress(ip));
  }
  const ALLOWED_V6 = ["2606:4700:4700::1111", "2a00:1450:4001::200e", "2001:200::1", "2606:2800:220:1::1", "::ffff:8.8.8.8"];
  const v6Wrong = ALLOWED_V6.filter(function (ip) { return lib.isBlockedAddress(ip); });
  check("public IPv6 addresses are allowed (" + ALLOWED_V6.join(", ") + ")", v6Wrong.length === 0, v6Wrong.join(","));
}

/* ── 2. the URL ────────────────────────────────────────────────────────── */
async function sectionUrl() {
  console.log("\n══ 2. the URL ══");
  for (const u of ["ftp://public.test/", "file:///etc/passwd", "gopher://public.test/", "data:text/html,<h1>x</h1>"]) {
    const a = await attempt(u);
    check(u + " refused invalid_url", !a.ok && a.err.code === "invalid_url", code(a));
  }
  for (const u of ["http://public.test:8080/", "http://public.test:22/", "https://public.test:6379/", "http://public.test:3000/"]) {
    const a = await attempt(u);
    check(u + " refused invalid_url (port)", !a.ok && a.err.code === "invalid_url", code(a));
  }
  const cred = await attempt("http://user:pass@public.test/");
  check("http://user:pass@public.test/ refused invalid_url (credentials)", !cred.ok && cred.err.code === "invalid_url", code(cred));
  const before = Object.values(hits).reduce(function (a, b) { return a + b; }, 0);
  for (const u of ["http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://0177.0.0.1/", "http://127.1/", "http://[::1]/",
    "http://[::ffff:127.0.0.1]/", "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[fd00::1]/", "http://0.0.0.0/", "http://192.168.1.1/"]) {
    const a = await attempt(u);
    check(u + " refused blocked, before connecting", !a.ok && a.err.code === "blocked", code(a));
  }
  const after = Object.values(hits).reduce(function (a, b) { return a + b; }, 0);
  check("no literal reached the server", after === before, (after - before) + " requests arrived");
  const good = await attempt("http://public.test/");
  check("http://public.test/ (public) is fetched", good.ok && good.value.ok && /<h1>Home<\/h1>/.test(good.value.body), code(good));
  const good6 = await attempt("http://public6.test/");
  check("http://public6.test/ (public IPv6) is fetched", good6.ok && good6.value.ok, code(good6));
}

/* ── 3. names and 4. rebinding ─────────────────────────────────────────── */
async function sectionNames() {
  console.log("\n══ 3. names ══");
  hits["/"] = 0;
  for (const name of ["internal.test", "loop.test", "metadata.test", "railway.test", "mixed.test"]) {
    const a = await attempt("http://" + name + "/");
    check(name + " (" + NAMES[name].map(function (x) { return x.address; }).join(", ") + ") refused blocked", !a.ok && a.err.code === "blocked", code(a));
  }
  check("none of them reached the server", !hits["/"], (hits["/"] || 0) + " arrived");
  const real = await attempt("http://localhost/", lib.guardedFetch);
  check("localhost through the real resolver is refused blocked", !real.ok && real.err.code === "blocked", code(real));

  console.log("\n══ 4. rebinding ══");
  rebindCalls = 0; resolverCalls = {}; dialed = [];
  const a = await attempt("http://rebind.test/");
  const d = dialed.filter(function (x) { return x.host === "rebind.test"; });
  check("a resolver answering public then private is asked exactly once", resolverCalls["rebind.test"] === 1, resolverCalls["rebind.test"]);
  check("the socket went to the address that was checked (" + PUBLIC_V4 + ")", d.length === 1 && d[0].address === PUBLIC_V4, JSON.stringify(d));
  check("the fetch succeeded", a.ok && a.value.ok, code(a));
}

/* ── 5. redirects ──────────────────────────────────────────────────────── */
async function sectionRedirects() {
  console.log("\n══ 5. redirects ══");
  hits["/landing"] = 0;
  for (const [p, want] of [["/r/private", "blocked"], ["/r/literal", "blocked"], ["/r/metadata", "blocked"], ["/r/port", "invalid_url"]]) {
    const a = await attempt("http://public.test" + p);
    check(p + " → refused " + want + " at the second hop", !a.ok && a.err.code === want, code(a));
  }
  check("no redirect target was reached", !hits["/landing"], (hits["/landing"] || 0) + " arrived at /landing");
  const rel = await attempt("http://public.test/r/relative");
  check("a relative redirect is followed", rel.ok && rel.value.ok && rel.value.redirects.length === 1, code(rel));
  const five = await attempt("http://public.test/chain/5");
  check("5 redirects are followed", five.ok && five.value.ok && five.value.redirects.length === 5, code(five) + " after " + (five.ok ? five.value.redirects.length : "?"));
  const six = await attempt("http://public.test/chain/6");
  check("a 6th redirect is refused too_many_redirects", !six.ok && six.err.code === "too_many_redirects", code(six));
}

/* ── 6. timeout ────────────────────────────────────────────────────────── */
async function sectionTimeout() {
  console.log("\n══ 6. timeout (three at once, about 10 s) ══");
  check("TOTAL_TIMEOUT_MS is 10000", lib.TOTAL_TIMEOUT_MS === 10000, lib.TOTAL_TIMEOUT_MS);
  const [hang, drip, silent] = await Promise.all([
    withWatchdog(attempt("http://public.test/hang"), 15000),
    withWatchdog(attempt("http://public.test/drip"), 15000),
    withWatchdog(attempt("http://silent.test/"), 15000)
  ]);
  check("a server that never answers is cut off at 10 s", !hang.ok && hang.err.code === "timeout" && hang.ms >= 9500 && hang.ms < 12000, code(hang) + " in " + hang.ms + " ms");
  check("a body dripped a byte at a time is cut off at 10 s in total", !drip.ok && drip.err.code === "timeout" && drip.ms < 12000, code(drip) + " in " + drip.ms + " ms");
  check("a lookup that never answers is cut off at 10 s", !silent.ok && silent.err.code === "timeout" && silent.ms < 12000, code(silent) + " in " + silent.ms + " ms");
  check("after connecting, the caller is told it was slow", !hang.ok && lib.publicMessage(hang.err) === "That website did not finish responding within 10 seconds.", !hang.ok && lib.publicMessage(hang.err));
  return silent;
}

/* ── 7. size ───────────────────────────────────────────────────────────── */
async function sectionSize() {
  console.log("\n══ 7. size ══");
  check("MAX_BODY_BYTES is 3 MB", lib.MAX_BODY_BYTES === THREE_MB, lib.MAX_BODY_BYTES);
  const declared = await withWatchdog(attempt("http://public.test/big-declared"), 15000);
  check("a declared 4 MB body is refused too_large without waiting for it", !declared.ok && declared.err.code === "too_large" && declared.ms < 5000, code(declared) + " in " + declared.ms + " ms");
  const stream = await attempt("http://public.test/big-stream");
  check("a streamed 3 MB + 1 byte body is refused too_large", !stream.ok && stream.err.code === "too_large", code(stream));
  const bomb = await attempt("http://public.test/bomb");
  check("a gzip that expands to 20 MB is refused too_large", !bomb.ok && bomb.err.code === "too_large", code(bomb));
  const exact = await attempt("http://public.test/exact");
  check("exactly 3 MB is read", exact.ok && exact.value.ok && exact.value.bytes === THREE_MB, code(exact));
  const gz = await attempt("http://public.test/gzip");
  check("a gzip body is decoded as UTF-8", gz.ok && gz.value.ok && /Zipped ünïcode/.test(gz.value.body), code(gz));
}

/* ── 8. content type ───────────────────────────────────────────────────── */
async function sectionContentType() {
  console.log("\n══ 8. content type ══");
  for (const [p, label] of [["/json", "application/json"], ["/pdf", "application/pdf"], ["/none", "no content type"]]) {
    const a = await attempt("http://public.test" + p);
    check(label + " is refused not_html", !a.ok && a.err.code === "not_html", code(a));
    if (!a.ok && a.err.code === "not_html") check("  and the caller is told what it was", lib.publicMessage(a.err).indexOf(label) !== -1, lib.publicMessage(a.err));
  }
  const html = await attempt("http://public.test/");
  check("text/html; charset=utf-8 is read", html.ok && html.value.ok, code(html));
  const xhtml = await attempt("http://public.test/xhtml");
  check("application/xhtml+xml is read", xhtml.ok && xhtml.value.ok, code(xhtml));
  const missing = await attempt("http://public.test/missing");
  check("a 404 comes back ok:false with its status and no body read", missing.ok && missing.value.ok === false && missing.value.status === 404 && missing.value.body === null, code(missing));
}

/* ── 9. challenge pages ────────────────────────────────────────────────── */
async function sectionChallenge() {
  console.log("\n══ 9. challenge pages served with 200 ══");
  for (const [p, label] of [["/cf-header", "cf-mitigated: challenge header"], ["/cf-title", "title \"Just a moment...\""], ["/aws-waf", "x-amzn-waf-action header"]]) {
    const a = await attempt("http://public.test" + p);
    check(label + " is refused challenge", !a.ok && a.err.code === "challenge", code(a));
  }
  const prose = await attempt("http://public.test/says-moment");
  check("a page that only SAYS \"just a moment\" is read", prose.ok && prose.value.ok, code(prose));
}

/* ── 10. nothing leaks ─────────────────────────────────────────────────── */
async function sectionLeak(silent) {
  console.log("\n══ 10. a refused address tells the caller nothing ══");
  const cases = {
    "blocked literal 10.0.0.1": await attempt("http://10.0.0.1/"),
    "blocked name internal.test": await attempt("http://internal.test/"),
    "redirect to a private name": await attempt("http://public.test/r/private"),
    "name that does not resolve": await attempt("http://nowhere.test/"),
    "connection refused": await attempt("http://refused.test/"),
    "lookup that never answered": silent
  };
  for (const label of Object.keys(cases)) {
    const a = cases[label];
    const msg = a.ok ? "(fetched)" : lib.publicMessage(a.err);
    check(label + " → the one unreachable message", msg === lib.UNREACHABLE_MESSAGE, msg);
  }
  const portA = lib.publicMessage((await attempt("http://10.0.0.1:8080/")).err || {});
  const portB = lib.publicMessage((await attempt("http://public.test:8080/")).err || {});
  check("a bad port reads the same whatever the host", portA === portB, portA + " | " + portB);
}

/* ── 12. options.accept, and what a caller gets back ───────────────────── */
const PLAIN = { accept: ["text/plain"] };
const XML = { accept: ["application/xml", "text/xml"] };
function sameJson(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
async function sectionAccept() {
  console.log("\n══ 12a. the default still reads HTML only ══");
  for (const [p, type] of [["/robots.txt", "text/plain"], ["/sitemap.xml", "application/xml"], ["/sitemap-tx", "text/xml"]]) {
    const a = await attempt("http://public.test" + p);
    check("default: " + type + " is refused not_html, with the message it always had",
      !a.ok && a.err.code === "not_html" && lib.publicMessage(a.err) === "That address returned " + type + ", not an HTML page.", code(a) + (a.ok ? "" : " | " + lib.publicMessage(a.err)));
  }

  console.log("\n══ 12b. options.accept reads only what it lists ══");
  const robots = await attempt("http://public.test/robots.txt", null, PLAIN);
  check("accept text/plain reads /robots.txt whole, as text/plain", robots.ok && robots.value.ok && robots.value.status === 200 && robots.value.body === ROBOTS && robots.value.contentType === "text/plain", code(robots));
  const cased = await attempt("http://public.test/robots-cased", null, PLAIN);
  check("\"Text/Plain; charset=utf-8\" matches text/plain", cased.ok && cased.value.ok && cased.value.body === ROBOTS && cased.value.contentType === "text/plain", code(cased));
  const upper = await attempt("http://public.test/robots.txt", null, { accept: [" TEXT/Plain "] });
  check("the accept list itself is matched case-insensitively", upper.ok && upper.value.ok, code(upper));
  for (const p of ["/sitemap.xml", "/sitemap-tx"]) {
    const a = await attempt("http://public.test" + p, null, XML);
    check("accept application/xml + text/xml reads " + p, a.ok && a.value.ok && a.value.body === SITEMAP, code(a));
  }
  for (const [p, opts, label] of [["/", PLAIN, "text/html when only text/plain is listed"], ["/xhtml", PLAIN, "application/xhtml+xml when only text/plain is listed"],
    ["/", XML, "text/html when only XML is listed"], ["/robots.txt", XML, "text/plain when only XML is listed"],
    ["/sitemap.xml", PLAIN, "application/xml when only text/plain is listed"], ["/json", PLAIN, "application/json"], ["/none", PLAIN, "no content type"]]) {
    const a = await attempt("http://public.test" + p, null, opts);
    check("accept refuses " + label + " (unaccepted_type)", !a.ok && a.err.code === "unaccepted_type", code(a));
  }
  const both = await attempt("http://public.test/", null, { accept: ["text/plain", "text/html"] });
  check("HTML is read under the option when it is listed", both.ok && both.value.ok && /<h1>Home<\/h1>/.test(both.value.body), code(both));
  const told = await attempt("http://public.test/", null, PLAIN);
  check("and a refused type tells the caller what came back and what was wanted",
    !told.ok && lib.publicMessage(told.err) === "That address returned text/html, not text/plain.", !told.ok && lib.publicMessage(told.err));
  hits["/robots.txt"] = 0;
  for (const bad of [[], "text/plain", ["text/plain; charset=utf-8"], ["*/*"], ["text"], [null]]) {
    const a = await attempt("http://public.test/robots.txt", null, { accept: bad });
    check("accept " + JSON.stringify(bad) + " is refused as a programming error", !a.ok && a.err instanceof TypeError, a.ok ? "fetched" : String(a.err));
  }
  check("and none of those reached the server", !hits["/robots.txt"], hits["/robots.txt"]);

  console.log("\n══ 12c. every address guard holds with the option set ══");
  hits["/robots.txt"] = 0;
  for (const [cidr] of lib.BLOCKED_IPV4) {
    const [base, bits] = cidr.split("/");
    const start = ip2int(base), size = 2 ** (32 - Number(bits));
    const inside = [start, start + Math.floor(size / 2), start + size - 1].map(int2ip);
    const results = [];
    for (const ip of inside) {
      NAMES["b-" + ip + ".test"] = [{ address: ip, family: 4 }];
      results.push(await attempt("http://" + ip + "/robots.txt", null, PLAIN));
      results.push(await attempt("http://b-" + ip + ".test/robots.txt", null, PLAIN));
    }
    const refused = results.filter(function (a) { return !a.ok && a.err.code === "blocked"; }).length;
    check("with accept: " + cidr + " refused as a literal and as a name (" + inside.join(", ") + ")", refused === 6, refused + " of 6 refused blocked");
  }
  const v6 = ["::1", "::7f00:1", "64:ff9b::7f00:1", "100::1", "fc00::1", "fd12:3456:789a::5", "fe80::1", "fec0::1", "ff02::1", "2001::1", "2001:db8::1",
    "2002:7f00:1::1", "3fff::1", "4000::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254"];
  let v6Refused = 0;
  for (const ip of v6) {
    NAMES["v6-" + v6.indexOf(ip) + ".test"] = [{ address: ip, family: 6 }];
    const lit = await attempt("http://[" + ip + "]/robots.txt", null, PLAIN);
    const name = await attempt("http://v6-" + v6.indexOf(ip) + ".test/robots.txt", null, PLAIN);
    if (!lit.ok && lit.err.code === "blocked" && !name.ok && name.err.code === "blocked") v6Refused++;
  }
  check("with accept: " + v6.length + " blocked IPv6 addresses refused as literals and as names", v6Refused === v6.length, v6Refused + " of " + v6.length);
  for (const name of ["internal.test", "loop.test", "metadata.test", "railway.test", "mixed.test"]) {
    const a = await attempt("http://" + name + "/robots.txt", null, XML);
    check("with accept: " + name + " refused blocked", !a.ok && a.err.code === "blocked", code(a));
  }
  const real = await attempt("http://localhost/robots.txt", lib.guardedFetch, PLAIN);
  check("with accept: localhost through the real resolver is refused blocked", !real.ok && real.err.code === "blocked", code(real));
  for (const u of ["ftp://public.test/robots.txt", "http://public.test:8080/robots.txt", "https://public.test:6379/robots.txt", "http://user:pass@public.test/robots.txt"]) {
    const a = await attempt(u, null, PLAIN);
    check("with accept: " + u + " refused invalid_url", !a.ok && a.err.code === "invalid_url", code(a));
  }
  check("with accept: no blocked address reached the server", !hits["/robots.txt"], (hits["/robots.txt"] || 0) + " arrived");
  rebindCalls = 0; resolverCalls = {}; dialed = [];
  const rebind = await attempt("http://rebind.test/robots.txt", null, PLAIN);
  const d = dialed.filter(function (x) { return x.host === "rebind.test"; });
  check("with accept: rebinding still asks once and connects to the address checked",
    rebind.ok && rebind.value.ok && resolverCalls["rebind.test"] === 1 && d.length === 1 && d[0].address === PUBLIC_V4, code(rebind) + " " + JSON.stringify(d));
  const blockedMsg = await attempt("http://internal.test/robots.txt", null, PLAIN);
  check("with accept: a blocked address still gets the one unreachable message", !blockedMsg.ok && lib.publicMessage(blockedMsg.err) === lib.UNREACHABLE_MESSAGE, !blockedMsg.ok && lib.publicMessage(blockedMsg.err));

  console.log("\n══ 12d. redirects with the option set ══");
  hits["/robots.txt"] = 0;
  for (const [p, want] of [["/r/robots-private", "blocked"], ["/r/robots-literal", "blocked"], ["/r/robots-meta", "blocked"], ["/r/robots-port", "invalid_url"]]) {
    const a = await attempt("http://public.test" + p, null, PLAIN);
    check("with accept: " + p + " → refused " + want + " at the second hop", !a.ok && a.err.code === want, code(a));
  }
  check("with accept: no redirect target was reached", !hits["/robots.txt"], (hits["/robots.txt"] || 0) + " arrived");
  const six = await attempt("http://public.test/chain/6", null, { accept: ["text/html"] });
  check("with accept: a 6th redirect is refused too_many_redirects", !six.ok && six.err.code === "too_many_redirects", code(six));

  console.log("\n══ 12e. the redirect chain ══");
  const mix = await attempt("http://public.test/mix/1", null, PLAIN);
  const wantMix = [{ url: "http://public.test/mix/1", status: 301 }, { url: "http://public.test/mix/2", status: 308 },
    { url: "http://public6.test/mix/3", status: 307 }, { url: "http://public6.test/robots.txt", status: 200 }];
  check("every hop is in the chain, in order, with its status (301, 308, 307, 200)", mix.ok && sameJson(mix.value.chain, wantMix), mix.ok ? JSON.stringify(mix.value.chain) : code(mix));
  check("url is the final URL and status the final status", mix.ok && mix.value.url === "http://public6.test/robots.txt" && mix.value.status === 200, mix.ok && mix.value.url + " " + mix.value.status);
  check("redirects is still the list of redirect targets", mix.ok && sameJson(mix.value.redirects, ["http://public.test/mix/2", "http://public6.test/mix/3", "http://public6.test/robots.txt"]), mix.ok && JSON.stringify(mix.value.redirects));
  const five = await attempt("http://public.test/chain/5");
  check("default: 5 redirects give a chain of 6, five 302s then the 200", five.ok && five.value.chain.length === 6 &&
    sameJson(five.value.chain.map(function (h) { return h.status; }), [302, 302, 302, 302, 302, 200]) &&
    sameJson(five.value.chain.map(function (h) { return h.url; }), ["http://public.test/chain/5", "http://public.test/chain/4", "http://public.test/chain/3",
      "http://public.test/chain/2", "http://public.test/chain/1", "http://public.test/landing"]), five.ok ? JSON.stringify(five.value.chain) : code(five));
  const one = await attempt("http://public.test/");
  check("default: no redirect gives a chain of the one answer", one.ok && sameJson(one.value.chain, [{ url: "http://public.test/", status: 200 }]), one.ok && JSON.stringify(one.value.chain));
  const stopped = await attempt("http://public.test/r/robots-private", null, PLAIN);
  check("a refusal carries the chain as far as it got", !stopped.ok && sameJson(stopped.err.chain, [{ url: "http://public.test/r/robots-private", status: 302 }]), !stopped.ok && JSON.stringify(stopped.err.chain));

  console.log("\n══ 12f. a reached 404 is a result; a blocked address is not ══");
  const m0 = await attempt("http://public.test/missing");
  const m1 = await attempt("http://public.test/missing", null, PLAIN);
  for (const [label, a] of [["default", m0], ["with accept", m1]]) {
    check(label + ": a 404 is returned, not thrown, with status 404, ok:false, no body and its chain",
      a.ok && a.value.status === 404 && a.value.ok === false && a.value.body === null && a.value.bytes === 0 &&
      sameJson(a.value.chain, [{ url: "http://public.test/missing", status: 404 }]), code(a));
  }
  const strip = function (v) { const o = Object.assign({}, v); delete o.ms; delete o.headers; return o; };
  check("the 404 result is the same with the option as without", m0.ok && m1.ok && sameJson(strip(m0.value), strip(m1.value)), m0.ok && m1.ok && JSON.stringify(strip(m1.value)));
  const viaRedirect = await attempt("http://public.test/r/relative-404", null, PLAIN);
  check("a 404 at the end of a redirect is returned with the whole chain", viaRedirect.ok && viaRedirect.value.status === 404 &&
    sameJson(viaRedirect.value.chain, [{ url: "http://public.test/r/relative-404", status: 302 }, { url: "http://public.test/missing", status: 404 }]),
    viaRedirect.ok ? JSON.stringify(viaRedirect.value.chain) : code(viaRedirect));
  const blk = await attempt("http://10.0.0.1/robots.txt", null, PLAIN);
  check("a blocked address is thrown with code blocked, never returned as a status", !blk.ok && blk.err.code === "blocked" && blk.err.status === undefined, code(blk));

  console.log("\n══ 12g. size and decompression for text/plain ══");
  const declared = await withWatchdog(attempt("http://public.test/plain-declared", null, PLAIN), 15000);
  check("text/plain: a declared 4 MB body is refused too_large", !declared.ok && declared.err.code === "too_large" && declared.ms < 5000, code(declared) + " in " + declared.ms + " ms");
  const stream = await attempt("http://public.test/plain-stream", null, PLAIN);
  check("text/plain: a streamed 3 MB + 1 byte body is refused too_large", !stream.ok && stream.err.code === "too_large", code(stream));
  const bomb = await attempt("http://public.test/plain-bomb", null, PLAIN);
  check("text/plain: a gzip that expands to 20 MB is refused too_large", !bomb.ok && bomb.err.code === "too_large", code(bomb));
  const exact = await attempt("http://public.test/plain-exact", null, PLAIN);
  check("text/plain: exactly 3 MB is read", exact.ok && exact.value.ok && exact.value.bytes === THREE_MB, code(exact));
  const gz = await attempt("http://public.test/plain-gzip", null, PLAIN);
  check("text/plain: a gzip body is decoded", gz.ok && gz.value.ok && gz.value.body === ROBOTS, code(gz));

  console.log("\n══ 12h. challenge pages with the option set ══");
  for (const [p, label] of [["/plain-cf", "cf-mitigated header"], ["/plain-aws", "x-amzn-waf-action header"]]) {
    const a = await attempt("http://public.test" + p, null, PLAIN);
    check("text/plain with a " + label + " is still refused challenge", !a.ok && a.err.code === "challenge", code(a));
  }
  const moment = await attempt("http://public.test/plain-moment", null, PLAIN);
  check("a text/plain body is not judged by a <title> in it", moment.ok && moment.value.ok, code(moment));
  const htmlTitle = await attempt("http://public.test/cf-title", null, { accept: ["text/html"] });
  check("HTML read under the option is still judged by its title", !htmlTitle.ok && htmlTitle.err.code === "challenge", code(htmlTitle));

  console.log("\n══ 12i. the 10 s limit for text/plain (two at once, about 10 s) ══");
  const [hang, drip] = await Promise.all([
    withWatchdog(attempt("http://public.test/plain-hang", null, PLAIN), 15000),
    withWatchdog(attempt("http://public.test/plain-drip", null, PLAIN), 15000)
  ]);
  check("text/plain: headers and then nothing is cut off at 10 s", !hang.ok && hang.err.code === "timeout" && hang.ms >= 9500 && hang.ms < 12000, code(hang) + " in " + hang.ms + " ms");
  check("text/plain: a dripped body is cut off at 10 s in total", !drip.ok && drip.err.code === "timeout" && drip.ms < 12000, code(drip) + " in " + drip.ms + " ms");
}

/* ── 11. the route, the task type, the frontend ────────────────────────── */
async function sectionRoute() {
  console.log("\n══ 11. the live optimize route, and seo_audit gone ══");
  const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
  const realExpress = require(EXPRESS_PATH);
  let app = null;
  const wrapper = function () { const made = realExpress.apply(this, arguments); if (!app) app = made; return made; };
  Object.keys(realExpress).forEach(function (k) { wrapper[k] = realExpress[k]; });
  require.cache[EXPRESS_PATH].exports = wrapper;
  process.env.PORT = process.env.CHECK_PORT || "0";
  require(SERVER_PATH);

  const layers = app._router.stack.filter(function (l) { return l.route; });
  const optimize = layers.filter(function (l) { return l.route.path === "/api/agents/seo/optimize" && l.route.methods.post; });
  check("POST /api/agents/seo/optimize is mounted once", optimize.length === 1, optimize.length);
  check("POST /api/seo/audit is no longer mounted", !layers.some(function (l) { return l.route.path === "/api/seo/audit"; }));
  const handler = optimize[0].route.stack[optimize[0].route.stack.length - 1].handle;
  for (const website of ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "localhost", "http://[::1]/", "10.0.0.1"]) {
    const r = await new Promise(function (resolveCall) {
      const res = { statusCode: 200, status: function (c) { this.statusCode = c; return this; }, json: function (p) { resolveCall({ status: this.statusCode, body: p }); return this; } };
      Promise.resolve(handler({ user: { id: "00000000-0000-0000-0000-000000000000" }, body: { website: website }, params: {}, query: {}, headers: {} }, res, function (e) { resolveCall({ status: 500, body: { error: String(e) } }); }));
    });
    check("optimize(" + website + ") → 422 with the one unreachable message", r.status === 422 && r.body && r.body.error === lib.UNREACHABLE_MESSAGE, r.status + " " + JSON.stringify(r.body));
  }

  const src = fs.readFileSync(SERVER_PATH, "utf8").replace(/\r\n/g, "\n");
  const start = src.indexOf("app.post(\"/api/agents/seo/optimize\"");
  const body = src.slice(start, src.indexOf("\napp.", start + 10))
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");   // comments may say "fetch()"
  check("the optimize handler fetches through guardedFetch and nowhere else", /guardedFetch\(targetUrl/.test(body) && !/[^d]fetch\(/.test(body.replace(/guardedFetch\(/g, "")));
  const allowed = /var allowedTaskTypes = \[([^\]]*)\]/.exec(src);
  check("allowedTaskTypes no longer contains seo_audit", allowed && allowed[1].indexOf("\"seo_audit\"") === -1);
  check("taskInstructions no longer contains seo_audit", src.indexOf("  seo_audit: \"") === -1);
  for (const f of ["agents/seo.html", "dashboard.html"]) {
    const p = path.join(FRONTEND, f);
    if (!fs.existsSync(p)) { check(f + " found beside this repo", false, p); continue; }
    check(f + " no longer offers seo_audit", fs.readFileSync(p, "utf8").indexOf("seo_audit") === -1);
  }
}

/* ── 13. the JSON mode (guardedJsonRequest) ─────────────────────────────── */
async function sectionJson() {
  const FAKE_TOKEN = "checkOnlyBearerValue_" + "Q7xT2mN9pR4sV8wY1zA3";
  const auth = { Authorization: "Bearer " + FAKE_TOKEN };
  check("13. guardedJsonRequest is exported, built from the same createGuardedFetch, and JSON_MAX_BODY_BYTES is 1 MB",
    typeof lib.guardedJsonRequest === "function" && typeof lib.createGuardedFetch().json === "function" && lib.JSON_MAX_BODY_BYTES === ONE_MB);

  console.log("\n══ 13a. https on 443 only, every address guard held ══");
  let before = hits["/j/ok"] || 0;
  let a = await attemptJson("http://public.test/j/ok", { headers: auth });
  check("http:// is refused before any request (invalid_url)", !a.ok && a.err.code === "invalid_url" && (hits["/j/ok"] || 0) === before, code(a));
  a = await attemptJson("http://public.test:443/j/ok", { headers: auth });
  check("http:// on port 443 is refused too: https, not just the port", !a.ok && a.err.code === "invalid_url" && (hits["/j/ok"] || 0) === before, code(a));
  a = await attemptJson("https://public.test:80/j/ok", { headers: auth });
  check("https on port 80 is refused before any request (invalid_url)", !a.ok && a.err.code === "invalid_url" && (hits["/j/ok"] || 0) === before, code(a));
  a = await attemptJson("https://public.test:8443/j/ok");
  check("https on port 8443 is refused (invalid_url)", !a.ok && a.err.code === "invalid_url", code(a));
  a = await attemptJson("https://user:pw@public.test/j/ok");
  check("credentials in the address are refused (invalid_url)", !a.ok && a.err.code === "invalid_url", code(a));
  jsonSeen = [];
  a = await attemptJson("https://public.test/j/ok", { headers: auth });
  check("https://public.test/j/ok is read: status 200 and the parsed JSON",
    a.ok && a.value.status === 200 && sameJson(a.value.json, { id: "109", username: "alice" }), code(a));
  check("the request was a GET to port 443 over https:, with agent:false and the guarded lookup",
    jsonSeen.length === 1 && jsonSeen[0].method === "GET" && jsonSeen[0].port === 443 && jsonSeen[0].protocol === "https:" && jsonSeen[0].agent === false,
    JSON.stringify(jsonSeen.map(function (s) { return [s.method, s.port, s.protocol, s.agent]; })));
  a = await attemptJson("https://public.test:443/j/ok");
  check("an explicit :443 is allowed", a.ok && a.value.status === 200, code(a));
  for (const lit of ["https://127.0.0.1/j/ok", "https://10.0.0.5/j/ok", "https://169.254.169.254/j/ok", "https://[::1]/j/ok", "https://[fd12:3456:789a::5]/j/ok", "https://2130706433/j/ok"]) {
    before = hits["/j/ok"] || 0;
    a = await attemptJson(lit, { headers: auth });
    check(lit + " is refused as blocked, and nothing arrives", !a.ok && a.err.code === "blocked" && (hits["/j/ok"] || 0) === before, code(a));
  }
  for (const name of ["internal.test", "loop.test", "metadata.test", "railway.test", "mixed.test"]) {
    before = hits["/j/ok"] || 0;
    a = await attemptJson("https://" + name + "/j/ok", { headers: auth });
    check("https://" + name + " resolves to a blocked address and is refused before connecting", !a.ok && a.err.code === "blocked" && (hits["/j/ok"] || 0) === before, code(a));
  }
  rebindCalls = 0; dialed = [];
  a = await attemptJson("https://rebind.test/j/ok");
  check("rebinding: one resolution, and the connection goes to the public address it checked",
    a.ok && rebindCalls === 1 && dialed.length === 1 && dialed[0].address === PUBLIC_V4, code(a) + " calls " + rebindCalls + " " + JSON.stringify(dialed));

  /* NAMED (Nov 7 2026, YouTube uploads, migration 177): BEFORE "GET or POST only", with DELETE among the refused methods.
     AFTER GET, POST or DELETE: videos.delete is a DELETE (lib/youtubeApi.js executeDelete). DELETE leaves the refused list
     and is proved to go through, carrying no body; every other method is still refused before any lookup, and the
     json-method-unrestricted mutation is still caught by them. The emptyOk option (a 2xx with an empty body is json null)
     is proved here too; without it an empty 2xx is still refused. */
  /* NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "GET, POST or DELETE only", with PUT among the refused
     methods. AFTER GET, POST, PUT or DELETE: Etsy's inventory update is a PUT of the whole inventory as JSON
     (lib/etsyApi.js writeInventory). PUT leaves the refused list and is proved to go through with its Authorization and
     exactly one JSON object as its body, sent as application/json; a PUT with no body, a string, a Buffer, an array, a
     form, or a caller's own Content-Type is refused before any lookup. Every other method is still refused, and the
     json-method-unrestricted mutation is still caught by them. */
  /* NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "GET, POST, PUT or DELETE only", with PATCH among
     the refused methods. AFTER GET, POST, PUT, PATCH or DELETE: Amazon's listings update is a PATCH of one JSON object
     (lib/amazonApi.js submitPatch). PATCH leaves the refused list and is proved to go through with its Authorization and
     exactly one JSON object as its body, under the same rules as a PUT (no body, a string, a Buffer, an array, a form or
     a caller's own Content-Type is refused before any lookup). "patch" in lower case and HEAD join the refused methods,
     so the json-method-unrestricted mutation is still caught by them. */
  console.log("\n══ 13b. GET, POST, PUT, PATCH or DELETE only ══");
  for (const m of ["patch", "get", "put", "delete", "HEAD", "OPTIONS"]) {
    resolverCalls = {};
    a = await attemptJson("https://public.test/j/echo", { method: m });
    check("method " + m + " is refused before any lookup", !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"], a.ok ? "fetched" : String(a.err && a.err.message));
  }
  a = await attemptJson("https://public.test/j/echo", { method: "PATCH", headers: auth, body: { productType: "MUG", patches: [{ op: "replace", path: "/attributes/fulfillment_availability", value: [{ fulfillment_channel_code: "DEFAULT", quantity: 4 }] }] } });
  check("a PATCH goes through with its Authorization and one JSON object as its body, as application/json",
    a.ok && a.value.json.method === "PATCH" && a.value.json.body === JSON.stringify({ productType: "MUG", patches: [{ op: "replace", path: "/attributes/fulfillment_availability", value: [{ fulfillment_channel_code: "DEFAULT", quantity: 4 }] }] }) &&
    a.value.json.headers.authorization === "Bearer " + FAKE_TOKEN && /^application\/json/.test(a.value.json.headers["content-type"] || ""), code(a));
  for (const [label, opts] of [["no body", {}], ["a string body", { body: "{\"x\":1}" }], ["a Buffer body", { body: Buffer.from("{}") }],
    ["an array body", { body: [1, 2] }], ["a form", { body: { x: 1 }, form: true }], ["a caller's Content-Type", { body: { x: 1 }, headers: { "Content-Type": "text/plain" } }]]) {
    resolverCalls = {};
    a = await attemptJson("https://public.test/j/echo", Object.assign({ method: "PATCH" }, opts));
    check("a PATCH with " + label + " is refused before any lookup", !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"], a.ok ? "fetched" : String(a.err && a.err.message));
  }
  a = await attemptJson("https://public.test/j/echo", { method: "PUT", headers: auth, body: { products: [{ sku: "A", offerings: [{ price: 12.5, quantity: 3 }] }] } });
  check("a PUT goes through with its Authorization and one JSON object as its body, as application/json",
    a.ok && a.value.json.method === "PUT" && a.value.json.body === JSON.stringify({ products: [{ sku: "A", offerings: [{ price: 12.5, quantity: 3 }] }] }) &&
    a.value.json.headers.authorization === "Bearer " + FAKE_TOKEN && /^application\/json/.test(a.value.json.headers["content-type"] || ""), code(a));
  for (const [label, opts] of [["no body", {}], ["a string body", { body: "{\"x\":1}" }], ["a Buffer body", { body: Buffer.from("{}") }],
    ["an array body", { body: [1, 2] }], ["a form", { body: { x: 1 }, form: true }], ["a caller's Content-Type", { body: { x: 1 }, headers: { "Content-Type": "text/plain" } }]]) {
    resolverCalls = {};
    a = await attemptJson("https://public.test/j/echo", Object.assign({ method: "PUT" }, opts));
    check("a PUT with " + label + " is refused before any lookup", !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"], a.ok ? "fetched" : String(a.err && a.err.message));
  }
  a = await attemptJson("https://public.test/j/echo", { method: "DELETE", headers: auth });
  check("a DELETE goes through, with its Authorization and no body", a.ok && a.value.json.method === "DELETE" && a.value.json.body === "" &&
    a.value.json.headers.authorization === "Bearer " + FAKE_TOKEN, code(a));
  a = await attemptJson("https://public.test/j/echo", { method: "DELETE", body: { x: 1 } });
  check("a DELETE with a body is refused", !a.ok && a.err instanceof TypeError, code(a));
  a = await attemptJson("https://public.test/j/empty204", { method: "DELETE", emptyOk: true });
  check("emptyOk: a 204 with no body answers json null", a.ok && a.value.status === 204 && a.value.json === null, code(a));
  a = await attemptJson("https://public.test/j/empty204", { method: "DELETE" });
  check("without emptyOk the same empty 204 is refused, as before", !a.ok, a.ok ? "accepted" : code(a));
  resolverCalls = {};
  a = await attemptJson("https://public.test/j/empty204", { method: "DELETE", emptyOk: "yes" });
  check("emptyOk that is not true or false is refused before any lookup", !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"], code(a));
  a = await attemptJson("https://public.test/j/echo", { method: "GET", body: { status: "x" } });
  check("a GET with a body is refused", !a.ok && a.err instanceof TypeError, code(a));
  a = await attemptJson("https://public.test/j/echo", { method: "POST", headers: Object.assign({ "Idempotency-Key": "draft-1", Host: "evil.test", "Content-Length": "1" }, auth), body: { status: "Hello", visibility: "public" } });
  const echoed = a.ok ? a.value.json : null;
  check("a POST carries its JSON body, its Authorization and Idempotency-Key, as JSON",
    !!echoed && echoed.method === "POST" && echoed.body === JSON.stringify({ status: "Hello", visibility: "public" }) &&
    echoed.headers.authorization === "Bearer " + FAKE_TOKEN && echoed.headers["idempotency-key"] === "draft-1" && /^application\/json/.test(echoed.headers["content-type"]), code(a));
  check("a caller cannot set Host or Content-Length", !!echoed && echoed.headers.host !== "evil.test" && Number(echoed.headers["content-length"]) === Buffer.byteLength(echoed.body), echoed && JSON.stringify([echoed.headers.host, echoed.headers["content-length"]]));

  console.log("\n══ 13c. a redirect is never followed ══");
  for (const p of ["/j/302", "/j/301", "/j/307", "/j/308", "/j/300"]) {
    before = hits["/j/ok"] || 0;
    a = await attemptJson("https://public.test" + p, { headers: auth });
    check(p + " is refused as redirected, and its target is never asked", !a.ok && a.err.code === "redirected" && (hits["/j/ok"] || 0) === before, code(a));
  }

  console.log("\n══ 13d. 1 MB of body, after decompression ══");
  a = await attemptJson("https://public.test/j/big-declared");
  check("a declared 2 MB body is refused (too_large)", !a.ok && a.err.code === "too_large", code(a));
  a = await attemptJson("https://public.test/j/big-stream");
  check("a streamed 1 MB + 1 body is refused (too_large)", !a.ok && a.err.code === "too_large", code(a));
  a = await attemptJson("https://public.test/j/exact");
  check("exactly 1 MB is read and parsed", a.ok && typeof a.value.json === "string" && a.value.json.length === ONE_MB - 2, code(a));
  a = await attemptJson("https://public.test/j/bomb");
  check("a gzip body that expands to 8 MB is refused (too_large)", !a.ok && a.err.code === "too_large", code(a));
  a = await attemptJson("https://public.test/j/gzip");
  check("gzip is decoded", a.ok && sameJson(a.value.json, { zipped: true }), code(a));
  a = await attemptJson("https://public.test/j/small", { maxBytes: 1000 });
  check("a smaller maxBytes is honoured", !a.ok && a.err.code === "too_large", code(a));
  /* NAMED (Nov 3 2026, store connections): BEFORE "a larger maxBytes is capped at 1 MB" (50 MB asked, the 1 MB + 1 body
     refused as too_large). AFTER a maxBytes over the 8 MB ceiling is refused outright, before any lookup, and nothing is
     read; up to 8 MB may be asked for (section 13i). Never looser: the 1 MB + 1 body is still not read. */
  resolverCalls = {};
  before = hits["/j/big-stream"] || 0;
  a = await attemptJson("https://public.test/j/big-stream", { maxBytes: 50 * ONE_MB });
  check("a maxBytes over the 8 MB ceiling is refused before any lookup, never clamped, and nothing is read",
    !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"] && (hits["/j/big-stream"] || 0) === before, code(a));

  console.log("\n══ 13e. what an answer must be, and what comes back ══");
  a = await attemptJson("https://public.test/j/html");
  check("a 2xx that is text/html is refused (unaccepted_type)", !a.ok && a.err.code === "unaccepted_type", code(a));
  a = await attemptJson("https://public.test/j/notjson");
  check("a 2xx application/json body that does not parse is refused (not_json)", !a.ok && a.err.code === "not_json", code(a));
  a = await attemptJson("https://public.test/j/401", { headers: auth });
  check("a 401 is returned, not thrown, with its JSON", a.ok && a.value.status === 401 && sameJson(a.value.json, { error: "The access token is invalid" }), code(a));
  a = await attemptJson("https://public.test/j/500-html");
  check("a 500 that is HTML is returned with json null", a.ok && a.value.status === 500 && a.value.json === null, code(a));
  a = await attemptJson("https://public.test/j/429");
  check("the result holds only status, json and headers; headers only retry-after, x-ratelimit-reset and x-ratelimit-remaining",
    a.ok && sameJson(Object.keys(a.value).sort(), ["headers", "json", "status"]) && a.value.status === 429 &&
    sameJson(a.value.headers, { "retry-after": "120", "x-ratelimit-reset": "2026-11-03T20:00:00.000Z", "x-ratelimit-remaining": "0" }), a.ok ? JSON.stringify(a.value.headers) : code(a));

  console.log("\n══ 13f. the token is never in an error, a detail or a log line ══");
  const refusals = [
    ["a blocked name", "https://internal.test/j/ok"],
    ["a name that does not resolve", "https://nowhere.test/j/ok"],
    ["a refused connection", "https://refused.test/j/ok"],
    ["a redirect", "https://public.test/j/302"],
    ["a body too large", "https://public.test/j/big-stream"],
    ["an http address", "http://public.test/j/ok"]
  ];
  for (const [what, url] of refusals) {
    a = await attemptJson(url, { method: "POST", headers: auth, body: { status: "x" } });
    const e = a.err || {};
    const everything = [String(e), e.message, e.detail, e.stack, lib.logLine(e), lib.publicMessage(e), JSON.stringify(e)].join(" | ");
    check(what + ": refused, and the token appears nowhere in the error, logLine or publicMessage",
      !a.ok && e.guardedFetch === true && everything.indexOf(FAKE_TOKEN) === -1 && everything.indexOf("Bearer") === -1, code(a));
  }
  for (const [what, url] of refusals.slice(0, 4)) {
    a = await attemptJson(url, { headers: auth });
    check(what + ": the caller is told UNREACHABLE_MESSAGE", !a.ok && lib.publicMessage(a.err) === lib.UNREACHABLE_MESSAGE, a.ok ? "fetched" : lib.publicMessage(a.err));
  }

  console.log("\n══ 13g. the same 10 s total limit (about 10 s) ══");
  a = await withWatchdog(attemptJson("https://public.test/j/hang", { headers: auth }), 20000);
  check("an API that never answers is cut off at about 10 s (timeout)", !a.ok && a.err.code === "timeout" && a.ms >= 9500 && a.ms < 15000, code(a) + " " + a.ms + " ms");

  console.log("\n══ 13h. the HTML mode is unchanged by it ══");
  a = await attempt("http://public.test/json");
  check("the HTML mode still refuses a JSON answer (not_html)", !a.ok && a.err.code === "not_html", code(a));
  a = await attempt("http://public.test/r/relative");
  check("the HTML mode still follows a redirect", a.ok && a.value.status === 200 && a.value.redirects.length === 1, code(a));

  await sectionJsonOptions(auth);
}

/* ── 13i. what a caller may raise, and how far (NAMED Nov 3 2026, store connections) ── */
async function sectionJsonOptions(auth) {
  console.log("\n══ 13i. exposeHeaders, maxBytes and timeoutMs: bounded, refused outside the bounds, never clamped ══");
  check("13i. JSON_MAX_BODY_BYTES_CEILING is 8 MB, and timeoutMs runs from 1000 to 30000",
    lib.JSON_MAX_BODY_BYTES_CEILING === 8 * ONE_MB && lib.JSON_MIN_TIMEOUT_MS === 1000 && lib.JSON_MAX_TIMEOUT_MS === 30000,
    JSON.stringify([lib.JSON_MAX_BODY_BYTES_CEILING, lib.JSON_MIN_TIMEOUT_MS, lib.JSON_MAX_TIMEOUT_MS]));
  async function refusedBeforeLookup(label, opts) {
    resolverCalls = {};
    const before = hits["/j/paged"] || 0;
    const a = await attemptJson("https://public.test/j/paged", Object.assign({ headers: auth }, opts));
    check(label + ": refused before any lookup (TypeError), nothing asked", !a.ok && a.err instanceof TypeError && !resolverCalls["public.test"] && (hits["/j/paged"] || 0) === before,
      a.ok ? "fetched " + JSON.stringify(a.value.headers) : String(a.err && (a.err.code || a.err.message)));
  }

  // exposeHeaders
  let a = await attemptJson("https://public.test/j/paged", { headers: auth });
  check("by default only retry-after, x-ratelimit-reset and x-ratelimit-remaining can come back (here: retry-after)",
    a.ok && sameJson(a.value.headers, { "retry-after": "1" }), a.ok ? JSON.stringify(a.value.headers) : code(a));
  a = await attemptJson("https://public.test/j/paged", { headers: auth, exposeHeaders: ["retry-after", "link", "x-wp-totalpages"] });
  check("exposeHeaders [retry-after, link, x-wp-totalpages] returns exactly those, and no other header",
    a.ok && sameJson(a.value.headers, { "retry-after": "1", "link": "<https://public.test/j/paged?page=2>; rel=\"next\"", "x-wp-totalpages": "3" }),
    a.ok ? JSON.stringify(a.value.headers) : code(a));
  a = await attemptJson("https://public.test/j/paged", { headers: auth, exposeHeaders: ["link", "x-absent"] });
  check("an exposed header the answer lacks is simply absent", a.ok && sameJson(a.value.headers, { "link": "<https://public.test/j/paged?page=2>; rel=\"next\"" }),
    a.ok ? JSON.stringify(a.value.headers) : code(a));
  const eight = ["a", "b", "c", "d", "e", "f", "g", "link"];
  a = await attemptJson("https://public.test/j/paged", { headers: auth, exposeHeaders: eight });
  check("8 names are allowed", a.ok && a.value.status === 200, code(a));
  await refusedBeforeLookup("9 names", { exposeHeaders: eight.concat(["x-wp-totalpages"]) });
  await refusedBeforeLookup("set-cookie", { exposeHeaders: ["link", "set-cookie"] });
  await refusedBeforeLookup("authorization", { exposeHeaders: ["authorization"] });
  await refusedBeforeLookup("a name with a capital (Link)", { exposeHeaders: ["Link"] });
  await refusedBeforeLookup("a name with a space or colon", { exposeHeaders: ["x-a: b"] });
  await refusedBeforeLookup("a 65-character name", { exposeHeaders: ["x".repeat(65)] });
  await refusedBeforeLookup("an empty name", { exposeHeaders: [""] });
  await refusedBeforeLookup("a list that is not a list", { exposeHeaders: "link" });

  // maxBytes
  a = await attemptJson("https://public.test/j/five-mb", { maxBytes: lib.JSON_MAX_BODY_BYTES_CEILING });
  check("maxBytes 8 MB reads a 5 MB JSON body (the 3 MB HTML cap does not cut it)", a.ok && typeof a.value.json === "string" && a.value.json.length === 5 * ONE_MB, code(a));
  a = await attemptJson("https://public.test/j/five-mb");
  check("...and without maxBytes the same body is refused at 1 MB (the default is unchanged), as too_large", !a.ok && a.err.code === "too_large", code(a));
  a = await attemptJson("https://public.test/j/over-ceiling", { maxBytes: lib.JSON_MAX_BODY_BYTES_CEILING });
  check("a streamed 8 MB + 1 body under maxBytes 8 MB fails with the code too_large, which a caller can tell apart",
    !a.ok && a.err instanceof lib.GuardedFetchError && a.err.code === "too_large", code(a));
  a = await attemptJson("https://public.test/j/declared-9mb", { maxBytes: lib.JSON_MAX_BODY_BYTES_CEILING });
  check("a declared 9 MB body under maxBytes 8 MB fails with the code too_large", !a.ok && a.err.code === "too_large", code(a));
  await refusedBeforeLookup("maxBytes 8 MB + 1", { maxBytes: lib.JSON_MAX_BODY_BYTES_CEILING + 1 });
  await refusedBeforeLookup("maxBytes 0", { maxBytes: 0 });
  await refusedBeforeLookup("maxBytes 1.5", { maxBytes: 1.5 });
  await refusedBeforeLookup("maxBytes as a string", { maxBytes: "5000000" });

  // timeoutMs
  a = await attemptJson("https://public.test/j/paged", { headers: auth, timeoutMs: 30000 });
  check("timeoutMs 30000 is allowed", a.ok && a.value.status === 200, code(a));
  await refusedBeforeLookup("timeoutMs 30001", { timeoutMs: 30001 });
  await refusedBeforeLookup("timeoutMs 999", { timeoutMs: 999 });
  await refusedBeforeLookup("timeoutMs 60000", { timeoutMs: 60000 });
  await refusedBeforeLookup("timeoutMs Infinity", { timeoutMs: Infinity });
  a = await withWatchdog(attemptJson("https://public.test/j/hang", { headers: auth, timeoutMs: 1500 }), 8000);
  check("timeoutMs 1500 cuts a hanging API off at about 1.5 s (timeout), not 10 s", !a.ok && a.err.code === "timeout" && a.ms >= 1300 && a.ms < 4000, code(a) + " " + a.ms + " ms");
}

/* ── 14. resolvePublicHost: for connections that are not HTTP (lib/memberEmail.js) ── */
async function sectionResolvePublicHost() {
  console.log("\n14. resolvePublicHost");
  const outcome = async function (host) {
    try { return { ok: await lib.resolvePublicHost(host, { resolve: resolve }) }; } catch (e) { return { code: e && e.code, guarded: !!(e && e.guardedFetch) }; }
  };
  const pub = await outcome("public.test");
  check("a public name resolves to its one vetted address and family", pub.ok && pub.ok.address === PUBLIC_V4 && pub.ok.family === 4, JSON.stringify(pub));
  const mixed = await outcome("mixed.test");
  check("a name with one public and one private address is refused (every address is checked, not the first)", mixed.code === "blocked" && mixed.guarded, JSON.stringify(mixed));
  for (const name of ["loop.test", "metadata.test", "railway.test"]) {
    const r = await outcome(name);
    check(name + " (a private address) is refused blocked", r.code === "blocked" && r.guarded, JSON.stringify(r));
  }
  resolverCalls = {};
  const literals = [];
  for (const literal of ["93.184.216.34", "127.0.0.1", "::1", "[2606:4700::1]"]) literals.push(await outcome(literal));
  check("an IP literal, public or private, is refused invalid_url before any lookup", literals.every(function (r) { return r.code === "invalid_url"; }) && Object.keys(resolverCalls).length === 0,
    JSON.stringify(literals));
  const none = await outcome("nowhere.test");
  const blank = await outcome("  ");
  check("an unknown name is refused dns; an empty host invalid_url", none.code === "dns" && blank.code === "invalid_url", JSON.stringify([none, blank]));
  resolverCalls = {};
  await outcome("public.test");
  check("one resolution per call", resolverCalls["public.test"] === 1, JSON.stringify(resolverCalls));
  check("resolvePublicHost is exported, and the default one takes no deps", typeof lib.resolvePublicHost === "function" && typeof lib.createGuardedFetch().resolvePublicHost === "function");
}

/* ── 15. the form option: an OAuth token endpoint's body (NAMED Nov 6 2026, Outlook sign-in) ── */
async function sectionForm() {
  console.log("\n15. guardedJsonRequest's form option");
  const form = { grant_type: "authorization_code", code: "c-1", redirect_uri: "https://bizforceai.net/mailbox.html", scope: "a b+c" };
  let a = await attemptJson("https://public.test/j/echo", { method: "POST", form: form });
  const e = a.ok ? a.value.json : null;
  check("a form POST is sent URL-encoded, under application/x-www-form-urlencoded, and nothing else",
    !!e && e.method === "POST" && e.body === new URLSearchParams(form).toString() && e.headers["content-type"] === "application/x-www-form-urlencoded",
    e ? JSON.stringify([e.headers["content-type"], e.body.length]) : code(a));
  check("its Content-Length is the encoded byte length", !!e && Number(e.headers["content-length"]) === Buffer.byteLength(e.body), e && e.headers["content-length"]);
  check("a JSON body still goes as application/json (the default is unchanged)", (await (async function () {
    const j = await attemptJson("https://public.test/j/echo", { method: "POST", body: { x: "1" } });
    return j.ok && /^application\/json/.test(j.value.json.headers["content-type"]);
  })()));
  async function refused(label, opts) {
    resolverCalls = {};
    const before = hits["/j/echo"] || 0;
    const r = await attemptJson("https://public.test/j/echo", opts);
    check(label + ": a TypeError before any lookup, nothing sent", !r.ok && r.err instanceof TypeError && !resolverCalls["public.test"] && (hits["/j/echo"] || 0) === before,
      r.ok ? "sent" : String(r.err && (r.err.code || r.err.message)));
  }
  await refused("form with a body", { method: "POST", form: form, body: { x: "1" } });
  await refused("form with a string body", { method: "POST", form: form, body: "a=1" });
  await refused("form with a caller Content-Type", { method: "POST", form: form, headers: { "Content-Type": "application/json" } });
  await refused("form with a lower-case caller content-type", { method: "POST", form: form, headers: { "content-type": "application/x-www-form-urlencoded" } });
  await refused("form on a GET", { method: "GET", form: form });
  await refused("form with a number value", { method: "POST", form: { a: 1 } });
  await refused("form as an array", { method: "POST", form: [["a", "b"]] });
  await refused("form as a URLSearchParams", { method: "POST", form: new URLSearchParams("a=b") });
}

(async function main() {
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  const closed = net.createServer();
  await new Promise(function (r) { closed.listen(0, "127.0.0.1", r); });
  closedPort = closed.address().port;
  await new Promise(function (r) { closed.close(r); });

  sectionAddresses();
  await sectionUrl();
  await sectionNames();
  await sectionRedirects();
  const silent = await sectionTimeout();
  await sectionSize();
  await sectionContentType();
  await sectionChallenge();
  await sectionLeak(silent);
  await sectionAccept();
  await sectionJson();
  await sectionRoute();
  await sectionResolvePublicHost();
  await sectionForm();

  console.log(failures ? "\n" + failures + " FAILED" : "\nALL CHECKS PASSED");
  process.exit(failures ? 1 : 0);
})().catch(function (e) {
  console.log("\nthrew: " + (e && e.stack || e));
  process.exit(1);
});
