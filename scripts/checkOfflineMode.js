"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkOfflineMode — offline mode: the app shell, the opt-in saved copy, and
   what a page does with no connection.

   Frontend "Offline mode: open your saved copy without a connection, nothing
   sent until you're back" added sw.js's app shell, scripts/bf-offline.js (the
   saved copy, the banner and the locked controls), the setting on Settings
   and Your data, and the deletion of the copy on every sign-out path. The
   backend's lib/yourData.js describes the copy (DEVICE_COPY) on the Your data
   page. This reads the frontend checkout beside this repo.

   WHAT THIS PROVES
     I.   sw.js, run in a vm with a stubbed cache and network: it caches only
          the app pages and static files it lists, never /api, another origin,
          a write, or the sign-in and billing pages; the cache is named by the
          build, which netlify.toml sets to the commit, and an older cache is
          deleted on activate; offline, a listed page comes from the cache and
          an unlisted one gets the needs-a-connection page; nothing is queued.
     II.  bf-offline.js, run in jsdom with a stubbed fetch and IndexedDB: the
          copy is written only when the setting is on, holds no token or
          payment data, never holds the export or a write, stays under its
          limits, and is deleted at once when the setting is turned off.
     III. Offline: with a copy, the data and the banner show and every write
          button is disabled (also ones drawn or re-enabled later), a form
          cannot submit, and a write is refused, never queued; without a copy,
          the page says plainly it needs a connection; a 401 or a 402 is never
          treated as offline; back online, the page reloads.
     IV.  Every sign-out path clears every per-member key, the Termaximus
          insight cache and the offline copy, through bf-session.js's one
          clearDevice: dashboard.html and settings.html's Sign Out,
          bf-session.js's end of a session, the account delete on
          your-data.html, and app.html opened with no session. Every storage
          key in the frontend is either on that list or kept for a reason.
     V.   Honest copy: lib/yourData.js's DEVICE_COPY says what bf-offline.js
          does, word for word; your-data.html shows it and works offline from
          its copy; the setting is on Settings (Account); the guide has its tip.

   MUTATE=<name> edits a frontend file IN MEMORY. MUTATE=all runs each in its
   own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR, never
   counted as caught. BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkOfflineMode: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkOfflineMode: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SW = "sw.js", OFF = "scripts/bf-offline.js", SESSION = "scripts/bf-session.js", DASH = "dashboard.html", SETTINGS = "settings.html",
  YOURDATA = "your-data.html", APP = "app.html", GUIDE = "scripts/termaximus-guide.js", TOML = "netlify.toml", WALLET = "wallet.html";

const MUTATIONS = {
  // the worker caches /api
  "sw-caches-api": [[SW, "if (url.pathname === \"/api\" || url.pathname.indexOf(\"/api/\") === 0) return \"pass\";",
    "if (url.pathname === \"/api\" || url.pathname.indexOf(\"/api/\") === 0) return \"static\";"]],
  // the worker caches the sign-in page
  "sw-caches-login": [[SW, "var NEVER_PAGES = [\"app.html\", \"billing.html\", \"reset-password.html\", \"verify-email.html\"];",
    "var NEVER_PAGES = [\"billing.html\", \"reset-password.html\", \"verify-email.html\"];\nOFFLINE_PAGES.push(\"app.html\");"]],
  // a deploy keeps the old cache
  "sw-keeps-old-cache": [[SW, "return n.indexOf(\"bf-shell-\") === 0 && n !== CACHE;", "return false;"]],
  // the copy is saved with the setting OFF
  "save-with-setting-off": [[OFF, "if (rule && enabled()) saveCopy(key, rule, response.clone());", "if (rule) saveCopy(key, rule, response.clone());"]],
  // the copy keeps Stripe keys
  "copy-keeps-stripe": [[OFF, "var SECRET_KEY = /token|secret|password|refresh|stripe|card|payment|billing|iban|api_?key/i;",
    "var SECRET_KEY = /token|secret|password|refresh|card|payment|billing|iban|api_?key/i;"]],
  // turning the setting off leaves the copy
  "off-keeps-copy": [[OFF, "    try { localStorage.removeItem(SETTING_KEY); } catch (e) { /* storage unavailable */ }\n    deleteCopy();\n",
    "    try { localStorage.removeItem(SETTING_KEY); } catch (e) { /* storage unavailable */ }\n"]],
  /* Sign-out does not clear, on each path.
     BEFORE (frontend c57bad5): each path removed bf_offline_copy and deleted the database inline, and each mutation removed those lines.
     AFTER: each path calls scripts/bf-session.js clearDevice(), and each mutation removes that call; two more break clearDevice itself. */
  "dashboard-signout-keeps-copy": [[DASH, "    window.BFSession.clearDevice();\n    window.location.replace(\"/app.html\"", "    window.location.replace(\"/app.html\""]],
  "settings-signout-keeps-copy": [[SETTINGS, "        window.BFSession.clearDevice();\n", ""]],
  "session-end-keeps-copy": [[SESSION, "    clearDevice();\n\n    /* THE REASON TRAVELS IN THE URL", "\n    /* THE REASON TRAVELS IN THE URL"]],
  "delete-keeps-copy": [[YOURDATA, "          if (window.BFSession) window.BFSession.clearDevice();\n", ""]],
  "app-keeps-copy": [[APP, "if (!localStorage.getItem(\"bf_token\") && window.BFSession) window.BFSession.clearDevice();", "if (false) window.BFSession.clearDevice();"]],
  // sign-out leaving bizforce_ai_mailbox
  "signout-leaves-mailbox": [[SESSION, "    \"bizforce_ai_mailbox\", \"bf_agent_memories\",\n", "    \"bf_agent_memories\",\n"]],
  // the Termaximus insights cached for the tab survive sign-out
  "insight-cache-kept": [[SESSION, "  var PER_USER_SESSION_PREFIXES = [\"bf_tmx_insight:\", \"bf_tmx_trail\"];", "  var PER_USER_SESSION_PREFIXES = [\"bf_tmx_trail\"];"]],
  // the Guide mode page trail survives sign-out
  "trail-kept-at-signout": [[SESSION, "  var PER_USER_SESSION_PREFIXES = [\"bf_tmx_insight:\", \"bf_tmx_trail\"];", "  var PER_USER_SESSION_PREFIXES = [\"bf_tmx_insight:\"];"]],
  // data-clear-only still runs the session guard (app.html would redirect to itself)
  "clear-only-runs-guard": [[SESSION, "  if (thisScript && thisScript.hasAttribute && thisScript.hasAttribute(\"data-clear-only\")) return;\n", ""]],
  // a write button left enabled offline
  "write-button-enabled-offline": [[OFF, "var WRITE_CONTROLS = \"button, input[type=submit], input[type=button], input[type=image], input[type=reset]\";",
    "var WRITE_CONTROLS = \"input[type=submit], input[type=button], input[type=image], input[type=reset]\";"]],
  // a button the page re-enables stays enabled
  "no-relock": [[OFF, "      observer = new MutationObserver(lockWrites);\n", "      observer = { observe: function () {} };\n"]],
  // a 401 shown as offline
  "401-shown-as-offline": [[OFF, "        if (!response.ok) return response;\n",
    "        if (!response.ok) return readCopy(key).then(function (rec) { if (!rec) return response; showSavedCopy(rec.savedAt); " +
    "return new Response(rec.body, { status: 200, headers: { \"Content-Type\": \"application/json\" } }); }, function () { return response; });\n"]],
  // a write offline is queued and sent when the connection returns
  "queue-writes": [[OFF, "        if (state.offline) return Promise.reject(new TypeError(LOCK_REASON));\n",
    "        if (state.offline) { var held = arguments, self = this; window.addEventListener(\"online\", function () { nativeFetch.apply(self, held); }); " +
    "return Promise.reject(new TypeError(LOCK_REASON)); }\n"]],
  // offline without a copy, the page says nothing
  "no-needs-message": [[OFF, "        if (!rule || !enabled()) { showNeedsConnection(); throw err; }\n", "        if (!rule || !enabled()) { throw err; }\n"]],
  // the Your data page's description of the copy drifts from what the code saves
  "description-drifts": [[OFF, "    { path: /^\\/api\\/wallet$/, what: \"your wallet balance and history\" },\n",
    "    { path: /^\\/api\\/wallet$/, what: \"your wallet balance and history\" },\n    { path: /^\\/api\\/messages$/, what: \"your messages\" },\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[SW, OFF, SESSION, DASH, SETTINGS, YOURDATA, APP, GUIDE, TOML, WALLET].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const flush = async (n) => { for (let i = 0; i < (n || 60); i++) await new Promise(r => setImmediate(r)); };

let JSDOM, VirtualConsole;
try { ({ JSDOM, VirtualConsole } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const ORIGIN = "https://bizforce.test";
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const TOKEN = "tok-SECRET-123";

/* ── a fake IndexedDB: only what bf-offline.js uses ─────────────────────── */
function fakeIDB() {
  const dbs = new Map();
  const log = { opens: 0, deletes: [] };
  const later = fn => setImmediate(fn);
  const request = () => ({ result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null });
  const copy = v => JSON.parse(JSON.stringify(v));
  const api = {
    open(name) {
      log.opens++;
      const req = request();
      later(() => {
        let stores = dbs.get(name), fresh = false;
        if (!stores) { stores = new Map(); dbs.set(name, stores); fresh = true; }
        const db = {
          onversionchange: null, closed: false,
          createObjectStore(st) { stores.set(st, new Map()); return {}; },
          transaction(st, mode) {
            const map = stores.get(st);
            if (!map) throw new Error("no store " + st);
            const tx = { oncomplete: null, onerror: null, onabort: null, error: null };
            let pending = 0, done = false;
            const finish = () => later(() => { if (!done && pending === 0) { done = true; if (tx.oncomplete) tx.oncomplete(); } });
            const op = fn => { const r = request(); pending++; later(() => { r.result = fn(); pending--; if (r.onsuccess) r.onsuccess(); finish(); }); return r; };
            const rw = () => { if (mode !== "readwrite") throw new Error("read-only transaction"); };
            tx.objectStore = () => ({
              put(v) { rw(); return op(() => { map.set(v.key, copy(v)); return v.key; }); },
              get(k) { return op(() => (map.has(k) ? copy(map.get(k)) : undefined)); },
              getAll() { return op(() => [...map.values()].map(copy)); },
              delete(k) { rw(); return op(() => { map.delete(k); }); }
            });
            finish();
            return tx;
          },
          close() { this.closed = true; }
        };
        req.result = db;
        if (fresh && req.onupgradeneeded) req.onupgradeneeded();
        if (req.onsuccess) req.onsuccess();
      });
      return req;
    },
    deleteDatabase(name) { log.deletes.push(name); dbs.delete(name); return request(); }
  };
  const rows = () => { const st = dbs.get("bf-offline"); return st && st.get("copies") ? [...st.get("copies").values()] : []; };
  const seed = (key, body, savedAt) => {
    if (!dbs.has("bf-offline")) dbs.set("bf-offline", new Map([["copies", new Map()]]));
    dbs.get("bf-offline").get("copies").set(key, { key, savedAt, body: JSON.stringify(body) });
  };
  return { api, dbs, log, rows, seed };
}

const json = (body, status) => new Response(JSON.stringify(body), { status: status || 200, headers: { "Content-Type": "application/json" } });

/* ── a page in jsdom with bf-offline.js loaded ───────────────────────────── */
function page(opts) {
  const reloads = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", e => { if (/navigation/i.test(String(e && e.message))) reloads.push(e.message); });
  const dom = new JSDOM(opts.html, { url: ORIGIN + "/" + (opts.file || "fixture.html"), runScripts: "outside-only", virtualConsole: vc });
  const w = dom.window;
  const idb = opts.idb || fakeIDB();
  const calls = [];
  w.indexedDB = idb.api;
  w.Response = Response;
  w.API_URL = API;
  if (opts.token !== null) w.localStorage.setItem("bf_token", opts.token || TOKEN);
  if (opts.on) w.localStorage.setItem("bf_offline_copy", "on");
  w.fetch = function (input, init) {
    const url = typeof input === "string" ? input : input.url;
    const method = String((init && init.method) || "GET").toUpperCase();
    calls.push({ url, method, init });
    // Marked handled, so a request sent with nobody listening (a queued write) is counted by the checks, not a crash.
    const answer = Promise.resolve().then(() => opts.net(url, method, init));
    answer.catch(() => {});
    return answer;
  };
  if (opts.before) opts.before(w);
  (opts.pre || []).forEach(code => w.eval(code));
  w.eval(FILES[OFF]);
  if (opts.script) w.eval(opts.script);
  return { w, doc: w.document, idb, calls, reloads };
}

const FIXTURE = `<!DOCTYPE html><html><head></head><body>
<nav><button id="navBtn" type="button">Wallet</button></nav>
<p id="balance">…</p><p id="err"></p>
<button id="runTask" type="button">Run task</button>
<button id="sendBfc" type="button">Send BFC</button>
<form id="saveForm"><input id="field" type="text"><button id="saveBtn" type="submit">Save</button></form>
<button id="buyBtn" type="button">Buy</button><button id="approveBtn" type="button">Approve</button>
<button id="deleteBtn" type="button">Delete</button><input id="goInput" type="submit" value="Go">
<button id="signOut" type="button" data-offline-ok>Sign Out</button>
</body></html>`;
const WRITE_IDS = ["runTask", "sendBfc", "saveBtn", "buyBtn", "approveBtn", "deleteBtn", "goInput"];
const LOAD_WALLET = `
  window.submitted = 0;
  document.getElementById("saveForm").addEventListener("submit", function (e) { window.submitted++; e.preventDefault(); });
  fetch(API_URL + "/api/wallet", { headers: { "Authorization": "Bearer " + localStorage.getItem("bf_token") } })
    .then(function (r) { window.walletStatus = r.status; return r.json(); })
    .then(function (d) { document.getElementById("balance").textContent = "Balance " + d.balance; })
    .catch(function () { document.getElementById("err").textContent = "could not load"; });
`;
const SAVED_RE = /^Offline — showing your saved copy from (.+)\. Nothing can be sent or changed until you're back online\.$/;
const NEEDS = "Offline — this page needs a connection: there is no saved copy of it on this device. Nothing can be sent or changed until you're back online.";
const bannerText = d => { const t = d.getElementById("bf-offline-text"); return t ? t.textContent : null; };
const netDown = () => Promise.reject(new TypeError("Failed to fetch"));

const WALLET_BODY = { balance: 1250, transactions: [{ id: "t1", type: "credit", amount: 100, description: "Certification", created_at: "2026-10-20T09:00:00Z",
  access_token: TOKEN, card: { last4: "4242" } }], bfcDisclaimer: "x" };
const ME_BODY = { user: { id: "u1", email: "owner+bftest@example.com", role: "user", subscription_status: "active", subscription_plan: "all_access", subscription_active: true },
  profile: { username: "owner" }, subscription: { plan: "all_access", status: "active", stripe_customer_id: "cus_PAY123", stripe_subscription_id: "sub_PAY123" },
  access: { active: true } };

(async function main() {
  const YD = require(path.join(REPO, "lib", "yourData.js"));
  const SERVER = lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8"));

  // ════ I. the service worker ════
  console.log("\n══ I. sw.js: the app shell ══");
  {
    function runWorker(src) {
      const listeners = {}, caches = new Map(), deleted = [], puts = [], net = [];
      let online = true;
      const cacheApi = {
        open: async name => {
          if (!caches.has(name)) caches.set(name, new Map());
          const m = caches.get(name);
          return { put: async (k, r) => { const key = typeof k === "string" ? k : k.url; puts.push({ name, key }); m.set(key, r); },
                   match: async k => m.get(typeof k === "string" ? k : k.url) };
        },
        keys: async () => [...caches.keys()],
        delete: async n => { deleted.push(n); return caches.delete(n); }
      };
      const self = {
        location: { origin: ORIGIN },
        addEventListener: (t, fn) => { (listeners[t] = listeners[t] || []).push(fn); },
        skipWaiting: () => {}, clients: { claim: async () => {}, matchAll: async () => [] }, registration: { showNotification: async () => {} }
      };
      const ctx = { self, caches: cacheApi, URL, Response, Promise, console,
        fetch: async (req) => {
          const url = typeof req === "string" ? new URL(req, ORIGIN).href : req.url;
          net.push(url);
          if (!online) throw new TypeError("Failed to fetch");
          const r = new Response("<html>" + url + "</html>", { status: 200 });
          // A same-origin response, and its clone, are "basic" in a browser; Node's are "default".
          const basic = x => { Object.defineProperty(x, "type", { value: "basic" }); const c = x.clone.bind(x); x.clone = () => basic(c()); return x; };
          return basic(r);
        } };
      vm.createContext(ctx);
      vm.runInContext(src, ctx);
      const kinds = Object.keys(listeners);
      const dispatch = async (type, init) => {
        const waits = []; let responded = null;
        const ev = Object.assign({ waitUntil: p => waits.push(p), respondWith: p => { responded = Promise.resolve(p); } }, init || {});
        (listeners[type] || []).forEach(fn => fn(ev));
        await Promise.all(waits);
        const res = responded ? await responded : null;
        await flush(10);
        return { responded: !!responded, res };
      };
      const req = (url, o) => Object.assign({ url: new URL(url, ORIGIN).href, method: "GET", mode: "cors" }, o || {});
      return { ctx, listeners, kinds, caches, deleted, puts, net, dispatch, req, setOnline: v => { online = v; } };
    }

    const BUILT = FILES[SW].split("__BF_BUILD__").join("abc1234");
    const sw = runWorker(BUILT);
    check("I1. it listens for install, activate, fetch, push and notificationclick only: no sync or background-fetch handler, so nothing is queued",
      JSON.stringify(sw.kinds.slice().sort()) === JSON.stringify(["activate", "fetch", "install", "notificationclick", "push"]), sw.kinds.join(","));
    const PAGES = vm.runInContext("OFFLINE_PAGES.slice()", sw.ctx), STATIC = vm.runInContext("STATIC_FILES.slice()", sw.ctx), NEVER = vm.runInContext("NEVER_PAGES.slice()", sw.ctx);
    check("I2. the sign-in and billing pages are on its never list", ["app.html", "billing.html", "reset-password.html", "verify-email.html"].every(p => NEVER.indexOf(p) !== -1), NEVER.join(","));
    check("I3. no listed page is a sign-in or billing page, and nothing listed is under /api",
      PAGES.length >= 20 && PAGES.every(p => NEVER.indexOf(p) === -1 && !/^api\//.test(p) && /\.html$/.test(p)) && STATIC.every(f => !/^\/api/.test(f)),
      PAGES.filter(p => NEVER.indexOf(p) !== -1).join(","));
    check("I4. every static file it lists is a stylesheet, script, icon or the manifest, and exists in the frontend",
      STATIC.every(f => /^\/(css\/[\w.-]+\.css|scripts\/[\w.-]+\.js|icons\/[\w.-]+\.(png|svg)|manifest\.json)$/.test(f) && fs.existsSync(path.join(FRONTEND, f))),
      STATIC.filter(f => !fs.existsSync(path.join(FRONTEND, f))).join(","));
    const pageSrc = p => lf(fs.readFileSync(path.join(FRONTEND, p), "utf8"));
    const missing = PAGES.filter(p => !fs.existsSync(path.join(FRONTEND, p)) || pageSrc(p).indexOf("<script src=\"/scripts/bf-offline.js\"></script>") === -1);
    check("I5. every listed page exists and loads bf-offline.js (so it has the banner and the locked controls offline)", missing.length === 0, missing.join(","));
    const loaders = [];
    (function walk(dir) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
        const p = path.join(dir, d.name);
        if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
        else if (d.name.endsWith(".html") && fs.readFileSync(p, "utf8").indexOf("/scripts/bf-offline.js") !== -1) loaders.push(path.relative(FRONTEND, p).replace(/\\/g, "/"));
      });
    })(FRONTEND);
    check("I6. the worker is registered from app pages only: every page that loads bf-offline.js is a listed app page, and no other page registers it",
      loaders.every(p => PAGES.indexOf(p) !== -1) && loaders.length === PAGES.length &&
      ["index.html", DASH].every(p => pageSrc(p).indexOf("serviceWorker.register") === -1) && /navigator\.serviceWorker\.register\("\/sw\.js"\)/.test(FILES[OFF]),
      loaders.filter(p => PAGES.indexOf(p) === -1).join(","));

    // install
    await sw.dispatch("install");
    const names = [...sw.caches.keys()];
    check("I7. the cache is named by the build: bf-shell-<commit>", names.length === 1 && names[0] === "bf-shell-abc1234", names.join(","));
    check("I8. netlify.toml's build writes the deploying commit into sw.js, and sw.js carries the placeholder it replaces",
      /command = 'sed -i "s\/__BF_BUILD__\/\$\{COMMIT_REF:-local\}\/" sw\.js'/.test(FILES[TOML]) && (FILES[SW].match(/__BF_BUILD__/g) || []).length === 1 &&
      /var BUILD = "__BF_BUILD__";\nvar CACHE = "bf-shell-" \+ BUILD;/.test(FILES[SW]));
    const installed = sw.puts.map(p => p.key);
    const allowed = PAGES.map(p => "/" + p).concat(STATIC);
    check("I9. install caches the listed pages and files, and nothing else", installed.length === allowed.length && installed.every(k => allowed.indexOf(k) !== -1),
      installed.filter(k => allowed.indexOf(k) === -1).join(","));

    // activate: an older shell cache goes, another app's cache stays
    sw.caches.set("bf-shell-old0000", new Map()); sw.caches.set("someone-else", new Map());
    await sw.dispatch("activate");
    check("I10. a new deploy deletes the older bf-shell cache on activate and keeps its own", sw.deleted.join(",") === "bf-shell-old0000" && sw.caches.has("bf-shell-abc1234") && sw.caches.has("someone-else"),
      sw.deleted.join(","));

    // requests it must never handle
    sw.puts.length = 0;
    const NEVER_REQ = [
      ["GET /api/wallet on this origin", sw.req("/api/wallet")],
      ["GET /api/me/export on this origin", sw.req("/api/me/export")],
      ["GET /api/unsubscribe (proxied by Netlify)", sw.req("/api/unsubscribe", { mode: "navigate" })],
      ["the API on its own origin", sw.req(API + "/api/wallet")],
      ["the sign-in page", sw.req("/app.html", { mode: "navigate" })],
      ["the sign-in page by its short path", sw.req("/app", { mode: "navigate" })],
      ["billing", sw.req("/billing.html", { mode: "navigate" })],
      ["reset-password", sw.req("/reset-password.html?token=abc", { mode: "navigate" })],
      ["verify-email", sw.req("/verify-email?token=abc", { mode: "navigate" })],
      ["a POST to a listed page", sw.req("/dashboard.html", { method: "POST", mode: "navigate" })],
      ["a script it does not list", sw.req("/scripts/unknown.js")],
      ["a font from another origin", sw.req("https://fonts.googleapis.com/css2?family=Orbitron")]
    ];
    const handled = [];
    for (const [label, r] of NEVER_REQ) { const out = await sw.dispatch("fetch", { request: r }); if (out.responded) handled.push(label); }
    check("I11. it never takes on /api, another origin, a write, the sign-in and billing pages, or a file it does not list",
      handled.length === 0 && sw.puts.length === 0, handled.join(" | ") + " / puts " + sw.puts.map(p => p.key).join(","));

    // a listed page: network first, cached, served from cache offline
    const dashNav = await sw.dispatch("fetch", { request: sw.req("/dashboard", { mode: "navigate" }) });
    check("I12. online, a listed page comes from the network and is cached under its .html name",
      dashNav.responded && (await dashNav.res.clone().text()).indexOf(ORIGIN + "/dashboard") !== -1 && sw.puts.some(p => p.key === "/dashboard.html"), sw.puts.map(p => p.key).join(","));
    await sw.dispatch("fetch", { request: sw.req("/scripts/bf-offline.js") });
    check("I13. online, a listed static file is cached", sw.puts.some(p => p.key === "/scripts/bf-offline.js"));
    sw.setOnline(false);
    const offDash = await sw.dispatch("fetch", { request: sw.req("/dashboard.html?tab=1", { mode: "navigate" }) });
    check("I14. offline, a listed page opens from the cache", offDash.responded && offDash.res && offDash.res.status === 200 && (await offDash.res.text()).indexOf("/dashboard") !== -1);
    const offOther = await sw.dispatch("fetch", { request: sw.req("/marketplace.html", { mode: "navigate" }) });
    const otherText = offOther.res ? await offOther.res.text() : "";
    check("I15. offline, a page it does not keep says plainly it needs a connection, and was never cached",
      offOther.responded && offOther.res.status === 503 && /needs a connection/.test(otherText) && !sw.puts.some(p => /marketplace/.test(p.key)), offOther.res && offOther.res.status);
    sw.setOnline(true);
    await sw.dispatch("fetch", { request: sw.req("/marketplace.html", { mode: "navigate" }) });
    check("I16. online, a page it does not keep is fetched and not cached", !sw.puts.some(p => /marketplace/.test(p.key)));
    check("I17. it holds no sync, background-fetch or request store anywhere", !/addEventListener\("(sync|periodicsync|backgroundfetch\w*)"/.test(FILES[SW]) && !/\bSyncManager\b|\.sync\.register\(/.test(FILES[SW] + FILES[OFF]));
  }

  // ════ II. the saved copy ════
  console.log("\n══ II. bf-offline.js: the saved copy ══");
  {
    const READS = {
      "/api/wallet": WALLET_BODY, "/api/auth/me": ME_BODY, "/api/business-profile": { business_name: "Rose Co", api_key: "sk-live-1", stripe_account_id: "acct_PAY1" },
      "/api/ai/tasks?limit=25": { tasks: [{ id: "a1", status: "completed" }] }, "/api/ai/tasks/a1": { task: { id: "a1", output: "done", refresh_token: TOKEN } },
      "/api/agents": { agents: [{ type: "seo" }] }, "/api/agents/seo": { agent: { type: "seo", last_run_at: "2026-10-20" } }, "/api/your-data": YD.describe(),
      "/api/me/export": { manifest: { complete: true }, users: [{ email: "owner+bftest@example.com" }] }, "/api/billing/portal": { url: "https://billing.example/x" },
      "/api/command-center": { needs: [] }, "/api/wallet/recipient?username=bob": { username: "bob" }, "/api/agents/sales/leads": { leads: [{ email: "lead+bftest@example.com" }] },
      "/api/auth/refresh": { token: TOKEN }, "/api/messages": { messages: [] }
    };
    const net = url => { const k = url.slice(API.length); return READS[k] ? json(READS[k]) : json({ error: "nope" }, 404); };
    const loadAll = async p => { for (const k of Object.keys(READS)) await p.w.fetch(API + k, { headers: { Authorization: "Bearer " + TOKEN } }).then(r => r.json()).catch(() => null); await flush(); };

    const offP = page({ html: FIXTURE, net });
    await loadAll(offP);
    check("II1. with the setting off (the default), nothing is saved: no database is even opened", offP.idb.log.opens === 0 && offP.idb.rows().length === 0 && offP.w.BFOffline.enabled() === false,
      offP.idb.log.opens + " opens");

    const onP = page({ html: FIXTURE, net });
    onP.w.BFOffline.setEnabled(true);
    check("II2. turning it on stores only the setting", onP.w.localStorage.getItem("bf_offline_copy") === "on");
    await loadAll(onP);
    const keys = onP.idb.rows().map(r => r.key).sort();
    const WANT = ["/api/agents", "/api/agents/seo", "/api/ai/tasks/a1", "/api/ai/tasks?limit=25", "/api/auth/me", "/api/business-profile", "/api/wallet", "/api/your-data"];
    check("II3. with it on, exactly the listed reads are saved: tasks and results, business profile, agents and last runs, wallet, account, Your data",
      JSON.stringify(keys) === JSON.stringify(WANT), keys.join(","));
    check("II4. never saved: the data export, billing, the token refresh, other members' details (recipient lookup, leads), or a page it does not list",
      ["/api/me/export", "/api/billing/portal", "/api/auth/refresh", "/api/wallet/recipient?username=bob", "/api/agents/sales/leads", "/api/command-center", "/api/messages"].every(k => keys.indexOf(k) === -1));
    // The Your data description is public copy (it names Stripe and API keys as things BizForce stores); every other copy is member data.
    const allBodies = onP.idb.rows().filter(r => r.key !== "/api/your-data").map(r => r.body).join("\n");
    check("II5. no saved copy holds a token, a Stripe id, a card or a key", allBodies.indexOf(TOKEN) === -1 && !/cus_|sub_PAY|4242|sk-live|stripe|"card"|access_token|refresh_token|api_key/i.test(allBodies),
      (allBodies.match(/cus_\w+|sub_PAY\w*|4242|sk-live-\d|stripe\w*|access_token|refresh_token|api_key/gi) || []).join(","));
    const me = JSON.parse((onP.idb.rows().find(r => r.key === "/api/auth/me") || { body: "{}" }).body);
    check("II6. /api/auth/me is saved without its subscription row; the account details stay", me.subscription === undefined && me.user && me.user.email === "owner+bftest@example.com" && me.access.active === true,
      Object.keys(me).join(","));
    const wal = JSON.parse((onP.idb.rows().find(r => r.key === "/api/wallet") || { body: "{}" }).body);
    check("II7. the wallet's balance and history are saved", wal.balance === 1250 && wal.transactions && wal.transactions[0].amount === 100);
    check("II8. each copy carries the time it was saved", onP.idb.rows().every(r => typeof r.savedAt === "number" && Math.abs(Date.now() - r.savedAt) < 60000));
    const before = onP.idb.rows().length;
    await onP.w.fetch(API + "/api/wallet/transfer", { method: "POST", headers: { Authorization: "Bearer " + TOKEN }, body: "{}" }).catch(() => null);
    await onP.w.fetch(API + "/api/business-profile", { method: "PUT", body: "{}" }).catch(() => null);
    await flush();
    check("II9. a write is sent as normal online and never saved", onP.idb.rows().length === before && onP.calls.filter(c => c.method !== "GET").length === 2);
    // a 401 or 402 is not saved
    const p402 = page({ html: FIXTURE, on: true, net: () => json({ error: "subscription required" }, 402) });
    await p402.w.fetch(API + "/api/wallet"); await flush();
    check("II10. a refused read (402) is not saved", p402.idb.rows().length === 0);

    // limits
    const big = page({ html: FIXTURE, on: true, net: url => json({ task: { id: url.slice(-2), output: "x".repeat(url.endsWith("99") ? 1100000 : 900000) } }) });
    for (let i = 10; i < 18; i++) { await big.w.fetch(API + "/api/ai/tasks/t" + i); await flush(); }
    await big.w.fetch(API + "/api/ai/tasks/t99"); await flush();
    const total = big.idb.rows().reduce((a, r) => a + r.body.length, 0), bigKeys = big.idb.rows().map(r => r.key);
    check("II11. the copy stays within about 5 MB: the oldest are removed first", total <= 5 * 1024 * 1024 && bigKeys.indexOf("/api/ai/tasks/t10") === -1 && bigKeys.indexOf("/api/ai/tasks/t17") !== -1,
      total + " chars, " + bigKeys.length + " copies");
    check("II12. a single response over 1 MB is not saved", bigKeys.indexOf("/api/ai/tasks/t99") === -1);

    // turning it off deletes at once
    onP.w.BFOffline.setEnabled(false);
    check("II13. turning it off deletes the copy at once, and the setting", onP.idb.log.deletes.indexOf("bf-offline") !== -1 && onP.idb.rows().length === 0 && onP.w.localStorage.getItem("bf_offline_copy") === null);
    await loadAll(onP);
    check("II14. ... and nothing more is saved after it", onP.idb.rows().length === 0);
    // the toggle on a page does the same
    const tg = page({ html: "<!DOCTYPE html><body><div id=\"slot\"></div></body>", on: true, net });
    tg.w.BFOffline.mountSetting(tg.doc.getElementById("slot"));
    const box = tg.doc.getElementById("bfOfflineToggle");
    check("II15. the setting shows as \"" + YD.DEVICE_COPY.setting + "\", ticked when on", !!box && box.checked === true && tg.doc.getElementById("slot").textContent.indexOf(YD.DEVICE_COPY.setting) !== -1);
    box.checked = false; box.dispatchEvent(new tg.w.Event("change"));
    check("II16. unticking it deletes the copy and says so", tg.idb.log.deletes.indexOf("bf-offline") !== -1 && tg.w.localStorage.getItem("bf_offline_copy") === null &&
      /deleted/.test(tg.doc.querySelector(".bf-offline-status").textContent));
    const fresh = page({ html: "<!DOCTYPE html><body><div id=\"slot\"></div></body>", net });
    fresh.w.BFOffline.mountSetting(fresh.doc.getElementById("slot"));
    check("II17. it is off by default", fresh.doc.getElementById("bfOfflineToggle").checked === false);
  }

  // ════ III. offline ════
  console.log("\n══ III. offline ══");
  {
    const SAVED_AT = Date.UTC(2026, 9, 20, 9, 5);
    const seeded = () => { const idb = fakeIDB(); idb.seed("/api/wallet", { balance: 777, transactions: [] }, SAVED_AT); return idb; };

    const p = page({ html: FIXTURE, on: true, idb: seeded(), net: netDown, script: LOAD_WALLET });
    await flush();
    const text = bannerText(p.doc) || "";
    check("III1. offline with a copy, the page shows the saved data", p.doc.getElementById("balance").textContent === "Balance 777" && p.w.walletStatus === 200, p.doc.getElementById("balance").textContent);
    check("III2. ... under the banner \"Offline — showing your saved copy from <date, time>. Nothing can be sent or changed until you're back online.\"",
      SAVED_RE.test(text) && /2026/.test(text), text);
    const banner = p.doc.getElementById("bf-offline-banner");
    check("III3. the banner is at the top of the page and is announced (role=status)", !!banner && p.doc.body.firstElementChild === banner && banner.getAttribute("role") === "status");
    const enabledWrites = WRITE_IDS.filter(id => !p.doc.getElementById(id).disabled);
    check("III4. every write button (run task, send BFC, save, buy, approve, delete, a submit input) is disabled", enabledWrites.length === 0, enabledWrites.join(","));
    check("III5. each says why", WRITE_IDS.every(id => p.doc.getElementById(id).title === "Offline: nothing can be sent or changed until you're back online."));
    check("III6. navigation and Sign Out stay usable", !p.doc.getElementById("navBtn").disabled && !p.doc.getElementById("signOut").disabled);
    const late = p.doc.createElement("button"); late.id = "late"; late.textContent = "Approve"; p.doc.body.appendChild(late);
    p.doc.getElementById("deleteBtn").disabled = false;
    await flush();
    check("III7. a button the page draws later, or re-enables, is disabled again", late.disabled === true && p.doc.getElementById("deleteBtn").disabled === true);
    const ev = new p.w.Event("submit", { cancelable: true, bubbles: true });
    p.doc.getElementById("saveForm").dispatchEvent(ev);
    check("III8. a form cannot submit", ev.defaultPrevented && p.w.submitted === 0, p.w.submitted);
    const before = p.calls.length;
    let refused = null;
    await p.w.fetch(API + "/api/wallet/transfer", { method: "POST", body: "{}" }).then(() => { refused = false; }, e => { refused = e; });
    check("III9. a write attempted anyway is refused here, never sent", refused && /nothing can be sent/.test(refused.message) && p.calls.length === before, refused && refused.message);
    // back online: a reload, and nothing that was refused is sent
    p.w.dispatchEvent(new p.w.Event("online"));
    await flush();
    check("III10. back online the page reloads (the banner clears and fresh data loads)", p.reloads.length === 1, p.reloads.length);
    check("III11. nothing was queued: the refused write is never sent, then or after", p.calls.filter(c => c.method !== "GET").length === 0, p.calls.map(c => c.method + " " + c.url).join(" | "));

    // two copies of different ages: the oldest is the time shown
    const idb2 = seeded(); idb2.seed("/api/business-profile", { business_name: "Rose" }, SAVED_AT + 86400000);
    const p2 = page({ html: FIXTURE, on: true, idb: idb2, net: netDown });
    await p2.w.fetch(API + "/api/business-profile").catch(() => null); await flush();
    const t1 = bannerText(p2.doc);
    await p2.w.fetch(API + "/api/wallet").catch(() => null); await flush();
    const t2 = bannerText(p2.doc);
    check("III12. the banner shows the oldest saved time on the page", t1 !== t2 && SAVED_RE.test(t2) && /20/.test(SAVED_RE.exec(t2)[1]), t1 + " → " + t2);

    // no copy
    const n = page({ html: FIXTURE, on: true, net: netDown, script: LOAD_WALLET });
    await flush();
    check("III13. offline without a copy, the page says plainly it needs a connection", bannerText(n.doc) === NEEDS && n.doc.getElementById("err").textContent === "could not load", bannerText(n.doc));
    check("III14. ... and its write buttons are disabled too", WRITE_IDS.every(id => n.doc.getElementById(id).disabled));
    const nOff = page({ html: FIXTURE, idb: seeded(), net: netDown, script: LOAD_WALLET });
    await flush();
    check("III15. with the setting off, an old copy is never shown: the page needs a connection", bannerText(nOff.doc) === NEEDS && nOff.idb.log.opens === 0);

    // 401 and 402 are answers, not offline
    for (const status of [401, 402]) {
      const q = page({ html: FIXTURE, on: true, idb: seeded(), net: () => json({ error: "no" }, status), script: LOAD_WALLET });
      await flush();
      check("III16. a " + status + " is not treated as offline: the page gets the " + status + ", no saved copy, no banner, nothing disabled",
        q.w.walletStatus === status && q.doc.getElementById("balance").textContent !== "Balance 777" && bannerText(q.doc) === null && WRITE_IDS.every(id => !q.doc.getElementById(id).disabled) &&
        q.w.BFOffline.isOffline() === false, q.w.walletStatus + " " + bannerText(q.doc));
    }
    // a cancelled request is not offline either
    const ab = page({ html: FIXTURE, on: true, idb: seeded(), net: () => { const e = new Error("aborted"); e.name = "AbortError"; return Promise.reject(e); } });
    let abErr = null; await ab.w.fetch(API + "/api/wallet").catch(e => { abErr = e; }); await flush();
    check("III17. a cancelled request (AbortError) is passed on, not answered from the copy", abErr && abErr.name === "AbortError" && bannerText(ab.doc) === null);

    // a real page: wallet.html's markup, offline
    const walletHtml = FILES[WALLET].replace(/<script[\s\S]*?<\/script>/g, "");
    const wp = page({ html: walletHtml, file: WALLET, on: true, idb: seeded(), net: netDown });
    await wp.w.fetch(API + "/api/wallet").catch(() => null); await flush();
    const open = [...wp.doc.querySelectorAll("button, input[type=submit]")].filter(b => !b.disabled && !b.closest("nav") && !b.closest("[data-offline-ok]"));
    check("III18. on wallet.html offline, Send BFC and Confirm are disabled, with every other button outside navigation",
      wp.doc.getElementById("send-btn").disabled && wp.doc.getElementById("send-confirm-btn").disabled && open.length === 0, open.map(b => b.id || b.textContent).join(","));
  }

  // ════ IV. every sign-out path clears every per-member key ════
  console.log("\n══ IV. sign-out clears every per-member key, cache and copy ══");
  {
    /* Every storage key in the frontend, found by reading every page and script, must be on one of these lists.
       BEFORE (frontend c57bad5): sign-out cleared bf_token, bf_refresh, bf_user and the offline copy only, inline on each path.
       AFTER: one shared scripts/bf-session.js clearDevice() clears PER_USER on every path; KEPT stays, each for its reason. */
    const PER_USER = ["bf_token", "bf_refresh", "bf_user", "bf_offline_copy", "bizforce_ai_mailbox", "bf_agent_memories", "bf_oracle_name", "bf_oracle_date", "mcTargetGoalConversions"];
    const SESSION_PREFIX = "bf_tmx_insight:";
    /* NAMED BEFORE → AFTER (Oct 28 2026, Termaximus Guide mode). BEFORE: sign-out cleared one sessionStorage prefix,
       "bf_tmx_insight:". AFTER: two, ["bf_tmx_insight:", "bf_tmx_trail"]; bf_tmx_trail is Guide mode's last five pages
       in this tab (scripts/termaximus-presence.js), a per-member session key, so IV0 lists it and sign-out clears it. */
    const SESSION_KEYS = ["bf_tmx_trail"];
    const KEPT = {
      bf_editor_theme: "the editor's look", bf_recent_highlights: "the editor's recent colours", bf_recent_textcolors: "the editor's recent colours",
      tmx_presence_active: "Termaximus on or off", tmx_presence_pos: "where Termaximus sits", tmx_mist_corner: "where Termaximus sits",
      tmx_agent_language: "the language Termaximus speaks", oracle_corner_star_pos: "where an Oracle widget sits", bf_oracle_moon_pos: "where an Oracle widget sits",
      bf_active_calendar: "which calendar is shown", bf_agent_order: "card order", bf_dashboard_order: "card order", bf_dashboard_custom: "card order",
      bf_return_to: "the public page to return to after signing in; app.html must still find it"
    };
    // Calls whose key is a parameter, each read here as a helper over keys that are on the lists.
    const DYNAMIC = { "scripts/bf-session.js": ["key"], "scripts/bf-dashboard-order.js": ["key"], "bizdoc.html": ["storageKey"], "scripts/termaximus-guide.js": ["insightCacheKey("] };
    const found = {}, unknown = [];
    (function walk(dir) {
      fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
        const p = path.join(dir, d.name);
        if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); return; }
        if (!/\.(html|js)$/.test(d.name) || /^test-/.test(d.name)) return;
        const rel = path.relative(FRONTEND, p).replace(/\\/g, "/");
        const text = FILES[rel] !== undefined ? FILES[rel] : lf(fs.readFileSync(p, "utf8"));
        for (const m of text.matchAll(/(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\(\s*([^,)]+)/g)) {
          const arg = m[1].trim(), lit = /^["']([^"']+)["']$/.exec(arg);
          let key = lit ? lit[1] : null;
          if (!key) { const c = new RegExp("(?:var|const|let)\\s+" + arg.replace(/[^\w$]/g, "") + "\\s*=\\s*\"([^\"]+)\"").exec(text); if (c) key = c[1]; }
          if (key) found[key] = (found[key] || []).concat(rel);
          else if (!(DYNAMIC[rel] || []).some(a => arg.indexOf(a) === 0)) unknown.push(rel + ": " + arg);
        }
      });
    })(FRONTEND);
    const unlisted = Object.keys(found).filter(k => PER_USER.indexOf(k) === -1 && SESSION_KEYS.indexOf(k) === -1 && !KEPT[k]);
    check("IV0. every storage key in the frontend is either cleared at sign-out or kept for a stated reason (" + Object.keys(found).length + " keys)",
      Object.keys(found).length >= 20 && unlisted.length === 0 && unknown.length === 0, unlisted.concat(unknown).join(", "));
    check("IV0b. ... and the lists are not stale: every key on them is still used", PER_USER.concat(SESSION_KEYS, Object.keys(KEPT)).filter(k => !found[k]).length === 0,
      PER_USER.concat(SESSION_KEYS, Object.keys(KEPT)).filter(k => !found[k]).join(","));
    check("IV0c. the Termaximus insight cache (sessionStorage) is keyed by the prefix sign-out clears", /var INSIGHT_CACHE_PREFIX = "bf_tmx_insight:";/.test(FILES[GUIDE]));

    // A browser with every key set, and a way to read what is left.
    function store(init) {
      const m = new Map(Object.entries(init));
      return { m, getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k),
        key: i => [...m.keys()][i] || null, get length() { return m.size; } };
    }
    const full = token => { const o = {}; PER_USER.forEach(k => { o[k] = "x"; }); Object.keys(KEPT).forEach(k => { o[k] = "kept"; }); if (token) o.bf_token = TOKEN; else delete o.bf_token; return o; };
    const sess = () => store({ [SESSION_PREFIX + "dashboard.html"]: "{\"text\":\"your insight\"}", bf_tmx_trail: "[{\"page\":\"crm.html\",\"t\":1}]", "unrelated-tab-key": "stays" });
    function verdict(ls, ss, idb) {
      const left = PER_USER.filter(k => ls.getItem(k) !== null), lost = Object.keys(KEPT).filter(k => ls.getItem(k) !== "kept");
      const ok = left.length === 0 && lost.length === 0 && ss.getItem(SESSION_PREFIX + "dashboard.html") === null && ss.getItem("unrelated-tab-key") === "stays" &&
        SESSION_KEYS.every(k => ss.getItem(k) === null) &&
        idb.log.deletes.indexOf("bf-offline") !== -1;
      return { ok, why: "left: " + left.join(",") + " / lost: " + lost.join(",") + " / insight " + ss.getItem(SESSION_PREFIX + "dashboard.html") + " / idb " + idb.log.deletes.join(",") };
    }
    // A vm "browser" with bf-session.js loaded, guard mode or data-clear-only.
    function browser(ls, ss, idb, clearOnly, fetchImpl) {
      const replaced = [];
      const ctx = { localStorage: ls, sessionStorage: ss, API_URL: API, AbortController, setTimeout, clearTimeout, console, URL, Promise, Headers,
        indexedDB: idb.api, location: { href: ORIGIN + "/page.html", replace: u => { replaced.push(u); } },
        document: { currentScript: { hasAttribute: n => clearOnly && n === "data-clear-only" } }, fetch: fetchImpl || (async () => ({ ok: true, status: 200 })) };
      ctx.window = ctx;
      vm.createContext(ctx);
      vm.runInContext(FILES[SESSION], ctx);
      return { ctx, replaced };
    }
    const inlineScripts = html => (html.match(/<script>([\s\S]*?)<\/script>/g) || []).map(t => t.slice(8, -9));

    {
      const stub = async () => ({ ok: true, status: 200 });
      const b = browser(store({}), store({}), fakeIDB(), true, stub);
      check("IV1. bf-session.js shares one clearDevice, listing exactly the per-member keys and the insight prefix",
        !!b.ctx.BFSession && typeof b.ctx.BFSession.clearDevice === "function" && JSON.stringify(b.ctx.BFSession.PER_USER_LOCAL.slice().sort()) === JSON.stringify(PER_USER.slice().sort()) &&
        JSON.stringify(b.ctx.BFSession.PER_USER_SESSION_PREFIXES) === JSON.stringify([SESSION_PREFIX].concat(SESSION_KEYS)), b.ctx.BFSession && b.ctx.BFSession.PER_USER_LOCAL.join(","));
      check("IV2. loaded data-clear-only with no session, it does nothing else: no redirect, no fetch wrapper", b.replaced.length === 0 && b.ctx.fetch === stub, b.replaced.join(","));
    }
    // dashboard.html logout()
    {
      const ls = store(full(true)), ss = sess(), idb = fakeIDB();
      let ok = false, why = "";
      try {
        const b = browser(ls, ss, idb, false);
        const code = inlineScripts(FILES[DASH]).find(c => c.indexOf("async function logout()") !== -1);
        vm.runInContext(code, b.ctx); await vm.runInContext("logout()", b.ctx);
        ok = /app\.html/.test(b.replaced.join(","));
      } catch (e) { why = String(e); }
      const v = verdict(ls, ss, idb);
      check("IV3. dashboard.html Sign Out clears every per-member key, the insight cache and the offline copy, and keeps the display choices", ok && v.ok, why || v.why);
    }
    // settings.html Sign Out (no connection)
    {
      const ls = store(full(true)), ss = sess(), idb = fakeIDB();
      let ok = false, why = "";
      try {
        const b = browser(ls, ss, idb, true, async () => { throw new TypeError("Failed to fetch"); });
        const at = FILES[SETTINGS].indexOf("document.getElementById(\"signOutBtn\").addEventListener(\"click\", async function () {");
        const open = FILES[SETTINGS].indexOf("{", FILES[SETTINGS].indexOf("async function ()", at));
        const fn = FILES[SETTINGS].slice(FILES[SETTINGS].indexOf("async function ()", at), s.braceMatch(FILES[SETTINGS], open));
        vm.runInContext("var signingOut = false; var handler = " + fn + ";", b.ctx); await vm.runInContext("handler()", b.ctx);
        ok = /signout-offline/.test(b.replaced.join(","));
      } catch (e) { why = String(e); }
      const v = verdict(ls, ss, idb);
      check("IV4. settings.html Sign Out does the same (here with no connection)", ok && v.ok, why || v.why);
      check("IV5. settings.html loads bf-session.js data-clear-only, in the head, so its own no-renewal sign-out stands",
        /<script src="\/scripts\/bf-session\.js" data-clear-only><\/script>\n  <script src="\/scripts\/bf-offline\.js"><\/script>\n<\/head>/.test(FILES[SETTINGS]));
    }
    // bf-session.js ending a session that cannot be renewed
    {
      const ls = store(full(true)), ss = sess(), idb = fakeIDB();
      ls.removeItem("bf_refresh");
      const b = browser(ls, ss, idb, false, async () => ({ status: 401, ok: false }));
      await b.ctx.fetch(API + "/api/wallet", { headers: { Authorization: "Bearer " + TOKEN } }); await flush();
      const v = verdict(ls, ss, idb);
      check("IV6. bf-session.js ending an expired session does the same", v.ok && /session=expired/.test(b.replaced.join(",")), v.why);
    }
    // your-data.html account delete
    {
      const pg = page({ html: FILES[YOURDATA].replace(/<script[\s\S]*?<\/script>/g, ""), file: YOURDATA, on: true,
        before: w => { const f = full(true); Object.keys(f).forEach(k => w.localStorage.setItem(k, f[k])); w.sessionStorage.setItem(SESSION_PREFIX + "dashboard.html", "x"); w.sessionStorage.setItem("unrelated-tab-key", "stays"); },
        pre: [FILES[SESSION]],
        net: (url) => /\/api\/me\/delete$/.test(url) ? json({ deleted: true, done: [], files: { deleted: 0, queued: 0, kept_for_buyers: 0, not_queued: 0 } }) : json(YD.describe()),
        script: inlineScripts(FILES[YOURDATA]).pop() });
      await flush();
      pg.doc.getElementById("delUsername").value = "owner"; pg.doc.getElementById("delPassword").value = "pw";
      pg.doc.getElementById("deleteForm").dispatchEvent(new pg.w.Event("submit", { cancelable: true, bubbles: true }));
      await flush();
      const v = verdict(pg.w.localStorage, pg.w.sessionStorage, pg.idb);
      check("IV7. deleting the account on your-data.html does the same", v.ok, v.why);
      check("IV8. your-data.html loads bf-session.js for clearDevice even signed out (data-clear-only)",
        FILES[YOURDATA].indexOf("document.write('<script src=\"/scripts/bf-session.js\"' + (localStorage.getItem(\"bf_token\") ? '' : ' data-clear-only') + '><\\/script>');") !== -1);
    }
    // app.html, with no session and with one
    {
      const code = inlineScripts(FILES[APP]).find(c => c.indexOf("clearDevice") !== -1) || "";
      const run = token => { const ls = store(full(token)), ss = sess(), idb = fakeIDB(); const b = browser(ls, ss, idb, true); vm.runInContext(code, b.ctx); return { ls, ss, idb, b }; };
      const out = run(false), inn = run(true);
      const v = verdict(out.ls, out.ss, out.idb);
      check("IV9. app.html opened with no session clears every per-member key, whichever way the session ended, and does not redirect", code !== "" && v.ok && out.b.replaced.length === 0, v.why);
      check("IV10. ... and leaves a signed-in member's keys alone", inn.ls.getItem("bf_token") === TOKEN && inn.ls.getItem("bizforce_ai_mailbox") === "x" && inn.idb.log.deletes.length === 0);
      check("IV11. app.html loads bf-session.js data-clear-only, just before that script",
        /<script src="\/scripts\/bf-session\.js" data-clear-only><\/script>\n<script>\n  \/\* No session on this browser/.test(FILES[APP]));
    }
  }

  // ════ V. honest copy ════
  console.log("\n══ V. what the pages say ══");
  {
    const p = page({ html: "<!DOCTYPE html><body><div id=\"slot\"></div></body>", net: netDown });
    const B = p.w.BFOffline;
    const DC = YD.DEVICE_COPY;
    check("V1. the Your data description lists exactly what bf-offline.js saves, in its words", JSON.stringify(DC.saved) === JSON.stringify(B.savedList()),
      JSON.stringify(B.savedList()));
    check("V2. ... and exactly what it never stores", JSON.stringify(DC.never) === JSON.stringify(B.neverStored()));
    check("V3. ... and the setting's name", DC.setting === B.settingLabel && DC.setting === "Keep a copy on this device for offline use");
    B.mountSetting(p.doc.getElementById("slot"));
    const explain = p.doc.querySelector(".bf-offline-explain").textContent;
    check("V4. the setting's own explanation names every saved and never-stored item, where (IndexedDB, this device), the 5 MB limit, and deletion",
      DC.saved.concat(DC.never).every(t => explain.indexOf(t) !== -1) && /IndexedDB/.test(explain) && /this device/.test(explain) && /5 MB/.test(explain) &&
      /Turning this off deletes the copy at once, and signing out deletes it/.test(explain), explain.slice(0, 120));
    check("V5. the description's lines say the same: each item, IndexedDB, 5 MB, off by default, deleted when off and at sign-out, nothing sent later",
      DC.saved.every(t => DC.lines[1].indexOf(t) !== -1) && DC.never.every(t => DC.lines[3].indexOf(t) !== -1) && /IndexedDB/.test(DC.lines[2]) && /5 MB/.test(DC.lines[2]) &&
      /is off unless you turn it on/.test(DC.lines[0]) && /deletes the copy at once\. Signing out deletes it/.test(DC.lines[4]) && /nothing is kept to send later/.test(DC.lines[5]));
    check("V6. GET /api/your-data serves the description with it", JSON.stringify(YD.describe().deviceCopy.lines) === JSON.stringify(DC.lines) && /res\.json\(yourData\.describe\(\)\)/.test(SERVER));
    // every saved read is a real GET route in server.js
    const ROUTES = ["/api/ai/tasks", "/api/ai/tasks/:id", "/api/business-profile", "/api/agents", "/api/agents/:type", "/api/wallet", "/api/auth/me", "/api/your-data"];
    const missingRoutes = ROUTES.filter(r => SERVER.indexOf("app.get(\"" + r + "\"") === -1);
    check("V7. every read it saves is a GET route the server has", missingRoutes.length === 0, missingRoutes.join(","));

    // your-data.html offline, from its copy
    const idb = fakeIDB(); idb.seed("/api/your-data", YD.describe(), Date.UTC(2026, 9, 21, 15, 30));
    const yd = page({ html: FILES[YOURDATA].replace(/<script[\s\S]*?<\/script>/g, ""), file: YOURDATA, on: true, idb, net: netDown,
      script: (FILES[YOURDATA].match(/<script>([\s\S]*?)<\/script>/g) || []).map(t => t.slice(8, -9)).pop() });
    await flush();
    const lis = [...yd.doc.querySelectorAll("#deviceCopy li")].map(li => li.textContent);
    check("V8. your-data.html shows the device-copy lines, from the description", JSON.stringify(lis) === JSON.stringify(DC.lines), lis.length + " lines");
    check("V9. your-data.html opens offline from its copy, with the banner, and Download and Delete disabled",
      !yd.doc.getElementById("described").hidden && SAVED_RE.test(bannerText(yd.doc) || "") && yd.doc.getElementById("downloadBtn").disabled && yd.doc.getElementById("deleteBtn").disabled,
      bannerText(yd.doc));
    check("V10. signed in, your-data.html draws the setting under \"On this device\"",
      !yd.doc.getElementById("offlineSetting").hidden && !!yd.doc.getElementById("bfOfflineToggle") && /<h2>On this device<\/h2>\n    <div class="card">\n      <ul id="deviceCopy"><\/ul>/.test(FILES[YOURDATA]));
    check("V11. Settings has the setting in the Account panel, before Sign Out, drawn by bf-offline.js (loaded in the head)",
      /id="panel-account"[\s\S]*<div class="toggle-title">Offline Copy<\/div>\s*<div class="toggle-desc" id="offlineSetting"><\/div>[\s\S]*id="signOutBtn"/.test(FILES[SETTINGS]) &&
      /window\.BFOffline\.mountSetting\(document\.getElementById\("offlineSetting"\)\)/.test(FILES[SETTINGS]) &&
      FILES[SETTINGS].indexOf("<script src=\"/scripts/bf-offline.js\"></script>") < FILES[SETTINGS].indexOf("</head>"));
    /* NAMED BEFORE → AFTER (Oct 28 2026, every guide rewritten to one standard). BEFORE: one dashboard tip, "To open
       your recent tasks, business profile and wallet history with no connection, turn on "Keep a copy on this device
       for offline use" in Settings, under Account. Offline, a page shows the time its copy was saved, …". AFTER: the
       tip belongs to Settings, which now loads the guide: two settings tips, one naming the setting as labelled and
       its panel, one saying what offline means; and the dashboard entry no longer carries it. */
    const entryOf = key => (new RegExp('"' + key.replace(/\./g, "\\.") + '": \\[[^\\]]*').exec(FILES[GUIDE]) || [""])[0];
    const tipOn = "Turn on \\\"Keep a copy on this device for offline use\\\" under \\\"Account\\\" to open recent tasks, profile and wallet with no connection.";
    const tipOff = "Offline, a page shows when its copy was saved, and nothing can be sent or changed until you're back online.";
    check("V12. the Termaximus guide has the tip on Settings (which loads the guide), naming the setting as it is labelled and its Account panel; the dashboard no longer has it",
      entryOf("settings.html").indexOf(tipOn) !== -1 && entryOf("settings.html").indexOf(tipOff) !== -1 &&
      FILES[SETTINGS].indexOf('<script src="/scripts/termaximus-guide.js"></script>') !== -1 && /Keep a copy on this device/.test(FILES[OFF]) &&
      entryOf("dashboard.html") !== "" && !/Keep a copy on this device/.test(entryOf("dashboard.html")));
  }

  check("no network was touched", NETWORK.length === 0, NETWORK.join(","));
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (err) {
  // A crash is a failure, never the mutation-anchor exit (3).
  console.log("    FAIL  checkOfflineMode crashed: " + (err && err.stack || err));
  process.exit(1);
});
