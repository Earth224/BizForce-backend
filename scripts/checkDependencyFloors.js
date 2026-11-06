"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDependencyFloors — the dependency record after the Nov 6 2026 audit.

   It reads package-lock.json, package.json and README.md, and nothing else:
   no npm, no registry, no network (Z1 is a tripwire).

   WHAT THIS PROVES
     F. FLOORS: every installed copy of body-parser is at least 1.20.9, qs at
        least 6.16.1 and undici at least 8.12.3 (the lockfile refresh of Nov 6
        2026). Versions are compared numerically by a comparison written here,
        which is itself tested (F4: 1.20.10 is above 1.20.9).
     P. PINS: node-cron is 3.0.3 in the lockfile and "^3.0.3" in package.json,
        for the DST reason recorded in checkCronJobs (which pins it too).
        imapflow 2.9.1, nodemailer 10.2.1 and postal-mime 2.7.5 are pinned in
        package.json and node_modules by checkMailboxConnect LIB1; this check
        adds only the lockfile side, and confirms LIB1 still holds them.
     A. ACCEPTED: the residue the architect accepted, each with its package,
        version, path, advisory ids and reason.
        A1. Every lockfile copy inside a range the Nov 6 audit named
            vulnerable is listed (an unlisted one fails).
        A2. Every listed entry is present at exactly that version and path
            (a fixed or moved one fails, so the list is updated when it is
            fixed).
        A3. follow-redirects is never below 1.16.1, and never above it while
            it is still listed.
        A4. The README's "Dependency exceptions" section names each one.
     N. NO_FORCE: no package.json script runs "npm audit fix".
     Z. Zero network.

   MUTATE=<name> edits the files IN MEMORY (the lockfile, package.json, the
   README, or the CORE block of this file). MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkDependencyFloors: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkDependencyFloors: no network"); };

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const lockEntry = (name, v) => "    \"node_modules/" + name + "\": {\n      \"version\": \"" + v + "\",";

const MUTATIONS = {
  // the refresh is undone for body-parser
  "body-parser-regressed": [["lock", lockEntry("body-parser", "1.20.9"), lockEntry("body-parser", "1.20.8")]],
  // the refresh is undone for qs
  "qs-regressed": [["lock", lockEntry("qs", "6.16.1"), lockEntry("qs", "6.16.0")]],
  // the refresh is undone for undici
  "undici-regressed": [["lock", lockEntry("undici", "8.12.3"), lockEntry("undici", "8.11.2")]],
  // node-cron moves to 4
  "node-cron-bumped": [["lock", lockEntry("node-cron", "3.0.3"), lockEntry("node-cron", "4.6.0")]],
  // an accepted entry is removed while its package is still present
  "residue-unlisted": [["core", "  { name: \"uuid\", version: \"8.3.2\",", "  { name: \"uuid-removed\", version: \"0.0.0\","]],
  // an entry is kept after its package version changed
  "residue-stale": [["lock", lockEntry("uuid", "8.3.2"), lockEntry("uuid", "11.1.1")]],
  // a lexicographic comparison instead of a numeric one
  "floor-compare-wrong": [["core", "  const pa = String(a).split(\"-\")[0].split(\".\").map(Number), pb = String(b).split(\"-\")[0].split(\".\").map(Number);",
    "  const pa = String(a).split(\"-\")[0].split(\".\"), pb = String(b).split(\"-\")[0].split(\".\");"]],
  // ── earned ──
  // follow-redirects is fixed but the entry stays
  "follow-redirects-bumped-listed": [["lock", lockEntry("follow-redirects", "1.16.1"), lockEntry("follow-redirects", "1.16.2")]],
  // follow-redirects goes below the accepted version
  "follow-redirects-below": [["lock", lockEntry("follow-redirects", "1.16.1"), lockEntry("follow-redirects", "1.16.0")]],
  // a script that runs npm audit fix
  "audit-fix-script": [["pkg", "    \"dev\": \"nodemon server.js\"\n", "    \"dev\": \"nodemon server.js\",\n    \"fix\": \"npm audit fix --force\"\n"]],
  // the README loses an exception
  "readme-exception-removed": [["readme", "- **uuid 8.3.2**, under node-cron 3.0.3 (advisory 1119441).", "- under node-cron 3.0.3 (advisory 1119441)."]],
  // a mail library moves in the lockfile only
  "imapflow-lock-moved": [["lock", lockEntry("imapflow", "2.9.1"), lockEntry("imapflow", "2.9.2")]],
  // a second, nested copy of qs below the floor
  "qs-nested-low": [["lock", "    \"node_modules/qs\": {", "    \"node_modules/stripe/node_modules/qs\": {\n      \"version\": \"6.11.0\"\n    },\n    \"node_modules/qs\": {"]],
  // a floor package disappears from the lockfile
  "floor-package-missing": [["core", "const FLOORS = { \"body-parser\": \"1.20.9\", qs: \"6.16.1\", undici: \"8.12.3\" };",
    "const FLOORS = { \"body-parser\": \"1.20.9\", qs: \"6.16.1\", undici: \"8.12.3\", \"undici-gone\": \"1.0.0\" };"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── CORE: the comparison, the floors, the pins, the audit ranges and the
   accepted residue. Read back from this file's text and run in a vm, so a
   mutation can change it. The wrapper function is never called; only the vm
   runs this text. ─────────────────────────────────────────────────────── */
// eslint-disable-next-line no-unused-vars
function coreTextOnly() {
// CORE BEGIN
function cmpVersion(a, b) {
  const pa = String(a).split("-")[0].split(".").map(Number), pb = String(b).split("-")[0].split(".").map(Number);
  for (let i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1; }
  return 0;
}
const FLOORS = { "body-parser": "1.20.9", qs: "6.16.1", undici: "8.12.3" };
const LOCK_PINS = { "node-cron": "3.0.3", imapflow: "2.9.1", nodemailer: "10.2.1", "postal-mime": "2.7.5" };
// The ranges the Nov 6 2026 npm audit named vulnerable, both ends inclusive ("*" is every version).
const AUDIT_NOV6 = {
  "body-parser": ["0.0.0", "1.20.8"], qs: ["6.7.0", "6.16.0"], undici: ["8.0.0", "8.12.1"], "follow-redirects": ["1.16.0", "1.16.1"],
  uuid: ["0.0.0", "11.1.0"], zod: ["0.0.0", "4.6.5"], "node-cron": ["3.0.2", "3.0.3"],
  "@atproto/api": "*", "@atproto/common-web": "*", "@atproto/lexicon": "*", "@atproto/xrpc": "*"
};
const ZOD_WHY = "no compatible fixed release exists (every @atproto/api requires zod 3; no zod 3 is fixed); an override to zod 4 is unsafe; the runtime use is a two-field error-body check on bsky.social responses, and no public route drives it";
const ACCEPTED = [
  { name: "zod", version: "3.25.76", path: "node_modules/zod", via: "@atproto/api 0.20.25 (and its common-web, lexicon, xrpc); @anthropic-ai/sdk as a peer", advisories: ["1243066"], reason: ZOD_WHY },
  { name: "@atproto/api", version: "0.20.25", path: "node_modules/@atproto/api", via: "direct", advisories: ["1243066 (via zod)"], reason: ZOD_WHY },
  { name: "@atproto/common-web", version: "0.5.3", path: "node_modules/@atproto/common-web", via: "@atproto/api", advisories: ["1243066 (via zod)"], reason: ZOD_WHY },
  { name: "@atproto/lexicon", version: "0.7.4", path: "node_modules/@atproto/lexicon", via: "@atproto/api", advisories: ["1243066 (via zod)"], reason: ZOD_WHY },
  { name: "@atproto/xrpc", version: "0.8.3", path: "node_modules/@atproto/xrpc", via: "@atproto/api", advisories: ["1243066 (via zod)"], reason: ZOD_WHY },
  { name: "uuid", version: "8.3.2", path: "node_modules/uuid", via: "node-cron 3.0.3", advisories: ["1119441"],
    reason: "only uuid.v4() with no buffer is called; node-cron stays at 3.0.3 for the DST reason in checkCronJobs" },
  { name: "node-cron", version: "3.0.3", path: "node_modules/node-cron", via: "direct", advisories: ["1119441 (via uuid)"],
    reason: "kept at 3.0.3 by the recorded DST decision (checkCronJobs); its only finding is the unreachable uuid path" },
  { name: "follow-redirects", version: "1.16.1", path: "node_modules/follow-redirects", via: "twilio 6.0.2 > axios 1.20.0", advisories: ["1244003"],
    reason: "until Nov 8 2026, when 1.16.2 passes the 14-day rule; Twilio is created without allowRedirects, so redirects are never followed" }
];
// CORE END
}

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const SELF = lf(fs.readFileSync(__filename, "utf8"));
const coreStart = SELF.indexOf("// CORE BEGIN\n"), coreEnd = SELF.indexOf("// CORE END\n", coreStart);
const ALL = {
  core: SELF.slice(coreStart, coreEnd),
  lock: lf(fs.readFileSync(path.join(REPO, "package-lock.json"), "utf8")),
  pkg: lf(fs.readFileSync(path.join(REPO, "package.json"), "utf8")),
  readme: lf(fs.readFileSync(path.join(REPO, "README.md"), "utf8"))
};
const CRON_CHECK = lf(fs.readFileSync(path.join(__dirname, "checkCronJobs.js"), "utf8"));
const MAIL_CHECK = lf(fs.readFileSync(path.join(__dirname, "checkMailboxConnect.js"), "utf8"));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) ALL[file] = s.replaceOnce(ALL[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;

let CORE = null, CORE_ERROR = null, LOCK = null, PKG = null;
try {
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(ALL.core + "\nthis.__core = { cmpVersion, FLOORS, LOCK_PINS, AUDIT_NOV6, ACCEPTED };", ctx);
  CORE = ctx.__core;
  LOCK = JSON.parse(ALL.lock);
  PKG = JSON.parse(ALL.pkg);
} catch (e) { CORE_ERROR = e; }

console.log("\n══ 0. the record loads ══");
check("0. the CORE block, package-lock.json (lockfileVersion 3) and package.json parse", !CORE_ERROR && coreStart > 0 && coreEnd > coreStart && LOCK && LOCK.lockfileVersion === 3 && !!LOCK.packages,
  CORE_ERROR && CORE_ERROR.message);
if (CORE_ERROR || !LOCK) { console.log("\nCHECKS FAILED: the record could not be read"); process.exit(1); }
const { cmpVersion, FLOORS, LOCK_PINS, AUDIT_NOV6, ACCEPTED } = CORE;

/* Every installed copy of a package: lockfile keys ending in node_modules/<name>. */
const copies = name => Object.keys(LOCK.packages).filter(k => k === "node_modules/" + name || k.endsWith("/node_modules/" + name))
  .map(k => ({ path: k, version: LOCK.packages[k].version }));
const inRange = (v, r) => r === "*" || (cmpVersion(v, r[0]) >= 0 && cmpVersion(v, r[1]) <= 0);

/* ════ F. floors ════ */
console.log("\n══ F. floors ══");
for (const name of Object.keys(FLOORS)) {
  const c = copies(name);
  check("F. every copy of " + name + " is at least " + FLOORS[name] + " (" + c.length + " cop" + (c.length === 1 ? "y" : "ies") + ")",
    c.length >= 1 && c.every(x => typeof x.version === "string" && cmpVersion(x.version, FLOORS[name]) >= 0), J(c));
}
check("F4. the comparison is numeric: 1.20.10 > 1.20.9, 6.16.1 > 6.9.0, 1.9.0 < 1.10.0, 8.12.3 = 8.12.3, 10.0.0 > 9.99.99",
  cmpVersion("1.20.10", "1.20.9") === 1 && cmpVersion("6.16.1", "6.9.0") === 1 && cmpVersion("1.9.0", "1.10.0") === -1 && cmpVersion("8.12.3", "8.12.3") === 0 &&
  cmpVersion("10.0.0", "9.99.99") === 1 && cmpVersion("1.20.8", "1.20.9") === -1);
check("F5. the floors are the Nov 6 refresh's: body-parser 1.20.9, qs 6.16.1, undici 8.12.3", J(FLOORS) === J({ "body-parser": "1.20.9", qs: "6.16.1", undici: "8.12.3" }));

/* ════ P. pins ════ */
console.log("\n══ P. pins ══");
const nc = copies("node-cron");
check("P1. node-cron is exactly 3.0.3 in the lockfile (one copy) and \"^3.0.3\" in package.json; the reason is checkCronJobs' DST decision, which pins it too",
  nc.length === 1 && nc[0].version === "3.0.3" && PKG.dependencies["node-cron"] === "^3.0.3" && LOCK.packages[""].dependencies["node-cron"] === "^3.0.3" &&
  CRON_CHECK.indexOf("This is why node-cron\n       stays on 3.0.3.") !== -1 && CRON_CHECK.indexOf("installed === \"3.0.3\" && lock.packages[\"node_modules/node-cron\"].version === \"3.0.3\"") !== -1, J(nc));
const mailOk = ["imapflow", "nodemailer", "postal-mime"].every(n => { const c = copies(n); return c.length === 1 && c[0].version === LOCK_PINS[n] && PKG.dependencies[n] === LOCK_PINS[n]; });
check("P2. imapflow 2.9.1, nodemailer 10.2.1 and postal-mime 2.7.5 are those exact versions in the lockfile (package.json and node_modules are checkMailboxConnect LIB1's, which still holds them)",
  mailOk && MAIL_CHECK.indexOf("pkg.dependencies.imapflow === \"2.9.1\" && pkg.dependencies.nodemailer === \"10.2.1\" && pkg.dependencies[\"postal-mime\"] === \"2.7.5\" &&") !== -1,
  J(["imapflow", "nodemailer", "postal-mime"].map(n => [n, copies(n).map(c => c.version)])));

/* ════ A. accepted residue ════ */
console.log("\n══ A. accepted residue ══");
const listed = (name, version) => ACCEPTED.some(e => e.name === name && e.version === version);
const unlisted = [];
for (const name of Object.keys(AUDIT_NOV6)) copies(name).forEach(c => { if (inRange(c.version, AUDIT_NOV6[name]) && !listed(name, c.version)) unlisted.push(name + "@" + c.version + " at " + c.path); });
check("A1. every copy still inside a range the Nov 6 audit named vulnerable is on the accepted list", unlisted.length === 0, unlisted.join(", "));
const stale = ACCEPTED.filter(e => !(LOCK.packages[e.path] && LOCK.packages[e.path].version === e.version && copies(e.name).every(c => c.version === e.version)));
check("A2. every accepted entry is present at exactly its version and path, and no other copy of it differs (update the list when one is fixed)",
  stale.length === 0, stale.map(e => e.name + " listed " + e.version + ", lockfile " + J(copies(e.name).map(c => c.version))).join("; "));
const fr = copies("follow-redirects"), frListed = ACCEPTED.some(e => e.name === "follow-redirects");
check("A3. follow-redirects is never below 1.16.1, and never above it while it is still listed",
  fr.length >= 1 && fr.every(c => cmpVersion(c.version, "1.16.1") >= 0) && (!frListed || fr.every(c => cmpVersion(c.version, "1.16.1") <= 0)), J(fr));
check("A4. each accepted entry names its version, path, dependency path, advisory ids and a reason",
  ACCEPTED.length >= 1 && ACCEPTED.every(e => e.name && /^\d+\.\d+\.\d+$/.test(e.version) && /^node_modules\//.test(e.path) && e.via && Array.isArray(e.advisories) &&
    e.advisories.length >= 1 && e.advisories.every(a => /^\d{6,7}\b/.test(a)) && typeof e.reason === "string" && e.reason.length >= 40));
const secAt = ALL.readme.indexOf("\n## Dependency exceptions\n");
const sec = secAt === -1 ? "" : ALL.readme.slice(secAt, (ALL.readme.indexOf("\n## ", secAt + 5) + 1 || ALL.readme.length + 1) - 1);
const readmeNames = [["zod", "3.25.76"], ["uuid", "8.3.2"], ["follow-redirects", "1.16.1"]];
check("A5. the README's \"Dependency exceptions\" section names checkDependencyFloors, the floors, and each accepted residue with its version",
  sec.indexOf("`scripts/checkDependencyFloors.js` is the record.") !== -1 && sec.indexOf("body-parser 1.20.9, qs 6.16.1, undici 8.12.3") !== -1 &&
  readmeNames.every(([n, v]) => sec.indexOf("- **" + n + " " + v + "**") !== -1) &&
  ["@atproto/api 0.20.25", "@atproto/common-web 0.5.3", "@atproto/lexicon 0.7.4", "@atproto/xrpc 0.8.3", "node-cron 3.0.3", "allowRedirects"].every(t => sec.indexOf(t) !== -1) &&
  ACCEPTED.every(e => sec.indexOf(e.name) !== -1), sec.slice(0, 200));

/* ════ N. no force ════ */
console.log("\n══ N. no npm audit fix ══");
const scripts = PKG.scripts || {};
check("N1. no package.json script runs npm audit fix", Object.keys(scripts).every(k => !/audit\s+fix/.test(String(scripts[k]))) && !/audit\s+fix/.test(J(scripts)), J(scripts));

console.log("\n══ Z. zero network ══");
check("Z1. no socket was opened and no name was looked up", NETWORK.length === 0, NETWORK.join(","));

console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : "CHECKS FAILED: " + failures + " of " + (passes + failures)));
process.exit(failures === 0 ? 0 : 1);
