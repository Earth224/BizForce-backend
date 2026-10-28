"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   buildAppMap — writes lib/appMap.json, the map of every frontend page that
   Termaximus's Guide mode (POST /api/guide/ask) is allowed to name, from the
   frontend checkout beside this repo and server.js's route table
   (lib/appMapBuild.js says what is in it and why).

     node scripts/buildAppMap.js          write lib/appMap.json
     node scripts/buildAppMap.js --check  write nothing; exit 1 if the file
                                          differs from what is built

   Run it after changing any frontend page, a page's controls or scripts, the
   guide's tips, or a route's gate, and commit lib/appMap.json.
   scripts/checkAppMap.js fails until it matches. BIZFORCE_FRONTEND_DIR
   overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { buildAppMap, serializeAppMap } = require("../lib/appMapBuild");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = path.join(REPO, "lib", "appMap.json");
const checkOnly = process.argv.indexOf("--check") !== -1;

// Every .html file in the frontend, relative to its root, skipping dot folders and node_modules.
function frontendPages() {
  const out = [];
  (function walk(dir) {
    fs.readdirSync(path.join(FRONTEND, dir), { withFileTypes: true }).forEach(d => {
      const rel = dir ? dir + "/" + d.name : d.name;
      if (d.isDirectory()) { if (!/^(\.|node_modules$)/.test(d.name)) walk(rel); }
      else if (/\.html$/i.test(d.name)) out.push(rel);
    });
  })("");
  return out;
}
function readFront(rel) {
  const p = path.join(FRONTEND, rel);
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n") : null;
}

if (!fs.existsSync(FRONTEND)) { console.error("Frontend not found: " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
const server = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const text = serializeAppMap(buildAppMap({ pages: frontendPages(), readFront, server }));
const now = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8").replace(/\r\n/g, "\n") : null;
if (now === text) { console.log("unchanged  lib/appMap.json (" + Buffer.byteLength(text) + " bytes)"); process.exit(0); }
if (checkOnly) { console.log("DIFFERS    lib/appMap.json — run node scripts/buildAppMap.js"); process.exit(1); }
fs.writeFileSync(OUT, text);
console.log("wrote      lib/appMap.json (" + Buffer.byteLength(text) + " bytes)");
