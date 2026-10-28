"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   buildSupportPage — writes the frontend's support.html from the same
   template GET /support/:username serves (lib/supportPage.js), with no member
   filled in. It carries the page's controls for the guide and the app map, and
   sends a visitor who opens support.html?u=<username> to /support/<username>.

     node scripts/buildSupportPage.js          write support.html
     node scripts/buildSupportPage.js --check  write nothing; exit 1 if it differs

   Run it after changing lib/supportPage.js, then node scripts/buildAppMap.js.
   scripts/checkMemberSupport.js fails until the two match.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const supportPage = require("../lib/supportPage");

const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(__dirname, "..", "..", "BizForce-fronyend");
const OUT = path.join(FRONTEND, "support.html");
const checkOnly = process.argv.indexOf("--check") !== -1;

if (!fs.existsSync(FRONTEND)) { console.error("Frontend not found: " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
const text = supportPage.render({ state: "shell" });
const now = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8").replace(/\r\n/g, "\n") : null;
if (now === text) { console.log("unchanged  support.html (" + Buffer.byteLength(text) + " bytes)"); process.exit(0); }
if (checkOnly) { console.log("DIFFERS    support.html — run node scripts/buildSupportPage.js"); process.exit(1); }
fs.writeFileSync(OUT, text);
console.log("wrote      support.html (" + Buffer.byteLength(text) + " bytes)");
