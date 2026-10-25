"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   buildLegalPages — writes terms.html, privacy.html, refund.html and
   contact.html into the frontend checkout beside this repo, from
   lib/legalPages.js (which reads lib/legal.js and the code each figure comes
   from).

     node scripts/buildLegalPages.js          write the four pages
     node scripts/buildLegalPages.js --check  write nothing; exit 1 if any
                                              page differs from what is built

   Run it after changing lib/legal.js, lib/legalPages.js, lib/yourData.js, a
   price, a BFC amount or limit, or the YouTube retention, and commit the
   frontend pages it rewrites. scripts/checkLegalPages.js fails until they
   match. BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { buildLegalPages } = require("../lib/legalPages");

const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(__dirname, "..", "..", "BizForce-fronyend");
const checkOnly = process.argv.indexOf("--check") !== -1;

const pages = buildLegalPages();
let differ = 0;
Object.keys(pages).forEach(function (name) {
  const file = path.join(FRONTEND, name);
  const now = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
  if (now === pages[name]) { console.log("unchanged  " + name); return; }
  differ++;
  if (checkOnly) { console.log("DIFFERS    " + name); return; }
  fs.writeFileSync(file, pages[name]);
  console.log("wrote      " + name + " (" + pages[name].length + " bytes)");
});
if (checkOnly && differ) process.exit(1);
