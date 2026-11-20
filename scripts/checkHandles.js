"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkHandles.js — P2-1 (Nov 19 2026): member handles and the place for Local.

     R  migrations 189 and 190: the highest, by name; 189's handle CHECK, the
        reserved list, the place columns; 190's notification columns
     H  lib/handles.js: the pattern is migration 189's character for
        character; 3 to 30; what a member typed is never cut short
     C  checkClaim: reserved 409, taken 409, the member's own handle fine, a
        failed read never lets a handle through
     P  PUT /api/bfp/profile/me and the legacy PUT /api/profile/me, run with a
        fake database: format 400, reserved 409, taken 409, the race (23505)
        409 and never a 500, a good handle saved
     A  /@handle: _redirects, seller.html reads it from the path, sign-in may
        come back to it
     L  the place: lib/places.js, GET and PUT /api/me/place, Settings, Local
        (a country from the list, never the device's location), Your data

   Run: node scripts/checkHandles.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const H = require("./_p21Harness");

const SERVER = "@server.js", HANDLES = "@lib/handles.js", PLACES = "@lib/places.js", YOURDATA = "@lib/yourData.js";
const M189 = "@supabase/migrations/189_handles_and_place.sql", M190 = "@supabase/migrations/190_notifications_links.sql";
const REDIRECTS = "_redirects", SELLER = "seller.html", APP = "app.html", SETTINGS = "settings.html", LOCAL = "scripts/bf-local-settings.js";

const MUTATIONS = {
  "pattern-drift": [[HANDLES, "const HANDLE_PATTERN = \"^[a-z0-9_][a-z0-9_-]{2,29}$\";", "const HANDLE_PATTERN = \"^[a-z0-9_][a-z0-9_-]{1,29}$\";"]],
  "migration-pattern-drift": [[M189, "username ~ '^[a-z0-9_][a-z0-9_-]{2,29}$'", "username ~ '^[a-z0-9_][a-z0-9_-]{2,39}$'"]],
  "long-handle-cut": [[HANDLES, "    .replace(/^-+|-+$/g, \"\");\n}", "    .replace(/^-+|-+$/g, \"\").slice(0, 30);\n}"]],
  "no-reserved-check": [[HANDLES, "  if (await isReserved(supabase, handle)) return", "  if (false) return"]],
  "reserved-read-fails-open": [[HANDLES, "  if (found.error) throw found.error;\n  return !!found.data;", "  return !!found.data;"]],
  "taken-by-self-refused": [[HANDLES, "existing.data.user_id !== opts.userId", "existing.data.user_id"]],
  "race-is-500": [[SERVER, "      .upsert(updates, { onConflict: \"user_id\" }).select(\"*\").single();\n    if (error) {\n      if (require(\"./lib/handles\").isUniqueViolation(error)) return res.status(409)", "      .upsert(updates, { onConflict: \"user_id\" }).select(\"*\").single();\n    if (error) {\n      if (false) return res.status(409)"]],
  "legacy-route-unchecked": [[SERVER, "const claim = await require(\"./lib/handles\").checkClaim(supabase, { raw: req.body.username, table: \"profiles\", userId: req.user.id });", "const claim = { handle: String(req.body.username).toLowerCase().replace(/^@/, \"\") };"]],
  "legacy-race-is-500": [[SERVER, "      .eq(\"user_id\", req.user.id)\n      .select(\"*\")\n      .single();\n\n    if (error) {\n      if (require(\"./lib/handles\").isUniqueViolation(error))", "      .eq(\"user_id\", req.user.id)\n      .select(\"*\")\n      .single();\n\n    if (error) {\n      if (false)"]],
  "no-at-redirect": [[REDIRECTS, "/@:handle /seller.html?u=:handle 200\n", ""]],
  "seller-ignores-path": [[SELLER, "  if (!handle) { var at = /^\\/@([a-z0-9_-]{1,40})$/i.exec(window.location.pathname); if (at) handle = at[1]; }\n", ""]],
  "country-unchecked": [[PLACES, "    else if (typeof c === \"string\" && COUNTRY_CODES.indexOf(c) !== -1) updates.place_country = c;", "    else if (typeof c === \"string\") updates.place_country = c;"]],
  "opt-in-any-value": [[PLACES, "    if (typeof b.local_opt_in !== \"boolean\") return", "    if (false) return"]],
  "place-text-unbounded": [[PLACES, "  if (t.length > PLACE_TEXT_MAX) return undefined;\n", ""]],
  "local-uses-device": [[LOCAL, "  function say(text, kind) {", "  if (navigator.geolocation) navigator.geolocation.getCurrentPosition(function () {});\n  function say(text, kind) {"]],
  "local-default-on": [[LOCAL, "    optIn.checked = place.local_opt_in === true;", "    optIn.checked = place.local_opt_in !== false;"]],
  "place-not-in-your-data": [[YOURDATA, "and your place for Local, if you set one", "and more"]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, HANDLES, PLACES, YOURDATA, M189, M190, REDIRECTS, SELLER, APP, SETTINGS, LOCAL]);
const { FILES, check, has, J } = T;
const ME = "11111111-1111-4111-8111-111111111111", OTHER = "22222222-2222-4222-8222-222222222222";

(async () => {
  /* ══ R ══ */
  console.log("\n══ R. migrations 189 and 190 ══");
  const migNames = fs.readdirSync(path.join(H.REPO, "supabase", "migrations")).filter(x => /^\d{3}_.*\.sql$/.test(x));
  const top = migNames.map(x => Number(x.slice(0, 3))).reduce((a, x) => Math.max(a, x), 0);
  // NAMED (Nov 20 2026, P2-2, migrations 191 and 192): BEFORE 190 was the highest. AFTER only 191_safety.sql and
  // NAMED (Nov 20 2026, P2-3, migrations 193 and 194): 193_posts.sql (posts, post_media) and 194_social_graph.sql (follows, likes, saves, comments, share days, the count triggers) are allowed above the earlier highest too, by name; "the highest" is checkBuyListingDigital R1's.
  // 192_buy_listing_digital.sql are above it, by name; "the highest" is checkBuyListingDigital R1's.
  check("R1. 190_notifications_links.sql is the only 190, and only 191_safety.sql and 192_buy_listing_digital.sql are above it; 189_handles_and_place.sql the only 189",
    top === 194 && migNames.filter(x => /^190_/.test(x)).join() === "190_notifications_links.sql" && migNames.filter(x => /^189_/.test(x)).join() === "189_handles_and_place.sql" &&
    migNames.filter(x => Number(x.slice(0, 3)) > 190).join() === "191_safety.sql,192_buy_listing_digital.sql,193_posts.sql,194_social_graph.sql", J([top]));
  const m189 = FILES[M189] || "", m190 = FILES[M190] || "";
  check("R2. 189 holds the handle format as a named CHECK, dropped first (safe to re-run)",
    has(m189, "DROP CONSTRAINT IF EXISTS bf_profiles_username_format;") && has(m189, "CHECK (username IS NULL OR username ~ '^[a-z0-9_][a-z0-9_-]{2,29}$')"));
  check("R3. reserved_handles: lowercase only, row level security on with every member role revoked",
    has(m189, "CREATE TABLE IF NOT EXISTS public.reserved_handles") && has(m189, "CHECK (handle = lower(handle))") &&
    has(m189, "ALTER TABLE public.reserved_handles ENABLE ROW LEVEL SECURITY;") && has(m189, "REVOKE ALL ON public.reserved_handles FROM anon, authenticated;"));
  const reserved = ((/INSERT INTO public\.reserved_handles \(handle\) VALUES([\s\S]*?)ON CONFLICT/.exec(m189) || [])[1] || "").match(/'([^']+)'/g) || [];
  check("R4. the 18 reserved handles (as confirmed live), admin, bizforce, support, help and inbox among them",
    reserved.length === 18 && ["'admin'", "'bizforce'", "'support'", "'help'", "'inbox'", "'home'", "'termaximus'"].every(x => reserved.indexOf(x) !== -1), reserved.join(","));
  check("R5. the place: city and region up to 80, a 2-letter uppercase country, local_opt_in off by default",
    has(m189, "ADD COLUMN IF NOT EXISTS local_opt_in  boolean NOT NULL DEFAULT false") && has(m189, "char_length(place_city) BETWEEN 1 AND 80") &&
    has(m189, "char_length(place_region) BETWEEN 1 AND 80") && has(m189, "place_country ~ '^[A-Z]{2}$'"));
  check("R6. 190: actor_id (SET NULL with the account), object_type, object_id, link: a path on this site of at most 300",
    has(m190, "ADD COLUMN IF NOT EXISTS actor_id    uuid REFERENCES public.users(id) ON DELETE SET NULL") && has(m190, "ADD COLUMN IF NOT EXISTS link        text;") &&
    has(m190, "CHECK (link IS NULL OR (link ~ '^/[^/]' AND char_length(link) <= 300))"));
  check("R7. neither deletes or rewrites a row", ![m189, m190].some(m => /\b(DELETE FROM|UPDATE public|DROP TABLE|DROP COLUMN)\b/i.test(m.replace(/--[^\n]*/g, ""))));

  /* ══ H ══ */
  console.log("\n══ H. lib/handles.js ══");
  const HL = T.libRequire("./lib/handles");
  const migPattern = (/username ~ '([^']+)'/.exec(m189) || [])[1];
  check("H1. HANDLE_PATTERN is migration 189's pattern character for character", HL.HANDLE_PATTERN === migPattern, J([HL.HANDLE_PATTERN, migPattern]));
  check("H2. normalizeHandle: a leading @ dropped, lowercase, other characters a -, no - at either end", HL.normalizeHandle("  @Earth Rose!! ") === "earth-rose" && HL.normalizeHandle("@@") === "");
  const long = "a".repeat(31);
  check("H3. what a member typed is never cut short: 31 characters stay 31 and are refused", HL.normalizeHandle(long) === long && HL.handleProblem(HL.normalizeHandle(long)) === HL.FORMAT_MESSAGE);
  check("H4. 3 and 30 characters pass; 2 and 31 fail; a leading - fails, a leading _ passes",
    HL.handleProblem("abc") === null && HL.handleProblem("a".repeat(30)) === null && HL.handleProblem("ab") !== null && HL.handleProblem(long) !== null &&
    HL.handleProblem("-abc") !== null && HL.handleProblem("_abc") === null && HL.handleProblem("Abc") !== null);
  check("H5. a Postgres 23505, or its message, is a unique violation; another error is not",
    HL.isUniqueViolation({ code: "23505" }) && HL.isUniqueViolation({ message: "duplicate key value violates unique constraint \"x\"" }) && !HL.isUniqueViolation({ code: "23514" }));
  check("H6. the messages say what to do", /3 to 30/.test(HL.FORMAT_MESSAGE) && /reserved/.test(HL.RESERVED_MESSAGE) && /taken/.test(HL.TAKEN_MESSAGE));

  /* ══ C ══ */
  console.log("\n══ C. checkClaim ══");
  function claimDb(opts) {
    return H.fakeDb((table, q) => {
      if (table === "reserved_handles") return opts.reservedError ? { data: null, error: { message: "down" } } : { data: H.filterVal(q, "eq", "handle") === "admin" ? { handle: "admin" } : null, error: null };
      if (opts.holder && String(H.filterVal(q, "ilike", "username")) === opts.holder.handle) return { data: { user_id: opts.holder.id }, error: null };
      return { data: null, error: null };
    });
  }
  const c1 = await HL.checkClaim(claimDb({}).client, { raw: "@Admin", table: "bf_profiles", userId: ME });
  const c2 = await HL.checkClaim(claimDb({ holder: { handle: "rose", id: OTHER } }).client, { raw: "rose", table: "bf_profiles", userId: ME });
  const c3 = await HL.checkClaim(claimDb({ holder: { handle: "rose", id: ME } }).client, { raw: "Rose", table: "bf_profiles", userId: ME });
  const c4 = await HL.checkClaim(claimDb({}).client, { raw: "", table: "bf_profiles", userId: ME });
  const c5 = await HL.checkClaim(claimDb({}).client, { raw: "ab", table: "bf_profiles", userId: ME });
  let c6 = null; try { c6 = await HL.checkClaim(claimDb({ reservedError: true }).client, { raw: "rose", table: "bf_profiles", userId: ME }); } catch (e) { c6 = "threw"; }
  check("C1. a reserved handle (any case, with @) is a 409 with the reserved message", c1.status === 409 && c1.error === HL.RESERVED_MESSAGE && c1.reason === "handle_reserved", J(c1));
  check("C2. another member's handle is a 409 with the taken message", c2.status === 409 && c2.error === HL.TAKEN_MESSAGE, J(c2));
  check("C3. the member's own handle may be saved again", c3.handle === "rose" && !c3.error, J(c3));
  check("C4. empty means no handle; too short is a 400", c4.handle === null && !c4.error && c5.status === 400 && c5.reason === "handle_format", J([c4, c5]));
  check("C5. when the reserved list cannot be read, the claim fails (throws), never lets the handle through", c6 === "threw", J(c6));

  /* ══ P ══ */
  console.log("\n══ P. the two username routes ══");
  function profileDb(opts) {
    return H.fakeDb((table, q) => {
      if (table === "reserved_handles") return { data: H.filterVal(q, "eq", "handle") === "support" ? { handle: "support" } : null, error: null };
      if (q.op === "select" && H.filterVal(q, "ilike", "username") !== undefined) return { data: opts.takenBy ? { user_id: opts.takenBy } : null, error: null };
      if (q.op === "upsert" || q.op === "update") return opts.race ? { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint" } } : { data: Object.assign({ user_id: ME }, q.payload), error: null };
      return { data: null, error: null };
    });
  }
  const STUB = { normalizeUrl: v => v, safeText: (v, n) => (v == null ? "" : String(v).slice(0, n)), BFP_FONTS: ["modern"] };
  async function put(routePath, body, opts) {
    const db = profileDb(opts || {});
    const fn = H.route(FILES[SERVER], "put", routePath, Object.assign({ supabase: db.client }, STUB), T.libRequire);
    if (!fn) return { status: "no route" };
    const r = await fn({ body });
    r.writes = db.log.filter(q => q.op === "upsert" || q.op === "update").map(q => q.payload);
    return r;
  }
  for (const [label, routePath] of [["new", "/api/bfp/profile/me"], ["legacy", "/api/profile/me"]]) {
    const fmt = await put(routePath, { username: "ab" });
    const res = await put(routePath, { username: "Support" });
    const taken = await put(routePath, { username: "rose" }, { takenBy: OTHER });
    const race = await put(routePath, { username: "rose" }, { race: true });
    const ok = await put(routePath, { username: "@Rose_B" });
    const tag = label === "new" ? "PUT /api/bfp/profile/me" : "the legacy PUT /api/profile/me";
    check("P" + (label === "new" ? 1 : 6) + ". " + tag + ": a bad format is a 400 with the format message, and nothing is written",
      fmt.status === 400 && fmt.body && /3 to 30/.test(fmt.body.error) && fmt.writes.length === 0, J([fmt.status, fmt.body, fmt.err && fmt.err.message]));
    check("P" + (label === "new" ? 2 : 7) + ". " + tag + ": a reserved handle is a 409 with the reserved message", res.status === 409 && res.body.reason === "handle_reserved" && res.writes.length === 0, J([res.status, res.body]));
    check("P" + (label === "new" ? 3 : 8) + ". " + tag + ": another member's handle is a 409", taken.status === 409 && taken.body.reason === "handle_taken" && taken.writes.length === 0, J([taken.status, taken.body]));
    check("P" + (label === "new" ? 4 : 9) + ". " + tag + ": two members racing for one handle: the loser gets a 409, not a 500", race.status === 409 && race.body.reason === "handle_taken" && !race.err, J([race.status, race.body, race.err && race.err.message]));
    check("P" + (label === "new" ? 5 : 10) + ". " + tag + ": a good handle is saved as the handle (@ dropped, lowercase)",
      ok.status === 200 && ok.writes.length === 1 && ok.writes[0].username === "rose_b", J([ok.status, ok.writes, ok.err && ok.err.message]));
  }
  const empty = await put("/api/bfp/profile/me", { username: "" });
  check("P11. on the new route an empty handle clears it (NULL), as before", empty.status === 200 && empty.writes[0] && empty.writes[0].username === null, J([empty.status, empty.writes]));

  /* ══ A ══ */
  console.log("\n══ A. /@handle ══");
  const red = FILES[REDIRECTS] || "";
  check("A1. _redirects rewrites /@handle to seller.html?u=handle (200: the address stays /@handle)", has(red, "\n/@:handle /seller.html?u=:handle 200\n"));
  check("A2. ...before any catch-all, so it is reached", red.indexOf("/@:handle") > -1 && (red.indexOf("\n/* ") === -1 || red.indexOf("/@:handle") < red.indexOf("\n/* ")));
  const seller = FILES[SELLER] || "";
  const atRe = (/var at = \/(.+?)\/i\.exec\(window\.location\.pathname\)/.exec(seller) || [])[1];
  let reOk = false;
  try { const re = new RegExp(atRe, "i"); reOk = re.exec("/@earth-rose")[1] === "earth-rose" && !re.test("/seller.html") && !re.test("/@a/b"); } catch (e) { reOk = false; }
  check("A3. seller.html reads the handle from /@handle when there is no ?u", reOk && seller.indexOf("var at = ") > seller.indexOf("get(\"u\")"), atRe);
  const app = FILES[APP] || "";
  const allow = (/if \(!(\/\^\\\/\(support[^\n]*?\$\/i)\.test\(u\.pathname\)\) return null;/.exec(app) || [])[1];
  let allowOk = false;
  try { const re = eval(allow); allowOk = re.test("/@earth-rose") && !re.test("/@ab") && re.test("/home.html") && re.test("/inbox.html") && !re.test("/@x/../evil"); } catch (e) { allowOk = false; }
  check("A4. after sign-in, app.html may return to /@handle, home.html and inbox.html (bf_return_to), and still nowhere else", allowOk, allow);

  /* ══ L ══ */
  console.log("\n══ L. the place for Local ══");
  const PL = T.libRequire("./lib/places");
  check("L1. the country list is the 249 ISO 3166-1 alpha-2 codes, each two uppercase letters, none twice",
    PL.COUNTRY_CODES.length === 249 && PL.COUNTRY_CODES.every(c => /^[A-Z]{2}$/.test(c)) && new Set(PL.COUNTRY_CODES).size === 249 && ["US", "GB", "NG", "IN", "BR"].every(c => PL.COUNTRY_CODES.indexOf(c) !== -1), PL.COUNTRY_CODES.length);
  const u1 = PL.placeUpdates({ place_city: "  Lagos  ", place_region: "", place_country: "NG", local_opt_in: true });
  check("L2. text trimmed, empty is cleared (null), a listed country and a true or false are kept",
    J(u1.updates) === J({ place_city: "Lagos", place_region: null, place_country: "NG", local_opt_in: true }), J(u1));
  const bad = [PL.placeUpdates({ place_country: "XX" }), PL.placeUpdates({ place_country: "ng" }), PL.placeUpdates({ local_opt_in: "yes" }), PL.placeUpdates({ place_city: "x".repeat(81) }), PL.placeUpdates({ place_region: 5 })];
  check("L3. a country not on the list (or lowercase), an opt-in that is not true or false, a place over 80 or not text: refused with the field",
    bad.map(b => b.field).join() === "place_country,place_country,local_opt_in,place_city,place_region", J(bad));
  check("L4. only the keys sent are changed", J(PL.placeUpdates({ local_opt_in: false }).updates) === J({ local_opt_in: false }));
  check("L5. the reply never shows a country off the list, and the opt-in is off unless it is true",
    J(PL.placeReply({ place_country: "ZZ", local_opt_in: "t" })) === J({ place_city: null, place_region: null, place_country: null, local_opt_in: false }) && PL.placeReply(null).local_opt_in === false);

  const placeDb = () => H.fakeDb((table, q) => {
    if (q.op === "upsert") return { data: Object.assign({ place_city: null, place_region: null, place_country: null, local_opt_in: false }, q.payload), error: null };
    return { data: { place_city: "Lagos", place_region: null, place_country: "NG", local_opt_in: true }, error: null };
  });
  const dbG = placeDb(), dbP = placeDb(), dbB = placeDb();
  const getR = await H.route(FILES[SERVER], "get", "/api/me/place", { supabase: dbG.client }, T.libRequire)({});
  check("L6. GET /api/me/place: the member's own row, with the country list",
    getR.status === 200 && getR.body.place.place_country === "NG" && getR.body.countries.length === 249 && H.filterVal(dbG.log[0], "eq", "user_id") === ME, J([getR.status, getR.body && getR.body.place]));
  const putR = await H.route(FILES[SERVER], "put", "/api/me/place", { supabase: dbP.client }, T.libRequire)({ body: { place_city: "Accra", place_country: "GH", local_opt_in: true, user_id: OTHER } });
  const wrote = (dbP.log.find(q => q.op === "upsert") || {}).payload || {};
  check("L7. PUT saves the member's own row only (a user_id in the body is ignored)", putR.status === 200 && wrote.user_id === ME && wrote.place_city === "Accra" && wrote.place_country === "GH" && putR.body.place.local_opt_in === true, J([putR.status, wrote]));
  const badR = await H.route(FILES[SERVER], "put", "/api/me/place", { supabase: dbB.client }, T.libRequire)({ body: { place_country: "Narnia" } });
  check("L8. a bad place is a 400 with the field, and nothing is written", badR.status === 400 && badR.body.field === "place_country" && !dbB.log.some(q => q.op === "upsert"), J([badR.status, badR.body]));

  const set = FILES[SETTINGS] || "", loc = FILES[LOCAL] || "";
  check("L9. Settings has a Local section: city, region, a country list and \"Show my posts in Local\"",
    has(set, "data-target=\"local\"") && has(set, "id=\"panel-local\"") && has(set, "id=\"placeCity\"") && has(set, "id=\"placeRegion\"") &&
    has(set, "<select id=\"placeCountry\">") && has(set, "Show my posts in Local") && has(set, "<script src=\"/scripts/bf-local-settings.js\"></script>"));
  const localPanel = set.slice(set.indexOf("<section class=\"settings-panel\" id=\"panel-local\""), set.indexOf("</section>", set.indexOf("id=\"panel-local\"")));
  check("L10. never the device's location: no geolocation in the Local section or its script", localPanel.length > 200 && !/geolocation|getCurrentPosition|watchPosition/.test(loc.replace(/\/\*[\s\S]*?\*\//g, "") + localPanel.replace(/<!--[\s\S]*?-->/g, "")), localPanel.length);
  check("L11. the toggle is off unless the saved answer is true", has(loc, "optIn.checked = place.local_opt_in === true;"));
  check("L12. the country names come from the member's language (Intl.DisplayNames), the codes from the server", has(loc, "new Intl.DisplayNames(") && has(loc, "fillCountries(d.countries || [])"));
  check("L13. Your data names the place in the bf_profiles row", has(FILES[YOURDATA], "and your place for Local, if you set one: the city, region and country you typed and whether your posts show in Local"));

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
