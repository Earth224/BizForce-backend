"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkBlocks.js — blocking and muting (P2-2, Nov 20 2026).

   A block works both ways: neither member can message, pay, buy from, or see
   the other's profile, storefront, listings or campaigns, and each drops out
   of the other's lists. A mute is one way and quiet: the muted member's
   listings and campaigns leave the muter's browse lists and Home, and nothing
   else changes. Neither is ever told.

   WHAT THIS PROVES
     A. THE LOOKUPS (lib/safety.js, run against a fake database):
        blockedEitherWay is true in both directions and only for that pair;
        blockedIds collects both sides; mutedIds only the member's own mutes;
        hiddenAmong only hidden or removed rows of the asked type. On a
        database error each logs one line and answers as if there were none.
     B. THE ROUTES (run in a vm with a fake database): POST /api/blocks by
        user_id or handle saves one row (idempotent upsert) and answers 201;
        yourself 400; nobody 404. DELETE removes only the member's own row.
        The same for mutes. requireAuth and blockLimiter (60 an hour) on all
        four. GET /api/me/relation reports blocked and muted; a message's
        sender is found only for its two parties. GET /api/me/safety lists.
     C. WHERE IT IS ENFORCED: the routes that call each lookup are exactly the
        lists owned here, and a guard runs before anything is written or sent.
     D. THE PAGES: bf-safety.js's reasons are lib/safety.js's, in order;
        Settings has "Blocked and muted" (#blocked opens it).

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const vm = require("vm");
const H = require("./_p21Harness");
const sh = require("./_shared");

const SERVER = "@server.js", SAFETY = "@lib/safety.js";
const MUTATIONS = {
  "block-one-way": [[SAFETY, "(row.blocker_id === a && row.blocked_id === b) || (row.blocker_id === b && row.blocked_id === a)", "(row.blocker_id === a && row.blocked_id === b)"]],
  "lookup-error-blocks": [[SAFETY, 'if (r.error) { logLookup("block", r.error); return false; }', "if (r.error) { return true; }"]],
  "mute-anyones": [[SAFETY, "if (row && row.muter_id === userId && isUuid(row.muted_id)) out.add(row.muted_id);", "if (row && isUuid(row.muted_id)) out.add(row.muted_id);"]],
  "hidden-includes-waiting": [[SAFETY, '.in("state", ["hidden", "removed"]);', ';']],
  "unblock-anyone": [[SERVER, "const gone = await supabase.from(table).delete().eq(mine, req.user.id).eq(theirs, req.params.userId);", "const gone = await supabase.from(table).delete().eq(theirs, req.params.userId);"]],
  "self-block": [[SERVER, "      if (target === req.user.id) return res.status(400).json({ error: SF.MESSAGES.self });\n", ""]],
  "relation-any-message": [[SERVER, '(req.query.object_type !== "message" || item.owner_id === req.user.id || item.receiver_id === req.user.id)', "true"]],
  "transfer-unguarded": [[SERVER, 'if (await require("./lib/safety").blockedEitherWay(supabase, req.user.id, recipientId)) {', "if (false) {"]],
  "settings-unwired": [["settings.html", 'if (name === "safety" && window.BFSafety) window.BFSafety.renderSettings(document.getElementById("safetyList"));', ""]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, SAFETY, "scripts/bf-safety.js", "settings.html"]);
const { FILES, check, J, has } = T;
const SF = T.libRequire("./lib/safety");

const ME = "11111111-1111-4111-8111-111111111111", THEM = "22222222-2222-4222-8222-222222222222", OTHER = "33333333-3333-4333-8333-333333333333";
const BLOCK_GUARDED = ["GET /api/profile/by-id/:userId", "GET /api/messages/:userId", "POST /api/messages", "GET /api/inbox/person/:userId", "POST /api/wallet/transfer",
  "POST /api/wallet/support", "POST /api/marketplace/listings/:id/buy", "GET /api/crowdfunding/campaigns/by-share/:shareId", "POST /api/crowdfunding/campaigns/:id/donate",
  "GET /api/bfp/profile/:userId", "GET /api/bfp/seller/:handle", "GET /api/marketplace/listings/:id"];
const BLOCK_FILTERED = ["GET /api/conversations", "GET /api/inbox/conversations", "GET /api/notifications", "GET /api/marketplace/listings", "GET /api/crowdfunding/campaigns", "GET /api/home/starter"];
const MUTE_FILTERED = ["GET /api/marketplace/listings", "GET /api/crowdfunding/campaigns", "GET /api/home/starter"];
const quiet = () => { const lines = []; const orig = console.error; console.error = (m) => lines.push(String(m)); return () => { console.error = orig; return lines; }; };

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the lookups ══");
  const rowsDb = rows => H.fakeDb(() => ({ data: rows, error: null })).client;
  check("A1. a block counts both ways", await SF.blockedEitherWay(rowsDb([{ blocker_id: ME, blocked_id: THEM }]), ME, THEM) &&
    await SF.blockedEitherWay(rowsDb([{ blocker_id: THEM, blocked_id: ME }]), ME, THEM));
  check("A2. a row about anyone else does not count; nor yourself, nor a non-id", !(await SF.blockedEitherWay(rowsDb([{ blocker_id: ME, blocked_id: OTHER }]), ME, THEM)) &&
    !(await SF.blockedEitherWay(rowsDb([{ blocker_id: ME, blocked_id: ME }]), ME, ME)) && !(await SF.blockedEitherWay(rowsDb([]), ME, "x")));
  const ids = await SF.blockedIds(rowsDb([{ blocker_id: ME, blocked_id: THEM }, { blocker_id: OTHER, blocked_id: ME }, { blocker_id: THEM, blocked_id: OTHER }]), ME);
  check("A3. blockedIds collects both sides, and only rows about the member", J([...ids].sort()) === J([THEM, OTHER].sort()), J([...ids]));
  const muted = await SF.mutedIds(rowsDb([{ muter_id: ME, muted_id: THEM }, { muter_id: OTHER, muted_id: OTHER }]), ME);
  check("A4. mutedIds is the member's own mutes only", J([...muted]) === J([THEM]), J([...muted]));
  const hdb = H.fakeDb(() => ({ data: [{ object_type: "listing", object_id: THEM, state: "hidden" }, { object_type: "listing", object_id: OTHER, state: "waiting" }], error: null }));
  const hidden = await SF.hiddenAmong(hdb.client, "listing", [THEM, OTHER]);
  const hq = hdb.log[0];
  check("A5. hiddenAmong: only hidden or removed rows of that type count, and it asks only for those", J([...hidden]) === J([THEM]) &&
    J(hq.filters) === J([["eq", "object_type", "listing"], ["in", "object_id", [THEM, OTHER]], ["in", "state", ["hidden", "removed"]]]), J(hq && hq.filters));
  const errDb = H.fakeDb(() => ({ data: null, error: { code: "57014" } })).client;
  const done = quiet();
  const errs = [await SF.blockedEitherWay(errDb, ME, THEM), (await SF.blockedIds(errDb, ME)).size, (await SF.mutedIds(errDb, ME)).size, (await SF.hiddenAmong(errDb, "listing", [THEM])).size];
  const logged = done();
  check("A6. a failed lookup answers as if there were none, and logs one line each", J(errs) === J([false, 0, 0, 0]) && logged.length === 4 && logged.every(l => /served as if there were none/.test(l)), J({ errs, logged }));

  /* ── B ── */
  console.log("\n══ B. the routes ══");
  const S = FILES[SERVER];
  const fnAt = sig => { const at = S.indexOf(sig); return at < 0 ? "" : S.slice(at, sh.braceMatch(S, S.indexOf("{", at)) + 1); };
  function blockRoutes(answer) {
    const db = H.fakeDb(answer);
    const ctx = { require: T.libRequire, supabase: db.client, nowIso: () => "2026-11-20T12:00:00.000Z", console };
    vm.createContext(ctx);
    vm.runInContext([fnAt("async function safetyTargetId(body) {"), fnAt("function safetyAdd(table, mine, theirs, flag) {"), fnAt("function safetyRemove(table, mine, theirs, flag) {")].join("\n"), ctx);
    const run = async (h, req) => {
      const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
      let err = null;
      await h(Object.assign({ user: { id: ME }, body: {}, params: {} }, req), res, e => { err = e; });
      return { status: res.statusCode, body: res.body, err };
    };
    return { db, ctx, run };
  }
  const known = (t, q) => t === "users" ? { data: H.filterVal(q, "eq", "id") === THEM || H.filterVal(q, "eq", "id") === ME ? { id: H.filterVal(q, "eq", "id") } : null, error: null }
    : t === "bf_profiles" ? { data: /^them$/i.test(H.filterVal(q, "ilike", "username") || "") ? { user_id: THEM } : null, error: null } : { data: null, error: null };
  let B = blockRoutes(known);
  const add = B.ctx.safetyAdd("member_blocks", "blocker_id", "blocked_id", "blocked");
  const r1 = await B.run(add, { body: { user_id: THEM } });
  const up = B.db.log.find(q => q.op === "upsert");
  check("B1. block by user_id: one row, idempotent, 201 { user_id, blocked: true }", r1.status === 201 && J(r1.body) === J({ user_id: THEM, blocked: true }) && up && up.table === "member_blocks" &&
    up.payload.blocker_id === ME && up.payload.blocked_id === THEM && J(up.opts) === J({ onConflict: "blocker_id,blocked_id", ignoreDuplicates: true }), J({ r1, up }));
  B = blockRoutes(known);
  const r2 = await B.run(B.ctx.safetyAdd("member_blocks", "blocker_id", "blocked_id", "blocked"), { body: { handle: "@Them" } });
  check("B2. block by handle (a storefront knows only the handle)", r2.status === 201 && r2.body.user_id === THEM, J(r2));
  B = blockRoutes(known);
  const r3 = await B.run(B.ctx.safetyAdd("member_blocks", "blocker_id", "blocked_id", "blocked"), { body: { user_id: ME } });
  const r4 = await B.run(B.ctx.safetyAdd("member_blocks", "blocker_id", "blocked_id", "blocked"), { body: { user_id: OTHER } });
  check("B3. yourself 400, nobody 404, and nothing written", r3.status === 400 && r3.body.error === SF.MESSAGES.self && r4.status === 404 && r4.body.error === SF.MESSAGES.noMember &&
    !B.db.log.some(q => q.op !== "select"), J({ r3, r4 }));
  B = blockRoutes(known);
  const r5 = await B.run(B.ctx.safetyRemove("member_blocks", "blocker_id", "blocked_id", "blocked"), { params: { userId: THEM } });
  const del = B.db.log.find(q => q.op === "delete");
  check("B4. unblock removes only the member's own row", r5.status === 200 && J(r5.body) === J({ user_id: THEM, blocked: false }) && del &&
    J(del.filters) === J([["eq", "blocker_id", ME], ["eq", "blocked_id", THEM]]), J(del && del.filters));
  B = blockRoutes(known);
  const r6 = await B.run(B.ctx.safetyAdd("member_mutes", "muter_id", "muted_id", "muted"), { body: { user_id: THEM } });
  const r7 = await B.run(B.ctx.safetyRemove("member_mutes", "muter_id", "muted_id", "muted"), { params: { userId: "nope" } });
  check("B5. mute the same way (member_mutes, { muted: true }); a bad id 404", r6.status === 201 && J(r6.body) === J({ user_id: THEM, muted: true }) &&
    B.db.log.find(q => q.op === "upsert").table === "member_mutes" && r7.status === 404);
  const REG = ['app.post("/api/blocks", requireAuth, blockLimiter, safetyAdd("member_blocks", "blocker_id", "blocked_id", "blocked"));',
    'app.delete("/api/blocks/:userId", requireAuth, blockLimiter, safetyRemove("member_blocks", "blocker_id", "blocked_id", "blocked"));',
    'app.post("/api/mutes", requireAuth, blockLimiter, safetyAdd("member_mutes", "muter_id", "muted_id", "muted"));',
    'app.delete("/api/mutes/:userId", requireAuth, blockLimiter, safetyRemove("member_mutes", "muter_id", "muted_id", "muted"));'];
  check("B6. the four routes: signed in, and limited", REG.every(r => T.count(S, r) === 1));
  const lim = (/const blockLimiter = rateLimit\(\{[\s\S]*?\n\}\);/.exec(S) || [""])[0];
  check("B7. blockLimiter: 60 an hour per member", has(lim, "windowMs: 60 * 60 * 1000,") && has(lim, "max: 60,") && has(lim, 'return "block-mute:" + (req.user && req.user.id);') && SF.BLOCKS_PER_HOUR === 60);

  const msgRow = { id: OTHER, sender_id: THEM, receiver_id: OTHER, content: "hi" };
  const relDb = (blocked, muted) => H.fakeDb((t, q) => t === "member_blocks" ? { data: blocked ? { blocked_id: THEM } : null, error: null }
    : t === "member_mutes" ? { data: muted ? { muted_id: THEM } : null, error: null } : t === "messages" ? { data: msgRow, error: null } : known(t, q));
  let rdb = relDb(true, false);
  const rel = H.route(S, "get", "/api/me/relation", { supabase: rdb.client }, T.libRequire);
  const rr = rel ? await rel({ user: { id: ME }, query: { user_id: THEM } }) : null;
  check("B8. relation: { user_id, self, blocked, muted }", rr && rr.status === 200 && J(rr.body) === J({ user_id: THEM, self: false, blocked: true, muted: false }), J(rr));
  rdb = relDb(false, true);
  const rel2 = H.route(S, "get", "/api/me/relation", { supabase: rdb.client }, T.libRequire);
  const rm = await rel2({ user: { id: ME }, query: { object_type: "message", object_id: OTHER } });
  const rm2 = await rel2({ user: { id: OTHER }, query: { object_type: "message", object_id: OTHER } });
  check("B9. a message names its sender only to its two parties", rm.status === 404 && rm2.status === 200 && rm2.body.user_id === THEM && rm2.body.muted === true, J({ rm, rm2 }));
  const sdb = H.fakeDb((t) => t === "member_blocks" ? { data: [{ blocked_id: THEM, created_at: "2026-11-20T10:00:00Z" }], error: null }
    : t === "member_mutes" ? { data: [], error: null } : t === "bf_profiles" ? { data: [{ user_id: THEM, username: "them", display_name: "Them Co", avatar_url: null }], error: null } : { data: [], error: null });
  const saf = H.route(S, "get", "/api/me/safety", { supabase: sdb.client }, T.libRequire);
  const sr = saf ? await saf({ user: { id: ME } }) : null;
  check("B10. GET /api/me/safety lists the member's own blocks and mutes, with names", sr && sr.status === 200 && sr.body.blocks.length === 1 && sr.body.blocks[0].user_id === THEM &&
    sr.body.blocks[0].since === "2026-11-20T10:00:00Z" && sr.body.blocks[0].username === "them" && sr.body.mutes.length === 0 &&
    sdb.log.filter(q => q.table === "member_blocks" || q.table === "member_mutes").every(q => q.filters.some(f => f[0] === "eq" && f[2] === ME)), J(sr));
  check("B11. relation and safety are signed-in routes", has(S, 'app.get("/api/me/relation", requireAuth, async function') && has(S, 'app.get("/api/me/safety", requireAuth, async function'));

  /* ── C ── */
  console.log("\n══ C. where it is enforced ══");
  const g = H.routesWith(S, "blockedEitherWay("), f = H.routesWith(S, "blockedIds("), m = H.routesWith(S, "mutedIds(");
  check("C1. a block is checked on exactly these " + BLOCK_GUARDED.length + " routes", J(g) === J(BLOCK_GUARDED), J(g));
  check("C2. blocked members are left out of exactly these " + BLOCK_FILTERED.length + " lists", J(f) === J(BLOCK_FILTERED), J(f));
  check("C3. muted members are left out of exactly these " + MUTE_FILTERED.length + " browse lists", J(m) === J(MUTE_FILTERED), J(m));
  const late = BLOCK_GUARDED.filter(r => {
    const [meth, p] = r.split(" ");
    const st = H.routeStatement(S, meth.toLowerCase(), p) || "";
    const at = st.indexOf("blockedEitherWay(");
    const writes = [".insert(", ".update(", ".upsert(", ".rpc(", "bfcSendWithinLimits(", "stripe."].map(w => st.indexOf(w)).filter(i => i !== -1);
    return !st || at === -1 || writes.some(i => i < at);
  });
  check("C4. on each, the block is checked before anything is written or sent", late.length === 0, J(late));
  const msgs = H.routeStatement(S, "post", "/api/messages") || "";
  check("C5. a message to a member who blocked you (or you blocked) answers as if they were missing",
    /if \(await require\("\.\/lib\/safety"\)\.blockedEitherWay\(supabase, req\.user\.id, receiverId\)\) \{\n\s+return res\.status\(404\)/.test(msgs), msgs.slice(msgs.indexOf("blockedEitherWay") - 60, msgs.indexOf("blockedEitherWay") + 200));
  const xfer = H.routeStatement(S, "post", "/api/wallet/transfer") || "";
  check("C6. a transfer to a member across a block is refused before the wallet moves", has(xfer, 'if (await require("./lib/safety").blockedEitherWay(supabase, req.user.id, recipientId)) {'));

  /* ── D ── */
  console.log("\n══ D. the pages ══");
  const js = FILES["scripts/bf-safety.js"] || "";
  const keys = (js.match(/\n    \["([a-z_]+)", "/g) || []).map(x => x.replace(/\n    \["|", "/g, ""));
  check("D1. the menu's 13 reasons are lib/safety.js's, in order", J(keys) === J(SF.REASONS) && keys.length === 13, J(keys));
  check("D2. the menu offers Block/Unblock and Mute/Unmute from GET /api/me/relation, and blocking asks first",
    has(js, 'call("GET", "/api/me/relation?" + q)') && has(js, "function confirmBlock(item, who) {") && has(js, '"/api/blocks"') && has(js, '"/api/mutes"'));
  const st = FILES["settings.html"] || "";
  check("D3. Settings: a \"Blocked and muted\" section that lists them, with Unblock and Unmute",
    has(st, '<button type="button" class="sidebar-item" data-target="safety">') && has(st, 'id="panel-safety" data-panel="safety"') && has(st, 'id="safetyList"') &&
    has(st, 'if (name === "safety" && window.BFSafety) window.BFSafety.renderSettings(document.getElementById("safetyList"));') && has(st, '<script src="/scripts/bf-safety.js"></script>') &&
    has(js, 'call("DELETE", "/api/" + btn.getAttribute("data-undo") + "/" + encodeURIComponent(btn.getAttribute("data-user")))'));
  check("D4. Settings opens the section at #blocked, and draws the list once bf-safety.js has loaded", has(st, 'if (window.location.hash === "#blocked") {\n        activateSection("safety");\n        window.addEventListener("load", function () { if (window.BFSafety) window.BFSafety.renderSettings(document.getElementById("safetyList")); });'));
  check("D5. no emoji in the menu or this check", !/\p{Extended_Pictographic}/u.test(js + require("fs").readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
