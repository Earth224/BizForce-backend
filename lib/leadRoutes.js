"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   LEAD RADAR'S ROUTES (LR-2, Nov 23 2026). Mounted by server.js (mountLeadRoutes) where the
   owner-only routes were. Every route is M (members only: requireActiveSubscription after
   requireAuth; a free account gets the members panel, 402) except GET /api/leads/archive,
   which is the owner's read-only view of the old bsky_leads rows (A, OWNER_ACCOUNT_ID).

     GET  /api/leads/fingerprint            the member's Fingerprint (built on first open)
     PUT  /api/leads/fingerprint            change any field; changed fields are locked
     POST /api/leads/fingerprint/rebuild    rebuild from BizForce; locked fields kept
     POST /api/leads/fingerprint/suggest    "Suggest more words" (Haiku 4.5, on the ledger)
     POST /api/leads/fingerprint/spare/swap a spare word in (at 12, in place of the word the member picks)
     GET  /api/leads                        the member's own leads, stats and source chips
     GET  /api/leads/summary                the dashboard tile and the orbit count
     POST /api/leads/:id/status             Save, Not a fit, Mark as won / lost, back to new
     POST /api/leads/:id/draft              a draft reply (Haiku 4.5, on the ledger); never posted
     POST /api/leads/:id/send               posts EXACTLY the approved text, from the member's
                                            own account (lib/leadReplies.js holds the rules)
     GET  /api/leads/archive                the owner's archive (bsky_leads, read only)

   deps: { sb, requireAuth, requireActiveSubscription, aiLimiter, ownerId, siteOrigin,
     callModel(userId, prompt, maxTokens, route) -> { text, model }   server.js callAnthropicText:
       the member's limits enforced first, their key first, the ledger row written;
     postingAccount(userId, role), actAs(userId, account, fn), actFailure(res, outcome, account, nothing),
     linkFacets(text), replyRefsFor(postView), caps: { perMember, ceiling }, sendLive() -> boolean,
     threads: { state(userId) -> { state, username }, reply(userId, replyToId, text) -> { ok, id, permalink, code } } }
   ═══════════════════════════════════════════════════════════════════════════ */

const FP = require("./leadFingerprint");
const MR = require("./memberRadar");
const LR = require("./leadReplies");
const CAT = require("./categories");

const SOURCES = ["bizforce", "bluesky", "youtube", "threads"];
const MEMBER_STATUSES = ["new", "saved", "dismissed", "won", "lost"];
const LIST_MAX = 100;
const DAY = 86400000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LEAD_FIELDS = "id, user_id, source, external_id, url, author_handle, author_place, text, posted_at, matched_keyword, match_reason, score, scored_at, outreach_safe, reply_invited, status, created_at, updated_at";

/* The lead as the screens see it. */
function leadView(l, nowMs) {
  var refusal = LR.replyRefusal(l, nowMs);
  return {
    id: l.id, source: l.source, url: l.url, author_handle: l.author_handle, author_place: l.author_place, text: l.text,
    posted_at: l.posted_at, matched_keyword: l.matched_keyword, match_reason: l.match_reason, score: l.score,
    outreach_safe: l.outreach_safe, reply_invited: l.reply_invited, status: l.status,
    can_reply: !refusal, reply_platform: !refusal ? l.source : null,
    need_post_id: l.source === "bizforce" ? l.external_id : null
  };
}

/* Shown by default: BizForce Needs and YouTube comments (never scored) always; Bluesky and Threads once scored 40 or more. */
function isWeak(l) { return MR.SCORED_SOURCES.indexOf(l.source) !== -1 && !(typeof l.score === "number" && l.score > MR.WEAK_BELOW - 1); }

async function fingerprintBody(deps, userId, row) {
  var all = await CAT.list(deps.sb);
  var fp = FP.shape(row);
  var bluesky = { posts_as: "none", handle: null };
  try {
    var acct = await deps.postingAccount(userId, null);
    var kind = acct.kind === "platform" && userId !== deps.ownerId ? "none" : acct.kind;
    bluesky = { posts_as: kind, handle: acct.handle || null };
  } catch (e) { bluesky = { posts_as: "unknown", handle: null }; }
  var threads = { state: "not_set_up", username: null };
  try { if (deps.threads && deps.threads.state) threads = await deps.threads.state(userId); } catch (e) { threads = { state: "unknown", username: null }; }
  // NAMED (Nov 24 2026, LR-2B): the member's spare words; a failed read shows none and is said so, never an error.
  var spare = { words: [], readable: true };
  try { spare.words = (await FP.readSpare(deps.sb, userId)).words; } catch (e) { spare.readable = false; }
  return {
    fingerprint: fp,
    spare_words: spare.words, spare_words_readable: spare.readable,
    categories: fp.categories.map(function (s) { return { slug: s, name: CAT.nameOf(all, s) || s }; }),
    all_categories: all.map(function (c) { return { slug: c.slug, name: c.name }; }),
    accounts: { bluesky: bluesky, threads: threads }
  };
}

async function ownLead(deps, userId, id) {
  if (!UUID_RE.test(String(id || ""))) return null;
  var r = await deps.sb.from("member_leads").select(LEAD_FIELDS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}

function mountLeadRoutes(app, deps) {
  var M = [deps.requireAuth, deps.requireActiveSubscription];
  var AI = deps.aiLimiter ? M.concat([deps.aiLimiter]) : M;
  var now = deps.now || function () { return Date.now(); };

  app.get("/api/leads/fingerprint", M, async function (req, res, next) {
    try {
      var row = await FP.getOrBuild(deps.sb, req.user.id, new Date(now()).toISOString());
      return res.json(await fingerprintBody(deps, req.user.id, row));
    } catch (err) { next(err); }
  });

  app.put("/api/leads/fingerprint", M, async function (req, res, next) {
    try {
      var all = await CAT.list(deps.sb);
      var edit = FP.validateEdit(req.body, new Set(all.map(function (c) { return c.slug; })));
      if (!edit.ok) return res.status(400).json({ error: edit.error, field: edit.field });
      var at = new Date(now()).toISOString();
      var existing = await FP.getOrBuild(deps.sb, req.user.id, at);
      var row = await FP.writeRow(deps.sb, req.user.id, FP.applyEdit(existing, edit, at));
      return res.json(await fingerprintBody(deps, req.user.id, row));
    } catch (err) { next(err); }
  });

  app.post("/api/leads/fingerprint/rebuild", M, async function (req, res, next) {
    try {
      var row = await FP.rebuild(deps.sb, req.user.id, new Date(now()).toISOString());
      return res.json(await fingerprintBody(deps, req.user.id, row));
    } catch (err) { next(err); }
  });

  /* NAMED (Nov 24 2026, LR-2B): a tap on a spare word. Under 12 words it is added; at 12 the body names the word it
     replaces (replace), which goes back to the spare words. The keywords are then the member's own (locked). */
  app.post("/api/leads/fingerprint/spare/swap", M, async function (req, res, next) {
    try {
      var userId = req.user.id, at = new Date(now()).toISOString();
      var body = req.body || {};
      if (typeof body.add !== "string" || (body.replace !== undefined && body.replace !== null && typeof body.replace !== "string")) {
        return res.status(400).json({ error: "Name the spare word to add, and the word it replaces when you have 12.", field: "add" });
      }
      var existing = await FP.getOrBuild(deps.sb, userId, at);
      var spare = await FP.readSpare(deps.sb, userId);
      var plan = FP.swapPlan(FP.shape(existing).keywords, spare.words, body.add, body.replace);
      if (!plan.ok) return res.status(plan.code === "pick_one" ? 409 : 400).json({ error: plan.error, code: plan.code });
      var row = await FP.writeRow(deps.sb, userId, FP.applyEdit(existing, { ok: true, fields: { keywords: plan.keywords }, locks: ["keywords"] }, at));
      await FP.writeSpare(deps.sb, userId, plan.spare, at);
      var out = await fingerprintBody(deps, userId, row);
      out.replaced = plan.replaced;
      return res.json(out);
    } catch (err) { next(err); }
  });

  /* Runs only when the member taps it. On the ledger and the member's own limits (callModel). Nothing is added. */
  app.post("/api/leads/fingerprint/suggest", AI, async function (req, res, next) {
    try {
      var userId = req.user.id;
      var row = await FP.getOrBuild(deps.sb, userId, new Date(now()).toISOString());
      var all = await CAT.list(deps.sb);
      var names = FP.shape(row).categories.map(function (s) { return CAT.nameOf(all, s) || s; });
      var out = await deps.callModel(userId, FP.suggestPrompt(row, names), 300, "POST /api/leads/fingerprint/suggest");
      return res.json({ suggestions: FP.parseSuggestions(out && out.text, FP.shape(row).keywords) });
    } catch (err) { next(err); }
  });

  app.get("/api/leads", M, async function (req, res, next) {
    try {
      var userId = req.user.id, nowMs = now();
      var source = String(req.query.source || "all");
      if (source !== "all" && SOURCES.indexOf(source) === -1) return res.status(400).json({ error: "Unknown source." });
      var weaker = String(req.query.weaker || "") === "1";
      var row = await FP.getOrBuild(deps.sb, userId, new Date(nowMs).toISOString());
      var fp = FP.shape(row);
      var q = deps.sb.from("member_leads").select(LEAD_FIELDS).eq("user_id", userId).not("status", "in", "(dismissed,archived)")
        .order("posted_at", { ascending: false, nullsFirst: false }).limit(LIST_MAX * 3);
      if (source !== "all") q = q.eq("source", source);
      var r = await q;
      if (r.error) throw r.error;
      var rows = (r.data || []).filter(function (l) { return fp.sources[l.source] !== false; });
      var weak = rows.filter(isWeak);
      var shown = (weaker ? rows : rows.filter(function (l) { return !isWeak(l); })).slice(0, LIST_MAX);
      var weekAgo = new Date(nowMs - 7 * DAY).toISOString();
      var counts = await Promise.all([
        deps.sb.from("member_leads").select("id", { count: "exact", head: true }).eq("user_id", userId).gt("created_at", weekAgo).neq("status", "archived"),
        deps.sb.from("member_lead_replies").select("id", { count: "exact", head: true }).eq("user_id", userId).not("platform_uri", "is", null),
        // NAMED (Nov 24 2026, LR-3): BEFORE won counted member_leads won only. AFTER it also counts Inbound items won, once
        // when a won lead_reply item is the same conversation as a won lead (lib/inbound.js wonCount).
        require("./inbound").wonCount(deps.sb, userId).then(function (n) { return { count: n }; })
      ]);
      counts.forEach(function (c) { if (c.error) throw c.error; });
      return res.json({
        leads: shown.map(function (l) { return leadView(l, nowMs); }),
        stats: { new_this_week: counts[0].count || 0, replied: counts[1].count || 0, won: counts[2].count || 0 },
        sources_on: fp.sources,
        weaker_hidden: weaker ? 0 : weak.length
      });
    } catch (err) { next(err); }
  });

  app.get("/api/leads/summary", M, async function (req, res, next) {
    try {
      var userId = req.user.id, nowMs = now();
      var r = await Promise.all([
        deps.sb.from("member_leads").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "new")
          .or("source.eq.bizforce,source.eq.youtube,score.gt." + (MR.WEAK_BELOW - 1)),
        deps.sb.from("member_leads").select("id", { count: "exact", head: true }).eq("user_id", userId).gt("created_at", new Date(nowMs - 7 * DAY).toISOString()).neq("status", "archived")
      ]);
      r.forEach(function (x) { if (x.error) throw x.error; });
      return res.json({ new_count: r[0].count || 0, new_this_week: r[1].count || 0 });
    } catch (err) { next(err); }
  });

  /* Save, Not a fit (dismissed: hidden, teaches nothing), Mark as won or lost, or back to new. "replied" is set only
     by a send, never here. */
  app.post("/api/leads/:id/status", M, async function (req, res, next) {
    try {
      var status = req.body && req.body.status;
      if (MEMBER_STATUSES.indexOf(status) === -1) return res.status(400).json({ error: "Status is saved, dismissed, won, lost or new.", field: "status" });
      var lead = await ownLead(deps, req.user.id, req.params.id);
      if (!lead) return res.status(404).json({ error: "Lead not found." });
      var u = await deps.sb.from("member_leads").update({ status: status, updated_at: new Date(now()).toISOString() }).eq("id", lead.id).eq("user_id", req.user.id)
        .select(LEAD_FIELDS).maybeSingle();
      if (u.error) throw u.error;
      return res.json({ lead: leadView(u.data || Object.assign(lead, { status: status }), now()) });
    } catch (err) { next(err); }
  });

  /* Whose account a reply would go out from. The platform's Bluesky account is the owner's alone. */
  async function replyAccount(userId, role, platform) {
    if (platform === "threads") {
      var t = deps.threads && deps.threads.state ? await deps.threads.state(userId) : { state: "not_set_up" };
      if (t.state === "ready") return { kind: "member", handle: t.username, platform: "threads" };
      if (t.state === "waiting_approval") return { kind: "waiting_approval", platform: "threads" };
      if (t.state === "needs_reconnect") return { kind: "needs_reconnect", platform: "threads" };
      return { kind: "none", platform: "threads" };
    }
    var a = await deps.postingAccount(userId, role);
    if (a.kind === "platform" && userId !== deps.ownerId) return { kind: "none", platform: "bluesky" };
    return Object.assign({ platform: "bluesky" }, a);
  }

  function accountRefusal(res, acct) {
    if (acct.kind === "none") {
      return res.status(409).json({ code: "not_connected", platform: acct.platform,
        error: acct.platform === "threads" ? "Connect your Threads account to reply." : "Connect your Bluesky account to reply." });
    }
    if (acct.kind === "needs_reconnect") return res.status(409).json({ code: "needs_reconnect", platform: acct.platform, error: "Reconnect your " + (acct.platform === "threads" ? "Threads" : "Bluesky") + " account to reply." });
    if (acct.kind === "waiting_approval") return res.status(409).json({ code: "waiting_approval", platform: "threads", error: "Waiting for Meta's approval. Threads replies open when Meta approves BizForce." });
    return null;
  }

  app.post("/api/leads/:id/draft", AI, async function (req, res, next) {
    try {
      var userId = req.user.id, nowMs = now();
      var lead = await ownLead(deps, userId, req.params.id);
      if (!lead) return res.status(404).json({ error: "Lead not found." });
      var refusal = LR.replyRefusal(lead, nowMs);
      if (refusal) return res.status(refusal.status).json({ error: refusal.error, code: refusal.code });
      var acct = await replyAccount(userId, req.user.role, lead.source);
      var refused = accountRefusal(res, acct);
      if (refused) return refused;
      var fp = await FP.getOrBuild(deps.sb, userId, new Date(nowMs).toISOString());
      var link = null;
      if (req.body && req.body.add_link === true) {
        link = await LR.listingUrlFor(deps.sb, userId, deps.siteOrigin, FP.shape(fp).categories);
        if (!link) return res.status(422).json({ code: "no_listing", error: "You have no active listing to link yet." });
      }
      var out = await deps.callModel(userId, LR.draftPrompt(FP.shape(fp), lead, link), 400, "POST /api/leads/:id/draft");
      var verdict = LR.splitVerdict(out && out.text);
      var draft = LR.cleanDraft(verdict.text, link);
      if (!draft) return res.status(502).json({ error: "The draft came back empty. Write it again." });
      // NAMED (Nov 23 2026, LR-2): BEFORE answers and no_hard_sell were always true. AFTER each from something real.
      return res.json({ draft: draft, platform: lead.source, posts_as: { kind: acct.kind, handle: acct.handle || null }, link: link,
        checks: { answers: verdict.answers, no_hard_sell: LR.hardSell(draft) === null, invited: lead.reply_invited === true },
        hard_sell_words: LR.HARD_SELL });
    } catch (err) { next(err); }
  });

  /* THE ONE SEND. Posts exactly the approved text (after the emoji strip, which the response returns), from the
     member's own account, inside one guarded step. Nothing else in Lead Radar posts. */
  app.post("/api/leads/:id/send", M, async function (req, res, next) {
    try {
      var userId = req.user.id, nowMs = now();
      if (!deps.sendLive()) return res.status(409).json({ code: "send_off", error: "Posting replies is switched off (SALES_SEND_LIVE). Nothing was posted." });
      var lead = await ownLead(deps, userId, req.params.id);
      if (!lead) return res.status(404).json({ error: "Lead not found." });
      var refusal = LR.replyRefusal(lead, nowMs);
      // NAMED (Nov 23 2026, LR-2): G23 fails on the record for a lead never screened or judged unsuitable, as send-approved recorded it.
      // A BizForce Need or a YouTube comment has no reply path and is refused before any gate (no record).
      if (refusal && refusal.code === "not_safe") recordOutreachGate(userId, { G23: { result: "fail", code: lead.outreach_safe == null ? "not_screened" : "unsafe_recipient" } });
      if (refusal) return res.status(refusal.status).json({ error: refusal.error, code: refusal.code });
      var raw = req.body && typeof req.body.text === "string" ? req.body.text : "";
      var text = LR.stripEmoji(raw);
      if (!text) return res.status(422).json({ code: "bad_text", error: "Write the reply you approve first. Nothing was posted." });
      if (LR.charCount(text) > LR.MAX_CHARS) return res.status(422).json({ code: "too_long", error: "A reply is at most " + LR.MAX_CHARS + " characters. Nothing was posted." });
      var link = null;
      if (req.body && req.body.add_link === true) link = await LR.listingUrlFor(deps.sb, userId, deps.siteOrigin, null);
      if (link && LR.linkRejection(text, link)) {
        // The member's own listing may be any of their active listings, not only the one the draft picked.
        var all = await deps.sb.from("marketplace_listings").select("id").eq("seller_id", userId).eq("status", "active").limit(50);
        if (all.error) throw all.error;
        var base = String(deps.siteOrigin || "").replace(/\/+$/, "") + "/listing.html?id=";
        var hit = (all.data || []).map(function (l) { return base + l.id; }).find(function (u) { return !LR.linkRejection(text, u); });
        if (hit) link = hit;
      }
      var bad = LR.linkRejection(text, link);
      if (bad) return res.status(422).json({ code: bad.code, error: bad.error + " Nothing was posted." });
      var acct = await replyAccount(userId, req.user.role, lead.source);
      var refused = accountRefusal(res, acct);
      if (refused) return refused;

      var outcome = await LR.serial(async function () {
        var slot = await LR.reserveReply(deps.sb, { user_id: userId, member_lead_id: lead.id, platform: lead.source, external_id: lead.external_id, text: text },
          deps.caps, nowMs);
        // NAMED (Nov 23 2026, LR-2): G23 passed (the lead is safe), and G22 (the caps) as the guarded step decided it.
        recordOutreachGate(userId, { G23: { result: "pass" }, G22: slot.ok ? { result: "pass" } : { result: "fail", code: G22_CODES[slot.code] || "check_failed" } });
        if (!slot.ok) return { sent: false, code: slot.code, status: slot.status };
        var posted;
        try {
          posted = lead.source === "threads"
            ? await deps.threads.reply(userId, lead.external_id, text)
            : await postBluesky(userId, acct, lead.external_id, text);
        } catch (sendErr) {
          posted = { ok: false, code: "unknown_outcome" };
        }
        // A post that MAY have gone out keeps its reservation: it counts as this member's reply to this post, so it
        // can never be sent twice. Only a failure that posted nothing gives the slot back.
        if (posted && posted.code === "unknown_outcome") return { sent: false, code: "unknown_outcome", status: 502 };
        if (!posted || !posted.ok) { await slot.release(); return { sent: false, code: (posted && posted.code) || "post_error", status: (posted && posted.status) || 502, outcome: posted }; }
        var fill = await deps.sb.from("member_lead_replies").update({ platform_uri: posted.uri || posted.permalink || posted.id || null }).eq("id", slot.id);
        if (fill.error) console.error("[leads/send] reply posted but its address was not recorded: " + fill.error.message);
        return { sent: true, uri: posted.uri || posted.permalink || null };
      });

      if (!outcome.sent) {
        if (outcome.outcome && outcome.outcome.actOutcome) return deps.actFailure(res, outcome.outcome.actOutcome, acct, "Nothing was posted.");
        return res.status(outcome.status || 409).json({ code: outcome.code, error: refusalText(outcome.code) });
      }
      var u = await deps.sb.from("member_leads").update({ status: "replied", updated_at: new Date(now()).toISOString() }).eq("id", lead.id).eq("user_id", userId);
      if (u.error) console.error("[leads/send] lead not marked replied: " + u.error.message);
      return res.json({ sent: true, uri: outcome.uri, text: text });
    } catch (err) { next(err); }
  });

  /* NAMED (Nov 23 2026, LR-2): the gates record of a send (lib/gates.js, action outreach_send: G23 then G22), as POST
     /api/agents/sales/send-approved kept it. Recording never blocks or changes the send: a failure is swallowed. */
  var G22_CODES = { already_replied: "already_contacted", post_full: "post_full", member_daily_cap: "daily_cap_reached",
    account_ceiling: "account_ceiling_reached", check_failed: "check_failed" };
  function recordOutreachGate(userId, observed) {
    try {
      if (typeof deps.recordGate !== "function") return;
      var p = deps.recordGate(userId, "outreach_send", "lead", observed, { facts: { agent: "sales" } });
      if (p && typeof p.catch === "function") p.catch(function () {});
    } catch (e) { /* the record is not the send */ }
  }

  /* One Bluesky reply from the decided account: the post is read in the same session and the reply references are
     Bluesky's own, never the request's. */
  async function postBluesky(userId, acct, uri, text) {
    var attempted = false;
    var acted = await deps.actAs(userId, acct, async function (agent) {
      var got = await agent.getPosts({ uris: [uri] });
      var posts = got && got.data && Array.isArray(got.data.posts) ? got.data.posts : [];
      var post = posts.find(function (p) { return p && p.uri === uri; }) || null;
      if (!post) return { ok: false, code: "post_gone", status: 404 };
      var refs = deps.replyRefsFor(post);
      if (!refs) return { ok: false, code: "post_error", status: 502 };
      var record = { $type: "app.bsky.feed.post", text: text, reply: refs, createdAt: new Date().toISOString() };
      var facets = deps.linkFacets(text);
      if (facets && facets.length) record.facets = facets;
      attempted = true;
      var made = await agent.post(record);
      return { ok: true, uri: made && made.uri };
    });
    if (!acted.ok && attempted) return { ok: false, code: "unknown_outcome", status: 502 };
    if (!acted.ok) return { ok: false, code: acted.reason === "rate_limited" ? "rate_limited" : "post_error", status: acted.reason === "rate_limited" ? 429 : 502, actOutcome: acted };
    return acted.value;
  }

  function refusalText(code) {
    return ({
      already_replied: "You already replied to this post. Nothing was posted.",
      post_full: "Three members have already replied to this post. Nothing was posted.",
      member_daily_cap: "You have posted your " + deps.caps.perMember + " replies for today. Nothing was posted.",
      account_ceiling: "BizForce has reached today's reply limit for everyone. Try again tomorrow. Nothing was posted.",
      check_failed: "The reply limits could not be checked just now, so nothing was posted. Try again.",
      post_gone: "That post is no longer on Bluesky. Nothing was posted.",
      rate_limited: "Bluesky is limiting requests for this account. Nothing was posted.",
      waiting_approval: "Waiting for Meta's approval. Nothing was posted.",
      unknown_outcome: "BizForce could not tell whether your reply went out. Open the post to check; BizForce will not send it again."
    })[code] || "The reply could not be posted. Nothing was posted.";
  }

  /* The owner's archive: the old platform radar's rows, read only. */
  app.get("/api/leads/archive", deps.requireAuth, async function (req, res, next) {
    try {
      if (req.user.id !== deps.ownerId) return res.status(403).json({ error: "The lead archive is the owner's.", code: "owner_only" });
      var r = await Promise.all([
        deps.sb.from("bsky_leads").select("post_uri, author_handle, post_text, matched_keyword, intent_score, intent_reason, source, status, post_created_at, created_at")
          .order("created_at", { ascending: false }).limit(200),
        deps.sb.from("sales_lead_pipeline").select("lead_post_uri, status, last_draft, updated_at").eq("user_id", req.user.id).order("updated_at", { ascending: false }).limit(200)
      ]);
      r.forEach(function (x) { if (x.error) throw x.error; });
      return res.json({ leads: r[0].data || [], pipeline: r[1].data || [], read_only: true });
    } catch (err) { next(err); }
  });
}

module.exports = { mountLeadRoutes, leadView, isWeak, SOURCES, MEMBER_STATUSES, LEAD_FIELDS };
