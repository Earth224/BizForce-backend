"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkInbox.js — P2-1 (Nov 19 2026): the Inbox (inbox.html) and its routes.

     L  lib/inbox.js: conversations grouped, thread pages, the before cursor,
        safe links, the message notice (actor, object, link)
     M  POST /api/messages: an unknown receiver is a 404 and nothing is
        written; the notice carries actor_id, object_type, object_id and
        /inbox.html?with=<sender>. GET /api/messages/:userId pages.
     N  notifications: newest first, ?exclude=message, links only on this
        site; PUT :id/read is a 404 for an id that is not the member's (not a
        500); read-all leaves messages alone; the support notice's link
     I  the inbox routes: conversations with unread counts, the person, read,
        the counts (the badge is notices plus messages)
     P  inbox.html: three tabs, three panes, ?with and ?tab, approvals with
        approve and reject, mark all read, Web Push, Your email;
        messages.html and proposals.html stay and link to it

   Run: node scripts/checkInbox.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", INBOXLIB = "@lib/inbox.js";
const PAGE = "inbox.html", MESSAGES = "messages.html", PROPOSALS = "proposals.html";

const MUTATIONS = {
  // NAMED (Nov 21 2026, P3-1B): a free account may start a conversation (M5b catches it)
  "free-starts-conversation": [[SERVER, "      if (!startedByThem.data || !startedByThem.data.length) {\n        return res.status(403)", "      if (false) {\n        return res.status(403)"]],
  "unknown-receiver-written": [[SERVER, "    if (!receiver.data) {\n      return res.status(404).json({ error: IN.RECEIVER_MISSING, reason: \"unknown_receiver\" });\n    }\n", ""]],
  "bad-id-receiver-500": [[SERVER, "    if (!IN.isUuid(receiverId)) {\n      return res.status(404).json({ error: IN.RECEIVER_MISSING, reason: \"unknown_receiver\" });\n    }\n", ""]],
  "notice-no-link": [[INBOXLIB, "    link: \"/inbox.html?with=\" + senderId\n", "    link: null\n"]],
  "notice-no-actor": [[INBOXLIB, "    actor_id: senderId,\n", ""]],
  "missing-notice-500": [[SERVER, "    if (!data) return res.status(404).json({ error: IN.NOTICE_MISSING });\n", ""]],
  "notice-not-own": [[SERVER, "      .eq(\"user_id\", req.user.id)\n      .select(\"*\")\n      .maybeSingle();\n\n    if (error) {\n      throw error;\n    }\n    if (!data) return res.status(404).json({ error: IN.NOTICE_MISSING });", "      .select(\"*\")\n      .maybeSingle();\n\n    if (error) {\n      throw error;\n    }\n    if (!data) return res.status(404).json({ error: IN.NOTICE_MISSING });"]],
  "read-all-takes-messages": [[SERVER, "    if (req.query.include !== \"message\") query = query.neq(\"type\", \"message\");\n", ""]],
  "off-site-link": [[INBOXLIB, "const LINK_RE = /^\\/[^/]/;", "const LINK_RE = /^\\//;"]],
  "list-oldest-first": [[SERVER, "      .order(\"created_at\", { ascending: false })\n      .limit(IN.NOTIFICATIONS_PAGE);", "      .order(\"created_at\", { ascending: true })\n      .limit(IN.NOTIFICATIONS_PAGE);"]],
  "thread-unpaged": [[INBOXLIB, "  const page = rows.slice(0, limit).reverse();", "  const page = rows.slice().reverse();"]],
  "groups-every-row": [[INBOXLIB, "    if (!other || seen.has(other)) return;", "    if (!other) return;"]],
  // NAMED (Nov 21 2026, P3-1B): re-anchored; BEFORE "badge: n + m });", which P3-2's counts object (with the owner's reports) replaced
  "badge-adds-approvals": [[SERVER, "approvals: approvals.count || 0, badge: n + m };", "approvals: approvals.count || 0, badge: n + m + (approvals.count || 0) };"]],
  "read-marks-everyone": [[SERVER, ".eq(\"user_id\", req.user.id).eq(\"type\", \"message\").eq(\"actor_id\", req.params.userId).eq(\"read\", false).select(\"id\");", ".eq(\"user_id\", req.user.id).eq(\"type\", \"message\").eq(\"read\", false).select(\"id\");"]],
  "support-no-link": [[SERVER, "            object_type: \"tip\",\n            link: \"/wallet.html\"\n", "            object_type: \"tip\"\n"]],
  "page-no-with": [[PAGE, "    openThread(withId);\n", ""]],
  "page-no-push": [[PAGE, "<button type=\"button\" class=\"btn\" id=\"pushBtn\">Turn on push notifications</button>", "<button type=\"button\" class=\"btn\" id=\"pushBtnX\" hidden>Turn on push notifications</button>"]],
  "page-no-email-link": [[PAGE, "<a href=\"mailbox.html\">Your email</a> is separate.", "Your email is separate."]],
  "page-unsafe-link": [[PAGE, "    var link = safeUrl(n.link);", "    var link = n.link;"]],
  "messages-page-unlinked": [[MESSAGES, " They are in your <a class=\"inbox-ref\" href=\"inbox.html\">Inbox</a> too.", ""]],
  "proposals-page-unlinked": [[PROPOSALS, " Waiting ones are in your <a class=\"inbox-ref\" href=\"inbox.html?tab=approvals\">Inbox</a> too.", ""]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, INBOXLIB, PAGE, MESSAGES, PROPOSALS]);
const { FILES, check, has, J } = T;
const ME = "11111111-1111-4111-8111-111111111111", OTHER = "22222222-2222-4222-8222-222222222222", THIRD = "33333333-3333-4333-8333-333333333333";
const SRC = FILES[SERVER] || "";
const run = (method, routePath, db, req) => {
  const fn = H.route(SRC, method, routePath, { supabase: db.client, safeText: (v, n) => (v == null ? "" : String(v).slice(0, n)) }, T.libRequire);
  return fn ? fn(req || {}) : Promise.resolve({ status: "no route" });
};

(async () => {
  /* ══ L ══ */
  console.log("\n══ L. lib/inbox.js ══");
  const IN = T.libRequire("./lib/inbox");
  const rows = [
    { sender_id: OTHER, receiver_id: ME, content: "newest from other", created_at: "2026-11-19T10:00:00.000Z" },
    { sender_id: ME, receiver_id: THIRD, content: "to third", created_at: "2026-11-19T09:00:00.000Z" },
    { sender_id: ME, receiver_id: OTHER, content: "older to other", created_at: "2026-11-19T08:00:00.000Z" }
  ];
  const g = IN.groupConversations(rows, ME, { [OTHER]: 2 });
  check("L1. one row per person, newest conversation first, with its last message and the unread count",
    g.length === 2 && g[0].other_id === OTHER && g[0].last_message === "newest from other" && g[0].unread === 2 && g[0].last_from_me === false &&
    g[1].other_id === THIRD && g[1].unread === 0 && g[1].last_from_me === true, J(g));
  check("L2. unread counted by who sent it", J(IN.unreadByActor([{ actor_id: OTHER }, { actor_id: OTHER }, { actor_id: null }])) === J({ [OTHER]: 2 }));
  const newestFirst = [5, 4, 3, 2, 1].map(i => ({ id: i, created_at: "2026-11-19T0" + i + ":00:00.000Z" }));
  const p = IN.threadPage(newestFirst, 4);
  check("L3. a thread page: the newest 4 of 5, oldest first, has_more, and the cursor is the oldest shown",
    J(p.messages.map(m => m.id)) === J([2, 3, 4, 5]) && p.has_more === true && p.next_before === "2026-11-19T02:00:00.000Z", J(p));
  check("L4. the last page says so", IN.threadPage(newestFirst.slice(0, 3), 4).has_more === false && IN.threadPage([], 4).next_before === null);
  check("L5. ?limit: 50 by default, at most 100, a bad value the default", IN.pageLimit(undefined) === 50 && IN.pageLimit("500") === 100 && IN.pageLimit("x") === 50 && IN.pageLimit("0") === 50 && IN.pageLimit("20") === 20);
  check("L6. ?before: an ISO time or nothing; anything else is an error (a 400), never silently the newest",
    IN.parseBefore("").before === null && IN.parseBefore("2026-11-19T02:00:00.000Z").before === "2026-11-19T02:00:00.000Z" && !!IN.parseBefore("yesterday").error && !!IN.parseBefore("1; drop").error);
  check("L7. a link is kept only as a path on this site",
    IN.safeLink("/inbox.html?with=x") === "/inbox.html?with=x" && IN.safeLink("//evil.test/x") === null && IN.safeLink("https://evil.test") === null &&
    IN.safeLink("javascript:alert(1)") === null && IN.safeLink("/" + "a".repeat(300)) === null && IN.safeLink(null) === null);
  const notice = IN.messageNotice(OTHER, ME, "m-1");
  check("L8. the message notice: to the receiver, type message, from the sender, about the message, opening the conversation with the sender",
    notice.user_id === OTHER && notice.type === "message" && notice.read === false && notice.actor_id === ME && notice.object_type === "message" &&
    notice.object_id === "m-1" && notice.link === "/inbox.html?with=" + ME, J(notice));
  check("L9. the object types are migration 190's list", J(IN.OBJECT_TYPES) === J(["post", "comment", "message", "proposal", "listing", "order", "tip", "follow", "report", "review", "campaign"]));

  /* ══ M ══ */
  console.log("\n══ M. messages ══");
  function msgDb(opts) {
    return H.fakeDb((table, q) => {
      if (table === "users") return { data: H.filterVal(q, "eq", "id") === OTHER ? { id: OTHER } : null, error: null };
      if (table === "messages" && q.op === "insert") return { data: Object.assign({ id: "m-9" }, q.payload), error: null };
      if (table === "messages") return { data: (opts && opts.rows) || [], error: null };
      if (table === "notifications") return { data: null, error: null };
      return { data: null, error: null };
    });
  }
  const writes = db => db.log.filter(q => q.op !== "select");
  const d1 = msgDb(), d2 = msgDb(), d3 = msgDb(), d4 = msgDb();
  const unknown = await run("post", "/api/messages", d1, { body: { receiver_id: THIRD, content: "hi" } });
  check("M1. a receiver id that is no member is a 404, and nothing is written", unknown.status === 404 && unknown.body.reason === "unknown_receiver" && writes(d1).length === 0, J([unknown.status, unknown.body, writes(d1).length]));
  const notId = await run("post", "/api/messages", d2, { body: { receiver_id: "not-an-id", content: "hi" } });
  check("M2. a receiver that is not an id at all is a 404 too, never a query or a 500", notId.status === 404 && d2.log.length === 0 && !notId.err, J([notId.status, notId.body]));
  const self = await run("post", "/api/messages", d3, { body: { receiver_id: ME, content: "hi" } });
  check("M3. a message to yourself is a 400", self.status === 400 && self.body.reason === "self_message" && writes(d3).length === 0, J([self.status, self.body]));
  const sent = await run("post", "/api/messages", d4, { body: { receiver_id: OTHER, content: "hello" } });
  const ins = d4.log.filter(q => q.op === "insert");
  const msgRow = (ins.find(q => q.table === "messages") || {}).payload || {};
  const noteRow = (ins.find(q => q.table === "notifications") || {}).payload || {};
  check("M4. a message to a member is written from the sender (201)", sent.status === 201 && msgRow.sender_id === ME && msgRow.receiver_id === OTHER && msgRow.content === "hello", J([sent.status, msgRow]));
  check("M5. its notice says who sent it and opens the conversation: actor_id, object_type message, object_id, /inbox.html?with=<sender>",
    noteRow.user_id === OTHER && noteRow.actor_id === ME && noteRow.object_type === "message" && noteRow.object_id === "m-9" && noteRow.link === "/inbox.html?with=" + ME, J(noteRow));
  /* NAMED (Nov 21 2026, P3-1B, the owner's rule): REPLY-ONLY MESSAGING. A free account replies in a conversation a member
     started with them, and cannot start one: with no message from the receiver to them, POST /api/messages is 403
     members_only with the members panel and one sentence, and nothing is written. A member starts any conversation. */
  const runAs = (plan, db, req) => {
    const fn = H.route(SRC, "post", "/api/messages", { supabase: db.client, safeText: (v, n) => (v == null ? "" : String(v).slice(0, n)),
      getUserPlan: async () => plan }, T.libRequire);
    return fn ? fn(req) : Promise.resolve({ status: "no route" });
  };
  const FREE_PLAN = { active: false, plan: null, inactive_reason: "no_subscription" };
  const theyWrote = H.fakeDb((table, q) => {
    if (table === "users") return { data: H.filterVal(q, "eq", "id") === OTHER ? { id: OTHER } : null, error: null };
    if (table === "messages" && q.op === "insert") return { data: Object.assign({ id: "m-10" }, q.payload), error: null };
    if (table === "messages") return { data: H.filterVal(q, "eq", "sender_id") === OTHER && H.filterVal(q, "eq", "receiver_id") === ME ? [{ id: "m-1" }] : [], error: null };
    return { data: null, error: null };
  });
  const dFree = msgDb(), dMember = msgDb();
  const starts = await runAs(FREE_PLAN, dFree, { body: { receiver_id: OTHER, content: "hello" } });
  const MEMB = T.libRequire("./lib/membership");
  check("M5b. P3-1B: a free account starting a conversation: 403 members_only, the owner's sentence and the members panel, nothing written",
    starts.status === 403 && starts.body.reason === "members_only" && starts.body.error === MEMB.FREE_RULES.start_conversation &&
    J(starts.body.members_panel) === J(MEMB.membersPanelFromCode()) && writes(dFree).length === 0, J([starts.status, starts.body && starts.body.error, writes(dFree).length]));
  const replies = await runAs(FREE_PLAN, theyWrote, { body: { receiver_id: OTHER, content: "thanks, yes please" } });
  const replyRow = (theyWrote.log.find(q => q.op === "insert" && q.table === "messages") || {}).payload || {};
  check("M5c. P3-1B: ...and replying where the member wrote first goes through (201)", replies.status === 201 && replyRow.sender_id === ME && replyRow.receiver_id === OTHER, J([replies.status, replyRow]));
  const memberStarts = await runAs({ active: true, plan: "all_access", inactive_reason: null }, dMember, { body: { receiver_id: OTHER, content: "hello" } });
  check("M5d. P3-1B: a member starts a conversation (201)", memberStarts.status === 201, J([memberStarts.status, memberStarts.body]));
  const many = Array.from({ length: 60 }, (_, i) => ({ id: i, created_at: new Date(Date.UTC(2026, 10, 19, 0, 60 - i)).toISOString() }));
  const d5 = msgDb({ rows: many });
  const page = await run("get", "/api/messages/:userId", d5, { params: { userId: OTHER }, query: { before: "2026-11-19T02:00:00.000Z" } });
  const mq = d5.log.find(q => q.table === "messages") || { filters: [] };
  check("M6. a thread is read a page at a time: 50 (one extra asked for has_more), newest first, before the cursor",
    page.status === 200 && page.body.messages.length === 50 && page.body.has_more === true && H.filterVal(mq, "limit") === 51 &&
    H.filterVal(mq, "lt", "created_at") === "2026-11-19T02:00:00.000Z", J([page.status, page.body && page.body.messages.length, mq.filters]));
  check("M7. ...only between the member and that person", String(H.filterVal(mq, "or")) === "and(sender_id.eq." + ME + ",receiver_id.eq." + OTHER + "),and(sender_id.eq." + OTHER + ",receiver_id.eq." + ME + ")", H.filterVal(mq, "or"));
  const d6 = msgDb();
  const badId = await run("get", "/api/messages/:userId", d6, { params: { userId: "x" } });
  const badBefore = await run("get", "/api/messages/:userId", d6, { params: { userId: OTHER }, query: { before: "soon" } });
  check("M8. a bad id or cursor is a 400 and nothing is read", badId.status === 400 && badBefore.status === 400 && d6.log.length === 0, J([badId.status, badBefore.status]));

  /* ══ N ══ */
  console.log("\n══ N. notifications ══");
  const nDb = (opts) => H.fakeDb((table, q) => {
    if (q.op === "update") return { data: opts && opts.updated !== undefined ? opts.updated : [{ id: "n1" }, { id: "n2" }], error: null };
    return { data: [{ id: "n1", type: "tip", link: "/wallet.html" }, { id: "n2", type: "x", link: "https://evil.test/" }, { id: "n3", type: "y", link: "//evil.test" }], error: null };
  });
  const n1 = nDb();
  const list = await run("get", "/api/notifications", n1, { query: { exclude: "message" } });
  const lq = n1.log[0];
  const order = lq.filters.find(f => f[0] === "order") || [];
  check("N1. the member's own, newest first, at most 100", H.filterVal(lq, "eq", "user_id") === ME && order[1] === "created_at" && order[2] && order[2].ascending === false && H.filterVal(lq, "limit") === 100, J(lq.filters));
  check("N2. ?exclude=message leaves message notices to the conversations", H.filterVal(lq, "neq", "type") === "message");
  check("N3. a link is passed only when it is a path on this site", list.status === 200 && J(list.body.notifications.map(n => n.link)) === J(["/wallet.html", null, null]), J(list.body));
  const n2 = nDb({ updated: null });
  const missing = await run("put", "/api/notifications/:id/read", n2, { params: { id: OTHER } });
  const uq = n2.log[0] || { filters: [] };
  check("N4. PUT :id/read for an id that is not one of the member's: a 404, not a 500",
    missing.status === 404 && !missing.err && missing.body.error === IN.NOTICE_MISSING && H.filterVal(uq, "eq", "user_id") === ME && uq.terminal === "maybeSingle", J([missing.status, missing.body, missing.err && missing.err.message]));
  const n3 = nDb();
  const notUuid = await run("put", "/api/notifications/:id/read", n3, { params: { id: "abc" } });
  check("N5. ...and an id that is not an id is a 404 without a query", notUuid.status === 404 && n3.log.length === 0);
  const n4 = nDb({ updated: { id: OTHER, read: true } });
  const ok = await run("put", "/api/notifications/:id/read", n4, { params: { id: OTHER } });
  check("N6. the member's own notice is marked read", ok.status === 200 && ok.body.notification.read === true && n4.log[0].payload.read === true);
  const n5 = nDb(), n6 = nDb();
  const all = await run("post", "/api/notifications/read-all", n5, {});
  const withMsg = await run("post", "/api/notifications/read-all", n6, { query: { include: "message" } });
  check("N7. mark all read: the member's unread notices, messages left to their conversations; it says how many",
    all.status === 200 && all.body.marked === 2 && H.filterVal(n5.log[0], "eq", "user_id") === ME && H.filterVal(n5.log[0], "neq", "type") === "message" &&
    H.filterVal(n6.log[0], "neq", "type") === undefined && withMsg.status === 200, J([all.body, n5.log[0].filters]));
  const sup = SRC.slice(SRC.indexOf("const notice = await supabase.from(\"notifications\").insert({\n            user_id: member.user_id,"), SRC.indexOf("const notice = await supabase.from(\"notifications\").insert({\n            user_id: member.user_id,") + 600);
  check("N8. the support notice now says who sent it and opens the wallet", has(sup, "actor_id: req.user.id,") && has(sup, "object_type: \"tip\",") && has(sup, "link: \"/wallet.html\""));
  check("N9. no proposal notice is written anywhere (none existed before P2-1; the Approvals tab reads the proposals themselves)",
    !/object_type: "proposal"/.test(SRC) && !/inbox\.html\?tab=approvals/.test(SRC));

  /* ══ I ══ */
  console.log("\n══ I. the inbox routes ══");
  const iDb = H.fakeDb((table, q) => {
    if (table === "messages") return { data: rows, error: null };
    if (table === "notifications" && q.op === "select" && q.head) return { count: H.filterVal(q, "eq", "type") === "message" ? 3 : 4, error: null };
    if (table === "notifications" && q.op === "select") return { data: [{ actor_id: OTHER }, { actor_id: OTHER }], error: null };
    if (table === "notifications" && q.op === "update") return { data: [{ id: "a" }], error: null };
    if (table === "agent_proposals") return { count: 5, error: null };
    const one = (rowsIn) => q.terminal === "maybeSingle" ? (rowsIn.find(r => r.user_id === H.filterVal(q, "eq", "user_id")) || null) : rowsIn;
    if (table === "bf_profiles") return { data: one([{ user_id: OTHER, username: "rose", display_name: "Rose", avatar_url: null }]), error: null };
    if (table === "profiles") return { data: one([{ user_id: THIRD, business_name: "Third Co" }]), error: null };
    if (table === "users") return { data: H.filterVal(q, "eq", "id") === OTHER ? { id: OTHER } : null, error: null };
    return { data: null, error: null };
  });
  const conv = await run("get", "/api/inbox/conversations", iDb, {});
  const unreadQ = iDb.log.find(q => q.table === "notifications" && q.op === "select") || { filters: [] };
  check("I1. conversations: one per person, with their name and the unread count from that person's message notices",
    conv.status === 200 && conv.body.conversations.length === 2 && conv.body.conversations[0].unread === 2 && conv.body.conversations[0].person.username === "rose" &&
    conv.body.conversations[1].person.name === "Third Co" && H.filterVal(unreadQ, "eq", "type") === "message" && H.filterVal(unreadQ, "eq", "read") === false, J(conv.body));
  const person = await run("get", "/api/inbox/person/:userId", iDb, { params: { userId: OTHER } });
  const nobody = await run("get", "/api/inbox/person/:userId", iDb, { params: { userId: THIRD } });
  check("I2. the person at the other end: handle and name only; no member is a 404", person.status === 200 && person.body.person.username === "rose" &&
    J(Object.keys(person.body.person).sort()) === J(["avatar_url", "id", "name", "username"]) && nobody.status === 404, J([person.body, nobody.status]));
  const rDb = H.fakeDb(() => ({ data: [{ id: "a" }], error: null }));
  const read = await run("post", "/api/inbox/read/:userId", rDb, { params: { userId: OTHER } });
  const rq = rDb.log[0] || { filters: [] };
  check("I3. opening a thread marks only that person's message notices to the member read",
    read.status === 200 && read.body.marked === 1 && H.filterVal(rq, "eq", "user_id") === ME && H.filterVal(rq, "eq", "actor_id") === OTHER && H.filterVal(rq, "eq", "type") === "message", J(rq.filters));
  const counts = await run("get", "/api/inbox/counts", iDb, {});
  check("I4. counts: unread notices 4, unread messages 3, waiting approvals 5; the badge is notices plus messages (7)",
    counts.status === 200 && J(counts.body) === J({ notifications: 4, messages: 3, approvals: 5, badge: 7 }), J(counts.body));

  /* ══ P ══ */
  console.log("\n══ P. the pages ══");
  const pg = FILES[PAGE] || "";
  check("P1. three tabs in a tablist: Messages, Approvals, Notifications", has(pg, "id=\"tab-messages\"") && has(pg, "id=\"tab-approvals\"") && has(pg, "id=\"tab-notifications\"") && has(pg, "role=\"tablist\""));
  check("P2. three panes: the list, the open item, the details", has(pg, "id=\"paneList\"") && has(pg, "id=\"paneOpen\"") && has(pg, "id=\"paneDetails\""));
  check("P3. ?with=<member id> opens that conversation; ?tab= opens a tab", has(pg, "if (withId && /^[0-9a-f-]{36}$/i.test(withId)) {\n    selectTab(\"messages\", true);\n    openThread(withId);") && has(pg, "selectTab(TABS.indexOf(tab) !== -1 ? tab : \"messages\")"));
  check("P4. conversations, the person, mark read and the thread come from the inbox routes; sending is POST /api/messages",
    ["\"/api/inbox/conversations\"", "\"/api/inbox/person/\"", "\"/api/inbox/read/\"", "api(\"/api/messages/\"", "api(\"/api/messages\", { method: \"POST\""].every(x => has(pg, x)));
  check("P5. approvals: the waiting proposals, approve or reject, and the full page one tap away",
    has(pg, "api(\"/api/proposals?status=pending\")") && has(pg, "api(\"/api/proposals/\" + encodeURIComponent(id) + \"/\" + action, { method: \"POST\" })") && has(pg, "href=\"proposals.html\">See every detail</a>"));
  check("P6. notifications: newest first from the server, messages left out, a tap marks it read and opens its link (on this site only)",
    has(pg, "api(\"/api/notifications?exclude=message\")") && has(pg, "var link = safeUrl(n.link);") && has(pg, "mark.then(function () { window.location.href = href; });"));
  check("P7. mark all read, and Web Push turned on from here (the same subscription as Settings)",
    has(pg, "api(\"/api/notifications/read-all\", { method: \"POST\" })") && has(pg, "id=\"pushBtn\">Turn on push notifications</button>") && has(pg, "api(\"/api/push/subscribe\", { method: \"POST\""));
  check("P8. a link to Your email (mailbox.html)", has(pg, "<a href=\"mailbox.html\">Your email</a> is separate."));
  check("P9. messages.html stays and links to the Inbox", has(FILES[MESSAGES], "They are in your <a class=\"inbox-ref\" href=\"inbox.html\">Inbox</a> too.") && has(FILES[MESSAGES], "threadMessages = d.messages || [];"));
  check("P10. proposals.html stays and links to the Approvals tab", has(FILES[PROPOSALS], "Waiting ones are in your <a class=\"inbox-ref\" href=\"inbox.html?tab=approvals\">Inbox</a> too."));
  check("P11. no Guide on the Inbox (its page end is the bar's spacer), the bfc notice and the legal footer are there",
    !has(pg, "termaximus-guide.js") && has(pg, "data-bf-legal-footer") && has(pg, "<script src=\"/scripts/bf-offline.js\"></script>"));

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
