"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   INBOUND'S ROUTES (LR-3, Nov 24 2026). Mounted by server.js (mountInboundRoutes). Every route is M (members only:
   requireActiveSubscription after requireAuth; a free account gets the members panel, 402), and every read and write
   is the member's own (user_id in the query itself, so anyone else's item is a 404, never a leak).

     GET  /api/inbound                 the member's items, newest first (?status=new|talking|won|lost|all,
                                       ?before=<created_at> for the next page, ?limit up to 100), with the counts
     GET  /api/inbound/summary         the counts per status and the won total the Leads tab shows
     POST /api/inbound/:id/status      { status: new | talking | won | lost }
     POST /api/inbound/:id/customer    "Add to my customers" on a won item: one crm_customers row, once

   deps: { sb, requireAuth, requireActiveSubscription, now() -> ISO time (optional) }
   ═════════════════════════════════════════════════════════════════════════════ */

const IB = require("./inbound");
const IN = require("./inbox");

function pageLimit(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) return IB.LIST_PAGE;
  return Math.min(n, IB.LIST_MAX);
}

/* The member's own Bluesky reply each lead_reply item points to, so tapping it opens that thread. */
async function replyUris(sb, userId, items) {
  const ids = items.filter(function (i) { return i.kind === "lead_reply"; }).map(function (i) { return i.source_id; });
  const out = {};
  if (!ids.length) return out;
  const r = await sb.from("member_lead_replies").select("id, platform_uri").eq("user_id", userId).in("id", ids);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (x) { out[x.id] = x.platform_uri; });
  return out;
}

function mountInboundRoutes(app, deps) {
  const sb = deps.sb;
  const M = [deps.requireAuth, deps.requireActiveSubscription];
  const now = typeof deps.now === "function" ? deps.now : function () { return new Date().toISOString(); };

  app.get("/api/inbound", M, async function (req, res, next) {
    try {
      const userId = req.user.id;
      const status = String(req.query.status || "all");
      if (status !== "all" && IB.STATUSES.indexOf(status) === -1) return res.status(400).json({ error: "Status is new, talking, won, lost or all.", field: "status" });
      const cursor = IN.parseBefore(req.query.before);
      if (cursor.error) return res.status(400).json({ error: cursor.error, field: "before" });
      const limit = pageLimit(req.query.limit);
      let q = sb.from(IB.TABLE).select(IB.FIELDS).eq("user_id", userId);
      if (status !== "all") q = q.eq("status", status);
      if (cursor.before) q = q.lt("created_at", cursor.before);
      const r = await q.order("created_at", { ascending: false }).limit(limit + 1);
      if (r.error) throw r.error;
      const page = (r.data || []).slice(0, limit);
      const uris = await replyUris(sb, userId, page);
      res.set("Cache-Control", "no-store");
      return res.json({
        items: page.map(function (i) { return IB.view(i, uris[i.source_id]); }),
        counts: await IB.counts(sb, userId),
        next_before: (r.data || []).length > limit ? page[page.length - 1].created_at : null
      });
    } catch (err) { next(err); }
  });

  app.get("/api/inbound/summary", M, async function (req, res, next) {
    try {
      const userId = req.user.id;
      const [c, won] = await Promise.all([IB.counts(sb, userId), IB.wonCount(sb, userId)]);
      res.set("Cache-Control", "no-store");
      return res.json({ counts: c, won_total: won });
    } catch (err) { next(err); }
  });

  app.post("/api/inbound/:id/status", M, async function (req, res, next) {
    try {
      const id = String(req.params.id || "");
      if (!IB.isUuid(id)) return res.status(404).json({ error: "That item is not one of yours." });
      const status = req.body && req.body.status;
      if (typeof status !== "string" || IB.STATUSES.indexOf(status) === -1) return res.status(400).json({ error: "Status is new, talking, won or lost.", field: "status" });
      const r = await sb.from(IB.TABLE).update({ status: status, updated_at: now() }).eq("id", id).eq("user_id", req.user.id).select(IB.FIELDS);
      if (r.error) throw r.error;
      const item = (r.data || [])[0];
      if (!item) return res.status(404).json({ error: "That item is not one of yours." });
      const uris = await replyUris(sb, req.user.id, [item]);
      return res.json({ item: IB.view(item, uris[item.source_id]) });
    } catch (err) { next(err); }
  });

  app.post("/api/inbound/:id/customer", M, async function (req, res, next) {
    try {
      const userId = req.user.id, id = String(req.params.id || "");
      if (!IB.isUuid(id)) return res.status(404).json({ error: "That item is not one of yours." });
      const found = await sb.from(IB.TABLE).select(IB.FIELDS).eq("id", id).eq("user_id", userId).maybeSingle();
      if (found.error) throw found.error;
      const item = found.data;
      if (!item) return res.status(404).json({ error: "That item is not one of yours." });
      if (item.status !== "won") return res.status(409).json({ error: "Mark it Won first, then add them to your customers.", code: "not_won" });
      if (item.customer_id) return res.json({ created: false, customer: { id: item.customer_id }, item: IB.view(item) });
      let lead = null;
      if (item.kind === "card_lead") {
        const l = await sb.from("card_leads").select("name, email, phone").eq("id", item.source_id).eq("user_id", userId).maybeSingle();
        if (l.error) throw l.error;
        lead = l.data;
      }
      const at = now();
      const made = await sb.from("crm_customers").insert(Object.assign({ user_id: userId, created_at: at, updated_at: at }, IB.customerFields(item, lead))).select("id, name").single();
      if (made.error) throw made.error;
      // Once: the item takes the customer only if it has none; a second tap that raced this one keeps the first.
      const linked = await sb.from(IB.TABLE).update({ customer_id: made.data.id, updated_at: at }).eq("id", id).eq("user_id", userId).is("customer_id", null).select(IB.FIELDS);
      if (linked.error) throw linked.error;
      if (!(linked.data || []).length) {
        await sb.from("crm_customers").delete().eq("id", made.data.id).eq("user_id", userId);
        const again = await sb.from(IB.TABLE).select(IB.FIELDS).eq("id", id).eq("user_id", userId).maybeSingle();
        if (again.error) throw again.error;
        return res.json({ created: false, customer: { id: again.data && again.data.customer_id }, item: IB.view(again.data) });
      }
      return res.status(201).json({ created: true, customer: made.data, item: IB.view(linked.data[0]) });
    } catch (err) { next(err); }
  });
}

module.exports = { mountInboundRoutes, pageLimit };
