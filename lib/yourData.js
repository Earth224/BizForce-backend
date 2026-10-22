/* ══════════════════════════════════════════════════════════════════════════
   lib/yourData.js — what BizForce stores about a member, the download of all
   of it, and deleting the account.

   ONE DESCRIPTION. DATA below is the only list of the member's data. The page
   (your-data.html, through GET /api/your-data), the export (GET
   /api/me/export) and the delete (POST /api/me/delete) all read it, so what
   the page says is stored, what the download contains and what deletion does
   cannot drift apart. scripts/checkYourData.js fails when a table in
   lib/backup.js's lists is in neither DATA nor NOT_MEMBER_DATA.

   Each entry:
     table      the table
     group      which heading the page lists it under
     what       one plain sentence: what it holds
     owner      the column(s) that hold the member's id; a row is theirs when
                ANY of them is their id
     via        or: { column, parent }: the row is theirs when `column` holds
                the id of one of their rows in `parent`
     key        the column the rows are read in order of (default "id")
     select     the columns read for the export, when not all of them; a column
                left out here never leaves the database
     members    columns holding ANOTHER member's id: the export shows that
                member by username only ("@name"), or "a deleted member"
     export     false when the rows are not exported, with exportWhy
     onDelete   "delete"     the member's own; deleted
                "keep"       other members' records depend on it; kept, and
                             the member is shown as a deleted member
                "evidence"   kept as consent evidence, emails and phones
                             replaced by a one-way hash, names removed
                "forfeit"    the wallet: balance forfeited in a ledger row
                "tombstone"  the users row: emptied, never removed
                "signatures" deleted on the member's own documents, kept on
                             other members' documents
                "sold"       deleted, except a listing another member
                             bought: taken off sale and kept, with its files
                             (lib/accountFiles.js keptForBuyers)
     why        why it is kept (every action but "delete")

   NOTHING HERE TALKS TO THE NETWORK. The Supabase client, the password check
   and the subscription read are passed in, so the check runs it all against
   in-memory tables.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");
const accountFiles = require("./accountFiles");

const GROUPS = [
  { key: "account",   title: "Your account and sign-in" },
  { key: "profile",   title: "Your profile and public pages" },
  { key: "business",  title: "Your business, customers and stock" },
  { key: "contacts",  title: "Your contacts, messages you sent them, and their consent" },
  { key: "agents",    title: "Your agents and what they did" },
  { key: "content",   title: "Your content, books and documents" },
  { key: "money",     title: "BizCash, purchases, sales and billing" },
  { key: "messages",  title: "Messages and notifications" },
  { key: "moderation", title: "Moderation records about your account" }
];

const KEEP_LEDGER = "it is one half of a money record another member also holds, and a ledger with a row missing no longer adds up";

const DATA = [
  // ── account and sign-in ──
  { table: "users", group: "account", what: "Your account: email, business name, industry, bio, picture, role, when you joined, and the address and time of your last sign-in.",
    owner: ["id"], select: "id, email, business_name, industry, bio, avatar_url, role, verification_status, email_verified_at, subscription_status, created_at, updated_at, last_login_at, last_login_ip, signup_ip",
    onDelete: "tombstone", why: "the orders, ledgers and messages other members hold point at it. It can never sign in again" },
  { table: "profiles", group: "account", what: "Your account profile: username, name, contact details, website and links.", owner: ["user_id"], onDelete: "delete" },
  { table: "user_preferences", group: "account", what: "Your settings: language, card order, notifications.", owner: ["user_id"], key: "user_id", onDelete: "delete" },
  { table: "auth_sessions", group: "account", what: "Your sign-in sessions: when each began and was last used, the browser and the address. The session secret is never exported.",
    owner: ["user_id"], select: "id, issued_at, expires_at, last_used_at, revoked_at, revoked_reason, user_agent, ip", onDelete: "delete" },
  { table: "webauthn_credentials", group: "account", what: "Your passkeys: each one's name and dates. The key material is never exported.",
    owner: ["user_id"], select: "id, nickname, backed_up, created_at, last_used_at", onDelete: "delete" },
  { table: "webauthn_challenges", group: "account", what: "Single-use passkey challenges that expire within minutes.",
    owner: ["user_id"], export: false, exportWhy: "single-use sign-in secrets that expire within minutes", onDelete: "delete" },
  { table: "push_subscriptions", group: "account", what: "Browsers you turned notifications on in: the browser and dates. The push credentials are never exported.",
    owner: ["user_id"], select: "id, user_agent, created_at, last_used_at", onDelete: "delete" },
  { table: "user_api_keys", group: "account", what: "AI provider API keys you added: listed by provider and date only. The key is never exported.",
    owner: ["user_id"], select: "id, provider, created_at, updated_at", onDelete: "delete" },

  // ── profile and public pages ──
  { table: "bf_profiles", group: "profile", what: "Your public profile page: username, name, tagline, bio, pictures, links and layout.", owner: ["user_id"], onDelete: "delete" },
  { table: "profile_products", group: "profile", what: "Products on your profile page.", owner: ["user_id"], onDelete: "delete" },
  { table: "profile_portfolio", group: "profile", what: "Portfolio entries on your profile page.", owner: ["user_id"], onDelete: "delete" },
  { table: "profile_music", group: "profile", what: "Music on your profile page.", owner: ["user_id"], onDelete: "delete" },
  { table: "profile_videos", group: "profile", what: "Videos on your profile page.", owner: ["user_id"], onDelete: "delete" },
  { table: "bf_music_tracks", group: "profile", what: "Track records for music you uploaded.", owner: ["user_id"], onDelete: "delete" },
  { table: "bf_videos", group: "profile", what: "Records for videos you uploaded.", owner: ["user_id"], onDelete: "delete" },
  { table: "digital_cards", group: "profile", what: "Your digital business cards.", owner: ["user_id"], onDelete: "delete" },

  // ── business, customers and stock ──
  { table: "business_profiles", group: "business", what: "Your business profile: name, offer, audience, goals, brand voice and keywords.", owner: ["user_id"], onDelete: "delete" },
  { table: "icp_profiles", group: "business", what: "Ideal-customer profiles you wrote.", owner: ["user_id"], onDelete: "delete" },
  { table: "prospects", group: "business", what: "Prospects you or your agents found, with their details and notes.", owner: ["user_id"], onDelete: "delete" },
  { table: "crm_activities", group: "business", what: "What happened with each CRM customer.", via: { column: "customer_id", parent: "crm_customers" }, onDelete: "delete" },
  { table: "crm_customers", group: "business", what: "Your CRM customers and their details.", owner: ["user_id"], onDelete: "delete" },
  { table: "inventory_movements", group: "business", what: "Every stock movement in your store.", via: { column: "item_id", parent: "inventory_items" }, onDelete: "delete" },
  { table: "inventory_items", group: "business", what: "Your store's stock items.", owner: ["user_id"], onDelete: "delete" },
  { table: "calendar_events", group: "business", what: "Your calendar events and reminders.", owner: ["user_id"], onDelete: "delete" },
  { table: "outreach_sends", group: "business", what: "Public posts you replied to through outreach.", owner: ["user_id"], onDelete: "delete" },
  { table: "sales_lead_pipeline", group: "business", what: "Where each lead stands in your sales pipeline, with drafts.", owner: ["user_id"], onDelete: "delete" },

  // ── contacts and consent ──
  { table: "email_sequence_enrollments", group: "contacts", what: "Which contacts are in which of your email sequences.", via: { column: "sequence_id", parent: "email_sequences" }, onDelete: "delete" },
  { table: "email_sequences", group: "contacts", what: "Email sequences you approved.", owner: ["owner_id"], onDelete: "delete" },
  { table: "sms_campaign_enrollments", group: "contacts", what: "Which SMS subscribers are in which of your campaigns.", owner: ["user_id"], onDelete: "delete" },
  { table: "sms_campaign_messages", group: "contacts", what: "The messages in your SMS campaigns.", owner: ["user_id"], onDelete: "delete" },
  { table: "sms_campaigns", group: "contacts", what: "Your SMS campaigns.", owner: ["user_id"], onDelete: "delete" },
  { table: "email_sends", group: "contacts", what: "Every email sent to your contacts, including your own account email, with its status.", via: { column: "contact_id", parent: "contacts" },
    onDelete: "evidence", why: "a bounce or spam report stops every member's mail to that address",
    deleteText: "A send that bounced or was marked as spam is kept unchanged, address included, because it stops every member's mail to that address, which protects the person it was sent to. Other sends are kept, with the address hashed, only to contacts whose consent record is kept; the rest are deleted." },
  { table: "consent_events", group: "contacts", what: "When each of your contacts agreed to, confirmed or withdrew consent, and where.", via: { column: "contact_id", parent: "contacts" },
    onDelete: "evidence", why: "it is the proof that messages already sent through BizForce had consent, needed to answer a complaint or claim about them",
    deleteText: "Kept unchanged, because it is the proof that messages already sent through BizForce had consent, needed to answer a complaint or claim about them. The contact it belongs to is kept with its email and phone hashed and its name removed." },
  { table: "contacts", group: "contacts", what: "Your contacts: name, email, phone and where they came from.", owner: ["owner_id"],
    onDelete: "evidence", why: "a contact with a consent record is kept, hashed, so that record still has someone to belong to; contacts without one are deleted" },
  { table: "lead_captures", group: "contacts", what: "People who gave you their email or phone, and what they consented to.", owner: ["owner_id"],
    onDelete: "evidence", why: "a capture that recorded consent is the proof of it; captures without consent are deleted" },
  { table: "sms_subscribers", group: "contacts", what: "Your SMS subscribers and their consent.", owner: ["user_id"],
    onDelete: "evidence", why: "it is the proof that texts already sent had consent" },
  { table: "sms_send_log", group: "contacts", what: "Every text sent for you.", owner: ["user_id"],
    onDelete: "evidence", why: "it is the record of what was sent, needed to answer a complaint about a text",
    deleteText: "Kept, with each phone number replaced by a one-way hash. The words of each text stay, because this is the record of what was sent, needed to answer a complaint about a text." },

  // ── agents ──
  { table: "ai_agents", group: "agents", what: "Your agents and their settings.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_assignments", group: "agents", what: "What each agent was assigned.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_autonomy", group: "agents", what: "Which agents you let act on their own.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_schedules", group: "agents", what: "When each agent runs.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_memory", group: "agents", what: "What your agents learned about your business.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_collaborations", group: "agents", what: "Work your agents passed to each other.", owner: ["user_id"], onDelete: "delete" },
  { table: "executive_dispatches", group: "agents", what: "What the executive agent sent to other agents.", owner: ["user_id"], onDelete: "delete" },
  { table: "testimonial_screen_removals", group: "agents", what: "Passages the testimonial screen removed from your agents' results.", owner: ["user_id"], onDelete: "delete" },
  { table: "social_post_drafts", group: "agents", what: "Social post drafts.", owner: ["user_id"], onDelete: "delete" },
  { table: "agent_proposals", group: "agents", what: "Proposals your agents made and what you decided.", owner: ["user_id"], onDelete: "delete" },
  { table: "ai_tasks", group: "agents", what: "Every agent run: what you asked and what it returned.", owner: ["user_id"], onDelete: "delete" },
  { table: "ai_reports", group: "agents", what: "Reports your agents wrote.", owner: ["user_id"], onDelete: "delete" },
  { table: "self_reviews", group: "agents", what: "Your weekly and monthly self-reviews.", owner: ["user_id"], onDelete: "delete" },
  { table: "saved_prompts", group: "agents", what: "Prompts you saved.", owner: ["user_id"], onDelete: "delete" },
  { table: "routines", group: "agents", what: "Routines you built.", owner: ["user_id"], onDelete: "delete" },
  { table: "automation_queue", group: "agents", what: "Automations you queued.", owner: ["user_id"], onDelete: "delete" },
  { table: "oracle_sync", group: "agents", what: "The details you gave the Oracle: names, birth details and focus.", owner: ["user_id"], key: "user_id", onDelete: "delete" },
  { table: "oracle_messages", group: "agents", what: "Your conversations with the Oracle.", owner: ["user_id"], onDelete: "delete" },
  { table: "chat_messages", group: "agents", what: "Your chat history.", owner: ["user_id"], onDelete: "delete" },
  { table: "usage_logs", group: "agents", what: "An old usage log of prompts and replies.", owner: ["user_id"], onDelete: "delete" },
  { table: "inner_iq_results", group: "agents", what: "Your assessment results.", owner: ["user_id"], onDelete: "delete" },
  { table: "birth_records", group: "agents", what: "Birth details you entered for readings.", owner: ["user_id"], onDelete: "delete" },
  { table: "user_certifications", group: "agents", what: "Certifications you took and earned.", owner: ["user_id"], onDelete: "delete" },

  // ── content ──
  { table: "content_library", group: "content", what: "Everything in your library, including published blog posts.", owner: ["user_id"], onDelete: "delete" },
  { table: "seo_refused_drafts", group: "content", what: "Articles the SEO checks refused.", owner: ["user_id"], onDelete: "delete" },
  { table: "bizbooks", group: "content", what: "Books you wrote.", owner: ["owner_id"], onDelete: "delete" },
  { table: "cover_wraps", group: "content", what: "Book covers you designed.", owner: ["owner_id"], onDelete: "delete" },
  { table: "bizdoc_signatures", group: "content", what: "Signatures you made, and signatures on your documents.", owner: ["signer_id"], via: { column: "document_id", parent: "bizdoc_documents" },
    members: ["signer_id"], othersPrivate: ["signer_name", "signer_email", "signature_data", "ip_address", "user_agent"],
    onDelete: "signatures", why: "a signature you made on another member's document is their signed record" },
  { table: "bizdoc_documents", group: "content", what: "Documents you wrote, with the parties you named.", owner: ["owner_id"], onDelete: "delete" },
  { table: "marketplace_listings", group: "content", what: "What you listed for sale.", owner: ["seller_id"],
    onDelete: "sold", why: "the member who bought it downloads their file through it" },
  { table: "crowdfunding_campaigns", group: "content", what: "Your crowdfunding campaigns.", owner: ["owner_id"], onDelete: "delete" },

  // ── money ──
  { table: "user_wallets", group: "money", what: "Your BizCash balance.", owner: ["user_id"],
    onDelete: "forfeit", why: "BizCash has no cash value; the balance is forfeited in a final ledger row, so the balance still equals the sum of its ledger" },
  { table: "wallet_transactions", group: "money", what: "Every BizCash movement in and out of your wallet.", owner: ["user_id"], onDelete: "keep", why: KEEP_LEDGER },
  { table: "marketplace_orders", group: "money", what: "What you bought and sold on the marketplace.", owner: ["buyer_id", "seller_id"], members: ["buyer_id", "seller_id"],
    onDelete: "keep", why: "the other member's purchase or sale is the same order" },
  { table: "campaign_donations", group: "money", what: "Donations you made, and donations to your campaigns.", owner: ["donor_id", "owner_id"], members: ["donor_id", "owner_id"],
    onDelete: "keep", why: "the other member's donation record is the same row" },
  { table: "subscriptions", group: "money", what: "Your subscription: plan, status, dates and payment-provider ids.", owner: ["user_id"],
    onDelete: "keep", why: "it is the billing record that matches the payment provider's, kept for accounts and for answering a refund or dispute" },
  { table: "revenue_events", group: "money", what: "Payments recorded from your subscription.", owner: ["user_id"], onDelete: "keep", why: "it is the money ledger kept for the accounts" },
  { table: "model_calls", group: "money", what: "What each AI model call cost: model, tokens and route. No prompt or reply is in it.", owner: ["user_id"],
    onDelete: "keep", why: "it is BizForce's record of what it paid for" },
  { table: "youtube_api_calls", group: "money", what: "YouTube API quota recorded against your account, if any.", owner: ["user_id"], onDelete: "keep", why: "it is the daily quota ledger" },

  // ── messages ──
  { table: "messages", group: "messages", what: "Messages you sent to and received from other members.", owner: ["sender_id", "receiver_id"], members: ["sender_id", "receiver_id"],
    onDelete: "keep", why: "the other member's conversation is the same messages" },
  { table: "notifications", group: "messages", what: "What BizForce told you.", owner: ["user_id"], onDelete: "delete" },

  // ── moderation ──
  { table: "moderation_logs", group: "moderation", what: "Moderation actions about your account, or taken by you as an admin.", owner: ["target_user_id", "admin_id"], members: ["target_user_id", "admin_id"],
    onDelete: "keep", why: "it is the only record of who was banned and why" },
  { table: "admin_flags", group: "moderation", what: "Flags an admin put on your account.", owner: ["user_id"], members: ["flagged_by"],
    onDelete: "keep", why: "it is the only record of an admin's flag" }
];

/* Tables that hold no member's data, or none that can be tied to a member. */
const NOT_MEMBER_DATA = {
  bsky_leads:     "public Bluesky posts the radars found; not tied to any member",
  reddit_leads:   "public Reddit posts the radars found; not tied to any member",
  engine_visits:  "a count of arrivals from links; no member and no visitor is named",
  job_runs:       "when each scheduled job last ran",
  ops_alerts:     "open alerts for the owner",
  radar_status:   "each radar's latest run",
  backup_runs:    "the history of the nightly backups",
  businesses:     "an old table with no owner column; nothing in the code writes it",
  tasks:          "an old table keyed to businesses, not to members; nothing in the code writes it",
  pending_storage_deletions: "files of accounts already deleted that Storage has not yet removed; no member id is stored"
};

/* What the export leaves out, and why. Shown on the page and put in the manifest. */
const NEVER_EXPORTED = [
  "Your password: BizForce stores only a bcrypt hash of it, and the hash is not exported.",
  "Sign-in secrets: session tokens, email-confirmation and password-reset tokens, and passkey challenges.",
  "Key material: your passkeys' keys and your browsers' push credentials.",
  "Your AI provider API keys: listed by provider and date only.",
  "Other members' private details: another member appears by username only, or as \"a deleted member\"."
];

const DELETE_NOTES = [
  "Deleting needs your username, typed exactly, and your password. Every account has a password; if you have forgotten it, reset it from the sign-in page first.",
  "It is refused while a paid subscription is active, in a trial or past due. Cancel it first on Billing; then delete.",
  "It cannot be undone. Download your data first if you want a copy.",
  "Every sign-in is ended and the account can never sign in again.",
  "Your email address can be used to open a new account afterwards. The new account starts empty: nothing from this one carries over.",
  "Your username is released, and another member may take it.",
  "Your files are deleted (pictures, audio, video, book and document files you uploaded), except files you sold, which stay available to the members who bought them. If any could not be removed right away, they are removed automatically within a few days."
];

/* Each claim, and the fact checkYourData asserts for it. */
const PROTECTIONS = [
  { key: "transit", text: "Encrypted in transit (HTTPS)." },
  { key: "at_rest", text: "Stored with our database host, Supabase. How the stored database is encrypted on disk is the host's setting, not something BizForce's code does or can show, so this page claims nothing about it." },
  { key: "passwords", text: "Your password is stored only as a bcrypt hash, never as the password itself." },
  { key: "api_keys", text: "AI provider API keys you add are encrypted (AES-256-GCM) before they are stored." },
  { key: "backups", text: "Backups are encrypted (AES-256-GCM) with a key held by the owner, and without that key no backup is made. Sessions, passkey challenges, API keys and push credentials are never put in a backup." },
  { key: "not_e2e", text: "Not end-to-end encrypted: BizForce's servers can read your data so the agents can work with it." },
  { key: "no_sale", text: "We do not sell your data. BizForce's server contains no advertising or third-party analytics code, and no page loads a tracker. Your data is sent only where a feature you use needs it: Supabase (the database), Railway (the server), Netlify (the pages), Anthropic (the AI agents), Stripe (payments), Resend (email), Twilio (text messages), Bluesky and Mastodon (replies sent through outreach), and your browser's push service (notifications you turned on). A web page an agent is asked to read receives only the request for that page." }
];

const ACTION_TEXT = {
  delete: "Deleted.",
  keep: "Kept, because {why}. You are shown as a deleted member.",
  evidence: "Kept as consent evidence, with email addresses and phone numbers replaced by a one-way hash and names removed: {why}.",
  forfeit: "Your balance is forfeited: {why}.",
  tombstone: "Emptied: your email, password, business name, industry, bio, picture, and sign-in tokens and addresses are removed. A record with only its id, dates, role and billing status stays, because {why}.",
  signatures: "Deleted on your own documents. Kept on other members' documents, because {why}.",
  sold: "Deleted, with their files, except a listing another member bought: it is taken off sale and kept, with its file and pictures, because {why}. You are shown as a deleted member."
};

function onDeleteText(entry) {
  if (entry.deleteText) return entry.deleteText;
  return ACTION_TEXT[entry.onDelete].replace("{why}", entry.why || "");
}

/* What GET /api/your-data serves, and everything the page shows. */
function describe() {
  return {
    groups: GROUPS.map(function (g) {
      return {
        key: g.key, title: g.title,
        items: DATA.filter(function (d) { return d.group === g.key; }).map(function (d) {
          return { table: d.table, what: d.what, exported: d.export !== false, onDelete: d.onDelete, onDeleteText: onDeleteText(d) };
        })
      };
    }),
    protections: PROTECTIONS.map(function (p) { return { key: p.key, text: p.text }; }),
    neverExported: NEVER_EXPORTED.slice(),
    deleteNotes: DELETE_NOTES.slice()
  };
}

// ── helpers ──────────────────────────────────────────────────────────────────
const PAGE_SIZE = 1000;
const MAX_PAGES = 500;
const IN_CHUNK = 100;
const HASH_PREFIX = "sha256:";
const DELETED_EMAIL_DOMAIN = "@deleted.invalid";
// Not 60 characters, so bcrypt's compare refuses it before looking at any password.
const DELETED_PASSWORD = "!deleted: this account was deleted; no password matches";
const FORFEIT_DESCRIPTION = "Forfeited on account deletion";

function entryOf(table) {
  for (var i = 0; i < DATA.length; i++) if (DATA[i].table === table) return DATA[i];
  return null;
}
function oneWay(value) {
  if (value === null || value === undefined || value === "") return value;
  var text = String(value);
  if (text.indexOf(HASH_PREFIX) === 0) return text;
  return HASH_PREFIX + crypto.createHash("sha256").update(text.trim().toLowerCase(), "utf8").digest("hex");
}
function chunks(list, size) {
  var out = [];
  for (var i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}
function fail(what, error) {
  var e = new Error(what + ": " + ((error && error.message) || error));
  e.step = what;
  return e;
}

/* Every row of `table` matching `filter`, a page at a time, handed to onPage. */
async function readPaged(supabase, table, cols, key, filter, onPage) {
  for (var page = 0; page < MAX_PAGES; page++) {
    var from = page * PAGE_SIZE;
    var r = await filter(supabase.from(table).select(cols)).order(key, { ascending: true }).range(from, from + PAGE_SIZE - 1);
    if (r.error) throw fail(table + " could not be read", r.error);
    var rows = r.data || [];
    await onPage(rows);
    if (rows.length < PAGE_SIZE) return;
  }
  throw fail(table + " could not be read", "more than " + (MAX_PAGES * PAGE_SIZE) + " rows");
}

/* The ids of the member's rows in `parent`, by its owner column(s). */
async function ownedIds(supabase, userId, parent, cache) {
  if (cache[parent]) return cache[parent];
  var e = entryOf(parent);
  var ids = [];
  for (var i = 0; i < e.owner.length; i++) {
    await readPaged(supabase, parent, e.key || "id", e.key || "id",
      function (q) { return q.eq(e.owner[i], userId); },
      function (rows) { rows.forEach(function (r) { if (ids.indexOf(r[e.key || "id"]) === -1) ids.push(r[e.key || "id"]); }); });
  }
  cache[parent] = ids;
  return ids;
}

/* "@name", "a deleted member", or "a member with no username" for each id. */
async function memberNames(supabase, ids) {
  var names = {};
  var todo = ids.filter(function (id) { return id; });
  for (var c of chunks(todo, IN_CHUNK)) {
    var users = await supabase.from("users").select("id, role").in("id", c);
    if (users.error) throw fail("members could not be named", users.error);
    var profiles = await supabase.from("bf_profiles").select("user_id, username").in("user_id", c);
    if (profiles.error) throw fail("members could not be named", profiles.error);
    var deleted = {};
    (users.data || []).forEach(function (u) { if (u.role === "deleted") deleted[u.id] = true; });
    c.forEach(function (id) { names[id] = deleted[id] ? "a deleted member" : "a member with no username"; });
    (profiles.data || []).forEach(function (p) { if (!deleted[p.user_id] && p.username) names[p.user_id] = "@" + p.username; });
  }
  return names;
}

// ── the export ───────────────────────────────────────────────────────────────
/* Writes one JSON document through write(text), a page at a time, and returns
   its manifest. A table that cannot be read is named in the manifest as
   unreadable; the download says it is incomplete rather than pretending. */
async function exportAccountData(opts) {
  var supabase = opts.supabase, userId = opts.userId, write = opts.write;
  var now = opts.now || new Date();
  var manifest = { format: "bizforce-your-data", version: 1, generated_at: now.toISOString(), tables: [], complete: true,
    not_exported: NEVER_EXPORTED.slice(), not_member_data: Object.keys(NOT_MEMBER_DATA) };
  var cache = {};
  write("{\"format\":\"bizforce-your-data\",\"version\":1,\"generated_at\":" + JSON.stringify(manifest.generated_at) + ",\"tables\":{");
  var firstTable = true;
  for (var i = 0; i < DATA.length; i++) {
    var e = DATA[i];
    if (e.export === false) { manifest.tables.push({ table: e.table, rows: 0, status: "not exported", why: e.exportWhy }); continue; }
    var count = 0, seen = {}, key = e.key || "id";
    write((firstTable ? "" : ",") + JSON.stringify(e.table) + ":[");
    firstTable = false;
    var firstRow = true;
    try {
      var filters = (e.owner || []).map(function (col) { return function (q) { return q.eq(col, userId); }; });
      if (e.via) {
        var parentIds = await ownedIds(supabase, userId, e.via.parent, cache);
        chunks(parentIds, IN_CHUNK).forEach(function (c) { filters.push(function (q) { return q.in(e.via.column, c); }); });
      }
      for (var f = 0; f < filters.length; f++) {
        await readPaged(supabase, e.table, e.select || "*", key, filters[f], async function (rows) {
          rows = rows.filter(function (r) { if (seen[r[key]]) return false; seen[r[key]] = true; return true; });
          var others = [];
          (e.members || []).forEach(function (col) { rows.forEach(function (r) { if (r[col] && r[col] !== userId && others.indexOf(r[col]) === -1) others.push(r[col]); }); });
          var names = others.length ? await memberNames(supabase, others) : {};
          rows.forEach(function (r) {
            var row = Object.assign({}, r);
            (e.members || []).forEach(function (col) {
              if (row[col] === null || row[col] === undefined) return;
              var mine = row[col] === userId;
              if (!mine && e.othersPrivate) e.othersPrivate.forEach(function (p) { delete row[p]; });
              row[col] = mine ? "you" : names[row[col]];
            });
            write((firstRow ? "" : ",") + JSON.stringify(row));
            firstRow = false;
            count++;
          });
        });
      }
      manifest.tables.push({ table: e.table, rows: count, status: "complete" });
    } catch (err) {
      manifest.complete = false;
      manifest.tables.push({ table: e.table, rows: count, status: "unreadable", error: String(err.message || err) });
    }
    write("]");
  }
  write("},\"manifest\":" + JSON.stringify(manifest) + "}");
  return manifest;
}

// ── the delete ───────────────────────────────────────────────────────────────
/* Order matters only where a foreign key would refuse or cascade: children
   before parents. Every "delete" entry in DATA is here exactly once (checked). */
const DELETE_ORDER = [
  "notifications", "chat_messages", "usage_logs", "oracle_messages", "oracle_sync", "inner_iq_results", "birth_records", "user_certifications",
  "executive_dispatches", "testimonial_screen_removals", "social_post_drafts", "email_sequence_enrollments", "email_sequences",
  "agent_proposals", "ai_tasks", "ai_reports", "self_reviews", "saved_prompts", "routines", "automation_queue",
  "ai_agents", "agent_assignments", "agent_autonomy", "agent_schedules", "agent_memory", "agent_collaborations",
  "sms_campaign_enrollments", "sms_campaign_messages", "sms_campaigns",
  "prospects", "crm_activities", "crm_customers", "icp_profiles", "inventory_movements", "inventory_items", "calendar_events",
  "outreach_sends", "sales_lead_pipeline", "business_profiles",
  "content_library", "seo_refused_drafts", "bizbooks", "cover_wraps", "bizdoc_documents", "marketplace_listings", "crowdfunding_campaigns",
  "profile_products", "profile_portfolio", "profile_music", "profile_videos", "bf_music_tracks", "bf_videos", "digital_cards"
];
/* Deleted last, just before the account row is emptied (deleteAccount says why). */
const FINAL_DELETES = ["auth_sessions", "webauthn_credentials", "webauthn_challenges", "push_subscriptions", "user_api_keys",
  "user_preferences", "bf_profiles", "profiles"];
// profiles last: its username is the one deleteAccount asks for, so it stays the same until the email takes its place.

async function deleteOwned(supabase, userId, table, cache) {
  var e = entryOf(table);
  if (e.via) {
    var parentIds = await ownedIds(supabase, userId, e.via.parent, cache);
    for (var c of chunks(parentIds, IN_CHUNK)) {
      var rv = await supabase.from(table).delete().in(e.via.column, c);
      if (rv.error) throw fail(table + " could not be deleted", rv.error);
    }
  }
  for (var i = 0; i < (e.owner || []).length; i++) {
    var r = await supabase.from(table).delete().eq(e.owner[i], userId);
    if (r.error) throw fail(table + " could not be deleted", r.error);
  }
}

/* The member's listings: those another member bought (keep.listings) are
   taken off sale and kept for that buyer; the rest are deleted. */
async function deleteListings(supabase, userId, keep, cache, now) {
  var mine = await ownedIds(supabase, userId, "marketplace_listings", cache);
  var sold = keep.listings || [];
  var unsold = mine.filter(function (id) { return sold.indexOf(id) === -1; });
  for (var c of chunks(unsold, IN_CHUNK)) {
    await must(supabase.from("marketplace_listings").delete().eq("seller_id", userId).in("id", c), "marketplace_listings could not be deleted");
  }
  for (var k of chunks(sold, IN_CHUNK)) {
    await must(supabase.from("marketplace_listings").update({ status: "paused", updated_at: now.toISOString() })
      .eq("seller_id", userId).eq("status", "active").in("id", k), "a sold listing could not be taken off sale");
  }
}

async function must(promise, what) {
  var r = await promise;
  if (r.error) throw fail(what, r.error);
  return r.data;
}

/* Consent evidence: kept, hashed, names removed; what is not evidence is deleted. */
async function keepEvidence(supabase, userId) {
  var contacts = [];
  await readPaged(supabase, "contacts", "id", "id", function (q) { return q.eq("owner_id", userId); },
    function (rows) { rows.forEach(function (r) { contacts.push(r.id); }); });
  var withConsent = [];
  for (var c of chunks(contacts, IN_CHUNK)) {
    await readPaged(supabase, "consent_events", "id, contact_id", "id", function (q) { return q.in("contact_id", c); },
      function (rows) { rows.forEach(function (r) { if (withConsent.indexOf(r.contact_id) === -1) withConsent.push(r.contact_id); }); });
  }
  var dropped = contacts.filter(function (id) { return withConsent.indexOf(id) === -1; });

  // email_sends: a bounce or complaint stays exactly as it is (every member's mail to that address is stopped by it).
  for (var c1 of chunks(contacts, IN_CHUNK)) {
    var sends = [];
    await readPaged(supabase, "email_sends", "id, contact_id, to_email, status", "id", function (q) { return q.in("contact_id", c1); },
      function (rows) { sends = sends.concat(rows); });
    for (var s of sends) {
      var stops = s.status === "bounced" || s.status === "complained";
      if (stops) {
        if (dropped.indexOf(s.contact_id) !== -1) await must(supabase.from("email_sends").update({ contact_id: null }).eq("id", s.id), "email_sends could not be kept");
      } else if (dropped.indexOf(s.contact_id) !== -1) {
        await must(supabase.from("email_sends").delete().eq("id", s.id), "email_sends could not be deleted");
      } else if (s.to_email && String(s.to_email).indexOf(HASH_PREFIX) !== 0) {
        await must(supabase.from("email_sends").update({ to_email: oneWay(s.to_email) }).eq("id", s.id), "email_sends could not be hashed");
      }
    }
  }
  for (var c2 of chunks(dropped, IN_CHUNK)) {
    await must(supabase.from("email_sequence_enrollments").delete().in("contact_id", c2), "email_sequence_enrollments could not be deleted");
    await must(supabase.from("contacts").delete().in("id", c2), "contacts could not be deleted");
  }
  var kept = [];
  for (var c3 of chunks(withConsent, IN_CHUNK)) {
    kept = kept.concat(await must(supabase.from("contacts").select("id, email, phone").in("id", c3), "contacts could not be read"));
  }
  for (var k of kept) {
    await must(supabase.from("contacts").update({ email: oneWay(k.email), phone: oneWay(k.phone), name: null }).eq("id", k.id), "contacts could not be hashed");
  }

  var captures = [];
  await readPaged(supabase, "lead_captures", "id, email, phone, sms_consent, email_consent", "id", function (q) { return q.eq("owner_id", userId); },
    function (rows) { captures = captures.concat(rows); });
  for (var lc of captures) {
    if (lc.sms_consent === true || lc.email_consent === true) {
      await must(supabase.from("lead_captures").update({ email: oneWay(lc.email), phone: oneWay(lc.phone), name: null }).eq("id", lc.id), "lead_captures could not be hashed");
    } else {
      await must(supabase.from("lead_captures").delete().eq("id", lc.id), "lead_captures could not be deleted");
    }
  }
  var subs = [];
  await readPaged(supabase, "sms_subscribers", "id, phone_number", "id", function (q) { return q.eq("user_id", userId); },
    function (rows) { subs = subs.concat(rows); });
  for (var sb of subs) {
    await must(supabase.from("sms_subscribers").update({ phone_number: oneWay(sb.phone_number), customer_name: null, product_purchased: null }).eq("id", sb.id), "sms_subscribers could not be hashed");
  }
  var texts = [];
  await readPaged(supabase, "sms_send_log", "id, phone_number", "id", function (q) { return q.eq("user_id", userId); },
    function (rows) { texts = texts.concat(rows); });
  for (var t of texts) {
    if (t.phone_number && String(t.phone_number).indexOf(HASH_PREFIX) !== 0) {
      await must(supabase.from("sms_send_log").update({ phone_number: oneWay(t.phone_number) }).eq("id", t.id), "sms_send_log could not be hashed");
    }
  }
  return { contactsKept: kept.length, contactsDeleted: dropped.length };
}

/* Signatures on the member's own documents go with them; signatures they made on others' stay. */
async function deleteOwnDocumentSignatures(supabase, userId, cache) {
  var docs = await ownedIds(supabase, userId, "bizdoc_documents", cache);
  for (var c of chunks(docs, IN_CHUNK)) {
    await must(supabase.from("bizdoc_signatures").delete().in("document_id", c), "bizdoc_signatures could not be deleted");
  }
}

async function forfeitWallet(supabase, userId) {
  var wallet = await must(supabase.from("user_wallets").select("balance").eq("user_id", userId).maybeSingle(), "the wallet could not be read");
  var balance = wallet ? Number(wallet.balance) || 0 : 0;
  if (balance <= 0) return 0;
  var r = await supabase.rpc("bfc_debit", { p_user_id: userId, p_amount: balance, p_description: FORFEIT_DESCRIPTION });
  if (r.error) throw fail("the BizCash balance could not be forfeited", r.error);
  return balance;
}

/* The username the member must type: their account username, else their profile page's. */
async function usernameOf(supabase, userId) {
  var p = await must(supabase.from("profiles").select("username").eq("user_id", userId).maybeSingle(), "your username could not be read");
  if (p && p.username) return p.username;
  var b = await must(supabase.from("bf_profiles").select("username").eq("user_id", userId).maybeSingle(), "your username could not be read");
  return b && b.username ? b.username : null;
}

/* opts: { supabase, storage, publicUrlBase, userId, body: { username, password }, comparePassword(plain, hash),
           activeSubscriptions(userId), ownerAccountId, now }
   Returns { status, body }, and on success `unqueued`: the files that could
   be neither removed nor queued, for the route to log and alert. */
async function deleteAccount(opts) {
  var supabase = opts.supabase, userId = opts.userId, body = opts.body || {};
  var user;
  try {
    user = await must(supabase.from("users").select("id, email, role, password_hash").eq("id", userId).maybeSingle(), "your account could not be read");
  } catch (err) {
    return { status: 503, body: { error: "Your account could not be read just now, so nothing was deleted. Try again in a minute.", reason: "unreadable" } };
  }
  if (!user || user.role === "deleted") return { status: 404, body: { error: "This account no longer exists.", reason: "already_deleted" } };
  if (user.role === "admin" || user.id === opts.ownerAccountId) {
    return { status: 403, body: { error: "An admin account cannot be deleted here. Nothing was deleted.", reason: "admin_account" } };
  }

  var expected;
  try { expected = await usernameOf(supabase, userId); } catch (err) {
    return { status: 503, body: { error: "Your username could not be read just now, so nothing was deleted. Try again in a minute.", reason: "unreadable" } };
  }
  var typed = typeof body.username === "string" ? body.username : "";
  var confirmWith = expected || user.email;
  if (typed !== confirmWith) {
    return { status: 400, body: { error: expected
      ? "Type your username exactly as it is, " + expected + ", to confirm. Nothing was deleted."
      : "Your account has no username, so type your email address exactly to confirm. Nothing was deleted.", reason: "username_mismatch" } };
  }
  var password = typeof body.password === "string" ? body.password : "";
  var passwordOk = false;
  try { passwordOk = !!password && await opts.comparePassword(password, user.password_hash); } catch (err) { passwordOk = false; }
  if (!passwordOk) return { status: 403, body: { error: "That password is not right. Nothing was deleted.", reason: "password_incorrect" } };

  var held;
  try { held = await opts.activeSubscriptions(userId); } catch (err) {
    return { status: 503, body: { error: "Your subscription could not be checked just now, so nothing was deleted. Try again in a minute.", reason: "subscription_unreadable" } };
  }
  var paying = (held || []).filter(function (s) { return ["active", "trialing", "past_due"].indexOf(s.status) !== -1; });
  if (paying.length) {
    return { status: 409, body: { error: "Your subscription is still " + paying[0].status.replace("_", " ") + ". Cancel it first on Billing (Manage / Cancel Subscription), so you cannot be charged after the account is gone; then delete. Nothing was deleted.",
      reason: "subscription_active", billing_url: "/billing.html" } };
  }

  /* THE FILES, read before anything is deleted, while the rows that record
     them still exist. A list that might be missing files is never used, so a
     failure here deletes nothing. */
  var files, keep;
  try {
    if (!opts.storage) throw new Error("no storage client");
    keep = await accountFiles.keptForBuyers({ supabase: supabase, userId: userId, publicUrlBase: opts.publicUrlBase });
    files = accountFiles.toRemove(await accountFiles.filesOwnedBy({ supabase: supabase, storage: opts.storage, userId: userId, publicUrlBase: opts.publicUrlBase }), keep);
  } catch (err) {
    return { status: 503, body: { error: "Your files could not be listed just now, so nothing was deleted. Try again in a minute.", reason: "files_unreadable" } };
  }

  var done = [];
  var cache = {};
  var now = opts.now || new Date();
  try {
    var forfeited = await forfeitWallet(supabase, userId);
    done.push("BizCash forfeited: " + forfeited);
    await deleteOwnDocumentSignatures(supabase, userId, cache);
    for (var i = 0; i < DELETE_ORDER.length; i++) {
      if (entryOf(DELETE_ORDER[i]).onDelete === "sold") await deleteListings(supabase, userId, keep, cache, now);
      else await deleteOwned(supabase, userId, DELETE_ORDER[i], cache);
      done.push(DELETE_ORDER[i]);
    }
    var ev = await keepEvidence(supabase, userId);
    done.push("consent evidence: " + ev.contactsKept + " contact(s) kept hashed, " + ev.contactsDeleted + " deleted");
  } catch (err) {
    return { status: 500, body: { error: "Deleting stopped part-way: " + (err.message || err) + ". You are still signed in, and what is not deleted yet is still there. Press Delete again to finish.",
      reason: "incomplete", done: done, failed: err.step || String(err.message || err) } };
  }
  /* LAST, sign-in itself. The sessions and passkeys go first and the account
     row is emptied after them, so at every point a failure leaves either a
     member who is still signed in, or one who can sign in with their password
     and press Delete again. Never an account that is half gone and locked. */
  try {
    for (var j = 0; j < FINAL_DELETES.length; j++) {
      await deleteOwned(supabase, userId, FINAL_DELETES[j], cache);
      done.push(FINAL_DELETES[j]);
    }
    var emptied = null;
    for (var attempt = 0; attempt < 2 && !(emptied && !emptied.error); attempt++) {
      emptied = await supabase.from("users").update({
        email: "deleted-" + userId + DELETED_EMAIL_DOMAIN, password_hash: DELETED_PASSWORD, role: "deleted",
        business_name: null, industry: null, bio: null, avatar_url: null, signup_ip: null, last_login_ip: null,
        email_verification_token: null, email_verification_expires_at: null, password_reset_token: null, password_reset_expires_at: null,
        email_verified_at: null, updated_at: now.toISOString()
      }).eq("id", userId);
    }
    if (emptied.error) throw fail("your account could not be emptied", emptied.error);
    done.push("users emptied");
  } catch (err) {
    var signedOut = done.indexOf("auth_sessions") !== -1;
    return { status: 500, body: { error: "Deleting stopped near the end: " + (err.message || err) + ". " +
      (signedOut ? "You have been signed out. Sign in again with your email and password, and press Delete again to finish."
                 : "You are still signed in. Press Delete again to finish.") +
      (done.indexOf("bf_profiles") !== -1 ? " If your username is already removed, the confirmation asks for your email address instead, and says so." : ""),
      reason: signedOut ? "incomplete_signed_out" : "incomplete", done: done, failed: err.step || String(err.message || err) } };
  }
  /* THE FILES GO LAST, once every row is gone. Storage refusing a batch never
     undoes the delete: those files are queued and the daily retry removes them. */
  var removed = await accountFiles.removeFiles({ supabase: supabase, storage: opts.storage, files: files, now: now });
  done.push("files: " + removed.deleted + " deleted, " + removed.queued + " queued, " + keep.files.length + " kept for buyers" +
    (removed.not_queued ? ", " + removed.not_queued + " NOT QUEUED" : ""));
  var unqueued = removed.failures.filter(function (f) { return f.queue_error; });
  return { status: 200, body: { deleted: true, done: done,
    files: { deleted: removed.deleted, queued: removed.queued, kept_for_buyers: keep.files.length, not_queued: removed.not_queued } },
    unqueued: unqueued };
}

module.exports = { GROUPS, DATA, NOT_MEMBER_DATA, NEVER_EXPORTED, DELETE_NOTES, PROTECTIONS, DELETE_ORDER, FINAL_DELETES,
  DELETED_PASSWORD, DELETED_EMAIL_DOMAIN, FORFEIT_DESCRIPTION, describe, onDeleteText, oneWay, exportAccountData, deleteAccount };
