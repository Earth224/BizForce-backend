"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE APPROVED DESIGN (FX1, Nov 20 2026): the owner's two phone pictures,
   Downloads\design\feed.png (Home feed) and Downloads\design\profile.png
   (Profile), each 390 x 844. Every figure here was measured from those
   pictures (pixel scans), and the live phone layout (max-width 760px) is
   held to them:
     scripts/checkDesignFidelity.js   the constants in the frontend's CSS and markup
     scripts/browserCheckPhone.js     PHONE_P23: measured boxes in a real browser,
                                      within TOLERANCE px
   A later block that touches these screens reads its figures from here.

   THE BAR AND THE SAFE AREA. The pictured phone has a 28 px home indicator,
   so its bottom bar is 84 px (BAR.HEIGHT 56 + PICTURED_SAFE_AREA 28) and
   starts at y 760. A browser without a safe area draws the same bar 56 px
   tall, starting at y 788. The feed's overlays are placed above the bar, so
   they are given here as distances above the bar's top edge; on the pictured
   phone they land exactly where the picture has them.

   KEPT from the site, never the pictures': the fonts and the music icon.
   Built in later blocks, their places kept now: the Local, Market and For
   You tabs, Live and Search (each opens a Coming soon sheet), Tip BFC (its
   rail slot is kept, invisible, so nothing moves when it arrives), the Buy
   strip (only on a post that carries a listing) and the Reviews tab (Coming
   soon).

   NAMED (Nov 21 2026, FX2): THE SECOND PASS. The owner's updated pictures are
   in Downloads at 2x ("Home the feed@2x.png", "A Need post in the feed@2x.png",
   "New post Share, Offer or Need@2x.png", "Profile with an optional
   banner@2x.png"; halved for these figures), and FX2's brief states the
   figures that changed:
     the rail's bottom 16 px above the bar's top (100 above the pictured
       phone's bottom), level with the bottom-left block; BEFORE 126;
     Tip BFC built: shown, gold, for a paid member; for a free viewer the
       slot stays as it was (unseen, so nothing moves);
     the product strip built: on every post that carries an active linked
       listing, one link that opens it;
     every feed tab on one line ("For You" never wraps);
     the Profile's top row 12 px below the safe area, the safe area counted
       once (css/bf-phone.css pads the page by it already); its ring at
       135 degrees; the optional banner (PROFILE.BANNER);
     the Agent Directory's three views (AGENTS), the Oracle's Sun (HQ.SUN)
       and the orbit's first settle (ORBIT).

   NAMED (Nov 22 2026, FX3): THE OWNER'S CANVAS, ROW 5 (four boards, 390 x 844):
   "HQ: the abyss sun" (TmxHQ), "The Guide open" (TmxGuideOpen), "The chat on
   a page" (TmxChatGuide) and "The chat with ORACLE open" (TmxChatOracle). Their
   figures are TMX below. BEFORE HQ.SUN (the NASA photograph); AFTER HQ.ABYSS.
   ══════════════════════════════════════════════════════════════════════════ */

const TOLERANCE = 2;
const SCREEN = { W: 390, H: 844 };
const PICTURED_SAFE_AREA = 28;

const COLOR = {
  ACCENT: "#22d3ee",        // cyan: the active underline, the Market dot, the follow badge, Buy, the storefront link
  VIOLET: "#8b5cf6",        // the gradient's second stop, the Inbox badge
  GOLD: "#f5c46b",          // Tip BFC, the BizCash count, the wallet button's mark
  TEXT: "#e6eaf5",          // names, captions, numbers
  MUTED: "#a9b3cc",         // handles, labels, inactive profile tabs, the bar's inactive items
  TAB_INACTIVE: "#c9d1e6",  // the feed's inactive tabs
  BIO: "#c9d1e6",
  WHITE: "#ffffff"
};

const FEED = {
  TOP: {
    ROW_TOP: 12,            // the overlay row's top, below the safe area
    BUTTON: 44,             // Live (left) and Search (right)
    LIVE_LEFT: 9,           // Live's left edge
    SEARCH_RIGHT: 2,        // Search's right edge, from the screen's
    TABS: ["Local", "Following", "Market", "For You"],
    TAB_NOWRAP: true,       // NAMED (Nov 21 2026, FX2): each tab on one line
    TAB_FONT: 16,
    TAB_WEIGHT: 600,
    TAB_HEIGHT: 44,
    TAB_PAD_X: 10,
    UNDERLINE: 3,           // under the active tab's text, at its bottom edge
    UNDERLINE_INSET: 8,     // from the tab's sides
    DOT: 7,                 // the Market dot
    DOT_TOP: 8              // from the tab's top
  },
  RAIL: {
    RIGHT: 10,              // from the screen's right edge
    WIDTH: 60,
    BOTTOM_ABOVE_BAR: 16,   // NAMED (Nov 21 2026, FX2): BEFORE 126 (210 above the pictured phone's bottom). AFTER 16: 100 above it, level with META
    GAP: 18,
    ORDER: ["avatar", "like", "talk", "tip", "save", "share"],
    AVATAR: 52,
    BADGE: 22,              // the follow "+", centred on the avatar's bottom edge
    ICON: 30,
    ICON_LABEL_GAP: 4,
    LABEL_FONT: 12,
    LABEL_LINE: 16,
    ITEM: 50                // ICON + ICON_LABEL_GAP + LABEL_LINE
  },
  META: {
    LEFT: 14,
    RIGHT: 80,              // the block's right edge, from the screen's
    BOTTOM_ABOVE_BAR: 16,   // 100 above the pictured phone's bottom
    GAP: 8,
    NAME_FONT: 17,
    NAME_WEIGHT: 800,
    CAPTION_FONT: 15,
    CAPTION_LINE: 1.4
  },
  // NAMED (Nov 21 2026, FX2): BEFORE "(a later block)". AFTER built: lib/posts.js sends an active linked listing as post.listing, and the
  // strip is one link to it (LINK); a post without one, or whose listing is no longer active, shows none.
  TIP: { MEMBER_ONLY: true },
  STRIP: {                  // the product strip: only on a post that carries an active listing
    LINK: "/listing/",      // + the listing's slug (or its id)
    RADIUS: 14,
    BORDER: "#2b3a6b",
    PAD: 8,
    TILE: 40,
    TITLE_FONT: 13,
    PRICE_FONT: 12,
    BUY_HEIGHT: 34,
    BUY_RADIUS: 17,
    BUY_WIDTH: 52
  }
};

const BAR = {
  HEIGHT: 56,               // + the safe area
  PLUS_W: 52,
  PLUS_H: 34,
  PLUS_RADIUS: 11,
  BG: "#070b18",
  BORDER: "#1e2848",
  FEED_BG: "#05070f",       // on the full-screen feed the bar is darker,
  FEED_BORDER: "#141b33",   // and the active item (Home) is white
  ITEMS: ["Home", "HQ", "Create", "Inbox", "Profile"]
};

const PROFILE = {
  TOP: {
    ROW_TOP: 12,
    BUTTON: 44,             // add friends (left), the menu (right)
    PAD_X: 12,
    NAME_FONT: 17,
    NAME_WEIGHT: 800
  },
  AVATAR: {
    TOP: 66,                // 10 below the top row
    SIZE: 92,
    RING: 3,
    RING_ANGLE: 135,        // NAMED (Nov 21 2026, FX2): BEFORE 180 (top to bottom). AFTER teal at the top left to purple at the bottom right
    INNER: "#121a36",
    INITIALS_FONT: 28
  },
  // NAMED (Nov 21 2026, FX2): the optional banner ("Profile with an optional banner"): from the screen's top (the safe area too) to the
  // picture's bottom edge (AVATAR.TOP + AVATAR.SIZE), cover-cropped, opaque to FADE_FROM of its height and gone at its bottom; a shade
  // SHADE px tall at its top keeps the top row readable. None by default.
  BANNER: { BOTTOM: 158, FADE_FROM: 0.5, SHADE: 72 },
  HANDLE: { FONT: 15, LINE: 20, GAP: 8 },
  STATS: {
    ORDER: ["following", "followers", "sales", "bizcash"],
    LABELS: ["Following", "Followers", "Sales", "BizCash"],
    PAD_X: 16,
    NUM_FONT: 18,
    NUM_LINE: 22,
    LABEL_FONT: 12,
    LABEL_LINE: 16,
    GAP: 13
  },
  BUTTONS: {
    TOP: 253,
    HEIGHT: 44,
    RADIUS: 12,
    FILL: "#1a2244",
    FONT: 14,
    WEIGHT: 600,
    GAP: 8,
    PAD_X: 16,
    WALLET: 44,
    WALLET_BG: "#2a2410"
  },
  BIO: { FONT: 14, LINE: 20, GAP: 9 },
  STORE: { HEIGHT: 44, FONT: 14, GAP: 3 },
  TABS: {
    TOP: 373,               // with a one-line bio
    ORDER: ["Posts", "Shop", "Services", "Reviews"],
    HEIGHT: 44,
    UNDERLINE: 2,
    DIVIDER: 1,
    DIVIDER_COLOR: "#1e2848"
  },
  GRID: {
    TOP: 420,               // with a one-line bio
    COLUMNS: 3,
    GAP: 2,
    INSET: 2,
    ASPECT: 4 / 3,          // height over width
    LABEL_FONT: 11
  }
};

// NAMED (Nov 21 2026, FX2): the Agent Directory (ai-agents.html) on a phone
const AGENTS = {
  VIEWS: ["large", "compact", "grid"],
  DEFAULT: "compact",
  BUTTON: 44,               // each view button
  ROW: 60,                  // a Compact row: the icon tile, the name, one line, the chevron
  TILE: 40,                 // the icon tile
  GRID_COLUMNS: 2,
  KEY: "bf_agents_view"     // the device copy; the member's choice is user_preferences.agents_card_view
};
// NAMED (Nov 21 2026, FX2): the HQ orbit's centre while ORACLE is open, and its first settle
// NAMED (Nov 22 2026, FX3): BEFORE HQ = { SUN: { FILE: "brand/sun-sdo-hmi-20261121.webp", MAX_BYTES: 120 * 1024, SHIMMER_S: 16 } }.
// AFTER the abyss sun (board TmxHQ): the disc is the orbit's centre (the Sun's size, unchanged), the chat box's void inside the gold ring.
const HQ = { ABYSS: {
  VOID_BASE: "rgba(2,1,10,0.98)",                                  // under the four gradients, as #tmx-chat
  VOID_SIZES: "200% 200%, 200% 200%, 200% 200%, 240% 240%",
  VOID_ANIMATION: "tmx-chat-void 22s ease-in-out infinite",
  STAR_BASE: { W: 288, H: 340, COUNTS: [70, 35, 16] },             // the chat box's starfield, per its own area
  BOARD_RING: 104,                                                 // the board's 104 px: the gold ring's outer box at 390 px (the disc inside it is
                                                                   // the centre's circle, the Sun's size, 98 px at 390)
  BOARD_COUNTS: [8, 4, 2],                                         // a 104 px box at the chat's density (the formula's worked example)
  RING: "gold",                                                    // the moon ring stays gold
  NO_GREEN_RING: [".orbit-core-halo", ".orbit-core-arc", ".orbit-goal-arc"]
} };
// NAMED (Nov 22 2026, FX3): Termaximus on the phone (760 px and below), the boards TmxGuideOpen, TmxChatGuide and TmxChatOracle
const TMX = {
  BOARDS: ["TmxHQ", "TmxGuideOpen", "TmxChatGuide", "TmxChatOracle"],
  MIST: { SIZE: 56, DESK_SIZE: 110, RIGHT: 16, ABOVE_BAR: 16, LABEL: "Ask Termaximus", Z: 46 },   // the board: right 16, bottom 100 (84 bar + 16)
  GUIDE: { TAB_W: 32, TAB_MIN_H: 170, TAB_PAD: "14px 0", TAB_RADIUS: "0 14px 14px 0", TAB_BG: "rgba(12, 18, 38, 0.78)", TAB_BLUR: 14,
    PANEL_W: 300, PANEL_EDGE: 48, PANEL_MAX_VH: 70, PANEL_RADIUS: "0 20px 20px 0", PANEL_BG: "rgba(12, 18, 38, 0.9)", PANEL_BLUR: 18, SLIDE_S: 0.3 },
  CHAT: { SIDE: 8, ABOVE_MIST: 10, HEIGHT: 420, TOP_GAP: 16 },   // the board: right 8, bottom 166 (100 + 56 + 10), 374 x 420
  STILL_FADE_S: 0.2                                              // under reduced motion every open and close is this fade
};
const ORBIT = { SETTLE_MS: 1300, SETTLE_MIN_MS: 1000, SETTLE_MAX_MS: 1500 };

/* NAMED (Nov 23 2026, P3-3): THE OWNER'S CANVAS, ROW 4: "New post: Share, Offer or Need" (Composer) and "A Need post in the feed"
   (NeedPost), Downloads at 2x, halved here; measured by pixel scans (runs, bounding boxes, corner fits). Positions are at
   390 x 844 with no safe area. KEPT, and named in the report as deviations from the pictures:
     COMPOSER.WHEN: the board's When control runs off the screen's edge ("Any" cut by it); here it fits inside the 16 px
       margins and Where takes the rest of the row (FIT: true);
     COMPOSER: every tap target is 44 px (the site's rule): the 40 px chips and Post pill and the 38 px segment pills are
       drawn inside 44 px labels and buttons, at the board's sizes;
     NEEDPOST: the board draws the rail before FX2 (126 px above the bar, no Tip slot) and "For You" on two lines; FX2's rail
       and its one-line tabs are kept (FEED.RAIL, FEED.TOP);
     NEEDPOST: "[reference photo, if they add one]" is the board's note, not drawn: a Need with a photo shows it as any post. */
const COMPOSER = {
  BOARD: "Composer",
  HEADER: { HEIGHT: 64, DIVIDER: "#1e2848", X_ICON: 12, X_CENTRE: 34, TITLE: "New post", TITLE_FONT: 17, TITLE_WEIGHT: 800,
    POST: { W: 71, H: 40, RADIUS: 20, RIGHT: 12, FONT: 16, HIT: 44 } },
  SIDE: 16,                       // the content's margins
  SECTION_GAP: 16,                // between the sections
  LABEL: { FONT: 13, LINE: 16, WEIGHT: 700, SPACING: 1.5, COLOR: "#a9b3cc", GAP: 8, FIRST_TOP: 81 },
  TILES: { TOP: 104, H: 64, W: 110, GAP: 12, RADIUS: 10, BORDER: 1.5, FILL: "#0e1428", LINE: "#2b3a6b", ON_FILL: "#0f2a3a", ON_LINE: "#22d3ee",
    TITLE_FONT: 16, SUB_FONT: 13, TITLE: "#c9d1e6", SUB: "#a9b3cc", ON_SUB: "#9ee6f2",
    ITEMS: [["share", "Share", "Show your work"], ["offer", "Offer", "Sell or book"], ["need", "Need", "Ask for help"]],
    MEMBERS_TAG: "Members" },
  LABELS: { share: "What do you want to say?", offer: "What are you offering?", need: "What do you need?" },
  NEED_HINT: "Example: Looking for a tattoo artist for a forearm piece, black and grey, this month.",
  TEXT: { TOP: 207.5, H: 108, RADIUS: 12, FILL: "#0b1022", LINE: "#2b3a6b", FONT: 16, LINE_H: 20, PAD: 13, MAX: 2200, COUNT_FONT: 13 },
  CHIPS: { TOP: 377, H: 40, RADIUS: 20, GAP: 8, PAD: 15, FONT: 14, FILL: "#0e1428", LINE: "#2b3a6b", TEXT: "#c9d1e6", ON_FILL: "#0f2a3a", ON_LINE: "#22d3ee",
    NOTE: "The same list as the Market. Swipe for more." },
  WHERE: { H: 44, RADIUS: 12, FILL: "#0b1022", LINE: "#2b3a6b", MAX: 80 },
  WHEN: { GAP: 11, PILL_H: 38, PILL_RADIUS: 9, FILL: "#0e1428", LINE: "#1e2848", ON: "#22d3ee", ITEMS: ["Today", "Week", "Any"], FIT: true },
  PHOTOS: { TOP: 562, SLOT: 78, GAP: 8, RADIUS: 10, COUNT: 4, DASH: "#2b3a6b", FILL: "#0b1022" },
  BOX: { H: 62, RADIUS: 14, FILL: "#0e1428", LINE: "#1e2848", ICON: 17, TEXT_LEFT: 62, FONT: 15,
    TEXT: "Members who offer this nearby will be told about your post." },
  AUDIENCE: { H: 44, PILL_H: 38, FILL: "#0e1428", LINE: "#1e2848", ON_FILL: "#1a2244", ITEMS: ["Public", "Followers"] }
};
const NEEDPOST = {
  BOARD: "NeedPost",
  TAG: { W: 56, H: 24, RADIUS: 12, FONT: 12, FILL: "#22d3ee", TEXT: "#070b18", WORD: "NEED", FOUND: "FOUND" },
  META: { GAP: 8, FONT: 14, LINE: 16, COLOR: "#c9d1e6", SEP: " \u00b7 ", WHEN: { today: "Today", week: "This week" } },
  STRIP: { H: 80, RADIUS: 14, LINE: "#2b3a6b", PAD: 8, ICON: 40, ICON_FILL: "#0f2a3a", TARGET: 15, TITLE_FONT: 13, SUB_FONT: 12,
    BUTTON_H: 34, BUTTON_W: 89, BUTTON_RADIUS: 17, BUTTON_FONT: 14,
    TITLE: "You offer this nearby", SUB: "Reply privately with your work", BUTTON: "I can help" },
  BACKDROP: { GLOW: "#123a4a", GLOW_AT: "77% 28%", TOP: "#0b1230", BOTTOM: "#070b1b" },
  SHARE_CATEGORY_FONT: 13
};

/* NAMED (Nov 23 2026, LR-2): THE OWNER'S CANVAS, ROW 6 ("Lead Radar for every member"): LeadsHome, LeadsReply and LeadsFingerprint,
   390 x 844, measured from the boards' own sources (their .dc.html CSS and inline styles, so every figure is exact). The page is
   agents/lead-radar.html. KEPT, and named in the report as deviations from the boards:
     the site's fonts (FONT), never the boards' Space Grotesk or Inter; the music icon (the boombox beside the logo on a desktop,
       docked at the bottom on a phone, as on every page);
     only the Leads and Fingerprint tabs (TABS.ITEMS; Inbound is LR-3, Get found LR-4); the bottom bar is the site's (BAR);
     every tap target is 44 px (the site's rule, HIT): the 40 px tabs, 34 px chips, 38 px buttons and 26 px switches are drawn at
       the boards' sizes inside 44 px buttons, with negative margins so the layout keeps the boards' spacing;
     the draft box's type is 16 px on a phone (css/bf-phone.css: no field under 16 px, so iOS never zooms into it), 15 px above;
     the source chips swipe (overflow-x auto) where the board clips them (overflow hidden), so a Threads chip is never cut;
     the sheet sits under the site's bar (z-index below 90), as the board draws its bar over the sheet.
   NAMED (Nov 24 2026, LR-3): + LeadsInbound ("Inbound: everything coming to you"), measured from its .dc.html (INBOUND). The tabs
   are now Leads, Inbound and Fingerprint (Get found is LR-4). KEPT, and named in the report as deviations from that board:
     the board draws five kinds; tip (the site's own coin, gold on #2a2410) and lead_reply (a reply arrow, violet on #1b2350)
       are not drawn, so they take the nearest drawn kind's colours;
     the board draws the NEW and WON pills; TALKING (#b79cfa on #070b18) and LOST (#c9d1e6 on #2b3a6b) are not drawn;
     the pill is a 44 px button (HIT) that opens the small menu (Talking, Won, Lost, Back to New), which the board does not draw;
     a won item carries "Add to my customers" under it (not drawn).
   NAMED (Nov 25 2026, LR-4): + LeadsFound ("Get found: your Found score"), measured from its .dc.html (FOUND). The tabs are now all
   four the board draws: Leads, Inbound, Get found, Fingerprint. KEPT, and named in the report as deviations from that board:
     the tab row swipes (overflow-x auto) where the board clips it (overflow hidden), so no tab is cut at 360 px (TABS.SWIPE);
     the gold items come first (the brief: "the order shows gold items first"), then the done ones, then the waiting row; the
       board draws "Add" first, two done items, then "Fix";
     the 34 px buttons are drawn inside 44 px targets (HIT), and a done profile row is a link to the page (min 44 px);
     the ring's figure is in the site's font, never Space Grotesk; the Posts Fix asks first (a card under the row, not drawn);
     the sixth item, "Fingerprint complete", is below the board's fold (not drawn), and is built in the same row style. */
const LEADS = {
  BOARDS: ["LeadsHome", "LeadsReply", "LeadsFingerprint", "LeadsInbound", "LeadsFound"],
  FONT: 'system-ui, -apple-system, "Segoe UI", Arial, sans-serif',
  PAGE: { BG: "#070b18", TEXT: "#e6eaf5" },
  HIT: 44,
  HEADER: { PAD: "12px 8px 4px", GAP: 6, BUTTON: 44, MARK: 34, MARK_RADIUS: 10, MARK_BG: "#0f2a3a", TITLE: "Lead Radar", TITLE_FONT: 18, TITLE_WEIGHT: 700,
    SETTINGS: "Radar settings" },
  TABS: { ITEMS: ["Leads", "Inbound", "Get found", "Fingerprint"], NOT_DRAWN: [], SWIPE: true, PAD: "0 12px 10px", GAP: 4, H: 40, PAD_X: 14, RADIUS: 20, FONT: 14, WEIGHT: 600,
    COLOR: "#a9b3cc", ON_BG: "#0f2a3a" },
  CONTENT: { PAD_X: 12, GAP: 10 },
  CARD: { RADIUS: 16, BORDER: "#1e2848", BG: "#0b1022", PAD: 12, GAP: 8 },
  STATS: { GAP: 8, PAD: 10, NUM_FONT: 20, NUM_WEIGHT: 700, LABEL_FONT: 12, LABELS: ["new this week", "you replied", "won"], WON: "#f5c46b" },
  CHIP: { H: 34, PAD_X: 12, RADIUS: 17, BORDER: "#2b3a6b", BG: "#0e1428", COLOR: "#c9d1e6", FONT: 12.5, WEIGHT: 500, GAP: 8, ON_BG: "#0f2a3a",
    SOURCES: ["All", "Inside BizForce", "Bluesky", "YouTube"] },
  BADGE: { H: 22, PAD_X: 8, RADIUS: 11, FONT: 10.5, WEIGHT: 700, SPACING: 1,
    NEED: { TEXT: "BIZFORCE NEED", BG: "#22d3ee", COLOR: "#070b18" },
    BSKY: { TEXT: "BLUESKY · ASKED THE ROOM", BG: "#1b2350", COLOR: "#b79cfa" },
    YT: { TEXT: "YOUTUBE COMMENT", BG: "#3a1414", COLOR: "#fca5a5", CARD_OPACITY: 0.8 } },
  LEAD: { META_FONT: 12, TEXT_FONT: 14.5, TEXT_LINE: 1.4, MATCH_FONT: 12, MATCH: "#6ee7b7" },
  BUTTON: { H: 38, PAD_X: 14, RADIUS: 19, BORDER: "#2b3a6b", COLOR: "#c9d1e6", FONT: 13, WEIGHT: 600, GAP: 10, PRIMARY_TEXT: "#070b18",
    NEED: ["I can help", "Save", "Not a fit"], BSKY: ["Draft a reply", "Open post", "Not a fit"] },
  FOOT: { TEXT: "You approve every reply. BizForce never messages anyone for you.", FONT: 12, COLOR: "#8e9bbf", LINE: 1.4, PAD_X: 10 },
  LABEL: { FONT: 11, WEIGHT: 600, SPACING: 1.6, COLOR: "#8e9bbf" },
  SWITCH: { W: 44, H: 26, RADIUS: 13, KNOB: 20, INSET: 3, ON: "#22d3ee", OFF: "#2b3a6b", KNOB_ON: "#070b18", KNOB_OFF: "#a9b3cc" },
  SHEET: { VEIL: "rgba(3,5,12,0.66)", H: 640, RADIUS: 22, BG: "#0b1022", TOP_LINE: "#2b3a6b", PAD: "10px 16px 20px", GAP: 12, UNDER_BAR: 90,
    GRAB: { W: 40, H: 4, RADIUS: 2, COLOR: "#2b3a6b" }, TITLE: "Your reply on Bluesky", TITLE_FONT: 17, CLOSE: 44,
    QUOTE: { LINE: 3, COLOR: "#8b5cf6", PAD: "6px 10px", FONT: 13.5, LINE_H: 1.4, TEXT: "#c9d1e6" },
    DRAFT_LABEL: "DRAFT (EDIT ANYTHING)",
    DRAFT: { MIN_H: 132, PAD: 12, RADIUS: 14, LINE: "#22d3ee", BG: "#070b18", FONT: 15, LINE_H: 1.45, PHONE_FONT: 16 },
    CHECKS: ["Answers what they asked", "No hard sell, no promises", "They asked the room, so a reply is welcome"], CHECK_GAP: 6, CHECK_FONT: 13, TICK: "#6ee7b7",
    LINK: "Add a link to my listing", LINK_FONT: 13.5, LINK_PAD: "8px 0",
    AGAIN: "Write it again", POST: "Post my reply", BIG_H: 48, BIG_RADIUS: 24, POST_FLEX: 1.4,
    FOOT: "Posted from your own connected Bluesky account. One reply per post, up to 5 a day.",
    CONNECT: "Connect your Bluesky account to reply" },
  FINGERPRINT: { PAD_X: 16, GAP: 12,
    INTRO: "Built for you from your profile, listings and posts. It updates by itself. Change anything.", INTRO_FONT: 13, INTRO_LINE: 1.45, INTRO_COLOR: "#c9d1e6",
    LABELS: ["WHAT YOU DO", "WHERE", "WORDS PEOPLE USE", "NOT FOR ME", "WHERE TO LOOK"], REACH: ["My city", "25 miles", "Online, anywhere"], ADD: "+ Add",
    LOOK: { PAD: "8px 0", TITLE_FONT: 13.5, TITLE_WEIGHT: 600, SUB_FONT: 12,
      ROWS: [["Inside BizForce", "Needs posted by people near you"], ["Bluesky", "Public posts that ask the room"], ["YouTube", "Comments asking for help, limited each day"]],
      THREADS_WAITING: "Waiting for Meta's approval" } },
  INBOUND: {
    PIPE: { PAD: "10px 12px", GAP: 8, LABEL: "YOUR PIPELINE", BAR_H: 10, BAR_RADIUS: 5, NEW: "#22d3ee", TALKING: "#8b5cf6", WON: "#f5c46b",
      COUNTS_FONT: 12, COUNT_NEW: "#22d3ee", COUNT_TALKING: "#b79cfa", COUNT_WON: "#f5c46b" },
    CHIPS: ["New", "Talking", "Won", "Lost"],
    ITEM: { GAP: 10, ICON: 40, ICON_RADIUS: 12, SVG: 20, MID_GAP: 3, KIND_FONT: 13, KIND_WEIGHT: 600, SUM_FONT: 13.5, SUM_LINE: 1.35, SUM_COLOR: "#c9d1e6" },
    ICONS: {
      message: { BG: "#0f2a3a", COLOR: "#22d3ee", PATH: "M4 5h16v11H9l-5 4z" },
      i_can_help: { BG: "#1b2350", COLOR: "#b79cfa", PATH: "M7 11V6a2 2 0 0 1 4 0v5M11 10V5a2 2 0 0 1 4 0v6M15 9a2 2 0 0 1 4 0v5a7 7 0 0 1-7 7h-1a6 6 0 0 1-5-3l-2-4a2 2 0 0 1 3-2l1 2" },
      sale: { BG: "#2a2410", COLOR: "#f5c46b", PATH: "M5 8h14l-1 12H6z" },
      card_lead: { BG: "#14302a", COLOR: "#6ee7b7", PATH: "M14 10h4M14 14h3" },
      campaign: { BG: "#2a2410", COLOR: "#f5c46b", PATH: "M12 21s-7-4.5-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 11c0 5.5-7 10-7 10z" } },
    NOT_DRAWN: ["tip", "lead_reply"],
    PILLS: { NEW: { BG: "#22d3ee", COLOR: "#070b18" }, WON: { BG: "#f5c46b", COLOR: "#070b18" } } },
  FOUND: {
    PANEL: { PAD_X: 16, GAP: 6 },
    TOP: { GAP: 16, PAD: "4px 0 8px", TITLE: "Found score", TITLE_FONT: 17, TITLE_WEIGHT: 700,
      TEXT: "How easy you are to find on Google and the apps people search. Do the gold ones first.", TEXT_FONT: 13, TEXT_LINE: 1.4, TEXT_COLOR: "#a9b3cc" },
    RING: { SIZE: 96, R: 40, STROKE: 8, TRACK: "#1e2848", ARC: "#f5c46b", CAP: "round", ROTATE: -90, DASH_TOTAL: 252, SAMPLE: [62, 156],
      NUM_X: 48, NUM_Y: 54, NUM_FONT: 24, NUM_WEIGHT: 700, NUM_COLOR: "#f7f3e8" },
    ROW: { GAP: 10, PAD: "10px 0", LINE: "#141b33", MARK: 26, MARK_RADIUS: 13, MARK_BORDER: 2, MARK_FONT: 13, MARK_WEIGHT: 700,
      TODO: "#f5c46b", DONE: "#6ee7b7", WAITING: "#8e9bbf", TITLE_FONT: 13.5, TITLE_WEIGHT: 600, SUB_FONT: 12, SUB_LINE: 1.35, SUB_COLOR: "#a9b3cc", BUTTON_H: 34 },
    MARKS: { todo: "!", done: "&#10003;", waiting: "&#8230;" },
    WEIGHTS: { basics: 15, profile: 20, listings: 20, posts: 15, connected: 15, fingerprint: 15 },
    TITLES: { basics: "Add your city and a short bio", profile: "Your profile page on Google", listings: "Your listings on Google", posts: "Posts shown in Google", fingerprint: "Fingerprint complete" },
    DETAILS: { basics: "Google and Need alerts use them to match you", waiting: "Connected, waiting for each platform's approval", connected: "Your posts and approved replies go out from your account" },
    WAITING_TITLE: "YouTube, TikTok, Instagram, Facebook" }
};

/* NAMED (Nov 25 2026, H1): THE OWNER'S CANVAS, ROW 7 (four boards, 390 x 844; Downloads\design\h1\project): "Home: Local"
   (FeedLocal), "Home: Following, nobody followed" (FeedFollowing), "Home: Market" (FeedMarket) and "Search" (FeedSearch).
   The site's fonts are kept, never the boards' Space Grotesk and Inter. scripts/bf-home-tabs.js draws them; the Local
   feed's cards are bf-feed.js's own (FEED above), with the Local line. */
const HOME = {
  BOARDS: ["FeedLocal", "FeedFollowing", "FeedMarket", "FeedSearch"],
  TABS: ["Local", "Following", "Market", "For You"],     // For You still opens its Coming soon sheet
  CHIPS: { LEFT: 12, TOP: 64, H: 34, HIT: 44, RADIUS: 17,   // H the drawn face; HIT the tap target around it (css/bf-phone.css I)
    PAD_X: 12, GAP: 8, BORDER: "#2b3a6b", BG: "rgba(14,20,40,.8)", TEXT: "#c9d1e6", FONT: 12.5, WEIGHT: 500,
    ON_BG: "#0f2a3a", PIN: 14, LOCAL: ["Within 25 mi", "Change"] },
  RAIL: { RIGHT: 10, ABOVE_BAR: 16, GAP: 18, WIDTH: 60, AVATAR: 52, PLUS: 22, MARKET: ["Like", "Ask", "Save", "Share"] },
  INFO: { LEFT: 14, RIGHT: 80, ABOVE_BAR: 16, GAP: 8, LINE_FONT: 13, LINE_COLOR: "#c9d1e6", TITLE_FONT: 21, TITLE_WEIGHT: 700, TITLE_LINE: 1.2, SUB_FONT: 14,
    PRICE_FONT: 22, PRICE_WEIGHT: 700, PRICE: "#f5c46b", BUY_H: 44, BUY_PAD_X: 26, BUY_RADIUS: 22, BUY_FONT: 15, BUY_WEIGHT: 700, BUY_TEXT: "#070b18" },
  LOCAL_LINE: { FONT: 13, COLOR: "#c9d1e6", EXAMPLE: "Hair & Beauty \u00b7 North Park \u00b7 0.8 mi" },   // the board: "Hair and Beauty"; the categories table says "Hair & Beauty"
  FOLLOW: { BG: "#070b18", TOP: 68, PAD: "16px 16px 0", GAP: 14, ICON: 64, ICON_BG: "#0f2a3a",
    TITLE: "Follow people to fill this tab", TITLE_FONT: 18, TITLE_WEIGHT: 700,
    SUB: "Posts from people you follow show here, newest first. Here are a few near you and in what you do.", SUB_FONT: 13.5, SUB_LINE: 1.45,
    LABEL: "SUGGESTED FOR YOU", LABEL_FONT: 11, LABEL_WEIGHT: 600, LABEL_SPACING: 1.6, LABEL_COLOR: "#8e9bbf",
    ROW_PAD: "10px 0", ROW_LINE: "#141b33", ROW_GAP: 10, AVATAR: 48, NAME_FONT: 14.5, NAME_WEIGHT: 600, ROW_SUB_FONT: 12.5,
    BTN_H: 34, BTN_HIT: 44, BTN_PAD_X: 14, BTN_RADIUS: 17, BTN_FONT: 13, BTN_WEIGHT: 700, BTN_TEXT: "#070b18", MAX: 8 },
  SEARCH: { TOP_PAD: 12, SIDE: 12, BOTTOM_PAD: 8, GAP: 8, BACK: 44, FIELD_H: 44, FIELD_RADIUS: 22, FIELD_BG: "#0b1022", FIELD_PAD_LEFT: 14, ICON: 18,
    INPUT_FONT: 16, CLEAR: 16, SCOPES: ["All", "People", "Listings", "Posts", "Needs"], GROUPS: ["PEOPLE", "LISTINGS", "POSTS", "NEEDS"], SEE_ALL: "See all", SEE_ALL_FONT: 13,
    THUMB: 56, THUMB_RADIUS: 12, L_TITLE_FONT: 14, L_TITLE_WEIGHT: 600, L_SUB_FONT: 12.5, PRICE_FONT: 14, PRICE_WEIGHT: 700, GRID_COLS: 3, GRID_RATIO: "3/4", GRID_RADIUS: 8, GRID_GAP: 4,
    RECENT_MAX: 8 }
};

// NAMED (Nov 25 2026, H1): + HOME. NAMED (Nov 25 2026, LR-4): + LEADS.FOUND, TABS four. NAMED (Nov 24 2026, LR-3): + LEADS.INBOUND. NAMED (Nov 23 2026, LR-2): + LEADS. NAMED (Nov 23 2026, P3-3): + COMPOSER, NEEDPOST. NAMED (Nov 21 2026, FX2): + AGENTS, HQ, ORBIT; NAMED (Nov 22 2026, FX3): + TMX, HQ.ABYSS for HQ.SUN
module.exports = { TOLERANCE, SCREEN, PICTURED_SAFE_AREA, COLOR, FEED, BAR, PROFILE, AGENTS, HQ, ORBIT, TMX, COMPOSER, NEEDPOST, LEADS, HOME };
