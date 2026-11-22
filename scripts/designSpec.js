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

module.exports = { TOLERANCE, SCREEN, PICTURED_SAFE_AREA, COLOR, FEED, BAR, PROFILE, AGENTS, HQ, ORBIT, TMX };   // NAMED (Nov 21 2026, FX2): + AGENTS, HQ, ORBIT; NAMED (Nov 22 2026, FX3): + TMX, HQ.ABYSS for HQ.SUN
