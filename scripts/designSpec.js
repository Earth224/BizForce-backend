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
    BOTTOM_ABOVE_BAR: 126,  // 210 above the pictured phone's bottom
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
  STRIP: {                  // the product strip: only on a post that carries a listing (a later block)
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
    INNER: "#121a36",
    INITIALS_FONT: 28
  },
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

module.exports = { TOLERANCE, SCREEN, PICTURED_SAFE_AREA, COLOR, FEED, BAR, PROFILE };
