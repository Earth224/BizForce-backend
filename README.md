# BizForce-backend

BizForce AI (https://bizforceai.net) is one subscription, All Access at $199 a month, that gives a small business a team of AI agents working from one business profile: SEO research and audits, email campaigns and sequences, blog articles, sales follow-up, analytics, and more. It also includes a digital business card, a public profile and storefront, a members' marketplace that trades in BizCash (BFC), and a wallet.

This repository is the backend: one Node/Express server (`server.js`) on Railway. It holds the API, the background jobs and the spend limits, and it talks to Supabase (Postgres and Storage), Stripe, Anthropic, Resend, Twilio and Bluesky. The frontend is a static site in `BizForce-fronyend` (spelled with a y), published by Netlify.

`RUNBOOK.md` says what to do when something breaks.

## Running it

```
npm install
node server.js          # what Railway runs (package.json "start")
```

The server reads `.env` (dotenv) in a local run. On Railway, every variable is set under the service's Variables.

## Environment variables

These are all 74 variables the running server reads: `server.js` and every local module it requires (`lib/`, `config/`, `leadRadar.js`, `mastodonRadar.js`, `youtubeRadar.js`, `redditRadar.js`). The list is generated from those reads (`node scripts/_envReads.js` prints it), and `scripts/checkLaunchBlockB.js` fails when this table leaves one out. Only names are listed here, never values.

A **gate** that says "exactly `true`" is off for `True`, `1`, `yes` or anything else, and the startup log names the variable when it is off. "On unless exactly `false`" is the reverse.

### Core services

| Variable | Default | Effect |
|---|---|---|
| `PORT` | `8080` | The HTTP port. Railway sets it. |
| `NODE_ENV` | none | `production`, or any of the three `RAILWAY_*` variables below, makes the process production: localhost is dropped from CORS, and Stripe events signed with the test secret are refused. |
| `RAILWAY_ENVIRONMENT` | set by Railway | Marks the process as production (see `NODE_ENV`). |
| `RAILWAY_ENVIRONMENT_NAME` | set by Railway | Marks the process as production. |
| `RAILWAY_PROJECT_ID` | set by Railway | Marks the process as production. |
| `RAILWAY_GIT_COMMIT_SHA` | set by Railway | The deployed commit, reported by `/health` and written into each backup's manifest. |
| `RAILWAY_PUBLIC_DOMAIN` | set by Railway (else `dynamic-prosperity-production-5382.up.railway.app`) | This API's own public host, used for the address a WooCommerce store hands its key back to (`/api/store/woocommerce/callback`) and for the Shopify webhook address (`/api/webhooks/shopify`). |
| `FRONTEND_URL` | `https://bizforceai.net` | The site that links in emails and Stripe redirects point to. |
| `SUPABASE_URL` | none (required) | The Supabase project. |
| `SUPABASE_SERVICE_KEY` | none (required) | The service-role key. The server reads and writes every table with it; never put it in the frontend. |
| `JWT_SECRET` | none (required) | Signs sign-in tokens and the HMAC on unsubscribe and confirm links. Changing it signs everyone out and breaks links already sent. |
| `ENCRYPTION_SECRET` | none | 64 hex characters (32 bytes). Encrypts the API keys members store (bring your own key). Missing or malformed, saving or using a stored key fails. |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | How long a SIGTERM waits for in-flight requests before closing them (a whole number from 1000 to 120000; anything else is the default). `lib/gracefulShutdown.js`. |

### Payments (Stripe)

| Variable | Default | Effect |
|---|---|---|
| `STRIPE_SECRET_KEY` | none | The Stripe API key. Without it, checkout and billing calls fail. |
| `STRIPE_STARTER_PRICE_ID` | none | The price ID of All Access. Without it, checkout is refused. |
| `STRIPE_WEBHOOK_SECRET` | none | Verifies live Stripe webhook events. Without it, every event is refused. |
| `STRIPE_TEST_WEBHOOK_SECRET` | none | Verifies Stripe test-mode events. Honoured only outside production. |
| `SUBSCRIPTION_GRACE_DAYS` | `3` | Days past `current_period_end` before a subscription stops entitling (0 to 90). |
| `SUBSCRIPTION_PAST_DUE_GRACE_DAYS` | `14` | Days a `past_due` subscription keeps entitling after a failed payment fell due (0 to 30). |

### AI models and spend limits

| Variable | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | none | The platform's Anthropic key. A member's own key, when they saved one, is used instead for their calls. |
| `MODEL_CALLS_DAILY_LIMIT_PER_USER` | `250` | Model calls per account per UTC day. A value that is not a positive whole number refuses calls. |
| `MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER` | `60` | Dollars of platform-paid model calls per account per calendar month. A value that is not a positive number refuses calls. |
| `PLATFORM_DAILY_SPEND_CAP_USD` | `25` | The ceiling on what all accounts together may spend in one UTC day. At 80% one alert is emailed; at 100% every non-owner model call is refused until midnight UTC. A value that is not a positive number refuses every non-owner call. Test accounts (`lib/testAccounts.js`) are not counted. |
| `ENABLE_AGENT_CHAINING` | off | Exactly `true` lets one agent call another's tools. |
| `CHAIN_MAX_DEPTH` | `2` | How deep a chain may go (1 to 5). |
| `CHAIN_MAX_FANOUT` | `3` | Tool calls one step may make (1 to 10). |
| `CHAIN_MAX_CALLS` | `10` | Tool calls one chain may make in all (1 to 50). |
| `ROUTINE_MAX_STEPS` | `10` | Steps in one routine (1 to 50). |
| `ROUTINE_STEPS_PER_MINUTE` | `20` | Routine steps one account may dispatch per minute (1 to 120). |

### Email (Resend)

| Variable | Default | Effect |
|---|---|---|
| `RESEND_API_KEY` | none | Sends every email: sign-up, password reset, campaigns, backups and ops alerts. |
| `RESEND_WEBHOOK_SECRET` | none | Verifies Resend's bounce and complaint webhooks. Without it, marketing email is not sent, because a bounce could not be recorded. |
| `EMAIL_MARKETING_DAILY_CAP` | `50` | Marketing emails one account may send per UTC day. |
| `ENABLE_EMAIL_SEQUENCES` | off | Exactly `true` starts the hourly email-sequence job. |
| `EMAIL_SEQUENCE_MAX_PER_TICK` | `25` | Sequence steps sent per hourly run. |
| `OPS_ALERT_EMAIL` | `BACKUP_EMAIL_TO` | Where ops alerts go. |
| `ENABLE_OPS_ALERTS` | on | On unless exactly `false`: the 30-minute alert scan and every alert email. |

### Backups

| Variable | Default | Effect |
|---|---|---|
| `ENABLE_NIGHTLY_BACKUP` | off | Exactly `true` schedules the nightly backup, and makes "no backup in 30 hours" an alert. |
| `BACKUP_CRON` | `0 8 * * *` | When the backup runs. |
| `BACKUP_TIMEZONE` | `America/Los_Angeles` | The timezone of `BACKUP_CRON`. |
| `BACKUP_ENCRYPTION_KEY` | none | Base64 of exactly 32 bytes. Each backup is encrypted with it (AES-256-GCM). Missing or malformed, no backup is sent and an alert says so. Keep a copy somewhere other than Railway: without it, no backup can be opened. |
| `BACKUP_EMAIL_TO` | none | Where the encrypted backup parts are emailed, and the fallback for `OPS_ALERT_EMAIL`. |

### SMS (Twilio) and push

| Variable | Default | Effect |
|---|---|---|
| `TWILIO_ACCOUNT_SID` | none | Twilio account. SMS sending is refused, naming what is missing, unless all three are set. |
| `TWILIO_AUTH_TOKEN` | none | Twilio auth token. It also verifies inbound SMS webhooks. |
| `TWILIO_PHONE_NUMBER` | none | The number SMS is sent from. |
| `TWILIO_WEBHOOK_URL` | rebuilt from the request | The exact public URL Twilio posts inbound SMS to, used to verify its signature. |
| `ENABLE_DRIP_SCHEDULER` | off | Exactly `true` runs the SMS drip engine every 5 minutes (and once at boot). |
| `VAPID_PUBLIC_KEY` | none | Web push key pair for calendar reminders. Without them, no push is sent. |
| `VAPID_PRIVATE_KEY` | none | See `VAPID_PUBLIC_KEY`. |

### Outlook sign-in (Microsoft)

| Variable | Default | Effect |
|---|---|---|
| `MS_CLIENT_ID` | none | The Application (client) ID of BizForce's Microsoft app registration (see "Microsoft app registration" below). Needed only for Sign in with Microsoft on Your Inbox; without it (or `MS_CLIENT_SECRET`) the Microsoft routes answer 503 "Outlook sign-in isn't set up yet." and the page disables the button. Set it on Railway; never commit it. |
| `MS_CLIENT_SECRET` | none | That registration's client secret value. Needed only for Sign in with Microsoft, with `MS_CLIENT_ID`. A secret; set it on Railway, never commit it, and replace it before Microsoft's expiry date. |

### Shopify app

| Variable | Default | Effect |
|---|---|---|
| `SHOPIFY_CLIENT_ID` | none | The Client ID of BizForce's Shopify app (see "Shopify app setup" below). Needed only for Connect Shopify on the Store Agent page; without it (or `SHOPIFY_CLIENT_SECRET`) the Shopify routes and `POST /api/webhooks/shopify` answer 503 "Shopify connection isn't set up yet.", `GET /api/store/connections` answers `shopify_available: false` and the page disables the button. Set it on Railway; never commit it. |
| `SHOPIFY_CLIENT_SECRET` | none | That app's client secret. It is sent in the token exchange and refresh, and it verifies the HMAC on Shopify's return to the Store Agent page and on every webhook. Needed only for Shopify, with `SHOPIFY_CLIENT_ID`. A secret; set it on Railway and never commit it. Rotating it in the Partner Dashboard means setting the new value on Railway at once, or webhooks are refused with 401. |
| `GOOGLE_OAUTH_CLIENT_ID` | none | The client ID of BizForce's Google OAuth client (see "YouTube app setup" below). Needed only for YouTube on the Social Agent page; without it (or `GOOGLE_OAUTH_CLIENT_SECRET`) the YouTube connect, video and proposal routes answer 503 "YouTube connection isn't set up yet.", `GET /api/youtube/status` answers `youtube_available: false` and the page disables the button. Set it on Railway; never commit it. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | none | That client's secret, sent in the code exchange and every refresh. Needed only for YouTube, with `GOOGLE_OAUTH_CLIENT_ID`. A secret; set it on Railway and never commit it. |
| `TIKTOK_CLIENT_KEY` | none | The client key of BizForce's TikTok app (see "TikTok app setup" below). Needed only for TikTok on the Social Agent page; without it (or `TIKTOK_CLIENT_SECRET`) the TikTok connect, creator-info, caption, proposal and status routes answer 503 "TikTok connection isn't set up yet.", `GET /api/tiktok/status` answers `tiktok_available: false` and the page disables the button. Set it on Railway; never commit it. |
| `TIKTOK_CLIENT_SECRET` | none | That app's client secret, sent in the code exchange, every refresh and the revoke. Needed only for TikTok, with `TIKTOK_CLIENT_KEY`. A secret; set it only on Railway and never commit it. |
| `INSTAGRAM_APP_ID` | none | The app id of BizForce's Instagram app (see "Instagram app setup" below). Needed only for Instagram on the Social Agent page; without it (or `INSTAGRAM_APP_SECRET`) the Instagram connect, caption, proposal and post routes answer 503 "Instagram connection isn't set up yet.", `GET /api/instagram/status` answers `instagram_available: false` and the page disables the button. Set it on Railway; never commit it. |
| `INSTAGRAM_APP_SECRET` | none | That app's secret, sent in the code exchange and the long-lived token exchange. Needed only for Instagram, with `INSTAGRAM_APP_ID`. A secret; set it only on Railway and never commit it. |
| `FACEBOOK_APP_ID` | none | The main App ID of the same Meta app (see "Facebook Pages setup" below); Instagram keeps its own pair. Needed only for Facebook on the Social Agent page; without it (or `FACEBOOK_APP_SECRET`) the Facebook connect, Page, caption, proposal and post routes answer 503 "Facebook connection isn't set up yet.", `GET /api/facebook/status` answers `facebook_available: false` and the page disables the button. Set it on Railway; never commit it. |
| `FACEBOOK_APP_SECRET` | none | That app's App Secret, sent in the code exchange and the long-lived token exchange. Needed only for Facebook, with `FACEBOOK_APP_ID`. A secret; set it only on Railway and never commit it. |

### Google Wallet

| Variable | Default | Effect |
|---|---|---|
| `GOOGLE_WALLET_ISSUER_ID` | none | The issuer ID of BizForce's Google Pay and Wallet Console account, 10 to 25 digits (see "Google Wallet setup" below). Needed only for "Add to Google Wallet" on public cards; without all three Google Wallet variables the button is not shown and `GET /api/cards/google-wallet` answers 503. |
| `GOOGLE_WALLET_SA_EMAIL` | none | The email address of the Google Cloud service account that signs the passes; it must end in `.iam.gserviceaccount.com`. Needed only for Google Wallet, with the other two. |
| `GOOGLE_WALLET_SA_KEY` | none | That service account's `private_key` from its JSON key file, pasted whole: `-----BEGIN PRIVATE KEY-----` to the end, and a literal `\n` as the file writes it is accepted. It signs the save links (RS256). A secret; set it on Railway and never commit it. A key that does not parse, or is not RSA, means Google Wallet is not configured. |

### Lead Radar and outreach

| Variable | Default | Effect |
|---|---|---|
| `BLUESKY_IDENTIFIER` | none | The one Bluesky account the radar searches and replies from. |
| `BLUESKY_APP_PASSWORD` | none | Its app password. The check suite blanks both in every check. |
| `ENABLE_MASTODON_RADAR` | off | Exactly `true` adds Mastodon to the radar. |
| `MASTODON_INSTANCE` | `https://mastodon.social` | The Mastodon server searched and posted to. |
| `MASTODON_ACCESS_TOKEN` | none | The Mastodon account's token, for replies. |
| `ENABLE_YOUTUBE_RADAR` | off | Exactly `true` adds YouTube comments to the radar. |
| `YOUTUBE_API_KEY` | none | The YouTube Data API key. |
| `YOUTUBE_DAILY_UNIT_CAP` | `5000` | YouTube API units the whole server may spend per day. |
| `YOUTUBE_RADAR_DAILY_UNITS` | `2500` | The radar's share of those units. |
| `ENABLE_YOUTUBE_RETENTION` | on | On unless exactly `false`: the daily deletion of YouTube data older than 30 days (YouTube's policy). |
| `ENABLE_LEAD_SCORING` | off | Exactly `true` scores captured leads with a model call. |
| `OUTREACH_MIN_INTENT` | `60` | The intent score (0 to 100) a lead needs before outreach considers it. |
| `OUTREACH_DAILY_CAP` | `5` | Outreach replies per day. |
| `OUTREACH_ACCOUNT_DAILY_CEILING` | `25` | Outreach sends per account per UTC day. A negative value stops outreach. |
| `ENABLE_SALES_AUTOLOOP` | off | Exactly `true` drafts a conversion for high-intent leads every 5 minutes (a model call each). |
| `SALES_AUTOLOOP_DRY_RUN` | on | On unless exactly `false`: the auto-loop drafts but never sends. |
| `SALES_SEND_LIVE` | off | Exactly `true` lets the Sales Agent actually send what it drafts. |
| `SALES_AUTOLOOP_DAILY_DRAFT_CAP` | `50` | Drafts the auto-loop may make per day. |

### Background jobs and the BizCash wallet

| Variable | Default | Effect |
|---|---|---|
| `ENABLE_STORE_PROPOSAL_JOB` | off | Exactly `true` runs the daily Store Agent proposals. |
| `ENABLE_SELF_REVIEW` | off | Exactly `true` runs the daily self-review pass. |
| `SELF_REVIEW_MAX_PER_TICK` | `10` | Reviews generated per daily run. |
| `ENABLE_AGENT_SCHEDULES` | off | Exactly `true` runs members' scheduled agent runs every hour. |
| `AGENT_SCHEDULE_MAX_PER_TICK` | `25` | Scheduled runs per hourly run. |
| `ENABLE_STORAGE_DELETION_RETRY` | on | On unless exactly `false`: the daily retry that removes a deleted account's files from Storage. |
| `ENABLE_GATE_DECISIONS_SWEEP` | on | On unless exactly `false`: the daily sweep that deletes gate decisions older than 90 days. |
| `ENABLE_SCHEMA_CHECK` | on | On unless exactly `false`: read-only head counts confirm every table the code relies on exists (lib/schemaCheck.js), once 60 s after boot and daily at 06:00 UTC; a missing table is emailed once, named with the migration file that creates it, and shown on `/api/admin/health` (admins only; the public `/health` is unchanged). |
| `ENABLE_STORE_SYNC` | off | Exactly `true` runs the daily read of every connected Shopify and WooCommerce store (lib/storeSync.js): products, stock and order summaries, never customer details. The sync never writes to a store; a price or stock change is made only when a member approves it, and only on a connection they allowed changes on. Members can connect a store and press "Sync now" either way. |
| `ENABLE_TRIGGERS` | off | Exactly `true` runs the hourly member-trigger pass (lib/triggerRunner.js). Anything else leaves triggers saved but never fired. |
| `TRIGGERS_DAILY_FIRINGS` | 10 | Firings per member per UTC day, a whole number clamped to 1 to 20. |
| `BFC_TRANSFER_MAX` | `1000` | The most BFC one send or donation may move. |
| `BFC_TRANSFER_DAILY_CAP` | `2000` | BFC one account may send and donate in 24 hours. |
| `BFC_TRANSFER_HOLD_DAYS` | `7` | Days a new account must wait before it may send BFC. |

## Background jobs

Every job is started by `server.js` only when it is the program (`node server.js`), never when a check loads it. Every cron job and interval is registered with `lib/gracefulShutdown.js` and stopped on SIGTERM. A job that writes shared state claims a `job_runs` row first, so two processes (during a deploy) cannot both run it.

| Job | Schedule | Gate |
|---|---|---|
| `storeProposalTick`: Store Agent proposals | cron `0 6 * * *`, America/Los_Angeles | `ENABLE_STORE_PROPOSAL_JOB` exactly `true` |
| `selfReviewTick`: weekly and monthly self-reviews | cron `0 7 * * *`, America/Los_Angeles | `ENABLE_SELF_REVIEW` exactly `true` |
| `agentScheduleTick`: members' scheduled agent runs | cron `0 * * * *`, UTC | `ENABLE_AGENT_SCHEDULES` exactly `true` |
| `emailSequenceTick`: one due step per enrollment | cron `0 * * * *`, UTC | `ENABLE_EMAIL_SEQUENCES` exactly `true` |
| `youtubeRetentionTick`: delete YouTube data older than 30 days | cron `0 9 * * *`, UTC | on unless `ENABLE_YOUTUBE_RETENTION` is exactly `false` |
| ops alert scan (`lib/opsAlert.js` scanTick) | cron `*/30 * * * *`, UTC | on unless `ENABLE_OPS_ALERTS` is exactly `false` |
| `pendingStorageDeletionTick`: deleted accounts' files | cron `15 4 * * *`, UTC | on unless `ENABLE_STORAGE_DELETION_RETRY` is exactly `false` |
| `gateDecisionsSweepTick`: gate decisions older than 90 days | cron `30 4 * * *`, UTC | on unless `ENABLE_GATE_DECISIONS_SWEEP` is exactly `false` |
| `cardLeadsPurgeTick`: card leads older than 12 months | cron `45 4 * * *`, UTC, claimed `card_leads_purge` | always on (no flag): a promised deletion; scheduled only when server.js is the program |
| `oauthStatesPurgeTick` (`lib/microsoftAuth.js`): one-time Microsoft, Shopify, YouTube, TikTok, Instagram and Facebook sign-in states older than a day | the same 04:45 UTC run, after the card leads purge, claimed `oauth_states_purge` | always on (no flag); runs only when server.js is the program |
| `webhookEventsPurgeTick` (`lib/shopifyAuth.js`): Shopify notification receipts older than 30 days | the same 04:45 UTC run, after the sign-in states purge, claimed `shopify_webhook_events_purge` | always on (no flag); runs only when server.js is the program |
| `retentionTick` (`lib/memberVideos.js`): a video's file once YouTube has it, TikTok has posted it, an Instagram Reel of it is published and a Facebook video post of it is published (and no pending proposal or unfinished Instagram or Facebook post needs it), any video's file 14 days after it was added, and bf-video files with no record after a day | the same 04:45 UTC run, after the Shopify receipts purge, claimed `member_videos_retention` | always on (no flag): a promised deletion; runs only when server.js is the program |
| `refreshTick` (`lib/instagramApi.js`): every connected Instagram token that expires within 10 days and is at least a day old is refreshed; an expired one is marked to reconnect, with one notice | the same 04:45 UTC run, after the video retention pass, claimed `instagram_token_refresh` | always on (no flag), skipped while `INSTAGRAM_APP_ID` or `INSTAGRAM_APP_SECRET` is missing; runs only when server.js is the program |
| `choosingPurgeTick` (`lib/facebookApi.js`): a Facebook connection still waiting for the member to choose a Page more than an hour after sign-in is deleted, with the user token it holds | the same 04:45 UTC run, after the Instagram refresh, claimed `facebook_choosing_purge` | always on (no flag); runs only when server.js is the program |
| `schemaCheckTick`: every table the code relies on exists (read-only head counts) | cron `0 6 * * *`, UTC, claimed `schema_check`; and once 60 s after boot | on unless `ENABLE_SCHEMA_CHECK` is exactly `false` |
| `storeSyncTick`: read connected Shopify and WooCommerce stores (the sync only reads) | cron `0 5 * * *`, UTC, claimed `store_sync` | `ENABLE_STORE_SYNC` exactly `true` |
| `triggerTick`: member triggers, each firing gated (G13, G9) and recorded | cron `30 * * * *`, UTC, claimed `hourly_triggers_h<hh>` | off unless `ENABLE_TRIGGERS` is exactly `true` |
| `runNightlyBackup` | cron `BACKUP_CRON` (`0 8 * * *`), `BACKUP_TIMEZONE` (America/Los_Angeles) | `ENABLE_NIGHTLY_BACKUP` exactly `true` |
| `dripTick`: SMS drip engine | every 5 minutes, and once at boot | `ENABLE_DRIP_SCHEDULER` exactly `true` |
| `reminderTick`: calendar push reminders | every 60 seconds | always, when `server.js` is the program |
| `salesAutoConvertTick`: Sales Agent auto-loop | every 5 minutes, first run 60 s after boot | `ENABLE_SALES_AUTOLOOP` exactly `true` |
| Lead Radar: Bluesky search | every 5 minutes | always, when `server.js` is the program (Mastodon, YouTube and scoring have their own gates above) |

`scripts/checkCronJobs.js` runs every cron expression under a fake clock across both daylight-saving changes.

## The check suite

The checks are `scripts/check*.js`. Each one is a plain Node script: it prints `pass` and `FAIL` lines and exits 0 only when everything passed. Most need no network and no database. The ones that do write rows write them as the check account and remove them again (`scripts/checkRunResidue.js` proves nothing is left).

Set the check account first. Without it, `scripts/runChecks.js` refuses to start, and the checks that write rows refuse one by one:

```powershell
$env:BIZFORCE_CHECK_USER_ID = '53e6b330-d31c-4958-a10b-516397e7b9c9'
node scripts/runChecks.js                 # every check, one process at a time
node scripts/runChecks.js --mutate        # and MUTATE=all for every check that has mutations
```

**On a machine with little memory, run it in batches**, one check at a time, each batch under 10 minutes:

```powershell
$env:BIZFORCE_CHECK_USER_ID = '53e6b330-d31c-4958-a10b-516397e7b9c9'
$all = Get-ChildItem scripts\check*.js | Sort-Object Name
$all[0..24] | ForEach-Object { node $_.FullName *> $null; "{0}  {1}" -f $LASTEXITCODE, $_.Name }
# then $all[25..49], $all[50..74], ... ; every line must start with 0
```

A check with `MUTATIONS` proves itself: `MUTATE=all node scripts/checkX.js` breaks the code in memory one way at a time, and each break must make the check fail. A mutation whose search text no longer matches is an error (exit 3), never a catch (`scripts/_shared.js`).

## Migrations

`supabase/migrations/NNN_name.sql`, numbered in order. Nothing applies them automatically. **The owner applies each new one by hand:** open the Supabase dashboard, go to SQL Editor, paste the whole file, and run it. Each file is written to be safe to run twice (`IF NOT EXISTS`, guarded constraints). Apply a new migration before deploying the code that needs it, unless its header says the code works without it.

A migration that was never applied is caught by the schema check (`lib/schemaCheck.js`): within 60 seconds of a deploy, and every day at 06:00 UTC, it emails the owner once per missing table with the exact file to run, and the nightly backup's failure names the same file.

`node scripts/buildScratchSchema.js` writes every migration, in order, into one file for a fresh database (the restore drill uses it).

The newest is `149_card_short_links_and_privacy.sql`: business card short links (`bizforceai.net/c/<slug>`) and the show email / phone / photo choices. Until it is applied, cards work as before, and saving a short link or a hidden field answers 503 saying that migration 149 is needed.

## Deploy order

1. **Migrations first**, in the Supabase SQL editor, for any new file in `supabase/migrations`.
2. **The backend**: push to `main`; Railway builds and deploys it. The old process gets SIGTERM, finishes its in-flight requests (up to `SHUTDOWN_TIMEOUT_MS`) and exits. Check `https://dynamic-prosperity-production-5382.up.railway.app/health` says `healthy`.
3. **The frontend**: push `BizForce-fronyend` to `main`; Netlify publishes it as is (its only build step stamps the commit into `sw.js`). The legal pages are built here: after changing `lib/legal.js` or `lib/legalPages.js`, run `node scripts/buildLegalPages.js` and commit the four pages it rewrites in the frontend.

Backend before frontend, because a page may call a route that only the new backend has.

## Email

- **Sending: Resend**, from `hello@mail.bizforceai.net`. The sending domain is `mail.bizforceai.net`, verified in Resend. Its DNS records are the ones Resend lists for that domain: a DKIM record, and at `send.mail.bizforceai.net` the MX and SPF records Resend uses for bounces. Bounces and complaints come back through Resend's webhook (`RESEND_WEBHOOK_SECRET`) and stop further mail to that address.
- **Receiving: ImprovMX**, for every address at `@bizforceai.net`, including the contact address the legal pages give (`lib/legal.js` `CONTACT_EMAIL`). The MX records on the apex `bizforceai.net` point to ImprovMX, which forwards to the owner's inbox. Sending uses a separate subdomain, so the two never conflict.

## Microsoft app registration

Sign in with Microsoft on Your Inbox (`lib/microsoftAuth.js`, migration 173) needs one app registration in the Microsoft Entra admin center (App registrations, New registration):

- **Supported account types:** accounts in any organisational directory and personal Microsoft accounts ("any organisational directory and personal Microsoft accounts"), so Outlook.com, Hotmail and Microsoft 365 mailboxes can all sign in. The code uses the `common` endpoints.
- **Platform:** Web. **Redirect URI**, exactly: `https://bizforceai.net/mailbox.html` (the server sends `FRONTEND_URL` + `/mailbox.html`, so the two must match).
- **API permissions, delegated:** `offline_access`, `openid`, `email`, `profile`, and from Office 365 Exchange Online `IMAP.AccessAsUser.All` and `SMTP.Send`.
- **Certificates and secrets:** one client secret. Put its value in `MS_CLIENT_SECRET` and the Application (client) ID in `MS_CLIENT_ID`, on Railway only. Note the secret's expiry date and rotate it before then: make a new secret, set it on Railway, then delete the old one.

Until both variables are set, the Microsoft routes answer 503 and the page shows "Outlook sign-in isn't set up yet." Disconnecting deletes BizForce's copy only; a member removes BizForce from their own Microsoft account under its app permissions.

## Shopify app setup

Connect Shopify on the Store Agent page (`lib/shopifyAuth.js`, `lib/shopifyApi.js`, migration 176) needs one public app in the Shopify Partner Dashboard:

- **App URL:** `https://bizforceai.net/store-agent.html`. When Shopify opens it (with `shop` and `hmac`, no `code`), the page fills the shop in and asks the member to press Connect Shopify; nothing is sent until they do.
- **Allowed redirection URL**, exactly: `https://bizforceai.net/store-agent.html` (the server sends `FRONTEND_URL` + `/store-agent.html`, so the two must match).
- **Access tokens:** expiring offline tokens. The server asks for them (`expiring=1`), keeps the access token and the refresh token sealed, and refreshes before expiry; each refresh replaces both.
- **Scopes:** `read_products`, `read_inventory`, `read_orders`, `read_locations`; with "Let BizForce make changes I approve" ticked, also `write_products` and `write_inventory`. A grant missing any asked-for scope is refused. `read_orders` covers the last 60 days of orders.
- **Webhooks**, all to `https://<RAILWAY_PUBLIC_DOMAIN>/api/webhooks/shopify` (JSON): `app/uninstalled`, and the three compliance topics `customers/data_request`, `customers/redact`, `shop/redact`. Uninstall and `shop/redact` delete the connection and everything read from it, as Disconnect does; BizForce stores no customer data, so the two customer topics are recorded and need no other action.
- **Credentials:** the Client ID in `SHOPIFY_CLIENT_ID` and the client secret in `SHOPIFY_CLIENT_SECRET`, on Railway only.

Until both variables are set, the Shopify routes answer 503 and the page shows "Shopify connection isn't set up yet." One shop connects to one BizForce account. Disconnecting deletes BizForce's copy; the member removes the app from their Shopify admin under Settings, then Apps. Webhook receipts are kept 30 days (`shopify_webhook_events`).

## YouTube app setup

YouTube on the Social Agent page (`lib/googleAuth.js`, `lib/youtubeApi.js`, `lib/memberVideos.js`, migration 177) needs one OAuth client in Google Cloud:

- **Project:** a Google Cloud project. The Google Wallet one may be reused.
- **API:** the YouTube Data API v3, enabled in that project.
- **OAuth consent screen:** with the two scopes `https://www.googleapis.com/auth/youtube.upload` and `https://www.googleapis.com/auth/youtube.readonly`. A grant missing either is refused.
- **OAuth client:** type Web application, with the authorized redirect URI exactly `https://bizforceai.net/agents/social.html` (the server sends `FRONTEND_URL` + `/agents/social.html`, so the two must match).
- **Credentials:** the client ID in `GOOGLE_OAUTH_CLIENT_ID` and the client secret in `GOOGLE_OAUTH_CLIENT_SECRET`, on Railway only.
- **Testing status:** while the app is in "testing", only its test users can connect, their refresh tokens expire after 7 days (they then connect again), and YouTube keeps every upload private.
- **Verification:** Google's app verification for these scopes is needed before uploads can be unlisted or public, and before anyone outside the test users can connect.

Until both variables are set, the YouTube routes answer 503 and the page shows "YouTube connection isn't set up yet." Videos wait in the private bucket `bf-video` (50 MB a file, MP4, WebM or MOV) and are deleted once every platform they were sent to has them, or 14 days after they were added. Every upload and removal waits for the member's approval, and YouTube API units are reserved in `youtube_api_calls` before each call. Disconnecting asks Google to revoke the access, as a best effort, and deletes BizForce's copy.

## TikTok app setup

TikTok on the Social Agent page (`lib/tiktokAuth.js`, `lib/tiktokApi.js`, `lib/memberVideos.js`, migration 178) needs one app on TikTok for Developers:

- **Account and app:** a TikTok for Developers account, and an app in it for BizForce.
- **Products:** Login Kit for Web, and the Content Posting API with Direct Post turned on.
- **Scopes:** `user.info.basic` and `video.publish`. A grant missing either is refused.
- **Redirect URI:** exactly `https://bizforceai.net/agents/social.html` (the server sends `FRONTEND_URL` + `/agents/social.html`, so the two must match).
- **URL prefix and domain verification:** only if TikTok asks for them; posting here sends the file itself (FILE_UPLOAD), not a URL for TikTok to fetch.
- **Credentials:** the client key in `TIKTOK_CLIENT_KEY` and the client secret in `TIKTOK_CLIENT_SECRET`, kept only on Railway.
- **Audit:** until TikTok audits the app, every post from BizForce is visible only to its owner (SELF_ONLY), whatever privacy the member picks.

Until both variables are set, the TikTok routes but status and disconnect answer 503 and the page shows "TikTok connection isn't set up yet." Each post follows TikTok's posting rules (the account's nickname shown, privacy chosen from TikTok's options with no default, interactions off unless turned on, the commercial content disclosure), checked again against a fresh creator_info when it is approved. Every post waits for the member's approval. TikTok has no API to delete a post, so the member deletes it in the TikTok app. Disconnecting asks TikTok to revoke the access, as a best effort, and deletes BizForce's copy.

## Instagram app setup

Instagram on the Social Agent page (`lib/instagramAuth.js`, `lib/instagramApi.js`, migration 179) needs one app on Meta for Developers:

- **Account and app:** a Meta developer account, and an app in it for BizForce with the Instagram product, set up as "API setup with Instagram login".
- **Scopes:** `instagram_business_basic` and `instagram_business_content_publish`.
- **Redirect URI:** exactly `https://bizforceai.net/agents/social.html` (the server sends `FRONTEND_URL` + `/agents/social.html`, so the two must match).
- **Credentials:** the Instagram app id in `INSTAGRAM_APP_ID` and the Instagram app secret in `INSTAGRAM_APP_SECRET`, kept only on Railway.
- **Testers:** while the app is in development, only the Instagram accounts added as testers in the app can connect.
- **Before the public can connect:** Business verification and App Review for both permissions.
- **Accounts:** only Instagram Business and Creator accounts can publish through the API; a personal account is refused at connect.

Until both variables are set, the Instagram routes but status and disconnect answer 503 and the page shows "Instagram connection isn't set up yet." Photos must be JPEG (from the Media Library) and Reels MP4 or MOV (from Your videos); each file's fingerprint is checked right before Instagram is given its address, and a Reel's address is a signed link that stops working after 2 hours. Every post waits for the member's approval and is published once. Instagram has no API to delete a post, so the member deletes it in the Instagram app. Disconnecting deletes BizForce's copy; the member removes BizForce in Instagram's settings, under Apps and websites.

## Facebook Pages setup

Facebook on the Social Agent page (`lib/facebookAuth.js`, `lib/facebookApi.js`, migration 180) uses the same Meta app as Instagram:

- **Product:** add Facebook Login for Business to that app.
- **Scopes:** `pages_show_list`, `pages_manage_posts` and `pages_read_engagement`. All three must be granted, or nothing is saved.
- **Redirect URI:** exactly `https://bizforceai.net/agents/social.html` (the server sends `FRONTEND_URL` + `/agents/social.html`, so the two must match).
- **Credentials:** the app's main App ID in `FACEBOOK_APP_ID` and its App Secret in `FACEBOOK_APP_SECRET`. The App Secret is kept only on Railway.
- **Before the public can connect:** App Review for the three permissions and Business verification. Until then, only people with a role on the app can connect.
- **Pages:** a member connects one Page they can create content on (its tasks include CREATE_CONTENT). With several, they choose one; an unfinished choice is deleted after an hour.

Until both variables are set, the Facebook routes but status and disconnect answer 503 and the page shows "Facebook connection isn't set up yet." Photos must be JPEG, PNG or GIF (from the Media Library) and videos MP4 or MOV (from Your videos); each file's fingerprint is checked right before Facebook is given its address, and a video's address is a signed link that stops working after 2 hours. Every post and every removal waits for the member's approval and runs once. Disconnecting deletes BizForce's copy; the member removes BizForce in Facebook's settings, under Business integrations.

## Google Wallet setup

"Add to Google Wallet" on public cards (Android visitors) needs the three `GOOGLE_WALLET_*` variables. BizForce signs each save link itself and makes no Google API call.

- **Issuer ID:** from the Google Pay and Wallet Console (`GOOGLE_WALLET_ISSUER_ID`).
- **Service account:** a Google Cloud service account with a JSON key; its email is `GOOGLE_WALLET_SA_EMAIL` and its `private_key` is `GOOGLE_WALLET_SA_KEY`.
- **Issuer user:** that service account added as a user of the issuer in the Wallet Console.
- **Origins:** the save links are signed for the origin `https://bizforceai.net`.
- **Publishing access:** requested from Google in the Wallet Console before the public can save passes; until then only the issuer's test accounts can.

The pass holds only what the card shows publicly. The class is `<issuer>.bizforce_card_v1`; each card's object id is derived from its id with a key from `JWT_SECRET`, so no BizForce id leaves the server (lib/googleWallet.js).

## Backups and the restore drill

With `ENABLE_NIGHTLY_BACKUP=true`, every night at `BACKUP_CRON` the server reads every table in `lib/backup.js` `BACKUP_TABLES`, encrypts the result with `BACKUP_ENCRYPTION_KEY`, and emails the parts to `BACKUP_EMAIL_TO`. A failed or incomplete backup emails an alert, and so does no successful backup in 30 hours.

**The restore drill**, once a quarter and before trusting a backup:

1. `node scripts/buildScratchSchema.js`: one SQL file with every migration.
2. Create a new, empty Supabase project. Paste that file into its SQL editor and run it.
3. Save the backup's part files from the email, and the key in a file.
4. `node scripts/restoreBackup.js --key-file <key file> --dry-run <part files>`: checks every part's integrity and the manifest, and writes nothing.
5. `node scripts/restoreBackup.js --key-file <key file> --target-url <scratch project URL> --target-key <its service key> <part files>`: restores into the scratch project, then counts every table against the manifest. Exit 0 means every table came back whole.
6. Run the printed `setval` lines in the scratch project's SQL editor, then delete the scratch project.

The restore refuses to write into production unless it is passed `--i-mean-production`, and refuses any table that is not empty. `scripts/checkBackupRestore.js` runs a backup and restore against a fixture database on every suite run.

## Dependency exceptions

`scripts/checkDependencyFloors.js` is the record. It reads `package-lock.json` and fails if a floor below regresses, or if this list and the lockfile disagree in either direction.

**Floors** (lockfile refresh, Nov 6 2026, versions published at least 14 days before): body-parser 1.20.9, qs 6.16.1, undici 8.12.3.

**Accepted residue** from the Nov 6 2026 `npm audit`, each with its reason:

- **zod 3.25.76**, under @atproto/api 0.20.25 and its @atproto/common-web 0.5.3, @atproto/lexicon 0.7.4 and @atproto/xrpc 0.8.3 (advisory 1243066). No compatible fixed release exists: every @atproto/api release still requires zod 3, and no zod 3 release is fixed. An override to zod 4 is unsafe. The runtime use is a two-field error-body check on bsky.social responses, and no public route drives it.
- **uuid 8.3.2**, under node-cron 3.0.3 (advisory 1119441). Only `uuid.v4()` with no buffer is called. node-cron stays at 3.0.3 for the DST reason recorded in `scripts/checkCronJobs.js`.
- **follow-redirects 1.16.1**, under twilio and axios (advisory 1244003), until its fix (1.16.2, published Oct 25 2026) passes the 14-day rule on Nov 8 2026. Twilio is created without `allowRedirects`, so redirects are never followed.

Never run `npm audit fix` in any form. `--force` would downgrade @atproto/api to 0.13.6 and move node-cron to 4.
