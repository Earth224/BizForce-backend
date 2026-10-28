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
