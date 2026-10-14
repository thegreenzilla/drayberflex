# DrayberFlex Hiring – project brief for Claude Code

## What this is
Driver acquisition system for Drayber Flex (part-time EV delivery drivers, Philippines).
Funnel: online application → interview booking → check-in & documents → orientation → interview →
driving test → **Passed** → 1-day paid training (applicant books on phone) → **Accredited**.
Owner: Dennis (non-technical). Explain changes in plain language, confirm before big changes.

## Live setup
- Site: https://apply.drayberflex.com (GitHub Pages, repo `thegreenzilla/drayberflex`, branch `main`, root).
  Old URL https://thegreenzilla.github.io/drayberflex/ redirects. `CNAME` file must stay.
- Deploy = commit + push `index.html` to `main`; live in ~1–2 min.
- Backend: Supabase project ref `xtwxydojxucrrkkxlraa` (Singapore).
  `config.js` holds the project URL + **publishable** key (public by design). Never put secret/service keys in this repo.
- DNS: GoDaddy, CNAME `apply` → `thegreenzilla.github.io`.
- **Test site**: https://apply.drayberflex.com/test/ – `test/index.html` (copy of `index.html`) + `test/config.js` (`TEST:true`, separate
  Supabase project `drayberflex-test`, ref `punybdtlwngmkhqjtmqh`). Red TEST banner, noindex. No email/SMS or Accounts functions there.
  Workflow: ship a change to `test/index.html` first; after Dennis tries it, copy the same file to the root `index.html` (live).
  New database setup = `supabase/sql/full_schema_for_new_projects_only.sql` (all updates included; keep it in step with each dated file).

## Code layout
- `index.html` – the whole app (vanilla JS, no build step). Staff app + public applicant pages (hash routes):
  - `#apply/<campaignId>` application (5 steps), `#ticket/<id>` applicant status/QR/results/training booking,
    `#app` applicant app (sign in with code + last 4 digits of mobile; `#status` opens the same page): next step, QR, reschedule once
    (≥12h before), cancel, upload NBI/medical later, progress + updates, Add to Home Screen. Landing page when no hash.
  - Test site only so far: `test/manifest.webmanifest`, `test/sw.js` (network-first, offline shell only), `test/icons/` – copy them to the root when going live.
- Staff navigation (test site): side menu on desktop (`renderNav`: main pages, My queues open, Tools folded, Help → What's new),
  ☰ slide-in menu on phones; full-screen screens (check-in desk, driving test mode) keep their own layout.
- `supabase/sql/` – schema + dated update scripts (run manually in Supabase → SQL Editor; all idempotent).
- `supabase/functions/notify` – email (Brevo or Resend) / SMS (Semaphore) when the desk approves/declines.
  `admin-users` – create user / reset password / delete (Admin only). Both deployed with **Verify JWT OFF**.

## Data model (Supabase)
- `applicants(id, code unique, data jsonb, notified_at)` – whole applicant record in `data`.
- `app_config(key in ('settings','bank','jobs'))` – settings (campaigns `camps`, `training` calendar, `driveItems`, rules; **readable by the public**), question bank, and `jobs` (staff-only: job orders, ad spend, ad budgets – keep anything private here, never in settings).
- `profiles` – staff accounts, `roles` text[]: admin, marketing, verifier (Check-in & documents), orientation, interviewer, tester (driving instructor), trainer, hr, operations (job orders only, no applicant details).
- Storage bucket `docs` (private): photos `<pid>.jpg`, attachments `att/<applicantId>/<fileId>.<ext>` (images + PDF, 10 MB).
- Public RPCs (anon): `submit_application`, `check_license`, `slot_counts`, `get_ticket`, `lookup_ticket`, `training_counts`, `training_respond`, `book_training`,
  applicant app: `app_login` (5 wrong tries/hour locks the code), `app_me`, `app_reschedule`, `app_cancel`, `app_add_doc`, `app_logout`
  (sessions in `applicant_sessions`, hashed key, 30 days; no direct table access).
- RLS: staff (active profile) read/write applicants; anon only through RPCs.

## Key business rules
- Stage logic in `stageRaw()`/`stage()`: failing any step stops the applicant (docs, interview, drive test, training).
- Results reach the applicant's phone **only after Check-in taps** Failed / Passed / Accredited ("Results to give").
- Auto-approved bookings show QR immediately (no message). Desk-approved/declined → email/SMS via `notify` (SMS has **no links** – PH telcos block them).
- Driver's license photo is **required** (client + `submit_application`). NBI/medical optional online, but asked for before the interview
  (app + staff flag "No NBI or medical uploaded yet"; soft – staff can photograph them at check-in).
- Expired NBI / older medical are accepted for the interview (verified with `older:true`); a valid copy is needed before training:
  the applicant uploads it in the app (`docs.<kind>.renew`, staff tap "Use new copy") and the Accredited result is blocked until then.
- Training: 1 day, schedule set by trainer in **Training calendar** (shared across campaigns); applicant can change date once, up to the day before.
- Driving test items + weights editable by Admin and Driving instructor; critical item fail = test fail.
- Minimum age 21.
- One person = one driver's license number (letter + 10 digits, compared without spaces/dashes). One active application per license;
  after a "Failed" result they wait the months in Rules & data, or are blocked for good (red flag, NBI hit, fake document,
  critical driving fail twice) unless Admin allows. Enforced in `submit_application` / `check_license` (SQL) and set when Check-in taps Failed.
- Who sees what: interview results = Interviewer, Check-in, HR, Admin; driving results = Check-in, HR, Admin. Page access per role is `VIEW_ROLES`.
- Campaigns close by themselves (never deleted) when accredited drivers reach the target or after the last day; dates are also enforced in SQL.

## Writing rules
- Applicant-facing text: natural **Taglish**. Staff screens: English.
- Spelling: **License** (never "Licence").
- No "Mober" brand on applicant-facing pages (consent text uses the Company setting for the Data Privacy Act).
- Fonts: landing = Montserrat + Space Mono labels; app pages = Inter.

## Before shipping any change
1. Check JS syntax of every `<script>` block.
2. Test staff screens for every role and all public routes (no console errors, no "undefined/NaN" on screen).
3. If a change needs SQL, add a new dated file in `supabase/sql/` (idempotent) and tell Dennis exactly what to paste.
4. Add an entry at the top of `WHATSNEW` in the app (date, plain-English title and bullets, who it's for, `where:"test"` until it is copied to live,
   then `"live"`). Staff see it on the What's new page; a red dot marks unseen updates.
   On the test site, add its tests to `WN_TESTS` under the same title ([id, who, title, steps, should happen]); results go to the
   `test_results` table and Dennis can paste them back with "Copy results for Claude".
