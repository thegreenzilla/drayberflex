# DrayberFlex – upload guide (Oct 2026 version, with Training calendar)

Do the steps in order. Each step ends with a ✅ check.

---

## STEP 1 – Update the database (2 min)
1. supabase.com → open project **DrayberFlex** (check the name top-left).
2. Left menu → **SQL Editor** → **+** (new query).
3. Open `2_Supabase_SQL/RUN_THIS_update.sql` → select all (⌘A) → copy → paste → **Run**.

✅ You see **"Success. No rows returned"**.
⚠️ Do NOT run `full_schema_for_new_projects_only.sql`. That is only for a brand-new project.

---

## STEP 2 – Edge Functions (5 min)
Left menu → **Edge Functions**.

### 2a. admin-users (for Add account / reset password / decline sign-up)
- If **admin-users** is already in the list → skip to 2b.
- Otherwise: **Deploy a new function → Via Editor** → name **`admin-users`** → delete sample code → paste
  `3_Supabase_Edge_Functions/admin-users/index.ts` → **Deploy**.

### 2b. notify (email/SMS when the desk approves or declines)
- If **notify** exists → open it → **Code** → replace everything with
  `3_Supabase_Edge_Functions/notify/index.ts` → **Deploy**.
- If not → **Deploy a new function → Via Editor** → name **`notify`** → paste the same file → **Deploy**.

### 2c. Turn off JWT for BOTH
Open each function → **Details / Settings** → **Verify JWT** = **OFF** → **Save**.

✅ Open these links in your browser:
- `https://xtwxydojxucrrkkxlraa.supabase.co/functions/v1/admin-users` → shows `{"error":"Sign in again."}`
- `https://xtwxydojxucrrkkxlraa.supabase.co/functions/v1/notify` → shows an `{"error":...}` message (not "NOT_FOUND")

---

## STEP 3 – Email sender with Brevo (10 min, no domain needed)
1. brevo.com → sign up (free).
2. **Senders, Domains & Dedicated IPs → Senders → Add a sender** → your recruiting email → verify it from your inbox.
3. **SMTP & API → API Keys → Generate a new API key** → copy it.
4. Supabase → **Edge Functions → Secrets** → add:

| Name | Value |
|---|---|
| `APP_URL` | `https://thegreenzilla.github.io/drayberflex/` |
| `MAIL_FROM` | `Drayber Flex <the-email-you-verified@...>` |
| `BREVO_API_KEY` | the key from Brevo |

Later (optional): `SEMAPHORE_API_KEY` and `SEMAPHORE_SENDER` = `DRAYBERFLX` to turn on SMS. Nothing else changes.

✅ Secrets list shows the 3 names.

---

## STEP 4 – Upload the app to GitHub (2 min)
1. Open **https://github.com/thegreenzilla/drayberflex/upload/main**
2. Drag in `1_GitHub/index.html` (and `1_GitHub/config.js` if it's not there yet).
3. **Commit changes**.
4. Wait 1–2 minutes → open **https://thegreenzilla.github.io/drayberflex/** → press **⌘ Shift R**.

✅ Landing page shows **"Ano ang Drayber Flex?"** and a **"Tingnan ang status"** button top-right.

---

## STEP 5 – Settings inside the app (5 min)
Sign in (scroll to the bottom of the landing page → **Staff sign in**).

1. **Campaigns → your campaign → Edit**
   - **3. Interview location**: real hub name + full address
   - **6. Approval**: Minimum age = **21**, passing score (e.g. 70%)
   - **Save changes**
2. **Rules & data**: check the **reminder text**. Replace any old text that says "Mober" with:
   `DRAYBERFLX: Paalala {first}, interview mo sa {date}, {time}, {address}. Code: {code}. Dalhin ang original NBI, medical cert at driver's license. Salamat!`
3. **Training calendar** (menu, Trainer or Admin): set training days, hours, trainees per day, days ahead, hub and address → **Save weekly default**. Tap a day to close it or change its seats.
4. **Driving test items** (menu): check the 10 items, weights, pass mark → **Save**.
5. **Accounts**: create the team accounts and roles (give the trainer the **OJT trainer** role).

---

## STEP 6 – Test it end to end (15 min)
Use your own phone and email.

| # | Do this | You should see |
|---|---|---|
| 1 | Apply with a passing profile | QR + code on screen right away (no email) |
| 2 | Apply again with low answers (or age under 21) | "Natanggap na namin…" + your code |
| 3 | Staff: **Requests → Approve** | Email "Approved na ang interview mo" arrives with the code |
| 4 | Landing → **Tingnan ang status** → code + last 4 digits | Your page opens |
| 5 | Check-in: scan QR or type the code → verify documents | Moves to Orientation |
| 6 | Orientation → Interview → Driving test | Each passes to the next module |
| 7 | **Results to give** → **Passed** | Phone shows "Congratulations… 1-day paid training" |
| 8 | Phone: **Oo, tatanggapin ko** → pick a date | Training ticket with date |
| 9 | Training module → **Pass** → Results to give → **Accredited** | Phone shows "Accredited Drayber Flex driver ka na" |
| 10 | Try a fail (e.g. fail interview) → **Failed** | Phone shows the "Salamat sa oras mo" message |

If anything looks wrong: screenshot the screen and send it.
