// DrayberFlex – "notify" Edge Function
// Sends the applicant an email and/or SMS when the desk APPROVES or DECLINES a booking request.
// Auto-approved applicants get nothing (they already see their QR on screen).
// Each channel is skipped until its secret is set, so you can start with email only.
// Secrets (Edge Functions → Secrets):
//   APP_URL            your site, e.g. https://thegreenzilla.github.io/drayberflex/
//   MAIL_FROM          sender, e.g. "Drayber Flex <hiring@yourdomain.com>"
//   RESEND_API_KEY     email via Resend (needs a verified domain)   – or –
//   BREVO_API_KEY      email via Brevo (can use a single verified sender address)
//   SEMAPHORE_API_KEY  SMS via Semaphore (add later)
//   SEMAPHORE_SENDER   approved sender name, e.g. DRAYBERFLX
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown) => new Response(JSON.stringify(b), { headers: { ...cors, "Content-Type": "application/json" } });
const env = (k: string) => Deno.env.get(k) ?? "";
const esc = (s: string) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { id } = await req.json();
    if (!id || typeof id !== "string") return json({ error: "missing id" });
    const sb = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"));

    const { data: row } = await sb.from("applicants").select("id,data,notified_at").eq("id", id).maybeSingle();
    const st = row?.data?.booking?.status;
    if (!row || row.notified_at || row.data?.booking?.auto !== false || (st !== "approved" && st !== "declined")) return json({ skipped: true });

    const { data: claimed } = await sb.from("applicants").update({ notified_at: new Date().toISOString() })
      .eq("id", id).is("notified_at", null).select("id");
    if (!claimed?.length) return json({ skipped: true });

    const a = row.data, ok = st === "approved";
    const first = String(a.name || "").split(" ")[0];
    const when = new Date(a.slot).toLocaleString("en-PH", { timeZone: "Asia/Manila", weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    const where = [a.hubName, a.location].filter((x: string) => x && !/set the address/i.test(x)).join(", ");
    const site = env("APP_URL").replace(/#.*$/, "");
    const out: Record<string, unknown> = {};

    // ---- email (links are fine in email) ----
    const subject = ok ? `Approved na ang interview mo – ${when}` : "Salamat sa pag-apply sa Drayber Flex";
    const html = ok
      ? `<p>Hi ${esc(first)},</p><p>Approved na ang interview mo sa Drayber Flex.</p>
         <p><b>Kailan:</b> ${esc(when)}<br><b>Saan:</b> ${esc(where)}<br><b>Code mo:</b> <span style="font-size:20px;letter-spacing:2px"><b>${esc(a.code)}</b></span></p>
         <p>Ipakita ang code na ito sa check-in desk pagdating mo. Makikita mo rin ang QR code mo dito:<br><a href="${site}#ticket/${a.id}">${site}#ticket/${a.id}</a></p>
         <p>Dalhin ang original ng NBI clearance, medical certificate at driver's license.</p><p>— Drayber Flex Recruitment</p>`
      : `<p>Hi ${esc(first)},</p><p>Salamat sa pag-apply sa Drayber Flex. Sa ngayon, hindi namin ma-confirm ang interview mo.${a.booking?.note ? " " + esc(a.booking.note) : ""}</p><p>— Drayber Flex Recruitment</p>`;
    if (a.email) {
      const from = env("MAIL_FROM") || "Drayber Flex <onboarding@resend.dev>";
      if (env("BREVO_API_KEY")) {
        const m = from.match(/^(.*)<(.+)>$/), name = m ? m[1].trim() : "Drayber Flex", email = m ? m[2].trim() : from;
        const r = await fetch("https://api.brevo.com/v3/smtp/email", { method: "POST",
          headers: { "api-key": env("BREVO_API_KEY"), "Content-Type": "application/json", accept: "application/json" },
          body: JSON.stringify({ sender: { name, email }, to: [{ email: a.email, name: a.name }], subject, htmlContent: html }) });
        out.email = r.ok ? "sent (brevo)" : `failed ${r.status}: ${await r.text()}`;
      } else if (env("RESEND_API_KEY")) {
        const r = await fetch("https://api.resend.com/emails", { method: "POST",
          headers: { Authorization: `Bearer ${env("RESEND_API_KEY")}`, "Content-Type": "application/json" },
          body: JSON.stringify({ from, to: [a.email], subject, html }) });
        out.email = r.ok ? "sent (resend)" : `failed ${r.status}: ${await r.text()}`;
      }
    }

    // ---- SMS (no links: PH telcos block SMS with links) ----
    if (env("SEMAPHORE_API_KEY") && a.phone) {
      const number = String(a.phone).replace(/[^\d+]/g, "").replace(/^\+?63/, "0");
      const message = ok
        ? `DRAYBERFLX: Hi ${first}, approved na ang interview mo sa ${when}${where ? ", " + where : ""}. Code mo: ${a.code}. Ipakita ang SMS na ito sa check-in desk. Dalhin ang original NBI, medical cert at driver's license.`
        : `DRAYBERFLX: Hi ${first}, salamat sa pag-apply. Sa ngayon, hindi namin ma-confirm ang interview mo.${a.booking?.note ? " " + a.booking.note : ""}`;
      const body = new URLSearchParams({ apikey: env("SEMAPHORE_API_KEY"), number, message });
      if (env("SEMAPHORE_SENDER")) body.set("sendername", env("SEMAPHORE_SENDER"));
      const r = await fetch("https://api.semaphore.co/api/v4/messages", { method: "POST", body });
      out.sms = r.ok ? "sent" : `failed ${r.status}: ${await r.text()}`;
    }

    console.log("notify", id, st, out);
    return json({ ok: true, ...out });
  } catch (e) {
    console.error(e);
    return json({ error: String(e) });
  }
});
