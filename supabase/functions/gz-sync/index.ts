// DrayberFlex – "gz-sync" Edge Function: the link with GreenZilla's GZWorkforce.
//
// GZWorkforce → here (header x-partner-key = PARTNER_SYNC_SECRET):
//   job_order  {jo:{no, role, role_label, count, account, priority, need_by, schedule, rate, requirements, reason}}
//              adds or updates the job order (client GreenZilla) on the Job orders page
//   cancel     {no}  marks that job order cancelled
// Signed-in DrayberFlex staff → here (their own sign-in token):
//   passed     {id}      sends an applicant who passed (Check-in gave "Passed") to GZWorkforce
//   sourcing   {job_id}  tells GZWorkforce a campaign was opened for its job order
//   status     {}        is the link set up? ({connected})
//
// Secrets (Supabase → Edge Functions → Secrets): PARTNER_SYNC_SECRET (the same in both systems),
// GZ_SYNC_URL (GZWorkforce's partner-sync address), SB_SECRET_KEY (this project's secret key) unless
// SUPABASE_SERVICE_ROLE_KEY is available. Deploy with "Verify JWT" OFF: callers are checked here.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-partner-key",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { ...cors, "Content-Type": "application/json" } });
const SECRET = Deno.env.get("PARTNER_SYNC_SECRET") ?? "";
const GZ_URL = Deno.env.get("GZ_SYNC_URL") ?? "";
const KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? Deno.env.get("SB_SECRET_KEY") ?? "";
const CLIENT = "GreenZilla";

function sameKey(a: string, b: string) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const clip = (v: unknown, n: number) => String(v ?? "").trim().slice(0, n);
const isDay = (v: unknown) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  if (!KEY) return json({ error: "Server is missing its secret key (SB_SECRET_KEY)." }, 500);
  const sb = createClient(Deno.env.get("SUPABASE_URL")!, KEY, { auth: { persistSession: false } });
  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "Bad request" }, 400); }

  const cfg = async (key: string) => ((await sb.from("app_config").select("data").eq("key", key).maybeSingle()).data?.data ?? {}) as Record<string, any>;
  const saveJobs = (data: Record<string, unknown>) => sb.from("app_config").update({ data, updated_at: new Date().toISOString() }).eq("key", "jobs");

  // ---------- calls from GZWorkforce ----------
  const partnerKey = req.headers.get("x-partner-key");
  if (partnerKey !== null) {
    if (!SECRET || !sameKey(partnerKey, SECRET)) return json({ error: "Not allowed" }, 401);
    const jobs = await cfg("jobs");
    const orders: any[] = Array.isArray(jobs.orders) ? jobs.orders : [];
    if (b.action === "job_order") {
      const jo = (b.jo ?? {}) as Record<string, unknown>;
      const no = clip(jo.no, 40), count = Math.round(Number(jo.count));
      if (!no || !(count >= 1 && count <= 500)) return json({ error: "Job order number and headcount are required." }, 400);
      const id = "gz-" + no.replace(/[^A-Za-z0-9-]/g, "");
      const notes = [
        jo.schedule ? `Schedule: ${clip(jo.schedule, 200)}` : "",
        jo.rate ? `Daily rate: ₱${Math.round(Number(jo.rate))}` : "",
        jo.priority === "Urgent" ? "Priority: URGENT" : "",
        jo.reason ? `Reason: ${clip(jo.reason, 300)}` : "",
      ].filter(Boolean).join("\n");
      const prev = orders.find((o) => o.id === id);
      const o = Object.assign({}, prev ?? { id, status: "open", createdAt: new Date().toISOString(), by: "gzworkforce" }, {
        client: CLIENT,
        position: `${clip(jo.role_label || jo.role, 60)}${jo.account ? ` (${clip(jo.account, 40)})` : ""}`,
        needed: count,
        neededBy: isDay(jo.need_by) ? jo.need_by : (prev?.neededBy ?? ""),
        hubName: prev?.hubName ?? "",
        location: prev?.location ?? "",
        reqs: clip(jo.requirements, 1500),
        notes,
        gz: { no, role: clip(jo.role, 8), account: jo.account ? clip(jo.account, 40) : null, priority: jo.priority === "Urgent" ? "Urgent" : "Normal", receivedAt: prev?.gz?.receivedAt ?? new Date().toISOString(), updatedAt: new Date().toISOString(), sent: prev?.gz?.sent ?? 0 },
      });
      if (prev && prev.status === "cancelled") o.status = "open";
      const next = prev ? orders.map((x) => (x.id === id ? o : x)) : [...orders, o];
      const { error } = await saveJobs({ ...jobs, orders: next });
      if (error) return json({ error: error.message }, 500);
      return json({ ok: true, id, updated: !!prev });
    }
    if (b.action === "cancel") {
      const id = "gz-" + clip(b.no, 40).replace(/[^A-Za-z0-9-]/g, "");
      if (!orders.some((x) => x.id === id)) return json({ ok: true, missing: true });
      const { error } = await saveJobs({ ...jobs, orders: orders.map((x) => (x.id === id ? { ...x, status: "cancelled", cancelledAt: new Date().toISOString() } : x)) });
      return error ? json({ error: error.message }, 500) : json({ ok: true });
    }
    return json({ error: "Unknown action" }, 400);
  }

  // ---------- calls from signed-in DrayberFlex staff ----------
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const { data: who } = await sb.auth.getUser(token);
  if (!who?.user) return json({ error: "Sign in again." }, 401);
  const { data: me } = await sb.from("profiles").select("roles,active,pending").eq("id", who.user.id).maybeSingle();
  const roles: string[] = me?.roles ?? [];
  if (!me || !me.active || me.pending || !roles.some((r) => ["admin", "verifier", "marketing"].includes(r))) return json({ error: "Not allowed" }, 403);
  if (b.action === "status") return json({ connected: !!(SECRET && GZ_URL) });
  if (!SECRET || !GZ_URL) return json({ error: "not_connected" }, 400);

  const settings = await cfg("settings"), jobs = await cfg("jobs");
  const camps: any[] = Array.isArray(settings.camps) ? settings.camps : [];
  const orders: any[] = Array.isArray(jobs.orders) ? jobs.orders : [];

  // numbers GZWorkforce shows as "At DrayberFlex"
  async function stats(job: any) {
    const ids = camps.filter((c) => c.jobId === job.id).map((c) => c.id);
    if (!ids.length) return { applied: 0, screening: 0, passed: 0 };
    const { data } = await sb.from("applicants").select("data").in("data->>campaignId", ids);
    const L = (data ?? []).map((r: any) => r.data ?? {}).filter((d: any) => d.booking?.status !== "declined" && d.calendlyCanceled !== true);
    const passed = L.filter((d: any) => d.released?.pass && !d.released?.fail).length;
    const screening = L.filter((d: any) => d.checkin?.status === "show" && !d.released?.pass && !d.released?.fail).length;
    return { applied: L.length, screening, passed };
  }
  async function send(payload: Record<string, unknown>) {
    try {
      const r = await fetch(GZ_URL, { method: "POST", headers: { "Content-Type": "application/json", "x-partner-key": SECRET }, body: JSON.stringify(payload) });
      const out = await r.json().catch(() => ({}));
      return r.ok && out.ok ? { ok: true as const, out } : { ok: false as const, error: out.error ?? `GZWorkforce answered ${r.status}` };
    } catch (e) {
      return { ok: false as const, error: "Could not reach GZWorkforce: " + String(e).slice(0, 120) };
    }
  }

  if (b.action === "sourcing") {
    const job = orders.find((x) => x.id === b.job_id);
    if (!job?.gz) return json({ ok: true, skipped: true });
    const camp = camps.filter((c) => c.jobId === job.id).map((c) => c.name).join(", ");
    const r = await send({ action: "sourcing", jo_no: job.gz.no, campaign: camp, stats: await stats(job) });
    return r.ok ? json({ ok: true }) : json({ error: r.error }, 502);
  }

  if (b.action === "passed") {
    const id = clip(b.id, 60);
    const { data: row } = await sb.from("applicants").select("id,data").eq("id", id).maybeSingle();
    const a = row?.data as any;
    if (!a) return json({ error: "Applicant not found" }, 404);
    if (!a.released?.pass || a.released?.fail) return json({ error: "Only applicants who passed are sent." }, 400);
    const camp = camps.find((c) => c.id === a.campaignId);
    const job = camp?.jobId ? orders.find((x) => x.id === camp.jobId) : null;
    if (!job?.gz) return json({ ok: true, skipped: true });
    const lic = a.docs?.license ?? {};
    const r = await send({
      action: "candidate", jo_no: job.gz.no, stats: await stats(job),
      candidate: {
        external_id: "drayberflex:" + id, name: clip(a.name, 120), mobile: clip(a.phone, 30), email: clip(a.email, 120) || null,
        birth_date: isDay(a.application?.birth) ? a.application.birth : null,
        license_no: clip(lic.number, 30) || null, license_expiry: isDay(lic.expiry) ? lic.expiry : null,
        passed_on: String(a.released.pass.at ?? "").slice(0, 10) || null, code: clip(a.code, 20),
      },
    });
    const now = new Date().toISOString();
    const gzSent = r.ok ? { at: now, ok: true, jo: job.gz.no } : { at: now, ok: false, jo: job.gz.no, error: r.error };
    const log = Array.isArray(a.log) ? a.log : [];
    log.unshift({ t: now, by: who.user.id, msg: r.ok ? `Sent to GreenZilla (${job.gz.no}) as a passed candidate` : `Could not send to GreenZilla (${job.gz.no}): ${r.error}` });
    await sb.from("applicants").update({ data: { ...a, gzSent, log: log.slice(0, 60) }, updated_at: now }).eq("id", id);
    if (r.ok) {
      const cnt = (await stats(job)).passed;
      await saveJobs({ ...jobs, orders: orders.map((x) => (x.id === job.id ? { ...x, gz: { ...x.gz, sent: cnt } } : x)) });
    }
    return r.ok ? json({ ok: true }) : json({ error: r.error }, 502);
  }
  return json({ error: "Unknown action" }, 400);
});
