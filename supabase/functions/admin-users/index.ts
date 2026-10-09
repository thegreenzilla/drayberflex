// DrayberFlex – "admin-users" Edge Function
// Lets an Admin create accounts, set a temporary password, or delete a declined sign-up.
// The service-role key stays on the server; the caller must be a signed-in, active Admin.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown) => new Response(JSON.stringify(b), { headers: { ...cors, "Content-Type": "application/json" } });
const ROLES = ["admin", "marketing", "verifier", "orientation", "interviewer", "tester", "trainer", "hr"];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const { data: { user } } = await sb.auth.getUser(token);
    if (!user) return json({ error: "Sign in again." });
    const { data: me } = await sb.from("profiles").select("roles,active,pending").eq("id", user.id).maybeSingle();
    if (!me || !me.active || me.pending || !me.roles?.includes("admin")) return json({ error: "Only an Admin can do this." });

    const b = await req.json();
    if (b.action === "create") {
      const email = String(b.email || "").trim().toLowerCase();
      const roles = (b.roles || []).filter((r: string) => ROLES.includes(r));
      if (!email || String(b.password || "").length < 8 || !roles.length) return json({ error: "Email, password (8+) and a role are required." });
      const { data, error } = await sb.auth.admin.createUser({ email, password: b.password, email_confirm: true, user_metadata: { name: b.name || "" } });
      if (error) return json({ error: error.message });
      await sb.from("profiles").update({ name: b.name || "", roles, active: true, pending: false, must_change: true,
        approved_by: user.id, approved_at: new Date().toISOString() }).eq("id", data.user.id);
      return json({ ok: true, id: data.user.id });
    }
    if (b.action === "setpw") {
      if (String(b.password || "").length < 8) return json({ error: "Password needs at least 8 characters." });
      const { error } = await sb.auth.admin.updateUserById(b.user_id, { password: b.password });
      if (error) return json({ error: error.message });
      await sb.from("profiles").update({ must_change: true }).eq("id", b.user_id);
      return json({ ok: true });
    }
    if (b.action === "delete") {
      if (b.user_id === user.id) return json({ error: "You can't delete your own account." });
      const { error } = await sb.auth.admin.deleteUser(b.user_id);
      if (error) return json({ error: error.message });
      return json({ ok: true });
    }
    return json({ error: "Unknown action" });
  } catch (e) {
    console.error(e);
    return json({ error: String(e) });
  }
});
