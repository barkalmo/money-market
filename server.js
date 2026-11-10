import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@supabase/supabase-js";

const E = process.env;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sb = createClient(E.SUPABASE_URL, E.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
const PLANS = { Silver: 1000, Diamond: 1500, Gold: 2000, Pro: 3000 };
const ORIGIN = (E.SITE_ORIGIN || "http://localhost:3000").replace(/\/$/, "");
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  fontSrc: ["https://fonts.gstatic.com"], imgSrc: ["'self'", "data:", "https:"], connectSrc: ["'self'"],
  objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } }));

/* ---------- helpers ---------- */
const audit = (actor, event) => sb.from("audit_log").insert({ actor, event });
const code = () => String(crypto.randomInt(100000, 1000000));
const phone = p => { const d = String(p).replace(/\D/g, ""); return d.startsWith("0") ? "254" + d.slice(1) : d; };
const clean = s => String(s || "").replace(/[%,()*\\]/g, "").trim();

async function sendEmail(to, subject, html) {            // Resend
  const r = await fetch("https://api.resend.com/emails", { method: "POST",
    headers: { Authorization: `Bearer ${E.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: E.MAIL_FROM, to, subject, html }) });
  if (!r.ok) throw new Error("email_failed");
}
async function sendSms(to, message) {                     // TalkSasa (confirm the endpoint in your TalkSasa dashboard docs)
  const r = await fetch("https://bulksms.talksasa.com/api/v3/sms/send", { method: "POST",
    headers: { Authorization: `Bearer ${E.TALKSASA_API_KEY}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ recipient: phone(to), sender_id: E.TALKSASA_SENDER_ID, type: "plain", message }) });
  if (!r.ok) throw new Error("sms_failed");
}
const auth = (...roles) => async (req, res, next) => {
  try {
    const { sub } = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), E.JWT_SECRET);
    const { data: u } = await sb.from("users").select("id,role,status,locked,email").eq("id", sub).single();
    if (!u || u.locked) return res.status(401).json({ error: "unauthorised" });
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: "forbidden" });
    req.user = u; next();
  } catch { res.status(401).json({ error: "unauthorised" }); }
};
const admin = auth("admin", "superadmin"), ops = auth("admin", "finance", "superadmin"),
      fin = auth("finance", "superadmin"), superOnly = auth("superadmin");
const settings = async keys => Object.fromEntries((await sb.from("settings").select("*").in("key", keys)).data.map(r => [r.key, r.value]));

/* date range (East Africa time) and client search shared by every list */
const dated = (q, col, { from, to }) => { if (from) q = q.gte(col, from + "T00:00:00+03:00"); if (to) q = q.lte(col, to + "T23:59:59+03:00"); return q; };
async function clientIds(term) {
  const t = clean(term); if (!t) return null;
  const { data } = await sb.from("users").select("id").or(`client_no.ilike.%${t}%,username.ilike.%${t}%,email.ilike.%${t}%,first_name.ilike.%${t}%,last_name.ilike.%${t}%`).limit(500);
  return (data || []).map(x => x.id);
}
const csv = (rows, cols) => [cols.map(c => c[0]).join(","), ...rows.map(r => cols.map(c => `"${String(c[1](r) ?? "").replace(/"/g, '""')}"`).join(","))].join("\n");
const WJOIN = "*, users!withdrawals_user_id_fkey(client_no,first_name,last_name,username,phone)";
const IJOIN = "*, users!investments_user_id_fkey(client_no,first_name,last_name,username)";
async function listW(req) {
  let q = sb.from("withdrawals").select(WJOIN).order("created_at", { ascending: false }).limit(500);
  if (req.query.status) q = q.eq("status", req.query.status);
  q = dated(q, "created_at", req.query);
  const ids = await clientIds(req.query.client); if (ids) q = q.in("user_id", ids);
  return (await q).data || [];
}
async function listI(req) {
  let q = sb.from("investments").select(IJOIN).order("paid_at", { ascending: false }).limit(500);
  q = dated(q, "paid_at", req.query);
  const ids = await clientIds(req.query.client); if (ids) q = q.in("user_id", ids);
  return (await q).data || [];
}
async function listU(req) {
  let q = sb.from("users").select("id,client_no,first_name,last_name,email,phone,username,id_number,role,status,locked,lock_until,created_at").order("created_at", { ascending: false }).limit(500);
  if (req.query.status) q = q.eq("status", req.query.status);
  q = dated(q, "created_at", req.query);
  const ids = await clientIds(req.query.client); if (ids) q = q.in("id", ids);
  return (await q).data || [];
}

/* withdrawal rule for display (the SQL function request_withdrawal enforces it) */
const eat = d => new Date(d.getTime() + 3 * 36e5).toISOString().slice(0, 10);
const gapDays = (a, b) => Math.round((Date.parse(a) - Date.parse(b)) / 864e5);
function rule(i, lim, idx, pend) {
  const act = new Date(new Date(i.paid_at).getTime() + 3 * 864e5);
  if (Date.now() < act) return { locked: true, activates_at: act };
  const today = eat(new Date()), first = eat(act), last = i.last_day || new Date(Date.parse(first) - 864e5).toISOString().slice(0, 10);
  const gap = gapDays(today, last);
  const cap = i.last_day === today ? +i.cap : lim * (gap - 1 > 1 ? gap : 1), used = i.last_day === today ? +i.used : 0;
  const val = Math.max(0, i.amount * idx / i.fund_index_at_buy - i.withdrawn);
  return { locked: false, limit: lim, cap, missed: Math.max(0, gap - 1), room: Math.max(0, Math.floor(Math.min(cap - used, val - pend))) };
}

/* ---------- Paystack webhook (raw body, before json parser) ---------- */
app.post("/api/paystack/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = crypto.createHmac("sha512", E.PAYSTACK_SECRET_KEY).update(req.body).digest("hex");
  if (sig !== req.headers["x-paystack-signature"]) return res.sendStatus(401);
  res.sendStatus(200);
  const ev = JSON.parse(req.body);
  if (ev.event !== "charge.success") return;
  const { reference, amount, metadata } = ev.data, plan = metadata?.plan, uid = metadata?.user_id;
  if (!PLANS[plan] || amount !== PLANS[plan] * 100) return audit(uid, `paystack mismatch ${reference}`);
  const { fund_index } = await settings(["fund_index"]);
  const { data: prior } = await sb.from("investments").select("id").eq("user_id", uid).limit(1);
  const { data: u } = await sb.from("users").select("referred_by").eq("id", uid).single();
  await sb.from("investments").insert({ user_id: uid, plan, amount: PLANS[plan], paystack_ref: reference,
    fund_index_at_buy: fund_index.idx, reward_for: !prior?.length ? u?.referred_by : null });   // unique ref ignores replays
});

app.use(express.json({ limit: "500kb" }));
app.get("/health", (_, res) => res.send("ok"));

/* ---------- public ---------- */
app.get("/api/public", async (_, res) => {
  const s = await settings(["brand", "rates", "fund_index", "withdraw_limits", "content"]);
  res.set("Cache-Control", "public, max-age=30").json({ brand: s.brand, rates: s.rates, idx: s.fund_index.idx, limits: s.withdraw_limits, plans: PLANS, content: s.content || {} });
});
app.post("/api/contact", rateLimit({ windowMs: 6e5, max: 5 }), async (req, res) => {
  const { name, email, body } = req.body;
  if (!name || !/.+@.+\..+/.test(email) || !body) return res.status(400).json({ error: "invalid" });
  await sb.from("messages").insert({ name: String(name).slice(0, 100), email, body: String(body).slice(0, 2000) });
  res.json({ ok: true });
});

/* ---------- register / login (3 strikes lock) ---------- */
app.post("/api/register", rateLimit({ windowMs: 36e5, max: 10 }), async (req, res) => {
  const { first_name, last_name, email, phone: ph, username, id_number, password, ref } = req.body;
  if (!(first_name && last_name && /.+@.+\..+/.test(email) && ph && username && id_number && password?.length >= 8)) return res.status(400).json({ error: "invalid" });
  const { data: r } = ref ? await sb.from("users").select("id").eq("ref_code", clean(ref).toUpperCase()).maybeSingle() : { data: null };
  const { error } = await sb.from("users").insert({ first_name, last_name, email: email.toLowerCase(), phone: ph, username, id_number,
    password_hash: await bcrypt.hash(password, 12), referred_by: r?.id ?? null });
  if (error) return res.status(409).json({ error: "username_or_email_taken" });
  res.json({ ok: true });
});
app.post("/api/login", rateLimit({ windowMs: 6e5, max: 30 }), async (req, res) => {
  const id = clean(req.body.identifier);
  const { data: u } = await sb.from("users").select("*").or(`username.ilike.${id},email.ilike.${id}`).maybeSingle();
  if (!u) return res.status(401).json({ error: "bad_credentials" });
  if (u.lock_until && new Date(u.lock_until) > new Date()) return res.status(423).json({ error: "temporarily_locked" });
  if (u.locked) return res.status(423).json({ error: "locked_ask_admin" });
  if (!(await bcrypt.compare(req.body.password || "", u.password_hash))) {
    const n = u.failed_attempts + 1, lock = n >= 3;
    await sb.from("users").update(lock ? { failed_attempts: 0, ...(u.role === "superadmin" ? { lock_until: new Date(Date.now() + 15 * 6e4) } : { locked: true }) } : { failed_attempts: n }).eq("id", u.id);
    if (lock) await audit(u.id, "account locked");
    return res.status(lock ? 423 : 401).json({ error: lock ? "locked" : "bad_credentials", attempts_left: Math.max(0, 3 - n) });
  }
  await sb.from("users").update({ failed_attempts: 0 }).eq("id", u.id);
  res.json({ token: jwt.sign({ sub: u.id }, E.JWT_SECRET, { expiresIn: "8h" }), role: u.role });
});

/* ---------- password reset: email code (Resend) AND SMS code (TalkSasa) ---------- */
app.post("/api/forgot", rateLimit({ windowMs: 6e5, max: 5 }), async (req, res) => {
  const id = clean(req.body.identifier);
  const { data: u } = await sb.from("users").select("id,email,phone").or(`username.ilike.${id},email.ilike.${id}`).maybeSingle();
  if (u) {
    const ec = code(), sc = code();
    await sb.from("reset_codes").upsert({ user_id: u.id, email_hash: await bcrypt.hash(ec, 8), sms_hash: await bcrypt.hash(sc, 8), expires_at: new Date(Date.now() + 6e5), tries: 0 });
    await Promise.allSettled([sendEmail(u.email, "Your Money Market reset code", `<p>Your email code is <b>${ec}</b>. It expires in 10 minutes.</p>`),
      sendSms(u.phone, `Money Market reset code: ${sc}. Expires in 10 min.`)]);
  }
  res.json({ ok: true });
});
app.post("/api/reset", rateLimit({ windowMs: 6e5, max: 10 }), async (req, res) => {
  const { email_code, sms_code, password } = req.body, id = clean(req.body.identifier);
  if (!(password?.length >= 8)) return res.status(400).json({ error: "weak_password" });
  const { data: u } = await sb.from("users").select("id").or(`username.ilike.${id},email.ilike.${id}`).maybeSingle();
  const { data: c } = u ? await sb.from("reset_codes").select("*").eq("user_id", u.id).maybeSingle() : { data: null };
  if (!c || new Date(c.expires_at) < new Date() || c.tries >= 3) return res.status(400).json({ error: "start_again" });
  if (!((await bcrypt.compare(String(email_code), c.email_hash)) && (await bcrypt.compare(String(sms_code), c.sms_hash)))) {
    await sb.from("reset_codes").update({ tries: c.tries + 1 }).eq("user_id", u.id); return res.status(400).json({ error: "wrong_codes" }); }
  await sb.from("users").update({ password_hash: await bcrypt.hash(password, 12) }).eq("id", u.id);   // does not unlock
  await sb.from("reset_codes").delete().eq("user_id", u.id); await audit(u.id, "password reset");
  res.json({ ok: true });
});

/* ---------- client portal ---------- */
app.get("/api/me", auth(), async (req, res) => {
  const { data } = await sb.from("users").select("id,client_no,first_name,last_name,email,phone,username,id_number,role,status,ref_code,created_at").eq("id", req.user.id).single();
  res.json(data);
});
app.get("/api/me/summary", auth("user"), async (req, res) => {
  const s = await settings(["fund_index", "withdraw_limits"]), idx = s.fund_index.idx;
  const { data: inv } = await sb.from("investments").select("*").eq("user_id", req.user.id).order("paid_at", { ascending: false });
  const { data: wd } = await sb.from("withdrawals").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
  const { data: refs } = await sb.from("users").select("first_name,last_name,status,created_at").eq("referred_by", req.user.id);
  const { data: rew } = await sb.from("investments").select("amount").eq("reward_for", req.user.id);
  const investments = inv.map(i => ({ ...i, value: Math.max(0, i.amount * idx / i.fund_index_at_buy - i.withdrawn),
    rule: rule(i, s.withdraw_limits[i.plan], idx, wd.filter(w => w.investment_id === i.id && w.status === "pending").reduce((a, w) => a + +w.amount, 0)) }));
  res.json({ investments, withdrawals: wd, referrals: refs, rewards: rew.reduce((a, r) => a + r.amount * 0.01, 0), idx });
});
app.post("/api/checkout", auth("user"), async (req, res) => {
  const plan = req.body.plan;
  if (!PLANS[plan]) return res.status(400).json({ error: "bad_plan" });
  if (req.user.status !== "approved") return res.status(403).json({ error: "not_approved" });
  const r = await fetch("https://api.paystack.co/transaction/initialize", { method: "POST",
    headers: { Authorization: `Bearer ${E.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: req.user.email, amount: PLANS[plan] * 100, currency: "KES", callback_url: `${ORIGIN}/portal/home?paid=1`, metadata: { user_id: req.user.id, plan } }) });
  const d = await r.json();
  if (!d.status) return res.status(502).json({ error: "paystack_failed" });
  res.json({ url: d.data.authorization_url });
});
app.post("/api/withdrawals", auth("user"), async (req, res) => {
  if (req.user.status !== "approved") return res.status(403).json({ error: "not_approved" });
  const { data, error } = await sb.rpc("request_withdrawal", { p_user: req.user.id, p_inv: req.body.investment_id, p_amt: Math.floor(Number(req.body.amount)) });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

/* ---------- admin ---------- */
app.get("/api/admin/stats", admin, async (_, res) => {
  const c = async (t, f) => (await f(sb.from(t).select("id", { count: "exact", head: true }))).count;
  res.json({ pending_users: await c("users", q => q.eq("status", "pending").eq("role", "user")), locked_users: await c("users", q => q.eq("locked", true)),
    pending_withdrawals: await c("withdrawals", q => q.eq("status", "pending")), clients: await c("users", q => q.eq("role", "user")) });
});
app.get("/api/admin/users", admin, async (req, res) => res.json(await listU(req)));
app.get("/api/admin/users/:id", admin, async (req, res) => {
  const [u, i, w] = await Promise.all([sb.from("users").select("id,client_no,first_name,last_name,email,phone,username,id_number,status,locked,created_at").eq("id", req.params.id).single(),
    sb.from("investments").select("*").eq("user_id", req.params.id).order("paid_at", { ascending: false }), sb.from("withdrawals").select("*").eq("user_id", req.params.id).order("created_at", { ascending: false })]);
  res.json({ user: u.data, investments: i.data, withdrawals: w.data });
});
app.post("/api/admin/users/:id/status", admin, async (req, res) => {
  if (!["approved", "rejected"].includes(req.body.status)) return res.status(400).end();
  await sb.from("users").update({ status: req.body.status }).eq("id", req.params.id);
  await audit(req.user.id, `${req.body.status} user ${req.params.id}`); res.json({ ok: true });
});
app.post("/api/admin/users/:id/unlock", admin, async (req, res) => {
  await sb.from("users").update({ locked: false, failed_attempts: 0, lock_until: null }).eq("id", req.params.id);
  await audit(req.user.id, `unlocked ${req.params.id}`); res.json({ ok: true });
});
app.post("/api/admin/withdrawals/:id", admin, async (req, res) => {
  const { data: w } = await sb.from("withdrawals").select("*").eq("id", req.params.id).eq("status", "pending").single();
  if (!w) return res.status(404).end();
  const status = req.body.status === "approved" ? "approved" : "rejected";
  await sb.from("withdrawals").update({ status, decided_by: req.user.id, decided_at: new Date() }).eq("id", w.id);
  const { data: i } = await sb.from("investments").select("withdrawn,used").eq("id", w.investment_id).single();
  await sb.from("investments").update(status === "approved" ? { withdrawn: +i.withdrawn + +w.amount } : { used: Math.max(0, i.used - w.amount) }).eq("id", w.investment_id);
  await audit(req.user.id, `${status} withdrawal ${w.id}`); res.json({ ok: true });
});
app.get("/api/admin/messages", admin, async (_, res) => res.json((await sb.from("messages").select("*").order("created_at", { ascending: false }).limit(200)).data));
app.post("/api/admin/logo", admin, async (req, res) => {
  const m = /^data:(image\/(png|jpeg|webp|svg\+xml));base64,(.+)$/.exec(req.body.dataUrl || "");
  if (!m) return res.status(400).json({ error: "bad_image" });
  const buf = Buffer.from(m[3], "base64"); if (buf.length > 3e5) return res.status(413).json({ error: "too_big" });
  await sb.storage.from("brand").upload("logo", buf, { upsert: true, contentType: m[1] });   // create a public bucket named "brand"
  const url = sb.storage.from("brand").getPublicUrl("logo").data.publicUrl + "?v=" + Date.now();
  const { brand } = await settings(["brand"]);
  await sb.from("settings").update({ value: { ...brand, logo: url } }).eq("key", "brand");
  await audit(req.user.id, "logo updated"); res.json({ url });
});

/* ---------- shared by admin and finance (filters: from, to, client, status) ---------- */
app.get("/api/ops/payments", ops, async (req, res) => res.json(await listI(req)));
app.get("/api/ops/withdrawals", ops, async (req, res) => res.json(await listW(req)));
app.get("/api/ops/export/:type", ops, async (req, res) => {
  const t = req.params.type, name = u => u ? `${u.first_name} ${u.last_name}` : "";
  let body;
  if (t === "payments") body = csv(await listI(req), [["Date", r => r.paid_at], ["Client ID", r => r.users?.client_no], ["Client", r => name(r.users)], ["Plan", r => r.plan], ["Amount KES", r => r.amount], ["Reference", r => r.paystack_ref]]);
  else if (t === "withdrawals") body = csv(await listW(req), [["Date", r => r.created_at], ["Client ID", r => r.users?.client_no], ["Client", r => name(r.users)], ["Phone", r => r.users?.phone], ["Amount KES", r => r.amount], ["Status", r => r.status], ["Paid ref", r => r.paid_ref]]);
  else if (t === "users") body = csv(await listU(req), [["Client ID", r => r.client_no], ["Name", r => name(r)], ["Email", r => r.email], ["Phone", r => r.phone], ["Status", r => r.status], ["Registered", r => r.created_at]]);
  else return res.status(404).end();
  res.type("text/csv").set("Content-Disposition", `attachment; filename=${t}.csv`).send(body);
});

/* ---------- finance ---------- */
app.get("/api/finance/summary", fin, async (req, res) => {
  const inv = await listI(req), wd = await listW({ query: { from: req.query.from, to: req.query.to } });
  const sum = a => a.reduce((s, r) => s + +r.amount, 0), by = s => wd.filter(w => w.status === s);
  res.json({ payments: inv.length, total_in: sum(inv), pending_approval: sum(by("pending")), awaiting_payout: sum(by("approved")), awaiting_count: by("approved").length, paid_out: sum(by("paid")) });
});
app.post("/api/finance/withdrawals/:id/pay", fin, async (req, res) => {
  const ref = clean(req.body.reference); if (!ref) return res.status(400).json({ error: "reference_required" });
  const { data } = await sb.from("withdrawals").update({ status: "paid", paid_ref: ref, paid_at: new Date(), paid_by: req.user.id }).eq("id", req.params.id).eq("status", "approved").select("id");
  if (!data?.length) return res.status(404).json({ error: "not_awaiting_payout" });
  await audit(req.user.id, `paid withdrawal ${req.params.id} ref ${ref}`); res.json({ ok: true });
});

/* ---------- superadmin ---------- */
app.post("/api/super/valuation", superOnly, async (req, res) => {
  const r = Number(req.body.percent); if (!isFinite(r) || r <= -100) return res.status(400).end();
  const { fund_index } = await settings(["fund_index"]);
  await sb.from("settings").update({ value: { idx: fund_index.idx * (1 + r / 100) } }).eq("key", "fund_index");
  await audit(req.user.id, `valuation ${r}%`); res.json({ ok: true });
});
app.put("/api/super/settings/:key", superOnly, async (req, res) => {
  if (!["rates", "withdraw_limits", "brand", "content"].includes(req.params.key)) return res.status(400).end();
  if (JSON.stringify(req.body).length > 20000) return res.status(413).end();
  await sb.from("settings").update({ value: req.body }).eq("key", req.params.key);
  await audit(req.user.id, `settings ${req.params.key}`); res.json({ ok: true });
});
app.post("/api/super/users/:id/role", superOnly, async (req, res) => {
  if (!["user", "admin", "finance"].includes(req.body.role)) return res.status(400).end();
  await sb.from("users").update({ role: req.body.role }).eq("id", req.params.id);
  await audit(req.user.id, `role ${req.body.role} ${req.params.id}`); res.json({ ok: true });
});
app.get("/api/super/audit", superOnly, async (_, res) => res.json((await sb.from("audit_log").select("*").order("created_at", { ascending: false }).limit(200)).data));

/* ---------- assisted access: superadmin may open any client portal; acting needs the client's own acceptance ---------- */
const GRANT_MIN = 30;
const activeGrant = async uid => (await sb.from("assist_grants").select("*").eq("user_id", uid).in("status", ["pending", "accepted"]).order("requested_at", { ascending: false }).limit(1)).data?.[0] ?? null;
const liveGrant = g => !g ? null
  : g.status === "accepted" && new Date(g.expires_at) < new Date() ? { ...g, status: "expired" }
  : g.status === "pending" && Date.now() - new Date(g.requested_at) > 864e5 ? { ...g, status: "expired" } : g;
const isLive = g => g && ["pending", "accepted"].includes(g.status);

app.get("/api/super/users/:id/portal", superOnly, async (req, res) => {          // read-only view, no password needed
  const { data: u } = await sb.from("users").select("id,client_no,first_name,last_name,email,phone,username,id_number,role,status,ref_code,created_at").eq("id", req.params.id).single();
  if (!u || u.role !== "user") return res.status(404).json({ error: "not_found" });
  if (req.query.open) await audit(req.user.id, `opened portal of ${u.client_no}`);
  res.json({ ...(await summaryFor(u.id)), user: u, grant: liveGrant(await activeGrant(u.id)) });
});
app.post("/api/super/users/:id/assist-request", superOnly, async (req, res) => {
  const cur = liveGrant(await activeGrant(req.params.id));
  if (isLive(cur)) return res.json(cur);
  const { data } = await sb.from("assist_grants").insert({ user_id: req.params.id, requested_by: req.user.id }).select().single();
  const { data: u } = await sb.from("users").select("phone,client_no").eq("id", req.params.id).single();
  sendSms(u.phone, "Money Market support asked to help with your account. Log in to accept or decline.").catch(() => {});
  await audit(req.user.id, `asked ${u.client_no} for permission to act`); res.json(data);
});
app.post("/api/super/users/:id/act/withdrawal", superOnly, async (req, res) => {   // the only action support may take, and only with consent
  const g = liveGrant(await activeGrant(req.params.id));
  if (!g || g.status !== "accepted") return res.status(403).json({ error: "consent_required" });
  const { data, error } = await sb.rpc("request_withdrawal", { p_user: req.params.id, p_inv: req.body.investment_id, p_amt: Math.floor(Number(req.body.amount)) });
  if (error) return res.status(400).json({ error: error.message });
  await audit(req.user.id, `acted for ${req.params.id}: withdrawal ${Math.floor(Number(req.body.amount))} (consent ${g.id})`); res.json(data);
});
app.get("/api/me/assist", auth("user"), async (req, res) => {
  const g = liveGrant(await activeGrant(req.user.id));
  if (!isLive(g)) return res.json([]);
  const { data: by } = await sb.from("users").select("first_name,last_name").eq("id", g.requested_by).single();
  res.json([{ ...g, by: `${by.first_name} ${by.last_name}` }]);
});
app.post("/api/me/assist/:id", auth("user"), async (req, res) => {
  const { data: g } = await sb.from("assist_grants").select("*").eq("id", req.params.id).eq("user_id", req.user.id).eq("status", "pending").maybeSingle();
  if (!g || liveGrant(g).status !== "pending") return res.status(404).json({ error: "not_found" });
  const accept = !!req.body.accept;
  await sb.from("assist_grants").update({ status: accept ? "accepted" : "declined", decided_at: new Date(), expires_at: accept ? new Date(Date.now() + GRANT_MIN * 6e4) : null }).eq("id", g.id);
  await audit(req.user.id, `${accept ? "accepted" : "declined"} support access ${g.id}`); res.json({ ok: true });
});
app.post("/api/me/assist/:id/revoke", auth("user"), async (req, res) => {
  await sb.from("assist_grants").update({ status: "revoked", decided_at: new Date() }).eq("id", req.params.id).eq("user_id", req.user.id).eq("status", "accepted");
  await audit(req.user.id, `revoked support access ${req.params.id}`); res.json({ ok: true });
});

/* ---------- website: static files, SEO per page, real URLs ---------- */
const PAGES = {
  "/": ["Money Market – Invest in licensed money market funds in Kenya", "Plans from KES 1,000, withdrawals from KES 100, regional rates and 24/7 help. Returns vary and are not guaranteed."],
  "/rates": ["Rates by region – Money Market", "Indicative exchange rates and fund unit value in Kenya, Uganda, Tanzania, Rwanda, Nigeria, South Africa, UK, Eurozone and USA."],
  "/help": ["Help center – Money Market", "Answers on registration, payments, withdrawals, password reset and account locks."],
  "/about": ["About us – Money Market", "Who we are, how the funds work and our partner fund manager."],
  "/contact": ["Contact us – Money Market", "Email, phone and social handles for Money Market support."],
  "/terms": ["Terms and conditions – Money Market", "Terms, fees, withdrawals and risk warning."],
  "/login": ["Log in – Money Market", "Log in to your Money Market portal."],
  "/register": ["Create account – Money Market", "Register with your ID or passport to start investing."],
};
const tpl = fs.readFileSync(path.join(__dirname, "public/index.html"), "utf8");
app.get("/robots.txt", (_, res) => res.type("text/plain").send(`User-agent: *\nAllow: /\nDisallow: /portal\nDisallow: /api/\nSitemap: ${ORIGIN}/sitemap.xml\n`));
app.get("/sitemap.xml", (_, res) => res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${Object.keys(PAGES).filter(p => !["/login"].includes(p)).map(p => `<url><loc>${ORIGIN}${p}</loc></url>`).join("")}</urlset>`));
app.use(express.static(path.join(__dirname, "public"), { index: false, maxAge: "1h" }));
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "not_found" });
  const [t, d] = PAGES[req.path] || PAGES["/"], priv = req.path.startsWith("/portal") || req.path.startsWith("/join") || req.path === "/forgot";
  res.set("Cache-Control", "no-cache").type("html").send(tpl.replaceAll("{{TITLE}}", t).replaceAll("{{DESC}}", d)
    .replaceAll("{{CANON}}", ORIGIN + (PAGES[req.path] ? req.path : "/")).replaceAll("{{ORIGIN}}", ORIGIN).replaceAll("{{ROBOTS}}", priv ? "noindex, nofollow" : "index, follow, max-image-preview:large"));
});
app.listen(E.PORT || 3000, () => console.log("Money Market up on", E.PORT || 3000));
