const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function clean(v, max = 100) { return String(v ?? "").trim().slice(0, max); }
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function hex(bytes) { return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join(""); }
function randomHex(n = 32) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }
async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return `${b64(salt)}:${b64(bits)}`;
}
async function verifyPassword(password, saved) {
  try {
    const [saltText, hashText] = saved.split(":");
    const actual = await hashPassword(password, unb64(saltText));
    const a = unb64(actual.split(":")[1]), b = unb64(hashText);
    if (a.length !== b.length) return false;
    let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch { return false; }
}
function cookieValue(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) { const i = part.indexOf("="); if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim()); }
  return "";
}
function cookie(token, maxAge = 604800) {
  return `cm_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
async function body(request) {
  try { return await request.json(); } catch { return null; }
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, plan: u.plan, blocked: !!u.blocked, createdAt: u.created_at };
}
async function getUser(request, env) {
  const token = cookieValue(request, "cm_session");
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.id,u.name,u.email,u.role,u.plan,u.blocked,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.blocked=0"
  ).bind(await sha256(token), Date.now()).first();
  return row || null;
}
async function sha256(value) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
async function requireAuth(request, env) {
  const user = await getUser(request, env);
  return user;
}
async function ownerSeed(env) {
  const email = clean(env.OWNER_EMAIL, 160).toLowerCase();
  const password = String(env.OWNER_PASSWORD || "");
  if (!email || !password) throw new Error("Owner secrets are missing. Set OWNER_EMAIL and OWNER_PASSWORD in Worker Secrets.");
  let user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  if (!user) {
    const id = crypto.randomUUID();
    const password_hash = await hashPassword(password);
    await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,role,plan,blocked,created_at) VALUES (?,?,?,?,?,?,0,?)")
      .bind(id, "مالك الموقع", email, password_hash, "owner", "lifetime", Date.now()).run();
    user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  } else {
    // Worker Secrets are the source of truth for the owner's password and privileges.
    const password_hash = await hashPassword(password);
    await env.DB.prepare("UPDATE users SET password_hash=?,role='owner',plan='lifetime',blocked=0 WHERE id=?")
      .bind(password_hash, user.id).run();
    user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(user.id).first();
  }
  return user;
}
async function createSession(user, env) {
  const token = randomHex(32), expires = Date.now() + 7 * 86400000;
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)")
    .bind(await sha256(token), user.id, expires).run();
  return token;
}
async function settings(env) {
  const rows = await env.DB.prepare("SELECT key,value FROM settings").all();
  const s = Object.fromEntries((rows.results || []).map(x => [x.key, x.value]));
  return { siteName: s.siteName || "Chat MeGa AI", maintenance: s.maintenance === "true", freeDailyLimit: Number(s.freeDailyLimit || 15) };
}
async function routeApi(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (!env.DB) return json({ error: "قاعدة البيانات D1 غير مربوطة بالـ Worker. راجع README." }, 503);
  if (path === "/api/health" && method === "GET") {
    const checks = { worker: true, assets: !!env.ASSETS, databaseBinding: !!env.DB,
      ownerEmailConfigured: !!env.OWNER_EMAIL, ownerPasswordConfigured: !!env.OWNER_PASSWORD };
    if (!env.DB) return json({ ok: false, checks, error: "قاعدة D1 غير مربوطة. أضف binding باسم DB في wrangler.toml." }, 503);
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      await env.DB.prepare("SELECT id FROM users LIMIT 1").first();
      await env.DB.prepare("SELECT key FROM settings LIMIT 1").first();
      checks.databaseTables = true;
      const ok = checks.ownerEmailConfigured && checks.ownerPasswordConfigured;
      return json({ ok, checks, error: ok ? null : "أضف OWNER_EMAIL وOWNER_PASSWORD كأسرار Worker." }, ok ? 200 : 503);
    } catch (error) {
      return json({ ok: false, checks, error: "جداول D1 غير جاهزة. نفّذ schema.sql على قاعدة البيانات." }, 503);
    }
  }
  if (path === "/api/status" && method === "GET") {
    const s = await settings(env);
    return json({ aiConfigured: !!env.OPENAI_API_KEY, siteName: s.siteName });
  }
  if (path === "/api/register" && method === "POST") {
    const data = await body(request); if (!data) return json({ error: "بيانات الطلب غير صالحة." }, 400);
    const name = clean(data.name, 50), email = clean(data.email, 160).toLowerCase(), password = String(data.password || "");
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10) return json({ error: "أدخل اسماً وبريداً صحيحاً وكلمة مرور من 10 أحرف على الأقل." }, 400);
    if (email === clean(env.OWNER_EMAIL, 160).toLowerCase()) return json({ error: "هذا البريد مخصص لمالك الموقع." }, 409);
    if (await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first()) return json({ error: "هذا البريد مسجل بالفعل." }, 409);
    const user = { id: crypto.randomUUID(), name, email, role: "user", plan: "free", blocked: 0, created_at: Date.now() };
    const passwordHash = await hashPassword(password);
    await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,role,plan,blocked,created_at) VALUES (?,?,?,?,?,?,0,?)")
      .bind(user.id, name, email, passwordHash, "user", "free", user.created_at).run();
    const token = await createSession(user, env);
    return json({ user: publicUser(user) }, 200, { "set-cookie": cookie(token) });
  }
  if (path === "/api/login" && method === "POST") {
    const data = await body(request); if (!data) return json({ error: "بيانات الطلب غير صالحة." }, 400);
    const email = clean(data.email, 160).toLowerCase(), password = String(data.password || "");
    let user = null;
    if (email === clean(env.OWNER_EMAIL, 160).toLowerCase()) user = await ownerSeed(env);
    else user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    if (!user || user.blocked || !(await verifyPassword(password, user.password_hash))) return json({ error: "بيانات الدخول غير صحيحة أو الحساب موقوف." }, 401);
    const token = await createSession(user, env);
    return json({ user: publicUser(user) }, 200, { "set-cookie": cookie(token) });
  }
  if (path === "/api/logout" && method === "POST") {
    const token = cookieValue(request, "cm_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
  }
  if (path === "/api/me" && method === "GET") {
    const user = await requireAuth(request, env); if (!user) return json({ error: "سجّل الدخول أولاً." }, 401);
    const s = await settings(env);
    return json({ user: publicUser(user), settings: { siteName: s.siteName, maintenance: s.maintenance } });
  }
  if (path.startsWith("/api/admin/")) {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: "سجّل الدخول أولاً." }, 401);
    if (user.role !== "owner") return json({ error: "هذه الصلاحية للمالك فقط." }, 403);
    if (path === "/api/admin/overview" && method === "GET") {
      const rows = await env.DB.prepare("SELECT id,name,email,role,plan,blocked,created_at FROM users ORDER BY created_at DESC").all();
      return json({ users: (rows.results || []).map(publicUser), settings: await settings(env), totalUsers: (rows.results || []).length });
    }
    if (path === "/api/admin/settings" && method === "PATCH") {
      const data = await body(request); if (!data) return json({ error: "بيانات الطلب غير صالحة." }, 400);
      const s = { siteName: clean(data.siteName, 60) || "Chat MeGa AI", freeDailyLimit: Math.max(1, Math.min(500, Number(data.freeDailyLimit) || 15)), maintenance: !!data.maintenance };
      for (const [k,v] of Object.entries(s)) await env.DB.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, String(v)).run();
      return json({ settings: s });
    }
    const match = path.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (match && method === "PATCH") {
      const target = await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(match[1]).first();
      if (!target) return json({ error: "المستخدم غير موجود." }, 404);
      if (target.role === "owner") return json({ error: "لا يمكن تعديل حساب المالك من هذه الشاشة." }, 400);
      const data = await body(request); if (!data) return json({ error: "بيانات الطلب غير صالحة." }, 400);
      if (typeof data.blocked === "boolean") await env.DB.prepare("UPDATE users SET blocked=? WHERE id=?").bind(data.blocked ? 1 : 0, target.id).run();
      if (["free","premium"].includes(data.plan)) await env.DB.prepare("UPDATE users SET plan=? WHERE id=?").bind(data.plan, target.id).run();
      const updated = await env.DB.prepare("SELECT id,name,email,role,plan,blocked,created_at FROM users WHERE id=?").bind(target.id).first();
      return json({ user: publicUser(updated) });
    }
  }
  if (path === "/api/chat" && method === "POST") {
    const user = await requireAuth(request, env); if (!user) return json({ error: "سجّل الدخول أولاً." }, 401);
    const s = await settings(env);
    if (s.maintenance && user.role !== "owner") return json({ error: "الموقع في وضع الصيانة حالياً." }, 503);
    if (!env.OPENAI_API_KEY) return json({ error: "خدمة الذكاء الاصطناعي غير مفعّلة. أضف OPENAI_API_KEY في Worker Secrets." }, 503);
    const data = await body(request); const messages = Array.isArray(data?.messages) ? data.messages : [];
    if (!messages.length || messages.length > 30) return json({ error: "المحادثة غير صالحة." }, 400);
    const day = new Date().toISOString().slice(0,10), key = `${user.id}:${day}`;
    const usedRow = await env.DB.prepare("SELECT count FROM usage WHERE usage_key=?").bind(key).first();
    const used = Number(usedRow?.count || 0), unlimited = user.role === "owner" || user.plan === "lifetime";
    const limit = user.plan === "premium" ? 300 : s.freeDailyLimit;
    if (!unlimited && used >= limit) return json({ error: "وصلت إلى الحد اليومي للرسائل." }, 429);
    const safeMessages = messages.slice(-20).map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: clean(m.content, 8000) }));
    try {
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "authorization": `Bearer ${env.OPENAI_API_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ model: env.OPENAI_MODEL || "gpt-4o-mini", messages: [{ role: "system", content: `أنت ${s.siteName}، مساعد ذكي مفيد. أجب بلغة المستخدم وبوضوح.` }, ...safeMessages], max_tokens: 1400 })
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) return json({ error: result.error?.message || "تعذر الاتصال بخدمة الذكاء الاصطناعي." }, 502);
      await env.DB.prepare("INSERT INTO usage (usage_key,count) VALUES (?,1) ON CONFLICT(usage_key) DO UPDATE SET count=count+1").bind(key).run();
      return json({ reply: result.choices?.[0]?.message?.content || "لم أتمكن من إنشاء رد.", unlimited, remaining: unlimited ? null : Math.max(0, limit-used-1) });
    } catch { return json({ error: "حدث خطأ أثناء الاتصال بخدمة الذكاء الاصطناعي." }, 502); }
  }
  return json({ error: "المسار غير موجود." }, 404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = { "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "x-frame-options": "DENY" };
    try {
      if (url.pathname.startsWith("/api/")) return await routeApi(request, env);
      if (url.pathname === "/admin" || url.pathname === "/admin/") url.pathname = "/admin.html";
      const assetRequest = new Request(url.toString(), request);
      const response = await env.ASSETS.fetch(assetRequest);
      const outHeaders = new Headers(response.headers);
      for (const [k,v] of Object.entries(headers)) outHeaders.set(k,v);
      return new Response(response.body, { status: response.status, headers: outHeaders });
    } catch (err) {
      console.error("Worker error:", err?.stack || err);
      return json({ error: "حدث خطأ داخلي في الخادم. تحقق من إعدادات Worker وD1." }, 500, headers);
    }
  }
};
