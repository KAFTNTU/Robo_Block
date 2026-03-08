import { signJwt, verifyJwt, hashPassword, verifyPassword, json, corsHeaders } from "./auth-utils";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(req.headers.get("Origin") || "*") });
    }

    if (url.pathname === "/health") return new Response("ok");

    if (url.pathname.startsWith("/auth/")) return handleAuth(req, env, url);
    if (url.pathname.startsWith("/admin/")) return handleAdmin(req, env, url);

    if (url.pathname === "/ws") {
      if ((req.headers.get("Upgrade") || "").toLowerCase() !== "websocket")
        return new Response("Expected websocket", { status: 426 });
      const room = url.searchParams.get("room") || "default";
      const id = env.ROOMS.idFromName(room);
      return env.ROOMS.get(id).fetch(req);
    }

    return new Response("Not found", { status: 404 });
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

async function getUser(req: Request, env: Env): Promise<any | null> {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) return null;
  return await verifyJwt(token, env.JWT_SECRET);
}

function checkAdmin(req: Request, env: Env, url: URL): boolean {
  const key = url.searchParams.get("admin_key") || req.headers.get("X-Admin-Key") || "";
  return key === env.ADMIN_KEY;
}

async function auditLog(env: Env, action: string, userId: number | null, actorId: number | null, ip: string, meta?: object) {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_log (action, user_id, actor_id, ip, meta) VALUES (?,?,?,?,?)"
    ).bind(action, userId, actorId, ip, meta ? JSON.stringify(meta) : null).run();
  } catch (_) {}
}

function getIp(req: Request): string {
  return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "?";
}

function randomKey(len = 16): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) s += chars[b % chars.length];
  return s.slice(0,4)+"-"+s.slice(4,8)+"-"+s.slice(8,12)+"-"+s.slice(12,16);
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

async function handleAuth(req: Request, env: Env, url: URL): Promise<Response> {
  const origin = req.headers.get("Origin") || "*";
  const ip = getIp(req);

  // POST /auth/register
  if (url.pathname === "/auth/register" && req.method === "POST") {
    const { email, password, username, invite_key } = await req.json() as any;
    if (!email || !password || !username)
      return json({ error: "Заповніть всі поля" }, 400, origin);
    if (password.length < 6)
      return json({ error: "Пароль мінімум 6 символів" }, 400, origin);

    // Перевірити invite_key якщо потрібно
    let keyRow: any = null;
    if (env.REQUIRE_INVITE_KEY === "1") {
      if (!invite_key) return json({ error: "Потрібен запрошувальний ключ" }, 403, origin);
      keyRow = await env.DB.prepare("SELECT id FROM invite_keys WHERE key=? AND used_by IS NULL").bind(invite_key.trim().toUpperCase()).first();
      if (!keyRow) return json({ error: "Ключ недійсний або вже використаний" }, 403, origin);
    }

    const existing = await env.DB.prepare("SELECT id FROM users WHERE email=?")
      .bind(email.toLowerCase()).first();
    if (existing) return json({ error: "Ця пошта вже зареєстрована" }, 409, origin);

    const hash = await hashPassword(password);
    const result = await env.DB.prepare(
      "INSERT INTO users (email,username,password_hash) VALUES (?,?,?) RETURNING id"
    ).bind(email.toLowerCase(), username, hash).first() as any;

    if (keyRow) {
      await env.DB.prepare("UPDATE invite_keys SET used_by=?,used_at=unixepoch() WHERE id=?")
        .bind(result.id, keyRow.id).run();
    }

    await auditLog(env, "register", result.id, null, ip, { email, username });
    const token = await signJwt({ sub: result.id, email: email.toLowerCase(), username }, env.JWT_SECRET);
    return json({ token, user: { id: result.id, email, username } }, 201, origin);
  }

  // POST /auth/login
  if (url.pathname === "/auth/login" && req.method === "POST") {
    const { email, password } = await req.json() as any;
    if (!email || !password) return json({ error: "Введіть пошту та пароль" }, 400, origin);

    const user = await env.DB.prepare(
      "SELECT id,email,username,password_hash,is_blocked FROM users WHERE email=?"
    ).bind(email.toLowerCase()).first() as any;

    if (!user || !user.password_hash) return json({ error: "Невірна пошта або пароль" }, 401, origin);
    if (user.is_blocked) return json({ error: "Акаунт заблоковано" }, 403, origin);
    if (!await verifyPassword(password, user.password_hash)) return json({ error: "Невірна пошта або пароль" }, 401, origin);

    await env.DB.prepare("UPDATE users SET last_login=unixepoch() WHERE id=?").bind(user.id).run();
    await auditLog(env, "login", user.id, null, ip);
    const token = await signJwt({ sub: user.id, email: user.email, username: user.username }, env.JWT_SECRET);
    return json({ token, user: { id: user.id, email: user.email, username: user.username } }, 200, origin);
  }

  // GET /auth/google
  if (url.pathname === "/auth/google" && req.method === "GET") {
    const params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: `${env.APP_URL}/auth/google/callback`,
      response_type: "code",
      scope: "openid email profile",
      access_type: "offline",
    });
    return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
  }

  // GET /auth/google/callback
  if (url.pathname === "/auth/google/callback" && req.method === "GET") {
    const code = url.searchParams.get("code");
    if (!code) return json({ error: "Немає коду авторизації" }, 400, origin);

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${env.APP_URL}/auth/google/callback`, grant_type: "authorization_code",
      }),
    });
    if (!tokenRes.ok) return json({ error: "Помилка Google OAuth" }, 502, origin);
    const { access_token } = await tokenRes.json() as any;

    const profile = await (await fetch("https://www.googleapis.com/oauth2/v3/userinfo",
      { headers: { Authorization: `Bearer ${access_token}` } })).json() as any;

    let user = await env.DB.prepare(
      "SELECT id,email,username,is_blocked FROM users WHERE google_id=? OR email=?"
    ).bind(profile.sub, profile.email).first() as any;

    if (user?.is_blocked) return Response.redirect(`${env.APP_URL}/?error=blocked#auth`, 302);

    if (!user) {
      user = await env.DB.prepare(
        "INSERT INTO users (email,username,google_id,avatar_url) VALUES (?,?,?,?) RETURNING id,email,username"
      ).bind(profile.email, profile.name, profile.sub, profile.picture).first() as any;
      await auditLog(env, "register", user.id, null, ip, { via: "google" });
    } else if (!user.google_id) {
      await env.DB.prepare("UPDATE users SET google_id=?,avatar_url=? WHERE id=?")
        .bind(profile.sub, profile.picture, user.id).run();
    }

    await env.DB.prepare("UPDATE users SET last_login=unixepoch() WHERE id=?").bind(user.id).run();
    await auditLog(env, "login", user.id, null, ip, { via: "google" });
    const jwtToken = await signJwt({ sub: user.id, email: user.email, username: user.username }, env.JWT_SECRET);
    return Response.redirect(`${env.APP_URL}/?token=${jwtToken}#auth`, 302);
  }

  // GET /auth/me
  if (url.pathname === "/auth/me" && req.method === "GET") {
    const token = req.headers.get("Authorization")?.replace("Bearer ", "");
    if (!token) return json({ error: "Не авторизовано" }, 401, origin);
    const payload = await verifyJwt(token, env.JWT_SECRET);
    if (!payload) return json({ error: "Токен недійсний" }, 401, origin);
    const user = await env.DB.prepare(
      "SELECT id,email,username,avatar_url,created_at FROM users WHERE id=?"
    ).bind(payload.sub).first();
    if (!user) return json({ error: "Користувача не знайдено" }, 404, origin);
    return json({ user }, 200, origin);
  }

  // SESSION endpoints
  if (url.pathname === "/auth/session/start" && req.method === "POST") {
    const user = await getUser(req, env);
    if (!user) return json({ error: "Не авторизовано" }, 401, origin);
    const result = await env.DB.prepare("INSERT INTO sessions (user_id) VALUES (?) RETURNING id")
      .bind(user.sub).first() as any;
    return json({ session_id: result.id }, 200, origin);
  }

  if (url.pathname === "/auth/session/heartbeat" && req.method === "POST") {
    const user = await getUser(req, env);
    if (!user) return json({ ok: false }, 401, origin);
    const { session_id } = await req.json() as any;
    await env.DB.prepare(
      "UPDATE sessions SET last_heartbeat=unixepoch(),duration_seconds=unixepoch()-started_at WHERE id=? AND user_id=?"
    ).bind(session_id, user.sub).run();
    return json({ ok: true }, 200, origin);
  }

  if (url.pathname === "/auth/session/end" && req.method === "POST") {
    const user = await getUser(req, env);
    if (!user) return json({ ok: false }, 401, origin);
    const { session_id } = await req.json() as any;
    await env.DB.prepare(
      "UPDATE sessions SET ended_at=unixepoch(),duration_seconds=unixepoch()-started_at WHERE id=? AND user_id=?"
    ).bind(session_id, user.sub).run();
    return json({ ok: true }, 200, origin);
  }

  return json({ error: "Not found" }, 404, origin);
}

// ── Admin handlers ─────────────────────────────────────────────────────────────

async function handleAdmin(req: Request, env: Env, url: URL): Promise<Response> {
  const origin = req.headers.get("Origin") || "*";
  const ip = getIp(req);

  if (!checkAdmin(req, env, url))
    return json({ error: "Доступ заборонено" }, 403, origin);

  // GET /admin/users — список всіх користувачів
  if (url.pathname === "/admin/users" && req.method === "GET") {
    const page = parseInt(url.searchParams.get("page") || "1");
    const limit = 50;
    const offset = (page - 1) * limit;
    const search = url.searchParams.get("q") || "";

    const rows = search
      ? await env.DB.prepare(
          "SELECT id,email,username,is_blocked,created_at,last_login FROM users WHERE email LIKE ? OR username LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ).bind(`%${search}%`, `%${search}%`, limit, offset).all()
      : await env.DB.prepare(
          "SELECT id,email,username,is_blocked,created_at,last_login FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ).bind(limit, offset).all();

    const total = (await env.DB.prepare("SELECT COUNT(*) as c FROM users").first() as any)?.c || 0;
    return json({ users: rows.results, total, page }, 200, origin);
  }

  // DELETE /admin/users/:id — видалити користувача
  if (url.pathname.match(/^\/admin\/users\/\d+$/) && req.method === "DELETE") {
    const userId = parseInt(url.pathname.split("/")[3]);
    const user = await env.DB.prepare("SELECT email,username FROM users WHERE id=?").bind(userId).first() as any;
    if (!user) return json({ error: "Користувача не знайдено" }, 404, origin);
    await env.DB.prepare("DELETE FROM users WHERE id=?").bind(userId).run();
    await auditLog(env, "delete", userId, null, ip, { email: user.email, username: user.username });
    return json({ ok: true }, 200, origin);
  }

  // POST /admin/users/:id/block — заблокувати
  if (url.pathname.match(/^\/admin\/users\/\d+\/block$/) && req.method === "POST") {
    const userId = parseInt(url.pathname.split("/")[3]);
    await env.DB.prepare("UPDATE users SET is_blocked=1 WHERE id=?").bind(userId).run();
    await auditLog(env, "block", userId, null, ip);
    return json({ ok: true }, 200, origin);
  }

  // POST /admin/users/:id/unblock — розблокувати
  if (url.pathname.match(/^\/admin\/users\/\d+\/unblock$/) && req.method === "POST") {
    const userId = parseInt(url.pathname.split("/")[3]);
    await env.DB.prepare("UPDATE users SET is_blocked=0 WHERE id=?").bind(userId).run();
    await auditLog(env, "unblock", userId, null, ip);
    return json({ ok: true }, 200, origin);
  }

  // GET /admin/keys — список ключів
  if (url.pathname === "/admin/keys" && req.method === "GET") {
    const rows = await env.DB.prepare(`
      SELECT k.id, k.key, k.note, k.created_at, k.used_at,
             u.username as used_by_name, u.email as used_by_email
      FROM invite_keys k
      LEFT JOIN users u ON u.id = k.used_by
      ORDER BY k.created_at DESC LIMIT 200
    `).all();
    return json({ keys: rows.results }, 200, origin);
  }

  // POST /admin/keys — створити новий ключ (або кілька)
  if (url.pathname === "/admin/keys" && req.method === "POST") {
    const body = await req.json() as any;
    const count = Math.min(parseInt(body.count) || 1, 50);
    const note = body.note || null;
    const created: string[] = [];
    for (let i = 0; i < count; i++) {
      const key = randomKey();
      await env.DB.prepare("INSERT INTO invite_keys (key,note) VALUES (?,?)").bind(key, note).run();
      await auditLog(env, "key_create", null, null, ip, { key, note });
      created.push(key);
    }
    return json({ keys: created }, 201, origin);
  }

  // DELETE /admin/keys/:id — видалити невикористаний ключ
  if (url.pathname.match(/^\/admin\/keys\/\d+$/) && req.method === "DELETE") {
    const keyId = parseInt(url.pathname.split("/")[3]);
    await env.DB.prepare("DELETE FROM invite_keys WHERE id=? AND used_by IS NULL").bind(keyId).run();
    return json({ ok: true }, 200, origin);
  }

  // GET /admin/journal — журнал дій
  if (url.pathname === "/admin/journal" && req.method === "GET") {
    const limit = parseInt(url.searchParams.get("limit") || "100");
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const action = url.searchParams.get("action") || null;

    const rows = action
      ? await env.DB.prepare(`
          SELECT a.id,a.ts,a.action,a.ip,a.meta,
                 u.username as user_name, u.email as user_email
          FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
          WHERE a.action=? ORDER BY a.ts DESC LIMIT ? OFFSET ?
        `).bind(action, limit, offset).all()
      : await env.DB.prepare(`
          SELECT a.id,a.ts,a.action,a.ip,a.meta,
                 u.username as user_name, u.email as user_email
          FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
          ORDER BY a.ts DESC LIMIT ? OFFSET ?
        `).bind(limit, offset).all();

    const total = (await env.DB.prepare("SELECT COUNT(*) as c FROM audit_log").first() as any)?.c || 0;
    return json({ log: rows.results, total }, 200, origin);
  }

  // GET /admin/stats + /auth/stats — статистика по логінах
  if ((url.pathname === "/admin/stats" || url.pathname === "/auth/stats") && req.method === "GET") {
    const [totalUsers, todayLogins, weekLogins, monthLogins, dailyLogins, topUsers, newUsersDaily, usersList] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) as count FROM users").first() as Promise<any>,
      env.DB.prepare("SELECT COUNT(DISTINCT user_id) as count FROM audit_log WHERE action='login' AND ts >= unixepoch('now','start of day')").first() as Promise<any>,
      env.DB.prepare("SELECT COUNT(DISTINCT user_id) as count FROM audit_log WHERE action='login' AND ts >= unixepoch()-604800").first() as Promise<any>,
      env.DB.prepare("SELECT COUNT(DISTINCT user_id) as count FROM audit_log WHERE action='login' AND ts >= unixepoch()-2592000").first() as Promise<any>,
      env.DB.prepare("SELECT date(ts,'unixepoch') as day, COUNT(DISTINCT user_id) as unique_users, COUNT(*) as total_logins FROM audit_log WHERE action='login' AND ts >= unixepoch()-2592000 GROUP BY day ORDER BY day DESC").all(),
      env.DB.prepare("SELECT u.username, u.email, COUNT(a.id) as login_count, MAX(a.ts) as last_login FROM users u LEFT JOIN audit_log a ON a.user_id=u.id AND a.action='login' AND a.ts >= unixepoch()-2592000 GROUP BY u.id ORDER BY login_count DESC LIMIT 20").all(),
      env.DB.prepare("SELECT date(created_at,'unixepoch') as day, COUNT(*) as new_users FROM users WHERE created_at >= unixepoch()-2592000 GROUP BY day ORDER BY day DESC").all(),
      env.DB.prepare("SELECT id,email,username,role,is_blocked,datetime(created_at,'unixepoch') as registered,datetime(last_login,'unixepoch') as last_seen FROM users ORDER BY created_at DESC LIMIT 500").all(),
    ]);
    return json({
      summary: { total_users: totalUsers?.count||0, active_today: todayLogins?.count||0, active_week: weekLogins?.count||0, active_month: monthLogins?.count||0 },
      daily_stats: dailyLogins.results, top_users: topUsers.results, new_users_daily: newUsersDaily.results,
      users: usersList.results,
    }, 200, origin);
  }

  // GET /admin/teachers — список вчителів з кількістю учнів
  if (url.pathname === "/admin/teachers" && req.method === "GET") {
    const rows = await env.DB.prepare(`
      SELECT u.id, u.username, u.email,
             datetime(u.last_login,'unixepoch') as last_seen,
             COUNT(ts.id) as student_count
      FROM users u
      LEFT JOIN teacher_students ts ON ts.teacher_id = u.id
      WHERE u.role = 'teacher'
      GROUP BY u.id ORDER BY u.username
    `).all();
    return json({ teachers: rows.results }, 200, origin);
  }

  // GET /admin/teacher-journal — журнал відвідуваності вчителя
  if (url.pathname === "/admin/teacher-journal" && req.method === "GET") {
    const teacherId = parseInt(url.searchParams.get("teacher_id") || "0");
    const from = url.searchParams.get("from") || "";
    const to   = url.searchParams.get("to")   || "";
    if (!teacherId) return json({ error: "teacher_id required" }, 400, origin);

    const teacher = await env.DB.prepare("SELECT id,username,email FROM users WHERE id=?").bind(teacherId).first();
    const students = await env.DB.prepare(
      "SELECT id, full_name FROM teacher_students WHERE teacher_id=? ORDER BY full_name"
    ).bind(teacherId).all();
    const marks = (from && to)
      ? await env.DB.prepare(
          "SELECT student_id,date,status FROM attendance WHERE teacher_id=? AND date>=? AND date<=? ORDER BY date"
        ).bind(teacherId, from, to).all()
      : await env.DB.prepare(
          "SELECT student_id,date,status FROM attendance WHERE teacher_id=? ORDER BY date"
        ).bind(teacherId).all();

    return json({ teacher, students: students.results, marks: marks.results, from, to }, 200, origin);
  }

  // DELETE /admin/user — видалити за email або username
  if (url.pathname === "/admin/user" && req.method === "DELETE") {
    const { query } = await req.json() as any;
    if (!query) return json({ error: "query required" }, 400, origin);
    const user = await env.DB.prepare(
      "SELECT id,email,username FROM users WHERE email=? OR username=?"
    ).bind(query, query).first() as any;
    if (!user) return json({ error: "Не знайдено" }, 404, origin);
    await env.DB.prepare("DELETE FROM users WHERE id=?").bind(user.id).run();
    await auditLog(env, "delete", user.id, null, ip, { email: user.email });
    return json({ ok: true }, 200, origin);
  }

  // POST /admin/set-role — призначити роль
  if (url.pathname === "/admin/set-role" && req.method === "POST") {
    const { query, role } = await req.json() as any;
    if (!query || !role) return json({ error: "query і role required" }, 400, origin);
    const user = await env.DB.prepare(
      "SELECT id FROM users WHERE email=? OR username=?"
    ).bind(query, query).first() as any;
    if (!user) return json({ error: "Не знайдено" }, 404, origin);
    await env.DB.prepare("UPDATE users SET role=? WHERE id=?").bind(role, user.id).run();
    await auditLog(env, "set_role", user.id, null, ip, { role });
    return json({ ok: true }, 200, origin);
  }

  // POST /admin/users/:id/block | /unblock
  if (url.pathname.match(/^\/admin\/users\/\d+\/(block|unblock)$/) && req.method === "POST") {
    const parts = url.pathname.split("/");
    const userId = parseInt(parts[3]);
    const action = parts[4] as "block"|"unblock";
    await env.DB.prepare("UPDATE users SET is_blocked=? WHERE id=?").bind(action==="block"?1:0, userId).run();
    await auditLog(env, action, userId, null, ip);
    return json({ ok: true }, 200, origin);
  }

  return json({ error: "Not found" }, 404, origin);
}

// ── Durable Object ────────────────────────────────────────────────────────────

type PID = "p1" | "p2";
type Bot = { x:number; y:number; a:number; vx:number; vy:number; wa:number; l:number; r:number };
function clamp(v:number,a:number,b:number){ return v<a?a:(v>b?b:v); }

export class RoomDO {
  state: DurableObjectState; env: Env;
  wsByPid: Record<PID, WebSocket|null> = { p1:null, p2:null };
  pidByWs = new Map<WebSocket, PID>();
  inputs: Record<PID, { l:number; r:number }> = { p1:{l:0,r:0}, p2:{l:0,r:0} };
  bots: Record<PID, Bot>;
  tick=0; loopStarted=false;
  phase: "lobby"|"countdown"|"fight"|"end" = "fight";

  constructor(state: DurableObjectState, env: Env) {
    this.state=state; this.env=env;
    this.bots = {
      p1:{x:-150,y:0,a:0,vx:0,vy:0,wa:0,l:0,r:0},
      p2:{x:150,y:0,a:Math.PI,vx:0,vy:0,wa:0,l:0,r:0},
    };
  }

  private visibleBots(){ return { p1:{x:this.bots.p1.x,y:this.bots.p1.y,a:this.bots.p1.a}, p2:{x:this.bots.p2.x,y:this.bots.p2.y,a:this.bots.p2.a} }; }

  async fetch(req: Request): Promise<Response> {
    if (new URL(req.url).pathname !== "/ws") return new Response("ok");
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as WebSocket[];
    server.accept();
    const pid: PID = this.wsByPid.p1 ? "p2" : "p1";
    this.wsByPid[pid]=server; this.pidByWs.set(server, pid);
    server.send(JSON.stringify({ t:"hello", pid, bots:this.visibleBots(), phase:this.phase }));
    server.addEventListener("message", (ev) => {
      try {
        const data = JSON.parse(typeof ev.data==="string"?ev.data:"");
        const who = this.pidByWs.get(server)||pid;
        if (data?.t==="input") { const m=data; this.inputs[who]={l:clamp(Number(m.l)||0,-100,100),r:clamp(Number(m.r)||0,-100,100)}; }
        if (data?.t==="restart") this.resetBots();
      } catch(_) {}
    });
    server.addEventListener("close", () => { this.pidByWs.delete(server); if(this.wsByPid[pid]===server) this.wsByPid[pid]=null; });
    if (!this.loopStarted) { this.loopStarted=true; await this.state.storage.setAlarm(Date.now()+33); }
    return new Response(null, { status:101, webSocket:client });
  }

  async alarm() {
    if (!this.wsByPid.p1 && !this.wsByPid.p2) { this.loopStarted=false; return; }
    const dt=1/30; this.tick++;
    for (const pid of ["p1","p2"] as const) { const b=this.bots[pid]; const i=this.inputs[pid]; b.l=i.l; b.r=i.r; }
    this.stepBot(this.bots.p1,dt); this.stepBot(this.bots.p2,dt); this.resolveCollision();
    const R=400-22;
    let winner: PID|null = null;
    if (Math.hypot(this.bots.p1.x,this.bots.p1.y)>R) winner="p2";
    else if (Math.hypot(this.bots.p2.x,this.bots.p2.y)>R) winner="p1";
    if (winner) this.resetBots();
    if (this.tick%3===0) this.broadcast(JSON.stringify({t:"state",bots:this.visibleBots(),phase:"fight",winner,msLeft:0}));
    await this.state.storage.setAlarm(Date.now()+33);
  }

  resetBots(){ this.bots.p1={x:-150,y:0,a:0,vx:0,vy:0,wa:0,l:0,r:0}; this.bots.p2={x:150,y:0,a:Math.PI,vx:0,vy:0,wa:0,l:0,r:0}; this.inputs.p1={l:0,r:0}; this.inputs.p2={l:0,r:0}; }
  broadcast(msg:string){ if(this.wsByPid.p1) this.wsByPid.p1.send(msg); if(this.wsByPid.p2) this.wsByPid.p2.send(msg); }
  stepBot(b:Bot,dt:number){ const vL=(b.l/100)*240,vR=(b.r/100)*240,v=(vL+vR)*0.5,w=(vR-vL)/60; b.vx=Math.cos(b.a)*v; b.vy=Math.sin(b.a)*v; b.wa=w; b.x+=b.vx*dt; b.y+=b.vy*dt; b.a+=b.wa*dt; }
  resolveCollision(){ const b1=this.bots.p1,b2=this.bots.p2,dx=b2.x-b1.x,dy=b2.y-b1.y,d=Math.hypot(dx,dy)||0.001; if(d<44){const push=(44-d)*0.5,nx=dx/d,ny=dy/d; b1.x-=nx*push; b1.y-=ny*push; b2.x+=nx*push; b2.y+=ny*push;} }
}

export interface Env {
  ROOMS: DurableObjectNamespace;
  DB: D1Database;
  JWT_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  APP_URL: string;
  ADMIN_KEY: string;
  REQUIRE_INVITE_KEY?: string;  // "1" = вимагати ключ при реєстрації
}
