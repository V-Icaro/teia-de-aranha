// Autenticação simples: usuários no Postgres com senha em scrypt (sal
// aleatório por usuário), sessão em cookie HttpOnly cujo valor é um token
// aleatório — no banco fica só o SHA-256 do token. Sem recuperação de senha e
// sem MFA por enquanto. No deploy a tabela já nasce com admin/admin marcado
// como "trocar senha no primeiro acesso": o login funciona, mas a tela obriga
// a definir uma senha nova antes de liberar o resto.
const crypto = require('node:crypto');
const db = require('./db');

const COOKIE = 'teia_session';
const SESSION_TTL_MIN = Math.max(1, Number.parseInt(process.env.SESSION_TTL_MINUTES || '15', 10) || 15);
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const ROLES = new Set(['admin', 'operador']);
const MIN_PASSWORD = 8;

// ---- schema -----------------------------------------------------------------
let schemaReady = false;
async function ensureSchema() {
  if (schemaReady) return;
  await db.pool.query(`create table if not exists app_users (
    id serial primary key,
    username text not null unique,
    name text,
    password_hash text not null,
    role text not null default 'operador' check (role in ('admin','operador')),
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_login_at timestamptz,
    must_change_password boolean not null default false
  )`);
  await db.pool.query('alter table app_users add column if not exists must_change_password boolean not null default false');
  await db.pool.query(`create table if not exists app_sessions (
    token_hash text primary key,
    user_id integer not null references app_users(id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    last_seen_at timestamptz not null default now(),
    ip text,
    user_agent text
  )`);
  await db.pool.query('create index if not exists idx_app_sessions_user on app_sessions(user_id)');
  // Usuário inicial do deploy: admin / admin (ou ADMIN_USER / ADMIN_PASSWORD),
  // obrigado a trocar a senha no primeiro login. Só é criado se não houver
  // nenhum usuário — depois disso nunca mais é recriado.
  const { rows } = await db.pool.query('select count(*)::int as n from app_users');
  if (rows[0].n === 0) {
    const u = String(process.env.ADMIN_USER || 'admin').trim().toLowerCase();
    const p = String(process.env.ADMIN_PASSWORD || 'admin');
    await db.pool.query(`insert into app_users (username, name, password_hash, role, must_change_password) values ($1,'Administrador',$2,'admin',true) on conflict (username) do nothing`,
      [u, hashPassword(p)]);
    console.log(`[auth] usuário inicial criado: ${u} (troca de senha obrigatória no primeiro acesso)`);
  }
  schemaReady = true;
}

// ---- senha ------------------------------------------------------------------
// Formato guardado: scrypt$N$r$p$salt_b64$hash_b64
const SCRYPT = { N: 16384, r: 8, p: 1, len: 64 };
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT.len, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function verifyPassword(password, stored) {
  try {
    const [algo, N, r, p, saltB64, hashB64] = String(stored || '').split('$');
    if (algo !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const got = crypto.scryptSync(String(password), Buffer.from(saltB64, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p) });
    return got.length === expected.length && crypto.timingSafeEqual(got, expected);
  } catch { return false; }
}
function checkPasswordPolicy(password) {
  const s = String(password || '');
  if (s.length < MIN_PASSWORD) throw Object.assign(new Error(`A senha precisa ter pelo menos ${MIN_PASSWORD} caracteres.`), { status: 400 });
}
function cleanUsername(u) {
  const s = String(u || '').trim().toLowerCase();
  if (!/^[a-z0-9._@-]{2,64}$/.test(s)) throw Object.assign(new Error('Usuário inválido: use 2–64 caracteres (letras, números, ponto, hífen, _ ou @).'), { status: 400 });
  return s;
}

const userOut = (r) => r && ({
  id: Number(r.id), username: r.username, name: r.name || null, role: r.role, enabled: r.enabled,
  mustChangePassword: !!r.must_change_password,
  createdAt: r.created_at, lastLoginAt: r.last_login_at || null
});

// ---- sessões ----------------------------------------------------------------
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setCookie(res, token, maxAgeSec) {
  const attrs = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (COOKIE_SECURE) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

async function createSession(userId, req, res) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_TTL_MIN * 60e3);
  await db.pool.query(`insert into app_sessions (token_hash, user_id, expires_at, ip, user_agent) values ($1,$2,$3,$4,$5)`,
    [sha256(token), userId, expires, clientIp(req), String(req.headers['user-agent'] || '').slice(0, 300)]);
  setCookie(res, token, SESSION_TTL_MIN * 60);
}

function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.socket?.remoteAddress || null;
}

// Devolve o usuário da sessão (ou null) e renova a validade a cada uso.
async function sessionUser(req, res) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (!token) return null;
  const h = sha256(token);
  const { rows } = await db.pool.query(`select u.*, s.expires_at from app_sessions s join app_users u on u.id = s.user_id
    where s.token_hash = $1 and s.expires_at > now() and u.enabled`, [h]);
  const u = rows[0];
  if (!u) return null;
  // Renovação deslizante: estende quando passou mais de 10 % do TTL.
  if (new Date(u.expires_at).getTime() - Date.now() < SESSION_TTL_MIN * 60e3 * 0.9) {
const expires = new Date(Date.now() + SESSION_TTL_MIN * 60e3);
    db.pool.query('update app_sessions set expires_at = $2, last_seen_at = now() where token_hash = $1', [h, expires]).catch(() => {});
    if (res) setCookie(res, token, SESSION_TTL_MIN * 60);
  }
  return userOut(u);
}

async function destroySession(req, res) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (token) await db.pool.query('delete from app_sessions where token_hash = $1', [sha256(token)]).catch(() => {});
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`);
}

// ---- proteção contra força bruta (em memória, por IP+usuário) ---------------
const fails = new Map(); // key -> { n, until }
const MAX_FAILS = 5;
const BLOCK_MS = 60000;
function failKey(req, username) { return `${clientIp(req)}|${username}`; }
function isBlocked(req, username) {
  const f = fails.get(failKey(req, username));
  return !!(f && f.until && f.until > Date.now());
}
function noteFail(req, username) {
  const k = failKey(req, username);
  const f = fails.get(k) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= MAX_FAILS) { f.until = Date.now() + BLOCK_MS; f.n = 0; }
  fails.set(k, f);
}
function clearFails(req, username) { fails.delete(failKey(req, username)); }

// ---- operações ---------------------------------------------------------------
async function countUsers() {
  await ensureSchema();
  const { rows } = await db.pool.query('select count(*)::int as n from app_users');
  return rows[0].n;
}

async function login({ username, password }, req, res) {
  await ensureSchema();
  const u = String(username || '').trim().toLowerCase();
  if (!u || !password) throw Object.assign(new Error('Informe usuário e senha.'), { status: 400 });
  if (isBlocked(req, u)) throw Object.assign(new Error('Muitas tentativas. Aguarde 1 minuto.'), { status: 429 });
  const { rows } = await db.pool.query('select * from app_users where username = $1', [u]);
  const user = rows[0];
  // Mesma resposta para usuário inexistente, senha errada ou conta desativada.
  if (!user || !user.enabled || !verifyPassword(password, user.password_hash)) {
    noteFail(req, u);
    throw Object.assign(new Error('Usuário ou senha inválidos.'), { status: 401 });
  }
  clearFails(req, u);
  await createSession(user.id, req, res);
  await db.pool.query('update app_users set last_login_at = now() where id = $1', [user.id]);
  console.log(`[auth] login: ${u} de ${clientIp(req)}`);
  return userOut(user);
}

async function changePassword(userId, { currentPassword, newPassword }) {
  await ensureSchema();
  const { rows } = await db.pool.query('select * from app_users where id = $1', [userId]);
  const user = rows[0];
  if (!user || !verifyPassword(currentPassword, user.password_hash)) throw Object.assign(new Error('Senha atual incorreta.'), { status: 400 });
  checkPasswordPolicy(newPassword);
  if (verifyPassword(newPassword, user.password_hash)) throw Object.assign(new Error('A nova senha precisa ser diferente da atual.'), { status: 400 });
  await db.pool.query('update app_users set password_hash = $2, must_change_password = false, updated_at = now() where id = $1', [userId, hashPassword(newPassword)]);
  return { ok: true };
}

async function listUsers() {
  await ensureSchema();
  const { rows } = await db.pool.query('select * from app_users order by lower(username)');
  return rows.map(userOut);
}

async function createUser({ username, password, name, role }) {
  await ensureSchema();
  const u = cleanUsername(username);
  checkPasswordPolicy(password);
  const r = ROLES.has(role) ? role : 'operador';
  try {
    // Senha inicial definida pelo admin: o novo usuário troca no primeiro login.
    const { rows } = await db.pool.query(`insert into app_users (username, name, password_hash, role, must_change_password) values ($1,$2,$3,$4,true) returning *`,
      [u, String(name || '').trim() || null, hashPassword(password), r]);
    return userOut(rows[0]);
  } catch (e) {
    if (e.code === '23505') throw Object.assign(new Error('Já existe um usuário com esse nome.'), { status: 409 });
    throw e;
  }
}

async function updateUser(id, { name, role, enabled, password }, actingUserId) {
  await ensureSchema();
  const sets = []; const params = [Number(id)];
  if (name !== undefined) { params.push(String(name || '').trim() || null); sets.push(`name = $${params.length}`); }
  if (role !== undefined) { if (!ROLES.has(role)) throw Object.assign(new Error('Perfil inválido.'), { status: 400 }); params.push(role); sets.push(`role = $${params.length}`); }
  if (enabled !== undefined) { params.push(!!enabled); sets.push(`enabled = $${params.length}`); }
  // Senha definida por um admin: o usuário troca no próximo login.
  if (password !== undefined) { checkPasswordPolicy(password); params.push(hashPassword(password)); sets.push(`password_hash = $${params.length}`); sets.push('must_change_password = true'); }
  if (!sets.length) throw Object.assign(new Error('Nada para atualizar.'), { status: 400 });
  // Não deixar o último admin ativo se rebaixar/desativar.
  if ((role !== undefined && role !== 'admin') || enabled === false) {
    const { rows } = await db.pool.query(`select count(*)::int as n from app_users where role = 'admin' and enabled and id <> $1`, [Number(id)]);
    const { rows: me } = await db.pool.query('select role, enabled from app_users where id = $1', [Number(id)]);
    if (me[0]?.role === 'admin' && me[0]?.enabled && rows[0].n === 0) throw Object.assign(new Error('Este é o último administrador ativo.'), { status: 400 });
  }
  const { rows } = await db.pool.query(`update app_users set ${sets.join(', ')}, updated_at = now() where id = $1 returning *`, params);
  if (!rows[0]) throw Object.assign(new Error('Usuário não encontrado.'), { status: 404 });
  if (enabled === false || password !== undefined) {
    // Desativar ou trocar a senha de alguém encerra as sessões dele.
    await db.pool.query('delete from app_sessions where user_id = $1', [Number(id)]);
  }
  return userOut(rows[0]);
}

async function deleteUser(id, actingUserId) {
  await ensureSchema();
  if (Number(id) === Number(actingUserId)) throw Object.assign(new Error('Você não pode excluir o próprio usuário.'), { status: 400 });
  const { rows: me } = await db.pool.query('select role, enabled from app_users where id = $1', [Number(id)]);
  if (!me[0]) throw Object.assign(new Error('Usuário não encontrado.'), { status: 404 });
  if (me[0].role === 'admin' && me[0].enabled) {
    const { rows } = await db.pool.query(`select count(*)::int as n from app_users where role = 'admin' and enabled and id <> $1`, [Number(id)]);
    if (rows[0].n === 0) throw Object.assign(new Error('Este é o último administrador ativo.'), { status: 400 });
  }
  await db.pool.query('delete from app_users where id = $1', [Number(id)]);
  return { ok: true };
}

// Limpeza de sessões vencidas (chamada periodicamente).
async function purgeSessions() {
  await ensureSchema();
  await db.pool.query('delete from app_sessions where expires_at < now()');
}

// ---- middleware --------------------------------------------------------------
// Exige sessão em tudo que começa com /api, exceto /api/auth/* e /api/health.
function requireAuth({ dbInit }) {
  return async (req, res, next) => {
    if (!req.path.startsWith('/api/') || req.path.startsWith('/api/auth/') || req.path === '/api/health') return next();
    try {
      if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
      const user = await sessionUser(req, res);
      if (!user) return res.status(401).json({ error: 'Não autenticado' });
      if (user.mustChangePassword) return res.status(403).json({ error: 'Troque a senha antes de continuar.', mustChangePassword: true });
      req.user = user;
      return next();
    } catch (e) {
      console.error('[auth]', e.message);
      return res.status(500).json({ error: 'Falha na autenticação' });
    }
  };
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Apenas administradores.' });
  return next();
}

module.exports = {
  ensureSchema, countUsers, login, destroySession, sessionUser, changePassword,
  listUsers, createUser, updateUser, deleteUser, purgeSessions, requireAuth, requireAdmin,
  _internals: { hashPassword, verifyPassword }
};
