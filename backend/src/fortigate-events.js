// Histórico persistente dos eventos de administradores do FortiGate.
// O log em memória do equipamento é volátil (descarta os antigos); aqui cada
// evento com usuário real é guardado no Postgres uma única vez, identificado
// por (fortigate_id, event_key), onde event_key = eventtime_raw_value (ns
// desde a época, único por evento no equipamento) + logid. Coleta: a cada
// EVENTS_COLLECT_MIN minutos para todos os firewalls cadastrados, e também em
// toda auditoria.
const crypto = require('node:crypto');
const db = require('./db');
const { requestJson } = require('./fortigate');

const ROWS = Math.max(50, Math.min(5000, Number.parseInt(process.env.FORTIGATE_EVENT_ROWS || '1000', 10) || 1000));
const COLLECT_MIN = Math.max(0, Number.parseInt(process.env.EVENTS_COLLECT_MIN || '5', 10) || 0);

async function ensureSchema() {
  await db.pool.query(`create table if not exists fortigate_admin_events (
    id bigserial primary key,
    fortigate_id integer not null references fortigate(id) on delete cascade,
    event_key text not null,
    event_at timestamptz not null,
    "user" text not null,
    action text,
    description text,
    message text,
    level text,
    status text,
    ui text,
    srcip text,
    method text,
    profile text,
    cfgpath text,
    cfgobj text,
    cfgattr text,
    logid text,
    subtype text,
    raw jsonb,
    collected_at timestamptz not null default now(),
    unique (fortigate_id, event_key)
  )`);
  await db.pool.query('create index if not exists idx_fg_admin_events_at on fortigate_admin_events(fortigate_id, event_at desc)');
  await db.pool.query('create index if not exists idx_fg_admin_events_user on fortigate_admin_events(fortigate_id, "user")');
  await db.pool.query(`create table if not exists fortigate_event_collect (
    fortigate_id integer primary key references fortigate(id) on delete cascade,
    last_collected_at timestamptz not null,
    last_read integer not null default 0,
    last_inserted integer not null default 0,
    last_event_at timestamptz,
    last_error text
  )`);
}

async function markCollect(fortigateId, { read = 0, inserted = 0, error = null } = {}) {
  await db.pool.query(`insert into fortigate_event_collect (fortigate_id, last_collected_at, last_read, last_inserted, last_event_at, last_error)
    values ($1, now(), $2, $3, (select max(event_at) from fortigate_admin_events where fortigate_id = $1), $4)
    on conflict (fortigate_id) do update set last_collected_at = excluded.last_collected_at, last_read = excluded.last_read,
      last_inserted = excluded.last_inserted, last_event_at = excluded.last_event_at, last_error = excluded.last_error`,
  [Number(fortigateId), read, inserted, error]);
}

const isRealUser = (u) => u && String(u).trim() && String(u).toUpperCase() !== 'N/A';

function eventKey(r) {
  const raw = r.eventtime_raw_value || (r.eventtime != null ? String(r.eventtime) : null);
  if (raw) return `${raw}:${r.logid || ''}`;
  // Sem eventtime (versões antigas): hash dos campos que identificam o evento.
  return 'h:' + crypto.createHash('sha1').update([r.date, r.time, r.logid, r.user, r.msg, r.ui].join('|')).digest('hex');
}

function eventAt(r) {
  const ts = Number(r?._metadata?.timestamp);
  if (Number.isFinite(ts) && ts > 0) return new Date(ts);
  if (r.date && r.time) {
    const tz = r.tz ? r.tz.replace(/(\d{2})(\d{2})$/, '$1:$2') : '';
    const d = new Date(`${r.date}T${r.time}${tz}`);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return null;
}

// Lê o log system do FortiGate e grava o que ainda não existe. Devolve
// { read, inserted }.
async function collectFortigateEvents(fg) {
  await ensureSchema();
  const path = `/api/v2/log/memory/event/system?rows=${ROWS}&filter=${encodeURIComponent('subtype==system')}`;
  let json;
  try {
    json = await requestJson(fg.host, path, fg.token, { port: fg.port });
  } catch (e) {
    await markCollect(fg.id, { error: e.message }).catch(() => {});
    throw e;
  }
  const rows = (Array.isArray(json?.results) ? json.results : []).filter((r) => r && isRealUser(r.user));
  let inserted = 0;
  const client = await db.pool.connect();
  try {
    await client.query('begin');
    for (const r of rows) {
      const at = eventAt(r);
      if (!at) continue;
      const { rowCount } = await client.query(`insert into fortigate_admin_events
        (fortigate_id, event_key, event_at, "user", action, description, message, level, status, ui, srcip, method, profile, cfgpath, cfgobj, cfgattr, logid, subtype, raw)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        on conflict (fortigate_id, event_key) do nothing`,
      [fg.id, eventKey(r), at, String(r.user), r.action || null, r.logdesc || null, r.msg || null, r.level || null, r.status || null,
        r.ui || null, r.srcip || null, r.method || null, r.profile || null, r.cfgpath || null, r.cfgobj || null, r.cfgattr || null,
        r.logid || null, r.subtype || null, JSON.stringify(r)]);
      inserted += rowCount;
    }
    await client.query('commit');
  } catch (e) {
    await client.query('rollback').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  await markCollect(fg.id, { read: rows.length, inserted }).catch(() => {});
  return { read: rows.length, inserted };
}

async function collectAll() {
  const list = await db.listFortigates();
  const out = [];
  for (const f of list) {
    try {
      const fg = await db.getFortigate(f.id);
      const r = await collectFortigateEvents(fg);
      out.push({ fortigateId: f.id, ...r });
      if (r.inserted) console.log(`[fgt-events] ${f.name}: ${r.inserted} evento(s) novo(s) de ${r.read} lidos`);
    } catch (e) {
      out.push({ fortigateId: f.id, error: e.message });
      console.error(`[fgt-events] ${f.name}: ${e.message}`);
    }
  }
  return out;
}

let timer = null;
let busy = false;
function startEventCollector() {
  if (timer || !COLLECT_MIN) return;
  const tick = async () => {
    if (busy) return;
    busy = true;
    try { await collectAll(); } finally { busy = false; }
  };
  setTimeout(tick, 15000); // primeira coleta logo após subir
  timer = setInterval(tick, COLLECT_MIN * 60 * 1000);
  console.log(`[fgt-events] coletor ativo a cada ${COLLECT_MIN} min`);
}

// ---- consulta ---------------------------------------------------------------
function rowOut(r) {
  return {
    id: Number(r.id),
    fortigateId: Number(r.fortigate_id),
    fortigateName: r.fortigate_name || null,
    when: r.event_at,
    user: r.user,
    action: r.action,
    description: r.description,
    message: r.message,
    level: r.level,
    status: r.status,
    ui: r.ui,
    srcip: r.srcip,
    method: r.method,
    profile: r.profile,
    config: [r.cfgpath, r.cfgobj].filter(Boolean).join(' ') || null,
    configAttr: r.cfgattr,
    logid: r.logid,
    collectedAt: r.collected_at
  };
}

async function queryEvents({ fortigateId, user, action, status, from, to, q, limit = 100, offset = 0 } = {}) {
  await ensureSchema();
  const where = [];
  const params = [];
  const add = (sql, v) => { params.push(v); where.push(sql.replace('?', `$${params.length}`)); };
  if (fortigateId) add('e.fortigate_id = ?', Number(fortigateId));
  if (user) add('e."user" = ?', String(user));
  if (action) add('coalesce(e.action, \'\') = ?', action === 'outro' ? '' : String(action));
  if (status === 'failure') where.push("(e.status = 'failure' or e.description ilike '%failed%')");
  if (status === 'success') where.push("(e.status = 'success' and e.description not ilike '%failed%')");
  if (from) add('e.event_at >= ?', new Date(from));
  if (to) add('e.event_at <= ?', new Date(to));
  if (q) {
    params.push(`%${String(q).trim()}%`);
    const p = `$${params.length}`;
    where.push(`(e.description ilike ${p} or e.message ilike ${p} or e.srcip ilike ${p} or e.ui ilike ${p} or e.cfgpath ilike ${p} or e.cfgobj ilike ${p} or e.cfgattr ilike ${p} or e."user" ilike ${p})`);
  }
  const w = where.length ? `where ${where.join(' and ')}` : '';
  const lim = Math.max(1, Math.min(1000, Number(limit) || 100));
  const off = Math.max(0, Number(offset) || 0);
  const fgParams = fortigateId ? [Number(fortigateId)] : [];
  const fgWhere = fortigateId ? 'where e.fortigate_id = $1' : '';
  const [{ rows }, totalRes, usersRes, actionsRes, lastRes] = await Promise.all([
    db.pool.query(`select e.*, f.name as fortigate_name from fortigate_admin_events e left join fortigate f on f.id = e.fortigate_id ${w} order by e.event_at desc, e.id desc limit ${lim} offset ${off}`, params),
    db.pool.query(`select count(*)::int as n from fortigate_admin_events e ${w}`, params),
    db.pool.query(`select e."user", count(*)::int as n from fortigate_admin_events e ${fgWhere} group by 1 order by 1`, fgParams),
    db.pool.query(`select coalesce(e.action, '') as action, count(*)::int as n from fortigate_admin_events e ${fgWhere} group by 1 order by 1`, fgParams),
    // Última coleta: hora da última passagem do coletor (grava mesmo sem novos eventos)
    // e hora do evento mais recente guardado.
    db.pool.query(`select max(last_collected_at) as last_collected_at, max(last_event_at) as last_event_at from fortigate_event_collect ${fgWhere.replace('e.', '')}`, fgParams)
  ]);
  return {
    lastCollectedAt: lastRes.rows[0]?.last_collected_at || null,
    lastEventAt: lastRes.rows[0]?.last_event_at || null,
    collectEveryMin: COLLECT_MIN,
    total: totalRes.rows[0]?.n || 0,
    limit: lim,
    offset: off,
    users: usersRes.rows.map((r) => ({ user: r.user, count: r.n })),
    actions: actionsRes.rows.map((r) => ({ action: r.action || 'outro', count: r.n })),
    events: rows.map(rowOut)
  };
}

module.exports = { ensureSchema, collectFortigateEvents, collectAll, startEventCollector, queryEvents };
