// Histórico persistente do log de tráfego (forward) do FortiGate.
// Mesmo princípio de fortigate-events.js: cada registro é guardado uma única
// vez, identificado por (fortigate_id, traffic_key), onde traffic_key vem do
// _metadata.timestamp do FortiGate (ou hash dos campos identificadores).
const crypto = require('node:crypto');
const db = require('./db');
const { requestJson } = require('./fortigate');

const ROWS = Math.max(50, Math.min(5000, Number.parseInt(process.env.FORTIGATE_TRAFFIC_ROWS || '1000', 10) || 1000));
const COLLECT_MIN = Math.max(0, Number.parseInt(process.env.TRAFFIC_COLLECT_MIN || '5', 10) || 0);
const config = require('./config');

async function ensureSchema() {
  await db.pool.query(`create table if not exists fortigate_traffic (
    id bigserial primary key,
    fortigate_id integer not null references fortigate(id) on delete cascade,
    traffic_key text not null,
    event_at timestamptz not null,
    srcip text, srcport integer,
    dstip text, dstport integer,
    srcintf text, dstintf text,
    protocol text, service text, action text,
    policyid integer,
    sentbyte bigint, rcvdbyte bigint,
    sentpkt bigint, rcvdpkt bigint,
    duration integer,
    appcat text, application text,
    logid text, raw jsonb,
    collected_at timestamptz not null default now(),
    unique (fortigate_id, traffic_key)
  )`);
  await db.pool.query('create index if not exists idx_fg_traffic_at on fortigate_traffic(fortigate_id, event_at desc)');
  await db.pool.query('create index if not exists idx_fg_traffic_src on fortigate_traffic(fortigate_id, srcip)');
  await db.pool.query('create index if not exists idx_fg_traffic_dst on fortigate_traffic(fortigate_id, dstip)');
  await db.pool.query(`create table if not exists fortigate_traffic_collect (
    fortigate_id integer primary key references fortigate(id) on delete cascade,
    last_collected_at timestamptz not null,
    last_read integer not null default 0,
    last_inserted integer not null default 0,
    last_event_at timestamptz,
    last_error text
  )`);
}

async function markCollect(fortigateId, { read = 0, inserted = 0, error = null } = {}) {
  await db.pool.query(`insert into fortigate_traffic_collect (fortigate_id, last_collected_at, last_read, last_inserted, last_event_at, last_error)
    values ($1, now(), $2, $3, (select max(event_at) from fortigate_traffic where fortigate_id = $1), $4)
    on conflict (fortigate_id) do update set last_collected_at = excluded.last_collected_at, last_read = excluded.last_read,
      last_inserted = excluded.last_inserted, last_event_at = excluded.last_event_at, last_error = excluded.last_error`,
  [Number(fortigateId), read, inserted, error]);
}

function trafficKey(r) {
  const raw = r?._metadata?.timestamp || r?.eventtime_raw_value || (r.eventtime != null ? String(r.eventtime) : null);
  if (raw) return `${raw}:${r.logid || ''}:${r.srcip || ''}:${r.dstip || ''}:${r.srcport || ''}:${r.dstport || ''}`;
  return 'h:' + crypto.createHash('sha1').update([r.date, r.time, r.logid, r.srcip, r.srcport, r.dstip, r.dstport, r.sentbyte, r.rcvdbyte].join('|')).digest('hex');
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

async function collectFortigateTraffic(fg) {
  await ensureSchema();
  const path = `/api/v2/log/memory/traffic/forward?rows=${ROWS}`;
  let json;
  try {
    json = await requestJson(fg.host, path, fg.token, { port: fg.port });
  } catch (e) {
    await markCollect(fg.id, { error: e.message }).catch(() => {});
    throw e;
  }
  const rows = Array.isArray(json?.results) ? json.results : [];
  let inserted = 0;
  const client = await db.pool.connect();
  try {
    await client.query('begin');
    for (const r of rows) {
      const at = eventAt(r);
      if (!at) continue;
      const { rowCount } = await client.query(`insert into fortigate_traffic
        (fortigate_id, traffic_key, event_at, srcip, srcport, dstip, dstport, srcintf, dstintf, protocol, service, action, policyid, sentbyte, rcvdbyte, sentpkt, rcvdpkt, duration, appcat, application, logid, raw)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
        on conflict (fortigate_id, traffic_key) do nothing`,
      [fg.id, trafficKey(r), at, r.srcip || null, r.srcport != null ? Number(r.srcport) : null, r.dstip || null, r.dstport != null ? Number(r.dstport) : null,
        r.srcintf || null, r.dstintf || null, r.proto != null ? String(r.proto) : null, r.service || null, r.action || null,
        r.policyid != null ? Number(r.policyid) : null, r.sentbyte != null ? Number(r.sentbyte) : null, r.rcvdbyte != null ? Number(r.rcvdbyte) : null,
        r.sentpkt != null ? Number(r.sentpkt) : null, r.rcvdpkt != null ? Number(r.rcvdpkt) : null, r.duration != null ? Number(r.duration) : null,
        r.appcat || null, r.application || r.app || null, r.logid || null, JSON.stringify(r)]);
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

async function purgeOld() {
  const days = Number(await config.get('traffic_retention_days', '7')) || 7;
  if (days <= 0) return;
  await ensureSchema();
  await db.pool.query('delete from fortigate_traffic where event_at < now() - ($1::int * interval \'1 day\')', [days]);
}

async function collectAll() {
  const enabled = await config.get('traffic_collect_enabled', '0');
  if (enabled === '0') {
    console.log('[fgt-traffic] coleta desativada nas configurações');
    return [];
  }
  await purgeOld();
  const list = await db.listFortigates();
  const out = [];
  for (const f of list) {
    try {
      const fg = await db.getFortigate(f.id);
      const r = await collectFortigateTraffic(fg);
      out.push({ fortigateId: f.id, ...r });
      if (r.inserted) console.log(`[fgt-traffic] ${f.name}: ${r.inserted} registro(s) novo(s) de ${r.read} lidos`);
    } catch (e) {
      out.push({ fortigateId: f.id, error: e.message });
      console.error(`[fgt-traffic] ${f.name}: ${e.message}`);
    }
  }
  return out;
}

let timer = null;
let busy = false;
function startTrafficCollector() {
  if (timer || !COLLECT_MIN) return;
  const tick = async () => {
    if (busy) return;
    busy = true;
    try { await collectAll(); } finally { busy = false; }
  };
  setTimeout(tick, 30000);
  timer = setInterval(tick, COLLECT_MIN * 60 * 1000);
  console.log(`[fgt-traffic] coletor ativo a cada ${COLLECT_MIN} min`);
}

async function queryTrafficByPolicy({ fortigateId, policyId, limit = 50 } = {}) {
  await ensureSchema();
  const lim = Math.max(1, Math.min(500, Number(limit) || 50));
  const params = [Number(fortigateId), Number(policyId)];
  const src = await db.pool.query(`select srcip, count(*)::int as hits, coalesce(sum(sentbyte),0)::bigint as bytes from fortigate_traffic where fortigate_id = $1 and policyid = $2 group by srcip order by hits desc limit $3`, [...params, lim]);
  const dst = await db.pool.query(`select dstip, count(*)::int as hits, coalesce(sum(rcvdbyte),0)::bigint as bytes from fortigate_traffic where fortigate_id = $1 and policyid = $2 group by dstip order by hits desc limit $3`, [...params, lim]);
  const svc = await db.pool.query(`select service, count(*)::int as hits from fortigate_traffic where fortigate_id = $1 and policyid = $2 group by service order by hits desc limit $3`, [...params, lim]);
  return { srcIps: src.rows, dstIps: dst.rows, services: svc.rows };
}

module.exports = { ensureSchema, collectFortigateTraffic, collectAll, startTrafficCollector, queryTrafficByPolicy, purgeOld };
