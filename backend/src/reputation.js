// Reputação de IPs públicos — SOMENTE AbuseIPDB (ABUSEIPDB_KEY).
// Binário: score 0 = confiável (verde) | score > 0 = não confiável (vermelho).
// Sem chave ou com a API fora = unknown. Privados = private (ignorados).
function isPublicIp(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip !== '::1' && !ip.toLowerCase().startsWith('fe80');
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a >= 224) return false; // multicast/reservados
  return true;
}

const ABUSE_KEY = process.env.ABUSEIPDB_KEY || '';
const REP_TTL = parseInt(process.env.REP_CACHE_TTL_MS || '21600000', 10); // 6h memória
const REP_PG_TTL_DAYS = parseInt(process.env.REP_PG_TTL_DAYS || '7', 10); // 7 dias Postgres
const TIMEOUT = parseInt(process.env.REP_TIMEOUT_MS || '8000', 10);

const cache = new Map(); // ip -> { result, expires }

// Cota diária: ao bater 429, segura até a próxima meia-noite UTC
let rateLimitedUntil = 0;

function quotaNote() {
  if (Date.now() < rateLimitedUntil) {
    const t = new Date(rateLimitedUntil).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    return `cota diária esgotada, volta ${t}`;
  }
  return null;
}

// Estado da cota para o front: sem isto o botão continua "funcionando" e
// devolve tudo como unknown quando o 429 já estourou.
function quotaState() {
  const limited = Date.now() < rateLimitedUntil;
  return {
    limited,
    until: limited ? new Date(rateLimitedUntil).toISOString() : null,
    note: quotaNote()
  };
}

// Linha do Postgres em qualquer idade (inclusive vencida): a cobertura precisa
// mostrar quantos dias o dado tem para o front decidir se vale renovar.
async function pgRow(ip) {
  try {
    const { pool } = require('./db.js');
    const r = await pool.query(
      `select *, extract(epoch from (now() - checked_at))/86400 as age_days from ip_reputation where ip = $1`, [ip]);
    return r.rows[0] || null;
  } catch { return null; } // sem Postgres: segue sem cache persistente
}

function rowResult(row) {
  return {
    ip: row.ip, verdict: row.verdict, sources: ['abuseipdb'],
    abuse: {
      score: row.score, reports: row.reports, distinctUsers: row.distinct_users,
      lastReported: row.last_reported, country: row.country, countryName: row.country_name,
      usageType: row.usage_type, isp: row.isp, domain: row.domain,
      hostnames: row.hostnames || [], whitelisted: row.whitelisted
    }
  };
}

async function pgGet(ip) {
  const row = await pgRow(ip);
  if (!row) return null;
  if (Number(row.age_days) > REP_PG_TTL_DAYS) return null;
  return rowResult(row);
}

async function pgPut(result) {
  if (!result.abuse) return;
  try {
    const { pool } = require('./db.js');
    const a = result.abuse;
    await pool.query(
      `insert into ip_reputation (ip, verdict, score, reports, distinct_users, last_reported,
        country, country_name, usage_type, isp, domain, hostnames, whitelisted, checked_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
       on conflict (ip) do update set verdict = excluded.verdict, score = excluded.score,
       reports = excluded.reports, distinct_users = excluded.distinct_users,
       last_reported = excluded.last_reported, country = excluded.country,
       country_name = excluded.country_name, usage_type = excluded.usage_type,
       isp = excluded.isp, domain = excluded.domain, hostnames = excluded.hostnames,
       whitelisted = excluded.whitelisted, checked_at = now()`,
      [result.ip, result.verdict, a.score ?? 0, a.reports ?? 0, a.distinctUsers ?? null,
       a.lastReported || null, a.country || null, a.countryName || null, a.usageType || null,
       a.isp || null, a.domain || null, a.hostnames || [], a.whitelisted ?? null]);
  } catch { /* ignora */ }
}

async function fetchJson(url, opts = {}, ms = TIMEOUT) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  } finally {
    clearTimeout(t);
  }
}

async function checkAbuseIpDb(ip) {
  if (Date.now() < rateLimitedUntil) {
    const e = new Error('quota'); e.quota = true; throw e;
  }
  let j;
  try {
    j = await fetchJson(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
      { headers: { Key: ABUSE_KEY, Accept: 'application/json' } }
    );
  } catch (e) {
    if (e.message && e.message.includes('429')) {
      const mid = new Date(); // zera à meia-noite UTC
      mid.setUTCHours(24, 0, 0, 0);
      rateLimitedUntil = mid.getTime();
      const q = new Error('quota'); q.quota = true; throw q;
    }
    throw e;
  }
  const d = (j && j.data) || {};
  return {
    score: d.abuseConfidenceScore ?? 0,
    reports: d.totalReports ?? 0,
    distinctUsers: d.numDistinctUsers ?? null,
    lastReported: d.lastReportedAt || null,
    country: d.countryCode || null,
    countryName: d.countryName || null,
    usageType: d.usageType || null,
    isp: d.isp || null,
    domain: d.domain || null,
    hostnames: Array.isArray(d.hostnames) ? d.hostnames.slice(0, 3) : [],
    whitelisted: d.isWhitelisted ?? null
  };
}

async function checkIp(ip) {
  if (!isPublicIp(ip)) return { ip, verdict: 'private', sources: [] };
  const hit = cache.get(ip);
  if (hit && hit.expires > Date.now()) return hit.result;

  if (!ABUSE_KEY) {
    const result = { ip, verdict: 'unknown', sources: [], note: 'sem ABUSEIPDB_KEY' };
    cache.set(ip, { result, expires: Date.now() + 60000 });
    return result;
  }

  // cache persistente (sobrevive a restart): evita queimar a cota todo dia
  const persisted = await pgGet(ip);
  if (persisted) {
    cache.set(ip, { result: persisted, expires: Date.now() + REP_TTL });
    return persisted;
  }

  try {
    const abuse = await checkAbuseIpDb(ip);
    const result = {
      ip,
      verdict: abuse.score > 0 ? 'malicious' : 'clean',
      sources: ['abuseipdb'],
      abuse
    };
    cache.set(ip, { result, expires: Date.now() + REP_TTL });
    pgPut(result); // fire-and-forget
    return result;
  } catch (e) {
    const q = quotaNote();
    return { ip, verdict: 'unknown', sources: [], note: q || 'falha na API' };
  }
}

async function checkMany(ips, concurrency = 6) {
  const uniq = [...new Set(ips)].filter((x) => typeof x === 'string').slice(0, 100);
  const out = {};
  let i = 0;
  async function worker() {
    while (i < uniq.length) {
      const ip = uniq[i++];
      try { out[ip] = await checkIp(ip); } catch { out[ip] = { ip, verdict: 'unknown', sources: [] }; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, uniq.length || 1) }, worker));
  return out;
}

// O que já temos local, SEM chamar o AbuseIPDB. Serve para o front pintar a
// lista na hora e para o botão dizer quantos IPs realmente valem uma consulta.
// cached = dentro do TTL (não precisa buscar); stale = dado velho, mostrado
// esmaecido mas ainda útil.
async function coverageFor(ips) {
  const out = {};
  for (const ip of [...new Set(ips)].filter((x) => typeof x === 'string').slice(0, 300)) {
    if (!isPublicIp(ip)) {
      out[ip] = { cached: true, from: 'privado', result: { ip, verdict: 'private', sources: [] } };
      continue;
    }
    const mem = cache.get(ip);
    if (mem && mem.expires > Date.now()) {
      out[ip] = { cached: true, from: 'memoria', result: mem.result };
      continue;
    }
    const row = await pgRow(ip);
    if (!row) {
      out[ip] = { cached: false, from: null, result: null };
      continue;
    }
    const ageDays = Math.round(Number(row.age_days || 0) * 10) / 10;
    const stale = ageDays > REP_PG_TTL_DAYS;
    out[ip] = { cached: !stale, stale, from: 'postgres', ageDays, result: rowResult(row) };
  }
  return out;
}

// Base de reputação do Postgres: os IPs públicos **vistos na rede**, com a
// reputação que temos deles e o histórico do ip_sightings.
// A consulta fica limitada a no máximo sete dias. order=rep|reports|bytes|seen|country
//
// A base éANCORADA no ip_sightings, não no ip_reputation. Antes o FROM era
// `ip_reputation left join ip_sightings` com `coalesce(s.last_seen, r.checked_at)`
// na janela, e aí um IP que só foi consultado na tela (digitado no "Buscar IP" ou
// no dossiê) entrava como se fosse parte do histórico de rede — com bytes 0 e
// firstSeen/lastSeen vazios. Medido: 65 IPs assim, 19 deles visíveis na Base.
async function listReputationDb({ days = 7, order = 'rep', limit = 2000 } = {}) {
  const { pool } = require('./db.js');
  const { intParam } = require('./params.js');
  const d = intParam(days, { nome: 'days', def: 7, min: 1, max: 7 });
  const lim = intParam(limit, { nome: 'limit', def: 2000, min: 1, max: 10000 });
  const orders = {
    rep: 'r.score desc nulls last, r.reports desc nulls last, s.bytes desc nulls last',
    reports: 'r.reports desc nulls last, r.score desc nulls last',
    bytes: 's.bytes desc nulls last, r.score desc nulls last',
    seen: 's.last_seen desc nulls last',
    country: 'country asc, r.score desc nulls last'
  };
  const janela = d ? `where s.last_seen >= now() - ($1 || ' days')::interval` : '';
  const r = await pool.query(
    `select r.ip, r.verdict, r.score, r.reports, r.distinct_users, r.last_reported,
       r.country, r.country_name, r.usage_type, r.isp, r.domain, r.hostnames,
       r.whitelisted, r.checked_at,
       s.bytes as total_bytes, s.flows as total_flows,
       s.first_seen, s.last_seen,
       coalesce(r.country, s.country, '??') as country,
       coalesce(r.country_name, s.country_name, '??') as country_name,
       count(*) over () as total_real
     from ip_sightings s left join ip_reputation r on r.ip = s.ip
     ${janela}
     order by ${orders[order] || orders.rep}
     limit $${d ? 2 : 1}`,
    d ? [String(d), lim] : [lim]);

  // Totais por país vêm do AGREGADO, não da soma da página: com 3409 IPs e
  // limite 2000, somar em cima de r.rows dava 2000 e não fechava com o `total`.
  const agg = await pool.query(
    `select coalesce(r.country, s.country, '??') as code,
       coalesce(nullif(r.country_name, ''), nullif(s.country_name, ''), '??') as country_name,
       count(*)::int as ips,
       count(*) filter (where coalesce(r.score, 0) > 0)::int as bad,
       sum(coalesce(s.bytes, 0))::bigint as bytes
     from ip_sightings s left join ip_reputation r on r.ip = s.ip
     ${janela}
     group by 1, 2`,
    d ? [String(d)] : []
  );
  // Nome do país por código, tirado do próprio agregado. Antes vinha só das
  // linhas da página: com limite 2000 de 4377 IPs, 41 das 45 regiões caíam no
  // fallback e mostravam "DE" em vez de "Germany".
  const nomeDe = {};
  for (const a of agg.rows) if (a.code && a.code !== '??' && a.country_name) nomeDe[a.code] = a.country_name;
  for (const x of r.rows) if (x.country && x.country !== '??' && !nomeDe[x.country]) nomeDe[x.country] = x.country_name;
  const regions = agg.rows.map((a) => ({
    country: a.code,
    countryName: nomeDe[a.code] || (a.code === '??' ? 'Desconhecido' : a.code),
    ips: a.ips, bad: a.bad, bytes: Number(a.bytes || 0)
  }));
  const ips = r.rows.map((x) => {
    const code = x.country || '??';
    return {
      ip: x.ip, verdict: x.verdict, score: x.score, reports: x.reports,
      distinctUsers: x.distinct_users, lastReported: x.last_reported,
      country: code, countryName: x.country_name,
      usageType: x.usage_type, isp: x.isp, domain: x.domain,
      hostnames: x.hostnames || [], whitelisted: x.whitelisted,
      checkedAt: x.checked_at,
      totalBytes: Number(x.total_bytes || 0), totalFlows: Number(x.total_flows || 0),
      firstSeen: x.first_seen, lastSeen: x.last_seen
    };
  });
  // `total` é o total real (count(*) over()), não o tamanho da página: a tela
  // mostra "N IPs verificados" e, sem isso, apareceria 2000 (o limite) em vez do
  // total — e os totais por país não fechariam com o painel.
  const totalReal = Number(r.rows[0]?.total_real || 0) || ips.length;
  // Countries stay sorted by # of bad IPs — that is the signal that matters.
  return {
    days: d, order: order === 'rep' ? 'rep' : order, total: totalReal,
    truncado: ips.length < totalReal,
    limit: lim,
    regions: regions.sort((a, b) => b.bad - a.bad || b.ips - a.ips),
    ips
  };
}

module.exports = { isPublicIp, checkIp, checkMany, coverageFor, quotaState, quotaUntil: () => rateLimitedUntil, listReputationDb, repTtlDays: () => REP_PG_TTL_DAYS };
