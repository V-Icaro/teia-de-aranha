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
// days=0 → sem corte de janela (a base toda). order=rep|reports|bytes|seen|country
//
// A base éANCORADA no ip_sightings, não no ip_reputation. Antes o FROM era
// `ip_reputation left join ip_sightings` com `coalesce(s.last_seen, r.checked_at)`
// na janela, e aí um IP que só foi consultado na tela (digitado no "Buscar IP" ou
// no dossiê) entrava como se fosse parte do histórico de rede — com bytes 0 e
// firstSeen/lastSeen vazios. Medido: 65 IPs assim, 19 deles visíveis na Base.
async function listReputationDb({ days = 0, order = 'rep', limit = 2000 } = {}) {
  const { pool } = require('./db.js');
  const { intParam, daysParam } = require('./params.js');
  const d = daysParam(days, { nome: 'days', def: 0 });
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

// ============================================================================
// Painel consolidado (tela "Reputação")
// ============================================================================
// Só Postgres (e o ES só na janela de 24h, para não perder o dia corrente).
// Nada aqui consulta o AbuseIPDB: é leitura da base, então não gasta cota.
//
// Três coisas que este painel NÃO pode mentir sobre:
//  1. "não verificado" é uma faixa própria. São IPs vistos na rede que nunca
//     chegaram ao AbuseIPDB; enfiá-los em "score 0" seria fabricar verde.
//  2. O score é o DE HOJE, aplicado retroativamente ao histórico. Quem viu um
//     IP há 20 dias aparece com o score que ele tem agora, não o que tinha.
//  3. ip_sightings guarda IP público visto como origem OU destino (é o que o
//     coletor das 06:15 registra) e bytes acumulados desde o primeiro avistamento
//     — não "bytes no período". Por isso a divisão de bytes vem do pair_daily
//     (que é por dia) e o período aparece como contexto, não como medida.

// Faixas: os limites espelham a leitura por pontos do AbuseIPDB (0 = limpo).
const SCORE_BUCKETS = [
  { key: '0', label: '0 (limpo)', min: 0 },
  { key: '1-10', label: '1 a 10', min: 1 },
  { key: '11-30', label: '11 a 30', min: 11 },
  { key: '31-50', label: '31 a 50', min: 31 },
  { key: '51-70', label: '51 a 70', min: 51 },
  { key: '71-90', label: '71 a 90', min: 71 },
  { key: '91-100', label: '91 a 100', min: 91 },
  { key: 'nao-verificado', label: 'não verificado', min: null }
];

// Contexto = classification do PRÓPRIO AbuseIPDB (usage_type), não heurística
// nossa. A distinção importa: nesta rede a faixa 91-100 é majoritariamente
// varredura de internet e cloud (Censys, Microsoft, DigitalOcean), que é barulho
// de fundo — não o mesmo risco de um host de saída falando com um C2.
const CONTEXTS = [
  { key: 'hospedagem', label: 'Hospedagem / CDN / datacenter' },
  { key: 'operadora', label: 'Operadora (ISP residencial e móvel)' },
  { key: 'institucional', label: 'Institucional / comercial' },
  { key: 'desconhecido', label: 'Sem classificação' }
];

const { localDay } = require('./time.js');

function isoDay(d) {
  // Date -> dia LOCAL. Strings (DATE do Postgres) já vêm no formato YYYY-MM-DD.
  return d instanceof Date ? localDay(d) : String(d).slice(0, 10);
}

async function overviewFor({ days = 7 } = {}) {
  const { pool } = require('./db.js');
  const { isPrivate } = require('./risk.js');
  const { daysParam } = require('./params.js');
  const d = daysParam(days, { nome: 'days', def: 0 });
  // days=0 = base inteira: sem filtro de janela.
  const w = d ? `where s.last_seen >= now() - ($1 || ' days')::interval` : '';
  const w1 = d ? [String(d)] : null;

  const CASE_FAIXA = `case
         when r.ip is null then 'nao-verificado'
         when r.score = 0 then '0'
         when r.score <= 10 then '1-10'
         when r.score <= 30 then '11-30'
         when r.score <= 50 then '31-50'
         when r.score <= 70 then '51-70'
         when r.score <= 90 then '71-90'
         else '91-100' end`;
  const CASE_CTX = `case
         when r.usage_type is null or r.usage_type = '' then 'desconhecido'
         when r.usage_type ilike '%Data Center%' or r.usage_type ilike '%Hosting%'
           or r.usage_type ilike '%Transit%' or r.usage_type ilike '%Content Delivery%' then 'hospedagem'
         when r.usage_type ilike '%ISP%' then 'operadora'
         when r.usage_type ilike '%University%' or r.usage_type ilike '%Education%'
           or r.usage_type ilike '%Government%' or r.usage_type ilike '%Commercial%'
           or r.usage_type ilike '%Corporate%' then 'institucional'
         else 'desconhecido' end`;
  const FROM = 'from ip_sightings s left join ip_reputation r on r.ip = s.ip';

  const [totais, faixas, ctxs, paises, isps, serie, retencao] = await Promise.all([
    pool.query(
      `select count(*)::int as ips,
              count(r.ip)::int as verificados,
              count(*) filter (where r.score > 0)::int as ruins,
              count(*) filter (where r.whitelisted)::int as whitelist,
              coalesce(sum(s.bytes), 0)::bigint as bytes,
              coalesce(sum(s.bytes) filter (where r.score > 0), 0)::bigint as bytes_ruins,
              min(s.first_seen) as desde, max(s.last_seen) as ate
         ${FROM} ${w}`, w1),
    pool.query(
      `select ${CASE_FAIXA} as faixa, count(*)::int as ips,
              coalesce(sum(s.bytes), 0)::bigint as bytes
         ${FROM} ${w} group by 1`, w1),
    pool.query(
      `select ${CASE_CTX} as contexto, count(*)::int as ips,
              count(*) filter (where r.score > 0)::int as ruins,
              coalesce(sum(s.bytes) filter (where r.score > 0), 0)::bigint as bytes_ruins
         ${FROM} ${w} group by 1`, w1),
    pool.query(
      `select coalesce(r.country, s.country, '??') as pais,
              coalesce(r.country_name, s.country_name, 'Desconhecido') as nome,
              count(*)::int as ips, count(*) filter (where r.score > 0)::int as ruins,
              coalesce(sum(s.bytes), 0)::bigint as bytes
         ${FROM} ${w} group by 1, 2 order by ruins desc, ips desc limit 12`, w1),
    pool.query(
      `select coalesce(r.isp, '(sem ISP)') as isp,
              count(*)::int as ips, count(*) filter (where r.score > 0)::int as ruins,
              coalesce(sum(s.bytes), 0)::bigint as bytes
         ${FROM} ${w ? `${w} and` : 'where'} r.isp is not null
        group by 1 order by ruins desc, ips desc limit 12`, w1),
    // Série por dia: pair_daily é o único com bytes POR DIA. O score aplicado é
    // o de hoje (ver nota 2 no cabeçalho).
    pool.query(
      `select pd.day::date as dia, sum(pd.bytes)::bigint as bytes,
              coalesce(sum(pd.bytes) filter (where r.score > 0), 0)::bigint as bytes_ruins,
              count(distinct pd.dst)::int as dsts,
              count(distinct pd.dst) filter (where r.score > 0)::int as dsts_ruins
         from pair_daily pd left join ip_reputation r on r.ip = pd.dst
        where pd.day >= $1::date - $2::int group by 1 order by 1`,
      [isoDay(new Date()), d || 30]),
    pool.query(
      `select min(day)::date as desde, max(day)::date as ate,
              count(distinct src)::int as srcs, count(distinct dst)::int as dsts
         from pair_daily where day >= $1::date - $2::int`,
      [isoDay(new Date()), d || 30])
  ]);

  const t = totais.rows[0] || {};
  let serieRows = serie.rows.map((r) => ({
    dia: isoDay(r.dia),
    bytes: Number(r.bytes), bytesRuins: Number(r.bytes_ruins),
    dsts: Number(r.dsts), dstsRuins: Number(r.dsts_ruins)
  }));

  // A série é por dia FECHADO, então numa janela de 24h não sobra nenhum dia e o
  // gráfico ficaria vazio. Nesse caso mostramos os últimos dias fechados que
  // existem e avisamos: gráfico vazio sem explicação parece bug.
  let serieSubstituida = false;
  if (!serieRows.length) {
    const alt = await pool.query(
      `select pd.day::date as dia, sum(pd.bytes)::bigint as bytes,
              coalesce(sum(pd.bytes) filter (where r.score > 0), 0)::bigint as bytes_ruins,
              count(distinct pd.dst)::int as dsts,
              count(distinct pd.dst) filter (where r.score > 0)::int as dsts_ruins
         from pair_daily pd left join ip_reputation r on r.ip = pd.dst
        group by 1 order by 1 desc limit 14`);
    serieRows = alt.rows.map((r) => ({
      dia: isoDay(r.dia), bytes: Number(r.bytes), bytesRuins: Number(r.bytes_ruins),
      dsts: Number(r.dsts), dstsRuins: Number(r.dsts_ruins)
    })).reverse();
    serieSubstituida = serieRows.length > 0;
  }

  // Bytes da janela pedida. Só 24h usa o ES (o pair_daily não tem o dia
  // corrente, por decisão de não poluir a baseline); acima disso o ES pode já
  // ter expirado e o par_daily é a fonte honesta. Base inteira (d=0) também vai
  // pelo par_daily: a janela de 24h do ES não representa "toda a base".
  let bytes = null;
  if (d === 1) {
    bytes = await liveBytes24h();
    if (bytes) bytes.fonte = 'es';
  }
  if (!bytes) {
    const dias = serieRows.map((r) => r.dia);
    const tot = serieRows.reduce((a, r) => a + r.bytes, 0);
    const ruins = serieRows.reduce((a, r) => a + r.bytesRuins, 0);
    bytes = { fonte: 'pair_daily', dias, total: tot, ruins };
  }

  // Hosts internos de verdade: pair_daily guarda par (src,dst) sem filtrar quem
  // é interno, então o distinct src puro contaria origem externa-para-externa.
  let hostsInternos = null;
  if (retencao.rows[0]?.srcs) {
    const srcs = await pool.query(
      `select distinct src from pair_daily where day >= $1::date - $2::int`,
      [isoDay(new Date()), d || 30]);
    hostsInternos = srcs.rows.filter((r) => isPrivate(r.src)).length;
  }

  const notas = [];
  const desde = t.desde ? new Date(t.desde).toISOString() : null;
  if (d && desde) {
    const disponivel = Math.floor((Date.now() - new Date(t.desde).getTime()) / 86400000);
    if (d > disponivel) {
      notas.push(`Pediu ${d} dias, mas o histórico de sightings começa em ${isoDay(t.desde)} (${disponivel}d). Não há dado anterior a isso.`);
    }
  }
  if (bytes.fonte === 'pair_daily' && bytes.dias.length) {
    notas.push(`Bytes vêm de ${bytes.dias.length} dia(s) fechados (${bytes.dias[0]} → ${bytes.dias[bytes.dias.length - 1]}), da série diária. O dia corrente não entra: está crescendo.`);
  }
  if (serieSubstituida) {
    notas.push(`A janela de ${d ? `${d}d` : 'base inteira'} não tem dia fechado (a série diária para ontem), então a linha do tempo mostra os últimos ${serieRows.length} dias coletados.`);
  }
  // Lacuna na série diária: o job das 06:40 só roda se o processo estiver no ar
  // naquele minuto. Dia faltando = baseline torta, então avisamos em vez de
  // desenhar uma linha contínua que não existe.
  if (retencao.rows[0]?.desde) {
    const ate = isoDay(retencao.rows[0].ate);
    const inicio = isoDay(retencao.rows[0].desde);
    const presentes = new Set(serieRows.map((r) => r.dia));
    const faltando = [];
    for (let x = new Date(`${inicio}T00:00:00Z`); isoDay(x) <= ate; x = new Date(x.getTime() + 86400000)) {
      if (!presentes.has(isoDay(x))) faltando.push(isoDay(x));
    }
    if (faltando.length) notas.push(`Série diária com ${faltando.length} dia(s) sem coleta: ${faltando.join(', ')}. O job das 06:40 só roda com o backend no ar — "coletar base" ou esperar o job recuperar.`);
  }

  const total = Number(t.ips || 0);
  return {
    days: d,
    desde, ate: t.ate ? new Date(t.ate).toISOString() : null,
    kpis: {
      ips: total,
      verificados: Number(t.verificados || 0),
      naoVerificados: total - Number(t.verificados || 0),
      ruins: Number(t.ruins || 0),
      whitelist: Number(t.whitelist || 0),
      bytesHistorico: Number(t.bytes || 0),
      bytesHistoricoRuins: Number(t.bytes_ruins || 0),
      bytes: bytes.total,
      bytesRuins: bytes.ruins,
      hostsInternos,
      cobertura: total ? Number(((Number(t.verificados || 0) / total) * 100).toFixed(1)) : 0
    },
    bytes,
    buckets: SCORE_BUCKETS.map((b) => {
      const row = faixas.rows.find((x) => x.faixa === b.key);
      return { key: b.key, label: b.label, ips: Number(row?.ips || 0), bytes: Number(row?.bytes || 0) };
    }),
    contexts: CONTEXTS.map((c) => {
      const row = ctxs.rows.find((x) => x.contexto === c.key);
      return { key: c.key, label: c.label, ips: Number(row?.ips || 0), ruins: Number(row?.ruins || 0), bytesRuins: Number(row?.bytes_ruins || 0) };
      // Gráfico de barras é ranking: sempre do maior para o menor. A ordem
      // "lógica" (hospedagem, operadora, institucional) só confundia quem lê.
    }).sort((a, b) => b.ips - a.ips || a.label.localeCompare(b.label, 'pt-BR')),
    paises: paises.rows.map((r) => ({
      country: r.pais, countryName: r.nome, ips: Number(r.ips), ruins: Number(r.ruins), bytes: Number(r.bytes)
      // Ranking explícito: a tela desenha barras, e barra sem ordem é ruído.
    })).sort((a, b) => b.ruins - a.ruins || b.ips - a.ips),
    isps: isps.rows.map((r) => ({
      isp: r.isp, ips: Number(r.ips), ruins: Number(r.ruins), bytes: Number(r.bytes)
    })).sort((a, b) => b.ruins - a.ruins || b.ips - a.ips),
    serie: serieRows,
    serieSubstituida,
    retencao: {
      serieDesde: retencao.rows[0]?.desde ? isoDay(retencao.rows[0].desde) : null,
      serieAte: retencao.rows[0]?.ate ? isoDay(retencao.rows[0].ate) : null,
      dsts: Number(retencao.rows[0]?.dsts || 0)
    },
    notas
  };
}

// Bytes das últimas 24h direto do ES: inclui o dia corrente, que o pair_daily
// não tem. Só 24h de propósito — janela maior no ES é cara e o par_daily cobre.
async function liveBytes24h() {
  try {
    const { client, ELASTIC_INDEX, F_DST } = require('./elastic.js');
    const r = await client.search({
      index: ELASTIC_INDEX, size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }] } },
      aggs: {
        p: {
          terms: { field: F_DST, size: 10000 },
          aggs: { bytes: { sum: { field: 'netflow.octetDeltaCount' } } }
        }
      }
    });
    const buckets = r.aggregations?.p?.buckets || [];
    const { pool } = require('./db.js');
    const ips = buckets.map((b) => String(b.key));
    if (!ips.length) return { fonte: 'es', total: 0, ruins: 0, dias: [], truncado: false };
    const sc = await pool.query('select ip, score from ip_reputation where ip = any($1::text[])', [ips]);
    const score = {};
    for (const x of sc.rows) score[x.ip] = Number(x.score || 0);
    let total = 0;
    let ruins = 0;
    for (const b of buckets) {
      const by = Math.round(b.bytes?.value || 0);
      total += by;
      if ((score[String(b.key)] || 0) > 0) ruins += by;
    }
    return {
      fonte: 'es', total, ruins,
      dias: [isoDay(new Date(Date.now() - 86400000)), isoDay(new Date())],
      truncado: buckets.length >= 10000
    };
  } catch {
    return null; // sem ES: o chamador cai no pair_daily
  }
}

module.exports = { isPublicIp, checkIp, checkMany, coverageFor, quotaState, quotaUntil: () => rateLimitedUntil, listReputationDb, overviewFor, repTtlDays: () => REP_PG_TTL_DAYS };
