// Coletor do histórico de IPs públicos (o job das 06:15).
//
// POR QUE EXISTE A TABELA ip_daily
// A versão anterior somava bytes/flows direto no ip_sightings a cada coleta
// (`bytes = ip_sightings.bytes + excluded.bytes`). Só que o job roda com janela
// de 24h e o botão da tela com 168h: as duas janelas cobrem os mesmos dias, e o
// mesmo byte era contado de novo. Medido no banco: 3,5× a 5,3× nos IPs de maior
// volume, e a soma nunca volta atrás.
//
// Agora a média de cada IP mora em ip_daily (uma linha por IP por dia) e o
// ip_sightings é o ROLLUP disso. Três consequências:
//   1. regravação por dia: rodar a coleta duas vezes dá exatamente o mesmo número
//   2. first_seen/last_seen passam a ser o primeiro/último avistamento real
//      (min/max de @timestamp). Antes entravam com a idade da janela de
//      colheita, e um IP visto há 2h "nascia" com 24h
//   3. dia sem documento no ES (expirou) é pulado, nunca virado em zero
const { pool } = require('./db');
const { client, ELASTIC_INDEX, F_SRC, F_DST } = require('./elastic');
const { checkIp, isPublicIp } = require('./reputation');
const { localDay, addDays, dayRange } = require('./time');

const REGIONS_CRON = process.env.REGIONS_CRON || '15 6 * * *';
const F_OCTETS = 'netflow.octetDeltaCount';
const MAX_IPS_POR_LADO = 10000;
const CONCURRENCY = 6;

// Dias LOCAIS que a janela [fromIso, toIso] toca.
function diasDaJanela(fromIso, toIso) {
  const out = [];
  const fim = localDay(new Date(toIso));
  let dia = localDay(new Date(fromIso));
  for (; dia <= fim; dia = addDays(dia, 1)) out.push(dia);
  return out;
}

// Lê um dia do ES. O range é [00:00 local, 00:00 do dia seguinte local),
// cortado em `ateIso` quando é o dia corrente (ainda em andamento). Así a
// janela do dia corrente cresce ao longo do dia e regravar nunca perde o que a
// coleta anterior gravou; dias fechados não vazam um para o outro.
async function harvestDia(dayIso, ateIso) {
  const { start, end } = dayRange(dayIso);
  const hi = ateIso && ateIso < end ? ateIso : end;
  const q = { bool: { filter: [{ range: { '@timestamp': { gte: start, lt: hi } } }] } };
  const aggIP = (field) => ({
    terms: { field, size: MAX_IPS_POR_LADO },
    aggs: {
      bytes: { sum: { field: F_OCTETS } },
      // format: epoch_millis porque o Postgres não aceita o ISO que o ES devolve
      // por padrão, e comparar string ISO com número daria resultado errado.
      primeiro: { min: { field: '@timestamp', format: 'epoch_millis' } },
      ultimo: { max: { field: '@timestamp', format: 'epoch_millis' } }
    }
  });
  const [a, b] = await Promise.all([
    client.search({ index: ELASTIC_INDEX, size: 0, query: q, aggs: { p: aggIP(F_SRC), _docs: { filter: { match_all: {} } } } }),
    client.search({ index: ELASTIC_INDEX, size: 0, query: q, aggs: { p: aggIP(F_DST) } })
  ]);
  // Sem documento no ES = dia que já expirou (ou sem tráfego). Não pode virar
  // "zero": isso apagaria o histórico já gravado.
  if (!(a.aggregations?._docs?.doc_count > 0)) return { day: dayIso, vazio: true, mapa: new Map() };
  const mapa = new Map();
  for (const bucket of [...a.aggregations.p.buckets, ...b.aggregations.p.buckets]) {
    const ip = String(bucket.key);
    if (!isPublicIp(ip)) continue;
    let r = mapa.get(ip);
    if (!r) { r = { bytes: 0, flows: 0, primeiro: null, ultimo: null }; mapa.set(ip, r); }
    r.bytes += bucket.bytes?.value || 0;
    r.flows += bucket.doc_count;
    // epoch_millis -> ISO. `Number()` porque o cliente pode devolver number OU
    // stringdepending do formato; sem isso virava "NaN" e a comparação falhava.
    const ms = (v) => {
      const n = Number(v?.value ?? v);
      return Number.isFinite(n) && n > 0 ? new Date(n).toISOString() : null;
    };
    const p = ms(bucket.primeiro);
    const u = ms(bucket.ultimo);
    if (p && (!r.primeiro || p < r.primeiro)) r.primeiro = p;
    if (u && (!r.ultimo || u > r.ultimo)) r.ultimo = u;
  }
  // `sum_other_doc_count > 0` = o teto de MAX_IPS_POR_LADO cortou IPs do lado,
  // ou seja: os bytes deste dia estão incompletos. Sinalizado, não escondido.
  const truncado = [a, b]
    .some((r) => (r.aggregations?.p?.sum_other_doc_count || 0) > 0);
  return { day: dayIso, vazio: false, truncado, mapa };
}

async function gravaDia(dayIso, mapa) {
  const linhas = [...mapa.entries()];
  const c = await pool.connect();
  try {
    await c.query('begin');
    for (let i = 0; i < linhas.length; i += 500) {
      const vals = [];
      const params = [];
      for (const [ip, r] of linhas.slice(i, i + 500)) {
        const b = params.length;
        vals.push(`($${b + 1}::date, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}::timestamptz, $${b + 6}::timestamptz, now())`);
        params.push(dayIso, ip, Math.round(r.bytes), Math.round(r.flows), r.primeiro, r.ultimo);
      }
      await c.query(
        `insert into ip_daily (day, ip, bytes, flows, first_ts, last_ts, updated_at)
         values ${vals.join(', ')}
         on conflict (day, ip) do update set
           bytes = excluded.bytes, flows = excluded.flows,
           first_ts = excluded.first_ts, last_ts = excluded.last_ts, updated_at = now()`,
        params
      );
    }
    await c.query('commit');
    return linhas.length;
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

// ip_sightings = rollup de ip_daily. bytes/flows são SUBSTITUÍDOS (nunca
// somados) e first_seen/last_seen vêm do primeiro/último avistamento real.
async function rollup(ips) {
  if (!ips.length) return;
  const c = await pool.connect();
  try {
    await c.query('begin');
    // country/country_name vêm do cache de reputação no mesmo passe. Sem esse
    // join, um IP que JÁ estava em ip_reputation mas que ainda não tinha passado
    // por consultarPaises() ficava com country = null para sempre: a função só
    // atualiza os IPs que ela acabou de consultar, e o cache antigo não conta.
    await c.query(
      `insert into ip_sightings (ip, first_seen, last_seen, bytes, flows, country, country_name, updated_at)
       select d.ip, min(d.first_ts), max(d.last_ts), sum(d.bytes), sum(d.flows),
              r.country, r.country_name, now()
         from ip_daily d
         left join ip_reputation r on r.ip = d.ip
        where d.ip = any($1::text[]) group by d.ip, r.country, r.country_name
       on conflict (ip) do update set
         first_seen = least(ip_sightings.first_seen, excluded.first_seen),
         last_seen = greatest(ip_sightings.last_seen, excluded.last_seen),
         bytes = excluded.bytes,
         flows = excluded.flows,
         country = coalesce(excluded.country, ip_sightings.country),
         country_name = coalesce(excluded.country_name, ip_sightings.country_name),
         updated_at = now()`,
      [ips]
    );
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

// Concorrência limitada. O Promise.all sem limite que existia aqui disparava
// milhares de consulta ao AbuseIPDB ao mesmo tempo quando a rede via >1000 IPs
// públicos novos: 429 na hora, e ainda assim gravava sighting sem veredito.
async function comConcorrencia(itens, limite, fn) {
  let i = 0;
  async function worker() {
    while (i < itens.length) await fn(itens[i++]);
  }
  await Promise.all(Array.from({ length: Math.min(limite, itens.length || 1) }, worker));
}

// Recolhe o histórico público. Aceita hours (janela) ou uma lista de dias.
async function harvest(hours = 24, opts = {}) {
  const { pais = true, aoConsultar = null } = (typeof opts === 'boolean' ? { pais: opts } : opts || {});
  const ate = new Date().toISOString();
  const dias = Array.isArray(hours)
    ? hours
    : diasDaJanela(new Date(Date.parse(ate) - hours * 3600000).toISOString(), ate);

  const porDia = [];
  for (const dia of dias) {
    porDia.push(await harvestDia(dia, ate));
    if (aoConsultar) aoConsultar(porDia[porDia.length - 1]);
  }

  const afetados = new Set();
  let upserted = 0;
  for (const d of porDia) {
    if (d.vazio) continue;
    upserted += await gravaDia(d.day, d.mapa);
    for (const ip of d.mapa.keys()) afetados.add(ip);
  }
  const ips = [...afetados];
  await rollup(ips);

  // País/reputação. checkIp() usa o cache persistente, então IP já conhecido não
  // gasta cota — mas mesmo assim com limite de concorrência.
  //
  // `pais: false` pula esta etapa. A reconstrução do histórico precisa disso:
  // são ~3.400 IPs e o AbuseIPDB free dá 1.000 consultas/dia, então consultar
  // durante o backfill estoura a cota e o ip_sightings fica sem país. Quem
  // consulta, depois, é consultarPaises() — uma vez só, com guarda de cota.
  if (!pais) {
    const vazios = porDia.filter((d) => d.vazio).map((d) => d.day);
    return {
      at: ate, hours: dias.length * 24, dias, ips: ips.length, upserted,
      semDocumento: vazios, truncadoES: porDia.some((d) => d.truncado),
      semPais: ips.length, paisConsultado: false
    };
  }
  const consultar = await consultarPaises(ips);
  const vazios = porDia.filter((d) => d.vazio).map((d) => d.day);
  return {
    at: ate,
    hours: Array.isArray(hours) ? dias.length * 24 : hours,
    dias,
    ips: ips.length,
    upserted,
    semDocumento: vazios,
    truncadoES: porDia.some((d) => d.truncado),
    semPais: consultar.semPais,
    cotaEsgotada: consultar.cotaEsgotada,
    paisConsultado: true
  };
}

// Uma passada de país/reputação sobre uma lista de IPs, com guarda de cota.
// Separado de harvest() para o backfill não consumir a cota do AbuseIPDB dia a
// dia: se a cota acabar no meio, os IPs restantes ficam sem país de forma
// DEFINITIVA (o job das 06:15 do dia seguinte já acha ip_daily gravado e não
// reconsulta).
async function consultarPaises(ips, { forcar = false } = {}) {
  const info = {};
  let cotaEsgotada = false;
  await comConcorrencia(ips, CONCURRENCY, async (ip) => {
    if (cotaEsgotada) return;
    try {
      const v = await checkIp(ip, { forcar });
      info[ip] = { country: v.abuse?.country || null, countryName: v.abuse?.countryName || null };
    } catch (e) {
      if (e?.limiteCota) cotaEsgotada = true;
    }
  });
  const comPais = Object.entries(info).filter(([, v]) => v.country);
  if (comPais.length) {
    await pool.query(
      `update ip_sightings s set country = v.country, country_name = v.country_name, updated_at = now()
         from unnest($1::text[], $2::text[], $3::text[]) as v(ip, country, country_name)
        where s.ip = v.ip and v.country is not null`,
      [comPais.map(([ip]) => ip), comPais.map(([, v]) => v.country), comPais.map(([, v]) => v.countryName)]
    );
  }
  return { consultados: ips.length, comPais: comPais.length, semPais: ips.length - comPais.length, cotaEsgotada };
}

// AGORA ESTE ARQUIVO É SÓ O COLETOR. A tela de Regiões foi removida: a listagem
// por país era duplicata de /api/reputation/db (que já devolve os mesmos IPs
// com score, país e histórico, ordenados por score).
//
// O que sobra é o que nenhuma tela mostra: o job das 06:15 que varre o ES, chama
// checkIp() de cada IP público novo e grava ip_daily/ip_sightings (país +
// reputação + bytes). É daqui que saem os scores do risco, a base dos destinos
// novos e o país do dossiê — apagar isto quebraria a tela de reputação.

module.exports = { harvest, consultarPaises, diasDaJanela, REGIONS_CRON };