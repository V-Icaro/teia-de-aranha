// Exposição a IP malicioso: o cruzamento que o mapa não fazia.
// ES dá o par interno↔externo com bytes na janela; o Postgres dá o score
// que já foi pago/consultado antes (ip_reputation). Nada de chamada extra à
// API externa aqui — o risco sai de dados que já temos.
//
// Risco = participação do volume que foi para IP com score>0, ponderada pelo
// próprio score (score 10 não pesa como 90). É 0..1, comparável entre hosts.
const { pool } = require('./db.js');
const { client, ELASTIC_INDEX, F_SRC, F_DST, F_PROTO, F_DPORT, F_FEND, buildTimeRange } = require('./elastic.js');

// Métricas: somas são numéricas e o exporter não as renomeia (ao contrário dos
// campos de IP/porta, que podem ser text+keyword). Deixamos literais.
const F_OCTETS = 'netflow.octetDeltaCount';
const F_PACKETS = 'netflow.packetDeltaCount';
const REP_MAX_AGE_DAYS = Math.max(1, parseInt(process.env.REP_PG_TTL_DAYS || '7', 10) || 7);

function octets4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip));
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((x) => x >= 0 && x <= 255) ? parts : null;
}

// Escopo deliberadamente IPv4: privados e especiais não devem parecer IPs
// públicos de Internet nas análises de exposição.
function isPrivate(ip) {
  const parts = octets4(ip);
  if (!parts) return false;
  const [a, b] = parts;
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
}
function isPublicIp4(ip) {
  const parts = octets4(ip);
  if (!parts) return false;
  const [a, b, c] = parts;
  const special = a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127) // shared address space (RFC 6598)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 192 && b === 88 && c === 99)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113);
  return !special;
}

// Traz os scores já cacheados no Postgres para um lote de IPs.
// Retorna { rep: {ip: {...}}, ok: boolean }.
//
// ok=false significa que o Postgres não respondeu. Isso NÃO pode virar "todos os
// IPs têm score 0": a tela leria "nenhum host fala com IP malicioso" quando o
// dado é inexistente. Antes o catch devolvia { rows: [] } e o risco saía 0 para
// todo mundo, com HTTP 200.
//
// A consulta é paginada em lotes: o `= any()` com teto de 4000 deixava tudo
// acima do teto sem score, o que produzia exatamente o mesmo problema (host que
// fala com o IP malicioso na posição 4001 aparecia como "sem exposição").
async function reputationFor(ips) {
  const uniq = [...new Set(ips)].filter(Boolean);
  if (!uniq.length) return { rep: {}, ok: true, requested: 0, found: 0, stale: 0, missing: 0 };
  const out = {};
  let stale = 0;
  for (let i = 0; i < uniq.length; i += 4000) {
    const lote = uniq.slice(i, i + 4000);
    let rows;
    try {
      ({ rows } = await pool.query(
        `select ip, verdict, score, country, country_name, isp, usage_type, checked_at
           from ip_reputation where ip = any($1::text[])`,
        [lote]));
    } catch (e) {
      // Reputação é enfeite aqui: o que a tela precisa é quem é novo. Se o
      // Postgres cair, devolvemos vazio (score nulo = "não verificado") mas
      // avisando, em vez de derrubar o endpoint inteiro em silêncio.
      return { rep: {}, ok: false, erro: e.message, requested: uniq.length, found: 0, stale: 0, missing: uniq.length };
    }
    for (const x of rows) {
      const checkedAt = x.checked_at ? new Date(x.checked_at).getTime() : 0;
      if (!checkedAt || Date.now() - checkedAt > REP_MAX_AGE_DAYS * 86400000) {
        stale += 1;
        continue;
      }
      out[x.ip] = {
        score: x.score ?? null,
        verdict: x.verdict,
        country: x.country || null,
        countryName: x.country_name || null,
        isp: x.isp || null,
        usageType: x.usage_type || null,
        checkedAt: x.checked_at
      };
    }
  }
  const found = Object.keys(out).length;
  return { rep: out, ok: true, requested: uniq.length, found, stale, missing: uniq.length - found };
}

// ---------------------------------------------------------------- risco por host
// Escopo: tráfego IPv4 TCP/UDP de host privado -> destino público. Scores são
// usados somente se foram consultados dentro do TTL; cache ausente/vencido fica
// como desconhecido, nunca como score zero.
async function hostRisk(query, { maxPairs = 12000 } = {}) {
  const afterPages = [];
  let after;
  let pairs = 0;
  let truncated = false;

  while (true) {
    const pageSize = Math.min(2000, maxPairs - pairs);
    if (pageSize <= 0) {
      if (after) {
        const probe = await client.search({
          index: ELASTIC_INDEX, size: 0,
          query: { bool: { filter: [{ range: buildTimeRange(query) }] } },
          aggs: { pares: { composite: { size: 1, after, sources: [
            { origem: { terms: { field: F_SRC } } },
            { destino: { terms: { field: F_DST } } }
          ] } } }
        });
        truncated = (probe.aggregations?.pares?.buckets || []).length > 0;
      }
      break;
    }
    const composite = {
      size: pageSize,
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } }
      ]
    };
    if (after) composite.after = after;

    const resp = await client.search({
      index: ELASTIC_INDEX,
      size: 0,
      query: { bool: { filter: [{ range: buildTimeRange(query) }] } },
      aggs: {
        pares: {
          composite,
          aggs: {
            bytes: { sum: { field: F_OCTETS } },
            packets: { sum: { field: F_PACKETS } },
            portas: { terms: { field: F_DPORT, size: 5 } },
            // Protocolo como SUB-agregação, não como fonte do composite.
            // Composite com 3 fontes multiplica os buckets por 10-50x e a
            // paginação fica inviável; e sem isto o filtro "só TCP/UDP" abaixo
            // nunca casa, porque key.protocolo não existe.
            protocolos: {
              terms: { field: F_PROTO, size: 2, include: [6, 17] },
              aggs: {
                pbytes: { sum: { field: F_OCTETS } },
                ppackets: { sum: { field: F_PACKETS } }
              }
            }
          }
        }
      }
    });
    const b = resp.aggregations?.pares?.buckets;
    if (!b || !b.length) break;
    afterPages.push(...b);
    pairs += b.length;
    after = resp.aggregations?.pares?.after_key;
    if (!after) break;
  }

  // Só interessa host interno -> destino público.
  // Bytes e pacotes vêm SOMADOS por protocolo dentro do par: o denominador do
  // risco é o tráfego de transporte (TCP/UDP), não o total — ICMP/GRE não são
  // "exposição externa" e incluí-los diluiria a razão.
  const rows = afterPages
    .map((x) => {
      const pb = (x.protocolos?.buckets || []);
      const transport = pb.filter((b) => b.key === 6 || b.key === 17);
      return {
        src: String(x.key.origem),
        dst: String(x.key.destino),
        bytes: transport.reduce((a, b) => a + (b.pbytes?.value || 0), 0),
        packets: transport.reduce((a, b) => a + (b.ppackets?.value || 0), 0),
        bytesAll: x.bytes?.value || 0,
        packetsAll: x.packets?.value || 0,
        transport: transport.length > 0,
        ports: (x.portas?.buckets || []).map((p) => p.key)
      };
    })
    .filter((x) => x.src !== x.dst && isPrivate(x.src) && isPublicIp4(x.dst) && x.transport);

  const repResult = await reputationFor(rows.map((x) => x.dst));
  const { rep, ok: repOk, erro: repErro } = repResult;

  const hosts = new Map();
  for (const r of rows) {
    const h = hosts.get(r.src) || {
      ip: r.src, bytesTotal: 0, bytesExternal: 0, bytesBad: 0,
      packetsTotal: 0, packetsBad: 0,
      externalPeers: 0, assessedPeers: 0, unknownPeers: 0, badPeers: 0,
      bytesAssessed: 0, bytesUnknown: 0,
      weighted: 0, maxScore: 0,
      countries: new Map(), badDest: [], allDest: []
    };
    h.bytesTotal += r.bytesAll;
    h.packetsTotal += r.packetsAll;
    h.bytesExternal += r.bytes;
    h.externalPeers += 1;

    const rv = rep[r.dst];
    h.allDest.push({ ip: r.dst, bytes: Math.round(r.bytes), score: rv?.score ?? null, verdict: rv?.verdict || 'unknown', country: rv?.countryName || null, isp: rv?.isp || null, ports: r.ports });
    if (rv) {
      h.assessedPeers += 1;
      h.bytesAssessed += r.bytes;
    } else {
      h.unknownPeers += 1;
      h.bytesUnknown += r.bytes;
    }
    if (rv?.countryName) {
      const c = h.countries.get(rv.countryName) || { country: rv.countryName, ips: 0, bytes: 0 };
      c.ips += 1;
      c.bytes += r.bytes;
      h.countries.set(rv.countryName, c);
    }
    const score = rv?.score ?? 0;
    if (score > 0) {
      h.badPeers += 1;
      h.bytesBad += r.bytes;
      h.packetsBad += r.packets;
      h.weighted += r.bytes * (score / 100); // 0..1 ponderado pelo score
      if (score > h.maxScore) h.maxScore = score;
      h.badDest.push({ ip: r.dst, bytes: Math.round(r.bytes), score, verdict: rv.verdict, country: rv.countryName || null, isp: rv.isp || null, checkedAt: rv.checkedAt });
    }
    hosts.set(r.src, h);
  }

  const list = [...hosts.values()].map((h) => {
    const ext = h.bytesExternal || 0;
    const assessed = h.bytesAssessed || 0;
    // Risco e classes usam a mesma métrica: volume avaliado, ponderado pelo
    // score. Destinos sem score não entram como limpos nem diluem o percentual.
    const risk = assessed > 0 ? Math.min(1, h.weighted / assessed) : null;
    const badShare = assessed > 0 ? h.bytesBad / assessed : null;
    const badPeerShare = h.assessedPeers > 0 ? h.badPeers / h.assessedPeers : null;
    const coveragePeers = h.externalPeers > 0 ? h.assessedPeers / h.externalPeers : 0;
    const coverageBytes = ext > 0 ? assessed / ext : 0;
    const level = !repOk ? 'indisponivel'
      : assessed === 0 ? 'parcial'
      : risk >= 0.5 ? 'critical'
      : risk >= 0.2 ? 'high'
      : risk > 0.05 ? 'med'
      : risk > 0 ? 'low'
      : h.unknownPeers > 0 ? 'parcial' : 'none';
    return {
      ip: h.ip,
      risk: risk == null ? null : Number(risk.toFixed(4)),
      badShare: badShare == null ? null : Number(badShare.toFixed(4)),
      badPeerShare: badPeerShare == null ? null : Number(badPeerShare.toFixed(4)),
      level,
      bytesTotal: Math.round(h.bytesTotal),
      bytesExternal: Math.round(h.bytesExternal),
      bytesAssessed: Math.round(assessed),
      bytesUnknown: Math.round(h.bytesUnknown),
      bytesBad: Math.round(h.bytesBad),
      packetsTotal: Math.round(h.packetsTotal),
      externalPeers: h.externalPeers,
      assessedPeers: h.assessedPeers,
      unknownPeers: h.unknownPeers,
      coveragePeers: Number(coveragePeers.toFixed(4)),
      coverageBytes: Number(coverageBytes.toFixed(4)),
      badPeers: h.badPeers,
      assessed: assessed > 0,
      maxScore: h.maxScore,
      countries: [...h.countries.values()]
        .map((c) => ({ ...c, bytes: Math.round(c.bytes), pct: ext > 0 ? Number((c.bytes / ext).toFixed(4)) : 0 }))
        .sort((a, b) => b.bytes - a.bytes).slice(0, 8),
      badDestinations: h.badDest.sort((a, b) => b.bytes - a.bytes).slice(0, 12),
      topDestinations: h.allDest.sort((a, b) => b.bytes - a.bytes).slice(0, 12)
    };
  }).sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1) || b.bytesBad - a.bytesBad);

  const coveragePeers = rows.length;
  const assessedPeers = rows.reduce((n, r) => n + (rep[r.dst] ? 1 : 0), 0);
  const externalBytes = rows.reduce((n, r) => n + r.bytes, 0);
  const assessedBytes = rows.reduce((n, r) => n + (rep[r.dst] ? r.bytes : 0), 0);
  const reputationCoverage = {
    peers: coveragePeers,
    assessedPeers,
    unknownPeers: coveragePeers - assessedPeers,
    peerPct: coveragePeers ? Number((assessedPeers / coveragePeers * 100).toFixed(1)) : 100,
    bytes: Math.round(externalBytes),
    assessedBytes: Math.round(assessedBytes),
    unknownBytes: Math.round(externalBytes - assessedBytes),
    bytePct: externalBytes ? Number((assessedBytes / externalBytes * 100).toFixed(1)) : 100,
    uniqueIps: repResult.requested,
    assessedIps: repResult.found,
    unknownIps: repResult.missing,
    staleEntries: repResult.stale || 0
  };

  // Com o Postgres fora, `rep` vem vazio. Publicar risk/level assim seria dizer
  // "nenhum host fala com IP malicioso" por falta de dado — devolva as linhas com
  // o aviso e deixe a tela pintar isso explicitamente.
  return {
    rows: list,
    pairs,
    truncated,
    reputacao: !repOk ? 'indisponivel' : assessedPeers < coveragePeers ? 'parcial' : 'ok',
    reputationCoverage,
    reputationRequested: repResult.requested,
    reputationFound: repResult.found,
    ...(repOk ? {} : { erro: repErro })
  };
}

// ---------------------------------------------------------------- entrada externa
// Fluxos públicos -> RFC1918. Inclui todos os protocolos (não só TCP/UDP),
// para que tráfego como PROTO-41/GRE/ICMP não desapareça da visão de exposição.
async function inboundFlows(query, { maxBuckets = 20000 } = {}) {
  const prefixes = ['0.', '10.', '127.', '169.254.', '192.168.',
    ...Array.from({ length: 16 }, (_, i) => `172.${i + 16}.`)];
  const baseQuery = {
    bool: {
      filter: [
        { range: buildTimeRange(query) },
        { bool: { should: prefixes.map((value) => ({ prefix: { [F_DST]: value } })), minimum_should_match: 1 } }
      ]
    }
  };
  const buckets = [];
  let after;
  let truncated = false;
  while (true) {
    const remaining = maxBuckets - buckets.length;
    if (remaining <= 0) {
      if (after) {
        const probe = await client.search({
          index: ELASTIC_INDEX, size: 0, query: baseQuery,
          aggs: { inbound: { composite: { size: 1, after, sources: [
            { origem: { terms: { field: F_SRC } } },
            { destino: { terms: { field: F_DST } } },
            { protocolo: { terms: { field: F_PROTO, missing_bucket: true } } }
          ] } } }
        });
        truncated = (probe.aggregations?.inbound?.buckets || []).length > 0;
      }
      break;
    }
    const composite = {
      size: Math.min(2000, remaining),
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } },
        { protocolo: { terms: { field: F_PROTO, missing_bucket: true } } }
      ]
    };
    if (after) composite.after = after;
    const resp = await client.search({
      index: ELASTIC_INDEX, size: 0, query: baseQuery,
      aggs: {
        inbound: {
          composite,
          aggs: {
            bytes: { sum: { field: F_OCTETS } },
            packets: { sum: { field: F_PACKETS } },
            lastSeen: { max: { field: F_FEND } },
            ports: { terms: { field: F_DPORT, size: 5 } }
          }
        }
      }
    });
    const page = resp.aggregations?.inbound?.buckets || [];
    if (!page.length) break;
    buckets.push(...page);
    after = resp.aggregations?.inbound?.after_key;
    if (!after) break;
  }

  const rows = buckets
    .map((b) => ({
      src: String(b.key.origem),
      dst: String(b.key.destino),
      protocol: b.key.protocolo == null ? null : Number(b.key.protocolo),
      bytes: Math.round(b.bytes?.value || 0),
      packets: Math.round(b.packets?.value || 0),
      flows: b.doc_count || 0,
      lastSeen: b.lastSeen?.value_as_string || null,
      ports: (b.ports?.buckets || []).map((p) => p.key),
      nonTransport: ![6, 17].includes(Number(b.key.protocolo))
    }))
    .filter((x) => x.src !== x.dst && isPublicIp4(x.src) && isPrivate(x.dst))
    // Protocolos fora de TCP/UDP sobem primeiro mesmo que tenham poucos bytes:
    // um PROTO-41 de 544 B não deve sumir atrás de centenas de fluxos web.
    .sort((a, b) => Number(b.nonTransport) - Number(a.nonTransport) || b.bytes - a.bytes);

  return { rows, total: rows.length, truncated, bucketsRead: buckets.length };
}

// --------------------------------------------------------------- destinos novos
// Isto mede novidade do IP público globalmente no sensor (ip_sightings), não a
// novidade do relacionamento src->dst. A UI deve preservar essa distinção.
async function newExternalPeers(query, { maxPairs = 4000 } = {}) {
  const afterPages = [];
  let after;
  let truncated = false;

  while (true) {
    const remaining = maxPairs - afterPages.length;
    if (remaining <= 0) {
      if (after) {
        const probe = await client.search({
          index: ELASTIC_INDEX, size: 0,
          query: { bool: { filter: [{ range: buildTimeRange(query) }] } },
          aggs: { pares: { composite: { size: 1, after, sources: [
            { origem: { terms: { field: F_SRC } } },
            { destino: { terms: { field: F_DST } } }
          ] } } }
        });
        truncated = (probe.aggregations?.pares?.buckets || []).length > 0;
      }
      break;
    }
    const composite = {
      size: Math.min(2000, remaining),
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } }
      ]
    };
    if (after) composite.after = after;
    const resp = await client.search({
      index: ELASTIC_INDEX,
      size: 0,
      query: { bool: { filter: [{ range: buildTimeRange(query) }] } },
      aggs: {
        pares: {
          composite,
          aggs: {
            bytes: { sum: { field: F_OCTETS } },
            packets: { sum: { field: F_PACKETS } },
            portas: { terms: { field: F_DPORT, size: 3 } }
          }
        }
      }
    });
    const b = resp.aggregations?.pares?.buckets;
    if (!b || !b.length) break;
    afterPages.push(...b);
    after = resp.aggregations?.pares?.after_key;
    if (!after) break;
  }

  const rows = afterPages
    .map((x) => ({
      src: String(x.key.origem),
      dst: String(x.key.destino),
      bytes: x.bytes?.value || 0,
      packets: x.packets?.value || 0,
      ports: (x.portas?.buckets || []).map((p) => p.key)
    }))
    .filter((x) => x.src !== x.dst && isPrivate(x.src) && isPublicIp4(x.dst));

  const dsts = [...new Set(rows.map((r) => r.dst))];
  const [repRes, seenRes] = await Promise.all([
    reputationFor(dsts),
    // Leitura paginada. Com `slice(0, 4000)` os destinos acima do quarto milésimo
    // não vinham do banco e caíam em "nunca visto" — e "nunca visto" é o que
    // acende o alerta. Era falha de teto, não-ip novo.
    (async () => {
      const seenMap = {};
      try {
        for (let i = 0; i < dsts.length; i += 4000) {
          const { rows: lote } = await pool.query(
            `select ip, first_seen, last_seen, bytes, flows, country_name
               from ip_sightings where ip = any($1::text[])`,
            [dsts.slice(i, i + 4000)]);
          for (const s of lote) seenMap[s.ip] = s;
        }
        const meta = await pool.query(
          'select min(first_seen) as history_since, max(updated_at) as history_updated_at from ip_sightings');
        return { seenMap, ok: true, historySince: meta.rows[0]?.history_since || null, historyUpdatedAt: meta.rows[0]?.history_updated_at || null };
      } catch {
        // Se o Postgres cai, `seenMap` vazio faria TODO destino parecer "nunca
        // visto". Falha de infraestrutura não pode virar notícia de segurança:
        // nesses casos dizemos que não deu.
        return { seenMap, ok: false };
      }
    })()
  ]);
  const rep = repRes.rep;
  const seenMap = seenRes.seenMap;
  const histOk = seenRes.ok;

  const winStart = windowStart(query);

  const out = rows.map((r) => {
    const s = seenMap[r.dst];
    const rv = rep[r.dst];
    // Sem registro na tabela significa apenas "não consta no snapshot diário".
    // O coletor roda uma vez/dia; não afirmar "nunca visto" para IPs da janela
    // posterior à última atualização do histórico.
    const notRecorded = histOk && !s;
    // Ou visto, mas só dentro da janela consultada (primeira aparição nela).
    // A janela vem da query inteira: com intervalo personalizado, comparar só
    // com `minutes` (que nem existe nesse caso) marcava como novo o que era
    // conhecido há horas.
    const firstFresh = histOk && !!s && winStart !== null && new Date(s.first_seen).getTime() >= winStart;
    return {
      src: r.src,
      dst: r.dst,
      bytes: Math.round(r.bytes),
      packets: Math.round(r.packets),
      ports: r.ports,
      new: notRecorded || firstFresh,
      confidence: notRecorded ? 'candidato' : firstFresh ? 'confirmado' : histOk ? 'historico' : 'indisponivel',
      kind: !histOk ? 'indisponivel' : notRecorded ? 'nao-consta-no-historico' : firstFresh ? 'primeira-vez' : 'conhecido',
      firstSeen: s?.first_seen || null,
      sightingBytes: s ? Number(s.bytes) : 0,
      score: rv?.score ?? null,
      verdict: rv?.verdict || 'unknown',
      country: rv?.countryName || null,
      isp: rv?.isp || null
    };
  });

  return {
    rows: out.sort((a, b) => Number(b.new) - Number(a.new) || b.bytes - a.bytes),
    total: out.length,
    newTotal: out.filter((r) => r.new).length,
    newIpCount: new Set(out.filter((r) => r.new).map((r) => r.dst)).size,
    confirmedNewCount: out.filter((r) => r.kind === 'primeira-vez').length,
    candidateCount: out.filter((r) => r.kind === 'nao-consta-no-historico').length,
    historico: histOk ? 'ok' : 'indisponivel',
    historySince: seenRes.historySince || null,
    historyUpdatedAt: seenRes.historyUpdatedAt || null,
    reputacao: !repRes.ok ? 'indisponivel' : repRes.found < repRes.requested ? 'parcial' : 'ok',
    reputationCoverage: {
      requested: repRes.requested,
      assessed: repRes.found,
      unknown: repRes.missing,
      stale: repRes.stale || 0,
      pct: repRes.requested ? Number((repRes.found / repRes.requested * 100).toFixed(1)) : 100
    },
    novelty: 'ip-destino-global',
    truncated
  };
}

// Início da janela realmente consultada, em ms (null = sem limite inferior).
// Precisa bater com buildTimeRange() do elastic.js: usar só `minutes` faria o
// "primeira vez na janela" cair em 15 min sempre que o usuário escolhesse um
// intervalo personalizado de 6 h ou de 1 dia — e aí todo par recente seria
// marcado como novidade, sendo que já é conhecido.
const WINDOW_UNITS = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 };

function windowStart(query) {
  if (query.from) {
    const t = new Date(query.from).getTime();
    return Number.isFinite(t) ? t : null;
  }
  // Só `to`, sem from/range/minutes: a consulta no ES fica sem gte (lte apenas),
  // logo "primeira vez na janela" não tem como ser afirmada.
  if (query.to) return null;
  if (query.range) {
    const m = /^now-(\d+)([smhdw])$/.exec(String(query.range).trim());
    return m ? Date.now() - Number(m[1]) * WINDOW_UNITS[m[2]] : null;
  }
  const min = parseInt(query.minutes || '15', 10);
  return Date.now() - (Number.isFinite(min) && min > 0 ? min : 15) * 60000;
}

module.exports = { hostRisk, inboundFlows, newExternalPeers, reputationFor, isPrivate, isPublicIp4, windowStart };
