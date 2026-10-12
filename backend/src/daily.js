// Série diária por par e porta de destino. O ES guarda o fluxo bruto por pouco
// tempo; esta tabela acumula por dia e nunca expira para relatórios históricos.
//
// Fluxo (o cabeçalho antigo descrevia o oposto do que o código faz — o dia é
// apagado e regravado, não somado; ver harvestDaily()):
//   harvestDaily()  -> lê o ES por dia/porta e regrava o dia inteiro (idempotente:
//                      rodar 2x dá o mesmo resultado, que é o motivo de apagar
//                      antes: somar no ON CONFLICT contaria o byte 2x)
const { pool } = require('./db.js');
const { client, ELASTIC_INDEX, F_SRC, F_DST, F_PROTO, F_DPORT } = require('./elastic.js');
const { localDay, dayRange } = require('./time.js');

// Métricas: somas numéricas, o exporter não as renomeia.
const F_OCTETS = 'netflow.octetDeltaCount';
const F_PACKETS = 'netflow.packetDeltaCount';

const DAILY_CRON = process.env.DAILY_CRON || '40 6 * * *';
const MAX_DAYS = Math.min(90, parseInt(process.env.DAILY_MAX_DAYS || '30', 10) || 30);
const MAX_COMPOSITE_PAGES = 100;

function dayList(days) {
  const out = [];
  const n = Math.min(MAX_DAYS, Math.max(1, days));
  for (let i = n - 1; i >= 0; i -= 1) {
    const d = new Date(Date.now() - i * 86400000);
    out.push(localDay(d));
  }
  return out;
}

function isoDay(d) {
  return d instanceof Date ? localDay(d) : String(d).slice(0, 10);
}

// Dias fechados que ainda NÃO estão em pair_daily. O job das 06:40 só roda se o
// processo estiver no ar naquele minuto; com o backend desligado no dia, o dia
// fecha sem registro e a série diária da Reputação fica incompleta.
//
// Um dia sem tráfego também não vira linha, então "faltando" aqui mistura os dois
// casos — e tanto faz: reprocessar um dia vazio não insere nada. Como
// harvestDaily() apaga o dia antes de regravar, reprocessar é seguro.
async function missingDays({ max = 14 } = {}) {
  const alvo = dayList(max).slice(0, -1);
  if (!alvo.length) return [];
  const r = await pool.query(
    'select distinct day::date as day from pair_daily where day >= $1::date',
    [alvo[0]]);
  const tem = new Set(r.rows.map((x) => isoDay(x.day)));
  return alvo.filter((d) => !tem.has(d));
}

// Agrega o ES dia a dia e grava em pair_daily. Só dias já fechados (até
// ontem): a série da tela de Reputação só compara dias inteiros.
//
// IDEMPOTENTE: cada dia é apagado antes de regravado, dentro da mesma
// transação. Somar no ON CONFLICT pareceria natural, mas rodar o job duas
// vezes (ou um backfill sobreposto) contaria o mesmo byte duas vezes e
  // distorceria os totais. Trocar o dia inteiro custa o mesmo e dá o resultado
  // certo sempre.
async function harvestDaily(days = 7) {
  // Aceita número (últimos N dias, descartando o corrente) ou lista explícita de
  // dias fechados — a recuperação de lacuna precisa disso, porque o dia faltando
  // nem sempre é o mais recente.
  const daysToDo = (Array.isArray(days) ? [...days] : dayList(days).slice(0, -1))
    .filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d < isoDay(new Date()));
  if (!daysToDo.length) return { at: new Date().toISOString(), days: 0, upserted: 0 };

  let upserted = 0;
  for (const day of daysToDo) {
    // Dia LOCAL completo, em instantes UTC. O range é [start, end) — o fim é
    // 00:00 do dia seguinte, exclusivo, para não vazar para o dia seguinte.
    const { start: gte, end: lt } = dayRange(day);
    const rows = [];
    let after;
    let guard = 0;
    do {
      const composite = {
        // dport increases daily cardinality; 20k buckets keeps the retained
        // history backfill to a handful of ES pages without approaching the
        // cluster's default 65k aggregation bucket limit.
        size: 20000,
        sources: [
          { src: { terms: { field: F_SRC } } },
          { dst: { terms: { field: F_DST } } },
          { proto: { terms: { field: F_PROTO, missing_bucket: true } } },
          { dport: { terms: { field: F_DPORT, missing_bucket: true } } }
        ]
      };
      if (after) composite.after = after;
      const resp = await client.search({
        index: ELASTIC_INDEX,
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte, lt } } }] } },
        aggs: {
          pares: {
            composite,
            aggs: {
              bytes: { sum: { field: F_OCTETS } },
              packets: { sum: { field: F_PACKETS } }
            }
          }
        }
      });
      for (const b of (resp.aggregations?.pares?.buckets || [])) {
        const src = String(b.key.src);
        const dst = String(b.key.dst);
        if (!src || !dst || src === dst) continue;
        rows.push([day, src, dst, b.key.proto ?? null, Number(b.key.dport ?? 0),
          Math.round(b.bytes?.value || 0), Math.round(b.packets?.value || 0),
          // doc_count é o número de registros NetFlow do bucket = fluxos de
          // verdade. Antes ia 1 fixo, então pair_daily.flows era a contagem de
          // linhas da tabela em vez de fluxos reais.
          b.doc_count || 0]);
      }
      after = resp.aggregations?.pares?.after_key;
      guard += 1;
     } while (after && guard < MAX_COMPOSITE_PAGES);
     if (after) throw new Error(`pair_daily backfill truncated on ${day} after ${MAX_COMPOSITE_PAGES} pages; increase the composite page limit before retrying.`);

    if (!rows.length) continue;
    const cx = await pool.connect();
    try {
      await cx.query('begin');
      await cx.query('delete from pair_daily where day = $1::date', [day]);
      // bulk em lote: um insert multi-linhas por chunk, não um por par
      const CHUNK = 500;
      for (let i = 0; i < rows.length; i += CHUNK) {
        const part = rows.slice(i, i + CHUNK);
        const vals = [];
        const params = [];
        part.forEach((r, n) => {
           const b = n * 8;
           vals.push(`($${b + 1}::date, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}, $${b + 6}, $${b + 7}, $${b + 8}, now())`);
          params.push(...r);
        });
        await cx.query(
          `insert into pair_daily (day, src, dst, proto, dport, bytes, packets, flows, updated_at)
           values ${vals.join(', ')} on conflict (day, src, dst, proto, dport) do update set
             bytes = excluded.bytes, packets = excluded.packets,
             flows = excluded.flows, updated_at = now()`,
          params);
      }
      await cx.query('commit');
      upserted += rows.length;
    } catch (e) {
      await cx.query('rollback').catch(() => {});
      throw e;
    } finally {
      cx.release();
    }
  }
  return { at: new Date().toISOString(), days: daysToDo.length, upserted };
}

module.exports = { harvestDaily, missingDays, DAILY_CRON, MAX_DAYS };
