// Reconstrução ÚNICA do histórico de IPs públicos.
//
// POR QUE
// A tabela ip_sightings era alimentada com `bytes = bytes + excluded.bytes`, e o
// job (24h) e o botão da tela (168h) cobriam os mesmos dias. O mesmo byte era
// somado várias vezes e a soma nunca voltava atrás: medido no banco, IPs grandes
// aparecerem com 3,53× a 5,26× os bytes que o ES realmente tinha. Depois disso o
// ip_sightings virou ROLLUP de ip_daily (uma linha por IP por dia), que é
// idempotente.
//
// O QUE ESTE SCRIPT FAZ
//   1. garante o schema (cria ip_daily e os índices)
//   2. guarda um dump das tabelas em SQL, por segurança
//   3. apaga ip_daily + ip_sightings (ip_reputation é PRESERVADA: é cache, e
//      apagá-la gastaria cota do AbuseIPDB à toa)
//   4. reprocessa dia a dia todos os dias que ainda existem no ES
//   5. consulta país/reputação numa passada única, com guarda de cota
//   6. refaz o backfill de pair_daily para os dias fechados, agora com
//      flows = doc_count de verdade
//   7. imprime a conferência: rollup bate com ip_daily? bytes plausíveis?
//
// USO
//   node scripts/rebuild-sightings.js            # só mostra o plano, não mexe
//   node scripts/rebuild-sightings.js --confirm  # executa
//
// INTERROMPER É SEGURO: cada dia é gravado por transação e regravado do zero
// (GravaReplace), então basta rodar de novo — ele retoma.
'use strict';
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { pool } = require('../src/db.js');
const { init: dbInit } = require('../src/db.js');
const { client, searchElastic, ELASTIC_INDEX } = require('../src/elastic.js');
const { harvest, consultarPaises } = require('../src/regions.js');
const { harvestDaily } = require('../src/daily.js');

const CONFIRMAR = process.argv.includes('--confirm');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '..', '.backup');
const isoDay = (d) => new Date(d).toISOString().slice(0, 10);
const carimbo = () => new Date().toISOString().replace(/[:.]/g, '-');

async function log(...a) { console.log(new Date().toISOString().slice(11, 19), ...a); }

async function tabelas() {
  const r = await pool.query(`select table_name from information_schema.tables
    where table_schema='public' order by 1`);
  return r.rows.map((x) => x.table_name);
}

async function foto(tag) {
  const [d, s, p, rep] = await Promise.all([
    pool.query(`select count(*)::int n, count(distinct ip)::int ips,
        coalesce(sum(bytes),0)::bigint bytes, min(day)::date de, max(day)::date ate
        from ip_daily`),
    pool.query(`select count(*)::int n, count(distinct ip)::int ips,
        coalesce(sum(bytes),0)::bigint bytes, min(first_seen) f, max(last_seen) l
        from ip_sightings`),
    pool.query(`select count(*)::int n, count(distinct day)::int dias,
        coalesce(sum(flows),0)::bigint flows from pair_daily`),
    pool.query('select count(*)::int n from ip_reputation')
  ]);
  const out = {
    tag,
    ip_daily: d.rows[0], ip_sightings: s.rows[0],
    pair_daily: p.rows[0], ip_reputation: rep.rows[0].n
  };
  return out;
}

async function mostrar(f) {
  log(`[${f.tag}] ip_daily     ${f.ip_daily.n} linhas / ${f.ip_daily.ips} IPs / ${f.ip_daily.bytes} bytes  (${f.ip_daily.de ? isoDay(f.ip_daily.de) : '-'} → ${f.ip_daily.ate ? isoDay(f.ip_daily.ate) : '-'})`);
  log(`[${f.tag}] ip_sightings  ${f.ip_sightings.n} linhas / ${f.ip_sightings.ips} IPs / ${f.ip_sightings.bytes} bytes  (${f.ip_sightings.f || '-'} → ${f.ip_sightings.l || '-'})`);
  log(`[${f.tag}] pair_daily   ${f.pair_daily.n} linhas / ${f.pair_daily.dias} dias / flows=${f.pair_daily.flows}`);
  log(`[${f.tag}] ip_reputation ${f.ip_reputation} linhas (preservada)`);
}

// Dump de segurança: só das três tabelas que este script mexe.
async function backup() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const arq = path.join(BACKUP_DIR, `sightings-${carimbo()}.sql`);
  const partes = [`-- dump ${new Date().toISOString()} (ip_daily, ip_sightings, pair_daily)\n`];
  for (const t of ['ip_daily', 'ip_sightings', 'pair_daily']) {
    // Não usar pg_get_tabledef: só existe no pg_dump, não no servidor.
    const dados = await pool.query(`select * from ${t}`);
    partes.push(`\n-- ==== ${t} (${dados.rows.length} linhas)\n`);
    for (const row of dados.rows) {
      const cols = Object.keys(row);
      const vals = cols.map((c) => {
        const v = row[c];
        if (v === null) return 'null';
        if (typeof v === 'number') return String(v);
        if (v instanceof Date) return `'${v.toISOString()}'`;
        return `'${String(v).replace(/'/g, "''")}'`;
      });
      partes.push(`insert into ${t} (${cols.join(',')}) values (${vals.join(',')});\n`);
    }
  }
  fs.writeFileSync(arq, partes.join(''), 'utf8');
  log('backup gravado em', arq, `(${(fs.statSync(arq).size / 1048576).toFixed(1)} MB)`);
  return arq;
}

// Dias que o ES ainda tem. O ES é a única fonte da verdade: o que expirou lá
// não tem como voltar.
async function diasNoES() {
  const r = await searchElastic({
    index: ELASTIC_INDEX, size: 0,
    aggs: { d: { date_histogram: { field: '@timestamp', calendar_interval: 'day', format: 'yyyy-MM-dd', time_zone: 'UTC', min_doc_count: 1 } } }
  });
  return r.aggregations.d.buckets.map((b) => b.key_as_string);
}

async function main() {
  const ts = await tabelas();
  if (!ts.includes('ip_daily')) {
    log('ip_daily não existe ainda; dbInit() vai criar.');
  }
  await dbInit();

  const antes = await foto('antes');
  await mostrar(antes);

  const dias = await diasNoES();
  const fechados = dias.filter((d) => d < isoDay(new Date()));
  const corrente = dias.filter((d) => d === isoDay(new Date()));
  log('\nES tem', dias.length, 'dias:', `${dias[0]} → ${dias[dias.length - 1]}`);
  log('  fechados (vão para ip_daily):', fechados.length);
  log('  dia corrente (cresce ao longo do dia, incluído):', corrente.join(', ') || '-');

  const seEspera = antes.ip_daily.de && isoDay(antes.ip_daily.de) < dias[0];
  if (seEspera) {
    log(`\nAVISO: ip_daily começa em ${isoDay(antes.ip_daily.de)} mas o ES só guarda desde ${dias[0]}.`);
    log('       Bytes anteriores a isso não têm mais de onde vir — serão perdidos.');
  }

  const faltandoFechados = fechados.filter((d) => {
    const x = antes.pair_daily.n;
    return x === 0 || true; // recalcula tudo mesmo; harvestDaily é idempotente
  });

  if (!CONFIRMAR) {
    console.log('\n--- PLANO (nada foi escrito) ---');
    console.log(' 1. garantir schema ip_daily + índices');
    console.log(' 2. backup de ip_daily, ip_sightings e pair_daily em', BACKUP_DIR);
    console.log(' 3. TRUNCATE ip_daily, ip_sightings   (ip_reputation fica)');
    console.log(` 4. reprocessar ${dias.length} dias do ES, um por transação, sem consultar AbuseIPDB`);
    console.log(' 5. passada única de país/reputação, parando se a cota acabar');
    console.log(` 6. backfill de pair_daily para ${fechados.length} dias fechados (flows = doc_count)`);
    console.log(' 7. conferência e relatório');
    console.log('\nPara executar de fato:  node scripts/rebuild-sightings.js --confirm');
    await Promise.all([pool.end(), client.close()]);
    return;
  }

  log('\n=== EXECUTANDO (--confirm) ===');
  const arq = await backup();

  // 3. limpeza. ip_reputation NÃO entra: é cache de consultas pagas.
  await pool.query('begin');
  try {
    await pool.query('truncate ip_daily');
    await pool.query('truncate ip_sightings');
    await pool.query('commit');
    log('tabelas limpas (ip_reputation intacta)');
  } catch (e) {
    await pool.query('rollback');
    throw new Error('falha ao limpar: ' + e.message);
  }

  // 4. dia a dia. Cada harvest([dia]) grava o dia inteiro e refaz o rollup
  //    só dos IPs daquele dia, então dá para interromper e retomar.
  let totalUpserted = 0;
  const t0 = Date.now();
  for (const dia of dias) {
    const ini = Date.now();
    const r = await harvest([dia], { pais: false });
    totalUpserted += r.upserted;
    log(`  ${dia}  ips=${String(r.ips).padStart(5)}  ip_daily+=${String(r.upserted).padStart(6)}  vazio=${r.vazio === true || (r.semDocumento || []).includes(dia)}  ${((Date.now() - ini) / 1000).toFixed(1)}s`);
    if (r.truncadoES) log(`    ATENÇÃO: ${dia} truncado pelo teto de ${'10000'} IPs por lado`);
  }
  log(`coleta concluída: ${totalUpserted} linhas em ${((Date.now() - t0) / 1000).toFixed(0)}s`);

  // 5. país/reputação, uma vez só.
  const semPais = await pool.query(`select s.ip from ip_sightings s
      left join ip_reputation r on r.ip = s.ip
     where r.ip is null or r.country is null limit 5000`);
  log(`\nconsultando país/reputação de ${semPais.rows.length} IPs sem cache...`);
  if (semPais.rows.length) {
    const c = await consultarPaises(semPais.rows.map((r) => r.ip));
    log(`  com país: ${c.comPais}  sem país: ${c.semPais}  cota esgotada: ${c.cotaEsgotada}`);
    if (c.cotaEsgotada) log('  (os que faltarem ganham país no job das 06:15 dos próximos dias)');
  }

  // 6. pair_daily: refaz só os fechados, agora com flows = doc_count.
  log(`\nbackfill de pair_daily (${fechados.length} dias fechados)...`);
  const hi = Date.now();
  const pd = await harvestDaily(fechados);
  log(`  ${pd.upserted} pares em ${((Date.now() - hi) / 1000).toFixed(0)}s`);

  // 7. conferência
  log('\n=== CONFERÊNCIA ===');
  const depois = await foto('depois');
  await mostrar(depois);

  const bat = await pool.query(`
    select count(*)::int divergentes
      from ip_sightings s
      join (select ip, sum(bytes)::bigint b, count(*)::int dias from ip_daily group by 1) d
        on d.ip = s.ip
     where s.bytes <> d.b or s.first_seen <> (select min(first_ts) from ip_daily x where x.ip = s.ip)`);
  log(`\nrollup x ip_daily: ${bat.rows[0].divergentes} IPs divergentes`);

  const sobra = await pool.query(`select count(*)::int n from ip_daily where bytes < 0`);
  log(`ip_daily com bytes negativos: ${sobra.rows[0].n}`);

  const dup = await pool.query(`select count(*)::int n from (
      select ip, day from ip_daily group by 1,2 having count(*) > 1) x`);
  log(`ip_daily com (ip, dia) duplicado: ${dup.rows[0].n}`);

  const fluxos = await pool.query(`select count(*)::int n, coalesce(sum(flows),0)::bigint s
      from pair_daily where flows <= 1`);
  log(`pair_daily com flows <= 1: ${fluxos.rows[0].n} linhas (soma ${fluxos.rows[0].s})`);

  log('\nbackup em', arq);
  await Promise.all([pool.end(), client.close()]);
}

main().catch(async (e) => {
  console.error('\nFALHOU:', e.message);
  console.error(e.stack);
  try { await pool.end(); } catch {}
  try { await client.close(); } catch {}
  process.exit(1);
});
