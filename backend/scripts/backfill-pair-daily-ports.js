'use strict';

// Reprocess pair_daily from retained NetFlow so old rows gain destination ports.
// No rows are written without the explicit --confirm flag.
require('dotenv').config();

const { init, pool } = require('../src/db.js');
const { client, ELASTIC_INDEX } = require('../src/elastic.js');
const { harvestDaily, MAX_DAYS } = require('../src/daily.js');

const daysArg = process.argv.find((arg) => /^\d+$/.test(arg));
const days = daysArg ? Number(daysArg) : MAX_DAYS;
const fromArg = process.argv.find((arg) => arg.startsWith('--from='))?.slice(7);
const toArg = process.argv.find((arg) => arg.startsWith('--to='))?.slice(5);
const confirm = process.argv.includes('--confirm');

function validDay(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function datesInRange(from, to) {
  const days = [];
  const cursor = new Date(`${from}T00:00:00.000Z`);
  const end = new Date(`${to}T00:00:00.000Z`);
  while (cursor <= end) {
    days.push(cursor.toISOString().slice(0, 10));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return days;
}

async function main() {
  const today = new Date().toISOString().slice(0, 10);
  let requestedDays;
  if (fromArg || toArg) {
    if (!validDay(fromArg) || !validDay(toArg) || fromArg > toArg || toArg >= today) {
      throw new Error('Use --from=YYYY-MM-DD e --to=YYYY-MM-DD para dias fechados válidos.');
    }
    requestedDays = datesInRange(fromArg, toArg);
    if (requestedDays.length > MAX_DAYS) throw new Error(`O intervalo excede DAILY_MAX_DAYS=${MAX_DAYS}.`);
  } else {
    if (!Number.isInteger(days) || days < 2 || days > MAX_DAYS) {
      throw new Error(`Informe 2–${MAX_DAYS} dias; aumente DAILY_MAX_DAYS (máximo 90) para reprocessar mais.`);
    }
    requestedDays = days;
  }
  const closedDays = Array.isArray(requestedDays) ? requestedDays.length : requestedDays - 1;
  if (!closedDays) throw new Error('Não há dias fechados para reprocessar.');
  await init();
  if (!confirm) {
    console.log(`Plano: reprocessar ${closedDays} dias fechados de ${ELASTIC_INDEX} e substituir esses dias em pair_daily, incluindo dport.`);
    console.log(`Linhas históricas fora da retenção do Elasticsearch permanecem com dport=0 (desconhecida).`);
    console.log(fromArg
      ? `Para executar: node scripts/backfill-pair-daily-ports.js --from=${fromArg} --to=${toArg} --confirm`
      : `Para executar: node scripts/backfill-pair-daily-ports.js ${days} --confirm`);
    return;
  }
  const result = await harvestDaily(requestedDays);
  console.log(JSON.stringify(result));
}

main()
  .catch((error) => { console.error(error.message || error); process.exitCode = 1; })
  .finally(async () => { await Promise.all([pool.end(), client.close()]); });
