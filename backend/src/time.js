// Fuso de relatório: o "dia" das séries diárias (pair_daily, ip_daily, acessos
// críticos, série da Reputação) é o dia LOCAL, não o dia UTC.
//
// Motivo: em Fortaleza (UTC-3) um dia fechado em UTC termina às 21h locais, ou
// seja, a virada dos relatórios caía no meio da noite e partia a janela de
// tráfego. Aqui o dia vai de 00:00 a 24:00 no fuso REPORT_TZ.
//
// As linhas JÁ gravadas com dia UTC NÃO são migradas automaticamente: só os dias
// novos (e os reprocessados por backfill com --confirm) passam a usar o dia
// local. Ver README.
const REPORT_TZ = process.env.REPORT_TZ || 'America/Fortaleza';

// YYYY-MM-DD do dia local para um instante (en-CA devolve ISO).
const dayFmt = new Intl.DateTimeFormat('en-CA', {
  timeZone: REPORT_TZ, year: 'numeric', month: '2-digit', day: '2-digit'
});

function localDay(date = new Date()) {
  return dayFmt.format(date);
}

function todayLocal() {
  return localDay(new Date());
}

// Offset do fuso (ms) no instante informado: local = utc + offset.
function tzOffsetMs(date) {
  const p = new Intl.DateTimeFormat('en-US', {
    timeZone: REPORT_TZ, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }).formatToParts(date).reduce((acc, part) => {
    if (part.type !== 'literal') acc[part.type] = part.value;
    return acc;
  }, {});
  const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
  return asUtc - date.getTime();
}

// Avança N dias numa data-calendário YYYY-MM-DD (aritmética de calendário, sem
// fuso, para não escorregar em viradas de horário de verão).
function addDays(day, n) {
  const [y, m, d] = day.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  dt.setUTCDate(dt.getUTCDate() + n);
  return dt.toISOString().slice(0, 10);
}

// Instante UTC de 00:00 no fuso, para o dia informado. Duas passadas cobrem uma
// eventual troca de offset entre o dia e o instante corrigido.
function localMidnight(day) {
  const [y, m, d] = day.split('-').map(Number);
  let ts = Date.UTC(y, m - 1, d);
  for (let i = 0; i < 2; i += 1) ts = Date.UTC(y, m - 1, d) - tzOffsetMs(new Date(ts));
  return ts;
}

// Intervalo [start, end) do dia local, como instantes ISO em UTC. `start` é
// inclusivo e `end` exclusivo (00:00 do dia seguinte) — bom para ranges do ES
// (gte/lt) e para comparar com DATE do Postgres.
function dayRange(day) {
  return {
    day,
    start: new Date(localMidnight(day)).toISOString(),
    end: new Date(localMidnight(addDays(day, 1))).toISOString()
  };
}

module.exports = { REPORT_TZ, localDay, todayLocal, addDays, dayRange };
