const fs = require('fs/promises');
const path = require('path');
const https = require('node:https');
const db = require('./db');

const DEFAULT_TIMEOUT_MS = Math.max(1000, Number.parseInt(process.env.FORTIGATE_TIMEOUT_MS || '60000', 10));

function formatDate(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

const DEFAULT_PORT = Number.parseInt(process.env.FORTIGATE_PORT || '443', 10) || 443;

function downloadBackup(host, token, { timeoutMs = DEFAULT_TIMEOUT_MS, vdom = 'root', scope = 'global', port } = {}) {
  return new Promise((resolve, reject) => {
    const vdomName = String(vdom || 'root').trim() || 'root';
    const headers = { Accept: '*/*', Authorization: `Bearer ${String(token).trim()}` };
    if (vdomName && vdomName.toLowerCase() !== 'global') {
      headers['X-VDOM'] = vdomName;
    }
    const scopeParam = encodeURIComponent(scope || 'global');
    const req = https.request({
      host,
      port: Number(port) || DEFAULT_PORT,
      path: `/api/v2/monitor/system/config/backup?scope=${scopeParam}`,
      method: 'POST',
      rejectUnauthorized: false,
      headers,
      timeout: timeoutMs
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => { chunks.push(Buffer.from(chunk)); });
      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const body = buffer.toString('utf8').slice(0, 400);
          const err = Object.assign(new Error(`FortiGate respondeu ${res.statusCode}${body ? `: ${body}` : ''}`), { status: res.statusCode >= 400 && res.statusCode < 500 ? res.statusCode : 502 });
          return reject(err);
        }
        resolve(buffer);
      });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Tempo esgotado ao baixar backup do FortiGate'), { status: 504 })));
    req.on('error', (e) => reject(Object.assign(new Error(`Falha de conexão com o FortiGate (porta ${Number(port) || DEFAULT_PORT}): ${e.message}`), { status: 502 })));
    req.write('');
    req.end();
  });
}

async function saveBackupFile(fortigate, buffer) {
  const storageRoot = path.resolve(__dirname, '..', 'storage', 'backups');
  await fs.mkdir(storageRoot, { recursive: true });
  const fgDir = path.join(storageRoot, String(fortigate.id));
  await fs.mkdir(fgDir, { recursive: true });
  const ts = formatDate(new Date());
  const safeName = String(fortigate.name || `fortigate-${fortigate.id}`).replace(/[^a-zA-Z0-9._-]+/g, '_');
  const fileName = `${safeName}_${ts}.conf`;
  const filePath = path.join(fgDir, fileName);
  await fs.writeFile(filePath, buffer);
  const stats = await fs.stat(filePath);
  return { fileName, filePath, sizeBytes: stats.size };
}

async function readBackupFile(filePath) {
  return fs.readFile(filePath, 'utf8');
}

async function deleteBackupFile(filePath) {
  try { await fs.unlink(filePath); } catch {}
}

async function runFortigateBackup({ fortigate, policyId = null, retentionDays = 30 } = {}) {
  const fg = fortigate;
  if (!fg) throw Object.assign(new Error('FortiGate não informado'), { status: 400 });
  const record = await db.createFortigateBackupRecord({ fortigateId: fg.id, policyId });
  try {
    const buffer = await downloadBackup(fg.host, fg.token, { vdom: fg.vdom || 'root', port: fg.port });
    const saved = await saveBackupFile(fg, buffer);
    await db.updateFortigateBackupRecord(record.id, {
      status: 'success',
      fileName: saved.fileName,
      filePath: saved.filePath,
      sizeBytes: saved.sizeBytes
    });
    // Retenção: cleanupFortigateBackups só lista os vencidos; apagar arquivo e
    // registro é responsabilidade daqui (antes o retorno era ignorado e nada
    // era removido).
    try {
      const expired = await db.cleanupFortigateBackups({ fortigateId: fg.id, retentionDays });
      for (const old of expired) {
        if (old.file_path) await deleteBackupFile(old.file_path);
        await db.deleteFortigateBackupRecord(old.id);
      }
    } catch (e) {
      console.error(`[fgt-backup] falha na retenção do FortiGate ${fg.id}: ${e.message}`);
    }
    return await db.getFortigateBackup(record.id);
  } catch (e) {
    try { await db.updateFortigateBackupRecord(record.id, { status: 'error', errorMsg: e.message || String(e) }); } catch {}
    throw e;
  }
}

// Executa uma política em todos os alvos, em série (um FortiGate por vez).
async function runFortigateBackupPolicy(policy) {
  const targets = await db.getFortigateBackupPolicyTargets(policy.id);
  const results = [];
  for (const t of targets) {
    try {
      const fg = await db.getFortigate(t.fortigate_id);
      if (!fg) throw new Error('FortiGate não encontrado');
      const rec = await runFortigateBackup({ fortigate: fg, policyId: policy.id, retentionDays: policy.retentionDays });
      results.push({ fortigateId: fg.id, ok: true, backup: rec });
    } catch (e) {
      results.push({ fortigateId: t.fortigate_id, ok: false, error: e.message });
    }
  }
  return results;
}

// ---- agendador -----------------------------------------------------------
// Partes da data/hora "agora" no fuso da política (sem depender do fuso do
// servidor). Devolve { ymd, dow, minutes }.
function nowInZone(timeZone) {
  let parts;
  try {
    parts = new Intl.DateTimeFormat('en-US', { timeZone, hourCycle: 'h23', weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date());
  } catch {
    parts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Sao_Paulo', hourCycle: 'h23', weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date());
  }
  const get = (type) => parts.find((p) => p.type === type)?.value;
  const dow = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(get('weekday'));
  return {
    ymd: `${get('year')}-${get('month')}-${get('day')}`,
    dow,
    minutes: Number(get('hour')) * 60 + Number(get('minute'))
  };
}

// Janela de tolerância: se o backend estava fora do ar no minuto agendado,
// ainda executa até CATCHUP_MIN depois. Fora disso, espera o próximo dia.
const CATCHUP_MIN = Math.max(0, Number.parseInt(process.env.BACKUP_CATCHUP_MIN || '180', 10) || 0);

function isDue(policy, state) {
  if (!policy.enabled) return false;
  const tz = policy.timezone || 'America/Sao_Paulo';
  const now = nowInZone(tz);
  const days = policy.runAllDays ? [0, 1, 2, 3, 4, 5, 6] : (policy.daysOfWeek || []).map(Number);
  if (!days.includes(now.dow)) return false;
  const scheduled = Number(policy.hour) * 60 + Number(policy.minute);
  if (now.minutes < scheduled || now.minutes > scheduled + CATCHUP_MIN) return false;
  // Uma execução por política por dia (no fuso da política).
  const lastDay = state.get(policy.id) || (policy.lastRunAt ? nowInZoneAt(policy.lastRunAt, tz) : null);
  return lastDay !== now.ymd;
}

function nowInZoneAt(date, timeZone) {
  try {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(date));
    const get = (type) => parts.find((p) => p.type === type)?.value;
    return `${get('year')}-${get('month')}-${get('day')}`;
  } catch { return null; }
}

let schedulerTimer = null;
let schedulerBusy = false;
const lastRunDay = new Map(); // policyId -> ymd da última execução (no fuso da política)

async function schedulerTick() {
  if (schedulerBusy) return;
  schedulerBusy = true;
  try {
    const policies = await db.listFortigateBackupPolicies();
    for (const policy of policies) {
      if (!isDue(policy, lastRunDay)) continue;
      const tz = policy.timezone || 'America/Sao_Paulo';
      lastRunDay.set(policy.id, nowInZone(tz).ymd);
      await db.markFortigateBackupPolicyRun(policy.id).catch(() => {});
      console.log(`[fgt-backup] executando política "${policy.name}" (#${policy.id}) às ${new Date().toISOString()}`);
      const results = await runFortigateBackupPolicy(policy);
      const ok = results.filter((r) => r.ok).length;
      console.log(`[fgt-backup] política #${policy.id}: ${ok}/${results.length} alvos com sucesso${results.filter((r) => !r.ok).map((r) => ` · fg ${r.fortigateId}: ${r.error}`).join('')}`);
    }
  } catch (e) {
    console.error(`[fgt-backup] agendador: ${e.message}`);
  } finally {
    schedulerBusy = false;
  }
}

function startFortigateBackupScheduler() {
  if (schedulerTimer) return;
  // Alinha o primeiro tick ao início do próximo minuto; depois a cada 60 s.
  const delay = 60000 - (Date.now() % 60000) + 500;
  setTimeout(() => {
    schedulerTick();
    schedulerTimer = setInterval(schedulerTick, 60000);
  }, delay);
  console.log(`[fgt-backup] agendador ativo (verifica a cada minuto, tolerância ${CATCHUP_MIN} min, fuso do servidor ${Intl.DateTimeFormat().resolvedOptions().timeZone})`);
}

module.exports = { downloadBackup, saveBackupFile, readBackupFile, deleteBackupFile, runFortigateBackup, runFortigateBackupPolicy, startFortigateBackupScheduler };
