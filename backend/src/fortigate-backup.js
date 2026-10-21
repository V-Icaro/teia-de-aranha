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
    try { await db.cleanupFortigateBackups({ fortigateId: fg.id, retentionDays }); } catch {}
    return await db.getFortigateBackup(record.id);
  } catch (e) {
    try { await db.updateFortigateBackupRecord(record.id, { status: 'error', errorMsg: e.message || String(e) }); } catch {}
    throw e;
  }
}

module.exports = { downloadBackup, saveBackupFile, readBackupFile, deleteBackupFile, runFortigateBackup };
