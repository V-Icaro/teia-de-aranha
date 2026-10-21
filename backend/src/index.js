require('dotenv').config();
const net = require('node:net');
const zlib = require('node:zlib');
const express = require('express');
const cors = require('cors');
const { client, searchElastic, elasticSearchStats, ELASTIC_INDEX, F_SRC, F_DST, F_DPORT, fetchConnections, fetchTopPairs, conversationDirection, fetchSessions, fetchBeaconProfile, toCytoscape, fetchMapGraph, fetchHostPeers, getPairGraph, fetchIpTraffic, fetchPairCompare, rankPorts, protocolName, portName, cidrContains } = require('./elastic');
const { hostRisk, inboundFlows, newExternalPeers, isPrivate, windowStart } = require('./risk');
const { topApplications, applicationConnections, topKnownPorts } = require('./dashboard');
const { subnetOf, resolveMany, resolveIp } = require('./names');
const { topTalkers } = require('./detect');
const { checkMany, checkIp, isPublicIp, listReputationDb, coverageFor, quotaState, repTtlDays } = require('./reputation');
const {
  pool, init: dbInit, listSubnets, addSubnet, patchSubnet, delSubnet,
  listInventory, inventoryApplicationsForIp, createInventoryServer, renameInventoryServer, deleteInventoryServer,
  addServerIp, deleteServerIp, createApplication, renameApplication,
  deleteApplication, addApplicationListener, deleteApplicationListener,
  addExpectedApplicationClient, deleteExpectedApplicationClient,
  listFortigates, getFortigate, createFortigate, updateFortigate, deleteFortigate,
  ensureFortigateBackupSchema,
  listFortigateBackupPolicies, createFortigateBackupPolicy, updateFortigateBackupPolicy, deleteFortigateBackupPolicy, getFortigateBackupPolicyTargets,
  listFortigateBackups, getFortigateBackup, createFortigateBackupRecord, updateFortigateBackupRecord, deleteFortigateBackupRecord, cleanupFortigateBackups
} = require('./db');
const { intParam } = require('./params.js');
const { topPolicies, fetchPolicies, fetchPolicyDetail, fetchPolicyConfigs, fetchPolicyTable } = require('./fortigate.js');
const { analyzePolicies } = require('./firewallAnalysis.js');
const { auditFortigate } = require('./fortigate-audit.js');
const cron = require('node-cron');
const { downloadBackup, saveBackupFile, readBackupFile, deleteBackupFile } = require('./fortigate-backup');
const { runFortigateBackup } = require('./fortigate-backup');

dbInit(); // cria tabelas se preciso (avisa e segue sem Postgres se falhar)

// A feature "Vigilância de hosts" foi removida: cadastrar host para vigiar,
// aprender peers e gerar achados rendeu 1.126 itens não acionados em 30 dias.
// A tela equivalente é Exposição, que não exige cadastro.

// Colheita diária do histórico de IPs públicos (acumula, nunca apaga)
if ((process.env.REGIONS_CRON || '15 6 * * *') !== '0') {
  cron.schedule(process.env.REGIONS_CRON || '15 6 * * *', async () => {
    try {
      const ok = await dbInit();
      if (!ok) return;
      const { harvest } = require('./regions.js');
      const r = await harvest();
      console.log(`[regions] colheita diária: ${r.ips} IPs`);
    } catch (e) {
      console.error(`[regions] falha na colheita: ${e.message}`);
    }
  }, { timezone: process.env.CRON_TZ || 'America/Sao_Paulo' });
  console.log(`[regions] agendado: ${process.env.REGIONS_CRON || '15 6 * * *'}`);
}

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
// Protege o ES e o heap do Node contra janelas/cardinalidades extremas. MAX_EDGES=0
// mantém a paginação ilimitada para instalações que conscientemente precisem dela.
const maxEdgesRaw = process.env.MAX_EDGES;
const maxEdgesParsed = Number.parseInt(maxEdgesRaw ?? '50000', 10);
const MAX_EDGES = maxEdgesRaw === '0' ? Infinity : Number.isSafeInteger(maxEdgesParsed) && maxEdgesParsed > 0 ? maxEdgesParsed : 50000;
const ACTIVE_WINDOW_SEC = parseInt(process.env.ACTIVE_WINDOW_SEC || '120', 10);
const COMPOSITE_PAGE_SIZE = Math.min(2000, Math.max(100, parseInt(process.env.COMPOSITE_PAGE_SIZE || '1000', 10) || 1000));
// Pares (src,dst) lidos para o detalhe de um host: ~2 por peer (ida e volta).
const HOST_MAX_PAIRS = Math.max(1000, parseInt(process.env.HOST_MAX_PAIRS || '40000', 10) || 40000);


// Janela efetiva da query, para a resposta dizer a verdade. `minutes` sozinho
// mente quando o front manda intervalo personalizado (aí não vem minutes).
function windowOf(q) {
  const start = windowStart(q);
  return {
    from: q.from || null,
    to: q.to || null,
    minutes: q.from ? null : intParam(q.minutes, { nome: 'minutes', def: 15, min: 1, max: 10080 }),
    start: start ? new Date(start).toISOString() : null
  };
}

function inventoryId(value) {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function inventoryError(res, error, fallback) {
  const status = error.status || (error.code === '23505' ? 409 : error.code === '23503' ? 400 : 500);
  if (status >= 500) console.error(error);
  const message = error.status ? error.message
    : error.code === '23505' ? 'Esse IP ou listener já está cadastrado.'
      : error.code === '23503' ? 'A máquina ou o IP associado não existe.'
        : fallback;
  return res.status(status).json({ error: message, ...(status >= 500 ? { detail: String(error.message || error) } : {}) });
}

app.get('/api/dashboard/applications', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const serverId = inventoryId(req.query.serverId);
    if (!serverId) return res.status(400).json({ error: 'Informe um serverId válido.' });
    const window = windowOf(req.query);
    const result = await topApplications(serverId, req.query);
    res.json({ window, ...result });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao carregar aplicações do dashboard', detail: String(e.message || e) });
  }
});

app.get('/api/dashboard/applications/:applicationId/connections', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const serverId = inventoryId(req.query.serverId);
    const applicationId = inventoryId(req.params.applicationId);
    if (!serverId || !applicationId) return res.status(400).json({ error: 'Informe serverId e applicationId válidos.' });
    const window = windowOf(req.query);
    const result = await applicationConnections(serverId, applicationId, req.query);
    res.json({ window, ...result });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao carregar conexões da aplicação', detail: String(e.message || e) });
  }
});

app.get('/api/dashboard/ports', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const serverId = inventoryId(req.query.serverId);
    if (!serverId) return res.status(400).json({ error: 'Informe um serverId válido.' });
    const window = windowOf(req.query);
    const result = await topKnownPorts(serverId, req.query, 5);
    res.json({ window, ...result });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao carregar portas do dashboard', detail: String(e.message || e) });
  }
});

app.get('/api/dashboard/conversations', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const top = intParam(req.query.top, { nome: 'top', def: 5, min: 1, max: 20 });
    const timeMinutes = { '1h': 60, '6h': 360, '24h': 1440 };
    const time = String(req.query.time || '1h');
    if (!timeMinutes[time]) return res.status(400).json({ error: 'Time deve ser 1h, 6h ou 24h.' });
    const flowType = String(req.query.flowType || 'ingress').toLowerCase();
    if (!['ingress', 'egress', 'both'].includes(flowType)) {
      return res.status(400).json({ error: 'Flow type deve ser ingress, egress ou both.' });
    }

    const inventory = await listInventory();
    const inventoryIps = [...new Set(inventory.flatMap((server) => server.ips.map((item) => item.ip)))];
    const query = { minutes: String(timeMinutes[time]) };
    const window = windowOf(query);
    if (!inventoryIps.length) {
      return res.json({ window, top, time, flowType, inventoryIps: 0, candidates: 0, pairs: [] });
    }

    const { topo, candidatos, truncadoES } = await fetchTopPairs(query, { limit: top, inventoryIps, flowType });
    const pairs = topo.map((group) => {
      const higherSideSpokeMore = group.bytesAlto > group.bytesBaixo;
      return {
        a: group.a,
        b: group.b,
        bytes: Math.round(group.bytes),
        packets: Math.round(group.pacotes || 0),
        flows: group.fluxos,
        mainSide: higherSideSpokeMore ? 'B>A' : 'A>B',
        mainSideBytes: Math.round(higherSideSpokeMore ? group.bytesAlto : group.bytesBaixo),
        secondarySideBytes: Math.round(higherSideSpokeMore ? group.bytesBaixo : group.bytesAlto),
        start: group.inicio,
        end: group.fim,
        ...conversationDirection(group),
        protocols: [...group.protocolos].map(protocolName),
        topPorts: [...group.portas.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 5)
          .map((port) => ({ port: port.port, bytes: Math.round(port.bytes) }))
      };
    });
    res.json({ window, top, time, flowType, inventoryIps: inventoryIps.length, candidates: candidatos, truncated: truncadoES, pairs });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao carregar conversas do inventário', detail: String(e.message || e) });
  }
});

// FortiGate: token cifrado no Postgres e nunca devolvido pela API.
app.get('/api/fortigate', async (_req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    res.json({ firewalls: await listFortigates() });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao listar FortiGates', detail: String(e.message || e) });
  }
});

app.post('/api/fortigate', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const firewall = await createFortigate({ name: req.body?.name, host: req.body?.host, vdom: req.body?.vdom, token: req.body?.token });
    res.status(201).json({ firewall });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao cadastrar FortiGate', detail: String(e.message || e) });
  }
});

app.patch('/api/fortigate/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const firewall = await updateFortigate(id, {
      ...(req.body?.name !== undefined ? { name: req.body.name } : {}),
      ...(req.body?.host !== undefined ? { host: req.body.host } : {}),
      ...(req.body?.vdom !== undefined ? { vdom: req.body.vdom } : {}),
      ...(req.body?.token !== undefined ? { token: req.body.token } : {})
    });
    res.json({ firewall });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao atualizar FortiGate', detail: String(e.message || e) });
  }
});

app.delete('/api/fortigate/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    res.json(await deleteFortigate(id));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao remover FortiGate', detail: String(e.message || e) });
  }
});

async function fortigateCredentials(id) {
  const firewall = await getFortigate(id);
  if (!firewall) throw Object.assign(new Error('FortiGate não encontrado.'), { status: 404 });
  return { firewall, credentials: { host: firewall.host, token: firewall.token, vdom: firewall.vdom || 'root' } };
}

app.post('/api/fortigate/:id/test', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const { firewall, credentials } = await fortigateCredentials(id);
    const result = await fetchPolicies(credentials);
    res.json({ ok: true, id, name: firewall.name, host: firewall.host, version: result.version, vdom: result.vdom, policies: result.policies.length });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao testar FortiGate', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate/:id/policies', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const limit = intParam(req.query.limit, { nome: 'limit', def: 20, min: 1, max: 100 });
    const offset = intParam(req.query.offset, { nome: 'offset', def: 0, min: 0, max: Number.MAX_SAFE_INTEGER });
    const sort = ['hits', 'bytes', 'packets', 'sessions'].includes(String(req.query.sort)) ? String(req.query.sort) : 'hits';
    const { credentials } = await fortigateCredentials(id);
    const vdom = String(req.query.vdom || credentials.vdom || 'root').trim() || 'root';
    res.json(await topPolicies({ ...credentials, vdom }, { limit, offset, sort }));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao consultar políticas', detail: String(e.message || e) });
  }
});

// Lista completa (sem paginação) no formato da "Interface Pair View" do
// FortiGate: configuração da CMDB + contadores do monitor por política.
app.get('/api/fortigate/:id/policy-table', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const { credentials } = await fortigateCredentials(id);
    const vdom = String(req.query.vdom || credentials.vdom || 'root').trim() || 'root';
    res.json(await fetchPolicyTable({ ...credentials, vdom }));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao consultar políticas', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate/:id/policy/:policyId', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const policyId = intParam(req.params.policyId, { nome: 'policyId', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const { credentials } = await fortigateCredentials(id);
    const vdom = String(req.query.vdom || credentials.vdom || 'root').trim() || 'root';
    res.json(await fetchPolicyDetail({ ...credentials, policyId, vdom }));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao consultar detalhe da política', detail: String(e.message || e) });
  }
});

// Auditoria de usuários (admins + tokens de API) e interfaces (serviços de
// gerência expostos). Somente leitura.
app.get('/api/fortigate/:id/audit', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const { firewall, credentials } = await fortigateCredentials(id);
    res.json({ firewall: { id: firewall.id, name: firewall.name, host: firewall.host }, ...(await auditFortigate(credentials)) });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha na auditoria do FortiGate', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate/:id/analysis', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const staleDays = intParam(req.query.staleDays, { nome: 'staleDays', def: 90, min: 1, max: 3650 });
    const { credentials } = await fortigateCredentials(id);
    const vdom = String(req.query.vdom || credentials.vdom || 'root').trim() || 'root';
    const [configs, stats] = await Promise.all([
      fetchPolicyConfigs({ ...credentials, vdom }),
      fetchPolicies(credentials)
    ]);
    res.json({ ...analyzePolicies({ configs: configs.configs, stats: stats.policies, options: { staleDays } }), vdom });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao analisar políticas FortiGate', detail: String(e.message || e) });
  }
});

// ---- FortiGate Backups ------------------------------------------------
app.get('/api/fortigate-backup/policies', async (_req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    res.json({ policies: await listFortigateBackupPolicies() });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao listar políticas de backup', detail: String(e.message || e) });
  }
});

app.post('/api/fortigate-backup/policies', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const policy = await createFortigateBackupPolicy(req.body || {});
    res.status(201).json({ policy });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao criar política de backup', detail: String(e.message || e) });
  }
});

app.put('/api/fortigate-backup/policies/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const policy = await updateFortigateBackupPolicy(id, req.body || {});
    res.json({ policy });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao atualizar política de backup', detail: String(e.message || e) });
  }
});

app.delete('/api/fortigate-backup/policies/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    res.json(await deleteFortigateBackupPolicy(id));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao remover política de backup', detail: String(e.message || e) });
  }
});

app.post('/api/fortigate/:id/backup', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const { firewall, credentials } = await fortigateCredentials(id);
    const record = await runFortigateBackup({ fortigate: { id: firewall.id, name: firewall.name, host: credentials.host, token: credentials.token, vdom: credentials.vdom }, policyId: null, retentionDays: Number(req.body?.retentionDays || 30) });
    res.json({ backup: record });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao executar backup', detail: String(e.message || e) });
  }
});

app.post('/api/fortigate-backup/policies/:id/run', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const policyId = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const policies = await listFortigateBackupPolicies();
    const policy = policies.find((p) => p.id === policyId);
    if (!policy) return res.status(404).json({ error: 'Política não encontrada' });
    const targets = await getFortigateBackupPolicyTargets(policyId);
    const results = [];
    for (const t of targets) {
      try {
        const fg = await getFortigate(t.fortigate_id);
        if (!fg) throw new Error('FortiGate não encontrado');
        const rec = await runFortigateBackup({ fortigate: fg, policyId, retentionDays: policy.retention_days });
        results.push({ fortigateId: fg.id, ok: true, backup: rec });
      } catch (e) {
        results.push({ fortigateId: t.fortigate_id, ok: false, error: e.message });
      }
    }
    res.json({ results });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao executar política', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate-backups', async (_req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    try { await db.fixStuckFortigateBackups(); } catch {}
    res.json({ backups: await listFortigateBackups() });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao listar backups', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate-backups/:id/content', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const backup = await getFortigateBackup(id);
    if (!backup) return res.status(404).json({ error: 'Backup não encontrado' });
    const content = await readBackupFile(backup.file_path || backup.filePath);
    res.json({ content, fileName: backup.file_name || backup.fileName });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao ler backup', detail: String(e.message || e) });
  }
});

app.get('/api/fortigate-backups/:id/download', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const backup = await getFortigateBackup(id);
    if (!backup) return res.status(404).json({ error: 'Backup não encontrado' });
    const content = await readBackupFile(backup.file_path || backup.filePath);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${backup.file_name || backup.fileName || 'backup.conf'}"`);
    res.send(content);
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao baixar backup', detail: String(e.message || e) });
  }
});

app.delete('/api/fortigate-backups/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    await ensureFortigateBackupSchema();
    const id = intParam(req.params.id, { nome: 'id', def: 0, min: 1, max: Number.MAX_SAFE_INTEGER });
    const backup = await getFortigateBackup(id);
    if (backup) await deleteBackupFile(backup.file_path || backup.filePath);
    res.json(await deleteFortigateBackupRecord(id));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao remover backup', detail: String(e.message || e) });
  }
});

// Health: verifica se o ES responde
app.get('/api/health', async (req, res) => {
  try {
    const ping = await client.ping();
    res.json({ ok: true, elastic: ELASTIC_INDEX, ping, searches: elasticSearchStats(), build: '2026-09-29d' });
  } catch (e) {
    res.status(502).json({ ok: false, error: String(e.message || e) });
  }
});

// ---- Mapa de conexões --------------------------------------------------
// O navegador não desenha dezenas de milhares de arestas: a rota agrega a
// janela inteira no ES (por par), guarda em cache curto e devolve só as
// `limit` arestas de maior volume. Trocar o limite, focar uma sub-rede ou
// reabrir a aba dentro do TTL reaproveita a mesma agregação.
const MAP_DEFAULT_EDGES = Math.max(100, Number.parseInt(process.env.MAP_DEFAULT_EDGES || '3000', 10) || 3000);
const MAP_MAX_EDGES_RESPONSE = Math.max(MAP_DEFAULT_EDGES, Number.parseInt(process.env.MAP_MAX_EDGES_RESPONSE || '30000', 10) || 30000);
// A agregação por par e o cache (MAP_MAX_PAIRS, MAP_PAGE_SIZE, MAP_CACHE_TTL_MS)
// ficam em elastic.js (getPairGraph): Pares, Dashboard e top talkers reaproveitam.

// Respostas do mapa passam fácil de alguns MB: gzip derruba ~85% do tráfego.
function sendJson(req, res, payload) {
  const body = JSON.stringify(payload);
  if (body.length < 32 * 1024 || !/\bgzip\b/.test(String(req.headers['accept-encoding'] || ''))) {
    return res.type('application/json').send(body);
  }
  zlib.gzip(body, { level: 5 }, (err, buf) => {
    if (err) return res.type('application/json').send(body);
    res.set({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Encoding': 'gzip', Vary: 'Accept-Encoding' });
    res.send(buf);
  });
}

// Grafo principal p/ o React + Cytoscape
// Ex: /api/graph?minutes=15 | /api/graph?from=...&to=...
// ?limit=3000 (0 = máximo permitido) · ?cidr=10.0.0.0/24 · ?ip=10.0.0.5 · ?fresh=1 (ignora cache)
// ?names=1 — enriquece nós com { name, subnet } via inventário + rDNS
app.get('/api/graph', async (req, res) => {
  const startedAt = Date.now();
  try {
    const ip = typeof req.query.ip === 'string' && net.isIP(req.query.ip.trim()) ? req.query.ip.trim() : null;
    const cidr = typeof req.query.cidr === 'string' && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(req.query.cidr.trim()) ? req.query.cidr.trim() : null;
    const limitRaw = String(req.query.limit ?? '');
    const limit = limitRaw === '0'
      ? MAP_MAX_EDGES_RESPONSE
      : Math.min(MAP_MAX_EDGES_RESPONSE, Math.max(100, Number.parseInt(limitRaw || String(MAP_DEFAULT_EDGES), 10) || MAP_DEFAULT_EDGES));

    const { data, cached } = await getPairGraph(req.query, { ip, fresh: req.query.fresh === '1' });
    // data.edges já vem ordenado por bytes (desc); o filtro preserva a ordem.
    const scoped = cidr
      ? data.edges.filter((e) => cidrContains(cidr, e.data.source) || cidrContains(cidr, e.data.target))
      : data.edges;
    const shown = scoped.length > limit ? scoped.slice(0, limit) : scoped;

    const allNodes = new Set();
    for (const e of scoped) { allNodes.add(e.data.source); allNodes.add(e.data.target); }
    const shownNodes = new Set();
    for (const e of shown) { shownNodes.add(e.data.source); shownNodes.add(e.data.target); }
    const nodes = [...shownNodes].map((id) => ({ data: { id, label: id, subnet: subnetOf(id) } }));

    if (req.query.names === '1') {
      const { names, info } = await resolveMany(nodes.map((n) => n.data.id));
      for (const n of nodes) {
        if (names[n.data.id]) n.data.name = names[n.data.id];
        const extra = info[n.data.id];
        if (extra) { n.data.asn = extra.asn; n.data.org = extra.org; n.data.prefix = extra.prefix; }
        const show = n.data.name || n.data.org;
        if (show) n.data.label = `${show}\n${n.data.id}`;
      }
    }

    sendJson(req, res, {
      nodes,
      edges: shown,
      meta: {
        edges: shown.length,
        nodes: nodes.length,
        totalEdges: scoped.length,
        totalNodes: allNodes.size,
        limit,
        limited: scoped.length > shown.length,
        // Teto de pares no ES (MAP_MAX_PAIRS) atingido: a própria agregação é parcial.
        truncated: data.truncated || false,
        pairs: data.pairs,
        esPages: data.pages,
        queryMs: data.queryMs,
        elapsedMs: Date.now() - startedAt,
        cached,
        scope: { cidr, ip },
        minutes: req.query.minutes || null,
        from: req.query.from || null,
        to: req.query.to || null,
        range: req.query.range || null
      }
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status === 400 ? e.message : 'Falha ao consultar Elasticsearch', detail: String(e.message || e) });
  }
});

// Resolução de nomes sob demanda: POST { "ips": ["8.8.8.8", ...] }
// -> { names: {...}, info: { "8.8.8.8": { asn, org, prefix } }, subnets: {...} }
app.post('/api/resolve', async (req, res) => {
  try {
    const ips = Array.isArray(req.body?.ips) ? req.body.ips.filter((x) => typeof x === 'string') : [];
    if (!ips.length) return res.status(400).json({ error: 'Envie { "ips": [...] }' });
    // Aguarda o DDL inicial para o inventário PostgreSQL participar já da
    // primeira resolução de nomes após o backend subir.
    await dbInit();
    const { names, info } = await resolveMany(ips.slice(0, 2000));
    const subnets = {};
    for (const ip of new Set(ips)) subnets[ip] = subnetOf(ip);
    res.json({ names, info, subnets });
  } catch (e) {
    res.status(e.status || 500).json({ error: 'Falha ao resolver nomes', detail: String(e.message || e) });
  }
});

// Detalhe de um host ao clicar no nó:
// Ex: /api/host/172.20.20.28?minutes=15
app.get('/api/host/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    if (!net.isIP(String(ip))) return res.status(400).json({ error: 'IP inválido' });
    const activeOnly = req.query.active === '1';
    const nowMs = Date.now();
    const { buckets, truncated, totals } = await fetchHostPeers(req.query, {
      ip,
      activeSec: activeOnly ? ACTIVE_WINDOW_SEC : null,
      maxPairs: HOST_MAX_PAIRS
    });

    const peers = {};
    const timeOf = (agg) => (agg?.value_as_string ? Date.parse(agg.value_as_string) : (agg?.value || null));

    for (const b of buckets) {
      const bytes = b.bytes?.value || 0;
      const pkts = b.pacotes?.value || 0;
      const isSrc = String(b.key.origem) === ip;
      const peer = isSrc ? String(b.key.destino) : String(b.key.origem);
      if (!peer || peer === ip) continue;
      if (!peers[peer]) peers[peer] = { ip: peer, bytes: 0, packets: 0, outBytes: 0, inBytes: 0, flows: 0, firstSeen: null, lastSeen: 0, outPairs: new Map(), inPairs: new Map(), srcPorts: new Set(), dstPorts: new Set(), ports: new Set(), protocols: new Set() };
      const p = peers[peer];
      p.bytes += bytes;
      p.packets += pkts;
      p.flows += b.doc_count || 0;
      if (isSrc) p.outBytes += bytes; else p.inBytes += bytes;
      // Pares sport→dport por direção (top 5 de cada lado na tabela)
      const pm = isSrc ? p.outPairs : p.inPairs;
      for (const d of b.portas?.buckets || []) {
        const dport = d.key ?? null;
        if (dport != null) { p.dstPorts.add(dport); p.ports.add(dport); }
        const origins = d.origens?.buckets || [];
        if (!origins.length) {
          const pk = `?>${dport}`;
          const pe = pm.get(pk) || { sport: null, dport, bytes: 0, flows: 0 };
          pe.bytes += d.bytes?.value || 0; pe.flows += d.doc_count || 0;
          pm.set(pk, pe);
        }
        for (const s of origins) {
          const sport = s.key ?? null;
          if (sport != null) p.srcPorts.add(sport);
          const pk = `${sport}>${dport}`;
          const pe = pm.get(pk) || { sport, dport, bytes: 0, flows: 0 };
          pe.bytes += s.bytes?.value || 0; pe.flows += s.doc_count || 0;
          pm.set(pk, pe);
        }
      }
      const fs = timeOf(b.firstSeen);
      const ls = timeOf(b.lastSeen);
      if (fs && (!p.firstSeen || fs < p.firstSeen)) p.firstSeen = fs;
      if (ls && ls > p.lastSeen) p.lastSeen = ls;
      for (const pr of b.protocolos?.buckets || []) if (pr.key != null) p.protocols.add(pr.key);
    }

    const peerCount = Object.keys(peers).length;
    const topPairs = (m) => [...m.values()]
      .sort((x, y) => y.bytes - x.bytes).slice(0, 5)
      .map((x) => ({ sport: x.sport, dport: x.dport, bytes: Math.round(x.bytes), flows: x.flows }));
    const connections = Object.values(peers)
      .map((p) => {
        return {
          ...p,
          outPairs: undefined, inPairs: undefined, // Maps internos, fora do JSON
          bytes: Math.round(p.bytes),
          outBytes: Math.round(p.outBytes),
          inBytes: Math.round(p.inBytes),
          firstSeen: p.firstSeen ? new Date(p.firstSeen).toISOString() : null,
          lastSeen: p.lastSeen ? new Date(p.lastSeen).toISOString() : null,
          active: !!p.lastSeen && (nowMs - p.lastSeen) <= ACTIVE_WINDOW_SEC * 1000,
          outTop: topPairs(p.outPairs),
          inTop: topPairs(p.inPairs),
          srcPorts: rankPorts([...p.srcPorts]), dstPorts: rankPorts([...p.dstPorts]), ports: rankPorts([...p.ports]), protocols: [...p.protocols].map(protocolName)
        };
      })
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 100);

    // Com filtro "ativas", conta quantos peers existem na janela cheia p/ avisar o que ficou oculto
    let windowPeers = null;
    if (activeOnly) {
      try {
        const range = req.query.from
          ? { '@timestamp': { gte: req.query.from, ...(req.query.to ? { lte: req.query.to } : {}) } }
          : { '@timestamp': { gte: `now-${intParam(req.query.minutes, { nome: 'minutes', def: 15, min: 1, max: 10080 })}m` } };
        const pc = await searchElastic({ index: ELASTIC_INDEX, size: 0,
          query: { bool: { filter: [{ range }, { bool: { should: [{ term: { [F_SRC]: ip } }, { term: { [F_DST]: ip } }], minimum_should_match: 1 } }] } },
          aggs: { s: { terms: { field: F_SRC, size: 2000 } }, d: { terms: { field: F_DST, size: 2000 } } } });
        const set = new Set([
          ...(pc.aggregations?.s?.buckets || []).map((x) => x.key),
          ...(pc.aggregations?.d?.buckets || []).map((x) => x.key)
        ]);
        set.delete(ip);
        windowPeers = set.size;
      } catch { /* sem contagem, sem aviso */ }
    }

    const inventory = await inventoryApplicationsForIp(ip).catch(() => null);
    res.json({
      ip,
      inventory,
      activeOnly,
      windowPeers,
      // Totais vêm de agregação própria: exatos mesmo se a lista de peers cortar.
      truncated,
      peerCount,
      shownPeers: connections.length,
      totalInBytes: Math.round(totals.inBytes),
      totalOutBytes: Math.round(totals.outBytes),
      totalInPackets: Math.round(totals.inPackets),
      totalOutPackets: Math.round(totals.outPackets),
      connections
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao consultar host', detail: String(e.message || e) });
  }
});

// Maiores falantes da janela. Ex: /api/alerts?minutes=15
app.get('/api/alerts', async (req, res) => {
  try {
    const minutes = intParam(req.query.minutes, { nome: 'minutes', def: 15, min: 1, max: 10080 });
    const now = Date.now();
    let curFrom, curTo;
    if (req.query.from) {
      curFrom = req.query.from;
      curTo = req.query.to || new Date(now).toISOString();
    } else {
      curTo = new Date(now).toISOString();
      curFrom = new Date(now - minutes * 60000).toISOString();
    }

    // Mesma agregação por par do mapa (cacheada). Janela relativa usa `minutes`
    // para casar com o cache do mapa; intervalo explícito usa from/to.
    const { data } = await getPairGraph(req.query.from ? { from: curFrom, to: curTo } : { minutes: String(minutes) });
    const current = data.edges.map((e) => ({
      key: { origem: e.data.source, destino: e.data.target },
      bytes: { value: e.data.bytes },
      pacotes: { value: e.data.packets }
    }));

    res.json({
      topTalkers: topTalkers(current),
      meta: { window: { from: curFrom, to: curTo } }
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha nos top talkers', detail: String(e.message || e) });
  }
});

// Exposição a IP malicioso por host: bytes que foram para score>0, ponderados.
// Cruza ES (par + bytes) com Postgres (score já em cache) — sem chamar a API.
// Ex: /api/risk?minutes=60&limit=50
app.get('/api/risk', async (req, res) => {
  try {
    const limit = intParam(req.query.limit, { nome: 'limit', def: 50, min: 1, max: 500 });
    const { rows, truncated, reputacao, reputationCoverage, erro } = await hostRisk(req.query, { maxPairs: 12000 });
    const only = String(req.query.only || '').toLowerCase();
    let list = rows;
    // Não esconder host com reputação desconhecida sob o filtro "withbad":
    // ele precisa aparecer como avaliação parcial, nunca como limpo.
    if (only === 'withbad') list = rows.filter((r) => r.badPeers > 0 || r.unknownPeers > 0 || r.level === 'indisponivel');
    else if (only === 'clean') list = rows.filter((r) => r.badPeers === 0 && r.unknownPeers === 0 && r.level === 'none');
    res.json({
      minutes: intParam(req.query.minutes, { nome: 'minutes', def: 15, min: 1, max: 10080 }),
      window: windowOf(req.query),
      hosts: list.slice(0, limit),
      total: rows.length,
      matches: list.length,
      shown: Math.min(list.length, limit),
      withBad: rows.filter((r) => r.badPeers > 0).length,
      withUnknown: rows.filter((r) => r.unknownPeers > 0 || r.level === 'indisponivel').length,
      byLevel: rows.reduce((a, r) => { a[r.level] = (a[r.level] || 0) + 1; return a; }, {}),
      processingTruncated: truncated,
      truncated: truncated || list.length > limit,
      reputacao,
      reputationCoverage,
      ...(erro ? { reputationError: erro } : {})
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao calcular risco', detail: String(e.message || e) });
  }
});

// Só os pares interno→externo que NÃO existiam no histórico acumulado.
// "Destino nunca visto" é o achado mais forte que o NetFlow entrega sozinho.
// Ex: /api/new-external?minutes=60&onlyNew=1
app.get('/api/new-external', async (req, res) => {
  try {
    const limit = intParam(req.query.limit, { nome: 'limit', def: 100, min: 1, max: 500 });
    const { rows, total, newTotal, newIpCount, confirmedNewCount, candidateCount, historySince, historyUpdatedAt, truncated, historico, reputacao, reputationCoverage, novelty } = await newExternalPeers(req.query, { maxPairs: 8000 });
    const onlyNew = String(req.query.onlyNew || '') === '1';
    const list = onlyNew ? rows.filter((r) => r.new) : rows;
    res.json({
      minutes: intParam(req.query.minutes, { nome: 'minutes', def: 15, min: 1, max: 10080 }),
      window: windowOf(req.query),
      pairs: list.slice(0, limit),
      total,
      matches: list.length,
      shown: Math.min(list.length, limit),
      newCount: newTotal,
      newIpCount,
      confirmedNewCount,
      candidateCount,
      // 'indisponivel' = o Postgres não respondeu e "nunca visto" não pôde ser
      // afirmado. A tela usa isso para não apresentar falha de leitura como
      // descoberta.
      historico,
      historySince,
      historyUpdatedAt,
      reputacao,
      reputationCoverage,
      novelty,
      processingTruncated: truncated,
      truncated: truncated || list.length > limit
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao listar destinos novos', detail: String(e.message || e) });
  }
});

// Tráfego público -> interno, incluindo protocolos que não são TCP/UDP.
// Separado do risco de saída: um fluxo de entrada não é o mesmo sinal que um
// host interno falando com um destino de má reputação.
app.get('/api/inbound', async (req, res) => {
  try {
    const limit = intParam(req.query.limit, { nome: 'limit', def: 200, min: 1, max: 500 });
    const { rows, total, truncated, bucketsRead } = await inboundFlows(req.query, { maxBuckets: 20000 });
    res.json({
      window: windowOf(req.query),
      flows: rows.slice(0, limit).map((r) => ({ ...r, protocolName: protocolName(r.protocol) })),
      total,
      shown: Math.min(total, limit),
      nonTransportCount: rows.filter((r) => r.nonTransport).length,
      processingTruncated: truncated,
      truncated: truncated || total > limit,
      bucketsRead
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao listar tráfego de entrada', detail: String(e.message || e) });
  }
});

// Sessões vivas: pares com fluxo ativo na janela + nome do serviço.
// NÃO é "conexão aberta" — NetFlow não tem estado. É o par que teve pacote
// nos últimos N segundos, que é o mais perto de sessão que o formato dá.
// Ex: /api/sessions?minutes=15&activeSec=120
app.get('/api/sessions', async (req, res) => {
  try {
    const activeSec = intParam(req.query.activeSec, { nome: 'activeSec', def: 120, min: 1, max: 3600 });
    const { buckets, truncated } = await fetchSessions(req.query, { activeSec });
    const rows = buckets.map((b) => {
      const src = String(b.key.origem);
      const dst = String(b.key.destino);
      const ports = (b.portas?.buckets || []).map((p) => ({ port: p.key, service: portName(p.key), bytes: Math.round(p.bytes?.value || 0) }));
      const fs = b.firstSeen?.value_as_string ? Date.parse(b.firstSeen.value_as_string) : null;
      const ls = b.lastSeen?.value_as_string ? Date.parse(b.lastSeen.value_as_string) : null;
      const durMs = fs && ls ? Math.max(0, ls - fs) : null;
      const bytes = b.bytes?.value || 0;
      return {
        src, dst,
        direction: isPrivate(src) ? 'out' : 'in',
        bytes: Math.round(bytes),
        packets: Math.round(b.packets?.value || 0),
        firstSeen: fs ? new Date(fs).toISOString() : null,
        lastSeen: ls ? new Date(ls).toISOString() : null,
        durationSec: durMs != null ? Math.round(durMs / 1000) : null,
        // bps só faz sentido com duração > 0; senão é infinito/ruim
        bps: durMs > 0 ? Math.round((bytes * 8) / (durMs / 1000)) : null,
        service: ports.find((p) => p.service)?.service || null,
        ports: ports.slice(0, 5)
      };
    }).sort((a, b) => b.bytes - a.bytes);

    const sessions = rows.slice(0, 300);
    res.json({ activeSec, sessions, count: rows.length, shown: sessions.length, truncated: truncated || rows.length > sessions.length });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao listar sessões', detail: String(e.message || e) });
  }
});

// Perfil de periodicidade de UM par (beacon/C2). Consulta com hits, então só
// para o par que o usuário escolheu — nunca varre o índice.
// Ex: /api/beacon?src=172.20.20.28&dst=1.2.3.4&minutes=240
app.get('/api/beacon', async (req, res) => {
  try {
    const { src, dst } = req.query;
    if (!src || !dst) return res.status(400).json({ error: 'Informe src e dst' });
    const minutes = intParam(req.query.minutes, { nome: 'minutes', def: 240, min: 1, max: 10080 });
    res.json({ src, dst, minutes, ...(await fetchBeaconProfile({ src, dst, minutes })) });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao medir periodicidade', detail: String(e.message || e) });
  }
});

// Só o que JÁ está em memória/Postgres: não chama o AbuseIPDB, não gasta cota.
// O front usa para pintar a lista na hora e o botão para dizer quantos IPs
// realmente precisam de consulta.
// POST { "ips": [...] } -> { coverage: { ip: { cached, stale, from, ageDays, result } }, quota, ttlDays }
app.post('/api/reputation/coverage', async (req, res) => {
  try {
    const ips = Array.isArray(req.body?.ips) ? req.body.ips.filter((x) => typeof x === 'string') : [];
    if (!ips.length) return res.status(400).json({ error: 'Envie { "ips": [...] }' });
    res.json({ coverage: await coverageFor(ips), quota: quotaState(), ttlDays: repTtlDays() });
  } catch (e) {
    res.status(e.status || 500).json({ error: 'Falha ao ler a cobertura de reputação', detail: String(e.message || e) });
  }
});

// Reputação de IPs públicos (só AbuseIPDB): POST { "ips": [...] }
// -> { rep: { "8.8.8.8": { verdict, sources, abuse } } }
// verdict: clean (score 0, verde) | malicious (score > 0, vermelho) | unknown | private
app.post('/api/reputation', async (req, res) => {
  try {
    const ips = Array.isArray(req.body?.ips) ? req.body.ips.filter((x) => typeof x === 'string') : [];
    if (!ips.length) return res.status(400).json({ error: 'Envie { "ips": [...] }' });
    res.json({ rep: await checkMany(ips) });
  } catch (e) {
    res.status(e.status || 500).json({ error: 'Falha na reputação', detail: String(e.message || e) });
  }
});

// Dossiê completo de um IP: identidade + reputação + tráfego na janela
// Ex: /api/ip/8.8.8.8?minutes=15
app.get('/api/ip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    if (!net.isIP(String(ip))) return res.status(400).json({ error: 'IP inválido' });
    await dbInit();
    const emptyTraffic = { inBytes: 0, outBytes: 0, inPackets: 0, outPackets: 0, flows: 0, truncated: false, topPeers: [], topPorts: [], unavailable: true };
    const [identity, rep, traffic, inventory] = await Promise.all([
      resolveIp(ip).catch(() => ({ ip, name: null, source: 'none', asn: null, org: null, prefix: null })),
      checkIp(ip).catch(() => ({ ip, verdict: 'unknown', sources: [] })),
      // Uma consulta: totais exatos por direção + top peers + top portas.
      fetchIpTraffic(req.query, ip).catch((e) => { console.warn(`[ip] tráfego de ${ip} indisponível: ${e.message}`); return emptyTraffic; }),
      inventoryApplicationsForIp(ip).catch(() => null)
    ]);

    res.json({
      ip,
      public: isPublicIp(ip),
      subnet: subnetOf(ip),
      name: identity.name || null,
      nameSource: identity.source || 'none',
      asn: identity.asn ?? null,
      org: identity.org || null,
      prefix: identity.prefix || null,
      inventory,
      reputation: rep,
      traffic: {
        ...traffic,
        inBytes: Math.round(traffic.inBytes),
        outBytes: Math.round(traffic.outBytes),
        inPackets: Math.round(traffic.inPackets),
        outPackets: Math.round(traffic.outPackets)
      }
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha no dossiê do IP', detail: String(e.message || e) });
  }
});

// Comparador de dois hosts: DIREÇÕES, timeline e top portas do par
// Ex: /api/compare?a=10.1.0.11&b=172.20.20.28&minutes=60
app.get('/api/compare', async (req, res) => {
  try {
    const { a, b } = req.query;
    if (!a || !b) return res.status(400).json({ error: 'Envie ?a=IP&b=IP' });
    if (a === b) return res.status(400).json({ error: 'IPs iguais' });
    const minutes = intParam(req.query.minutes, { nome: 'minutes', def: 60, min: 1, max: 10080 });
    const now = Date.now();
    const to = req.query.to || new Date(now).toISOString();
    const from = req.query.from || new Date(now - minutes * 60000).toISOString();

    if (!net.isIP(String(a)) || !net.isIP(String(b))) return res.status(400).json({ error: 'Informe dois IPs válidos' });

    // Uma consulta só, já filtrada no par: direções, top portas e timeline.
    // Intervalo pelo tamanho REAL da janela (from/to pode vir do front).
    const spanMin = Math.max(1, (Date.parse(to) - Date.parse(from)) / 60000 || minutes);
    const interval = spanMin <= 30 ? '1m' : spanMin <= 180 ? '5m' : spanMin <= 720 ? '15m' : '1h';
    const agg = await fetchPairCompare({ a, b, from, to, interval });
    const fmtDir = (d) => ({
      bytes: Math.round(d?.bytes?.value || 0),
      packets: Math.round(d?.pacotes?.value || 0),
      flows: d?.doc_count || 0,
      topPorts: (d?.portas?.buckets || []).map((p) => ({ port: p.key ?? null, bytes: Math.round(p.bytes?.value || 0), flows: p.doc_count || 0 }))
    });
    const ba = Object.fromEntries((agg.bToA?.over?.buckets || []).map((x) => [x.key, Math.round(x.bytes?.value || 0)]));
    const timeline = (agg.aToB?.over?.buckets || []).map((x) => ({
      t: x.key_as_string, aToB: Math.round(x.bytes?.value || 0), bToA: ba[x.key] || 0
    }));

    res.json({ a, b, from, to, interval, truncated: false,
      aToB: fmtDir(agg.aToB), bToA: fmtDir(agg.bToA), timeline });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao comparar', detail: String(e.message || e) });
  }
});

// ---- inventário de máquinas, IPs e aplicações ----------------------
app.get('/api/inventory', async (_req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    res.json({ servers: await listInventory() });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao listar o inventário');
  }
});

app.post('/api/inventory/servers', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const name = String(req.body?.name || '').trim();
    const ips = [...new Set((Array.isArray(req.body?.ips) ? req.body.ips : [])
      .map((ip) => String(ip).trim()).filter(Boolean))];
    if (!name || name.length > 128) return res.status(400).json({ error: 'Informe o nome da máquina (máximo 128 caracteres).' });
    if (!ips.length) return res.status(400).json({ error: 'Cadastre pelo menos um IP para a máquina.' });
    if (ips.some((ip) => !net.isIP(ip))) return res.status(400).json({ error: 'Um ou mais IPs são inválidos.' });
    const server = await createInventoryServer(name, ips);
    res.status(201).json({ server });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao cadastrar máquina');
  }
});

app.patch('/api/inventory/servers/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    const name = String(req.body?.name || '').trim();
    if (!id) return res.status(400).json({ error: 'ID de máquina inválido.' });
    if (!name || name.length > 128) return res.status(400).json({ error: 'Informe o nome da máquina (máximo 128 caracteres).' });
    res.json({ server: await renameInventoryServer(id, name) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao renomear máquina');
  }
});

app.delete('/api/inventory/servers/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID de máquina inválido.' });
    res.json(await deleteInventoryServer(id));
  } catch (e) {
    return inventoryError(res, e, 'Falha ao remover máquina');
  }
});

app.post('/api/inventory/servers/:id/ips', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const serverId = inventoryId(req.params.id);
    const ip = String(req.body?.ip || '').trim();
    if (!serverId) return res.status(400).json({ error: 'ID de máquina inválido.' });
    if (!net.isIP(ip)) return res.status(400).json({ error: 'IP inválido.' });
    res.status(201).json({ ip: await addServerIp(serverId, ip) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao adicionar IP');
  }
});

app.delete('/api/inventory/ips/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID de IP inválido.' });
    res.json(await deleteServerIp(id));
  } catch (e) {
    return inventoryError(res, e, 'Falha ao remover IP');
  }
});

app.post('/api/inventory/servers/:id/applications', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const serverId = inventoryId(req.params.id);
    const name = String(req.body?.name || '').trim();
    const listeners = Array.isArray(req.body?.listeners) ? req.body.listeners : [];
    if (!serverId) return res.status(400).json({ error: 'ID de máquina inválido.' });
    if (!name || name.length > 128) return res.status(400).json({ error: 'Informe o nome da aplicação (máximo 128 caracteres).' });
    if (!listeners.length || listeners.length > 100) return res.status(400).json({ error: 'Informe entre 1 e 100 listeners.' });
    const clean = [];
    for (const listener of listeners) {
      const serverIpId = inventoryId(listener?.serverIpId);
      const protocol = String(listener?.protocol || '').toUpperCase();
      const port = Number(listener?.port);
      if (!serverIpId || !['TCP', 'UDP'].includes(protocol) || !Number.isInteger(port) || port < 1 || port > 65535) {
        return res.status(400).json({ error: 'Listener inválido: selecione IP, protocolo TCP/UDP e porta 1–65535.' });
      }
      clean.push({ serverIpId, protocol, port });
    }
    res.status(201).json({ application: await createApplication(serverId, name, clean) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao cadastrar aplicação');
  }
});

app.patch('/api/inventory/applications/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    const name = String(req.body?.name || '').trim();
    if (!id) return res.status(400).json({ error: 'ID de aplicação inválido.' });
    if (!name || name.length > 128) return res.status(400).json({ error: 'Informe o nome da aplicação (máximo 128 caracteres).' });
    res.json({ application: await renameApplication(id, name) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao renomear aplicação');
  }
});

app.delete('/api/inventory/applications/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID de aplicação inválido.' });
    res.json(await deleteApplication(id));
  } catch (e) {
    return inventoryError(res, e, 'Falha ao remover aplicação');
  }
});

app.post('/api/inventory/applications/:id/listeners', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const applicationId = inventoryId(req.params.id);
    const serverIpId = inventoryId(req.body?.serverIpId);
    const protocol = String(req.body?.protocol || '').toUpperCase();
    const port = Number(req.body?.port);
    if (!applicationId || !serverIpId || !['TCP', 'UDP'].includes(protocol) || !Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'Listener inválido: selecione IP, protocolo TCP/UDP e porta 1–65535.' });
    }
    res.status(201).json({ listener: await addApplicationListener(applicationId, { serverIpId, protocol, port }) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao adicionar listener');
  }
});

app.delete('/api/inventory/listeners/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID de listener inválido.' });
    res.json(await deleteApplicationListener(id));
  } catch (e) {
    return inventoryError(res, e, 'Falha ao remover listener');
  }
});

app.post('/api/inventory/applications/:id/expected-clients', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const applicationId = inventoryId(req.params.id);
    const ip = String(req.body?.ip || '').trim();
    if (!applicationId) return res.status(400).json({ error: 'ID de aplicação inválido.' });
    if (!net.isIP(ip)) return res.status(400).json({ error: 'IP cliente inválido.' });
    res.status(201).json({ client: await addExpectedApplicationClient(applicationId, ip) });
  } catch (e) {
    return inventoryError(res, e, 'Falha ao adicionar cliente esperado');
  }
});

app.delete('/api/inventory/expected-clients/:id', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const id = inventoryId(req.params.id);
    if (!id) return res.status(400).json({ error: 'ID de cliente esperado inválido.' });
    res.json(await deleteExpectedApplicationClient(id));
  } catch (e) {
    return inventoryError(res, e, 'Falha ao remover cliente esperado');
  }
});

// ---- sub-redes monitoradas ------------------------------------------
// Único resíduo da feature de vigilância: cadastrar CIDRs para o mapa
// filtrar e abrir junto com o sistema. Nada de host, achado ou peer.
function validCidr(cidr) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr || '');
  if (!m) return false;
  if (+m[5] > 32) return false;
  return m.slice(1, 5).every((o) => +o <= 255);
}

app.get('/api/subnets', async (_req, res) => {
  try {
    res.json({ subnets: await listSubnets() });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha ao listar sub-redes', detail: String(e.message || e) });
  }
});

app.post('/api/subnets', async (req, res) => {
  try {
    const cidr = (req.body?.cidr || '').trim();
    const name = (req.body?.name || '').trim() || null;
    if (!validCidr(cidr)) return res.status(400).json({ error: 'CIDR inválido (ex. 10.190.164.0/26)' });
    res.json({ subnet: await addSubnet(cidr, name) });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao adicionar sub-rede', detail: String(e.message || e) });
  }
});

app.patch('/api/subnets/:cidr', async (req, res) => {
  try {
    const cidr = decodeURIComponent(req.params.cidr);
    const body = {};
    if (req.body?.name !== undefined) body.name = (req.body.name || '').trim() || null;
    if (req.body?.is_default !== undefined) body.is_default = !!req.body.is_default;
    res.json({ subnet: await patchSubnet(cidr, body) });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao atualizar sub-rede', detail: String(e.message || e) });
  }
});

app.delete('/api/subnets/:cidr', async (req, res) => {
  try {
    res.json(await delSubnet(decodeURIComponent(req.params.cidr)));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Falha ao remover sub-rede', detail: String(e.message || e) });
  }
});

// Top 10 pares que mais conversam entre si (bidirecional somado).
// ?subnet=CIDR filtra ANTES do ranking (top da sub-rede, não do global).
// Ex: /api/top-pairs?minutes=60&subnet=172.20.20.0/24
app.get('/api/top-pairs', async (req, res) => {
  try {
    const subnet = (req.query.subnet || '').trim() || null;
    if (subnet && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(subnet)) {
      return res.status(400).json({ error: 'Sub-rede inválida', detail: `Use IPv4/CIDR, ex.: 10.0.0.0/8 — recebido "${subnet}"` });
    }
    // `limit` era aceito e ignorado (o slice tinha 10 fixo): limit=-1 devolvia
    // 200 com os 10 maiores, sem reclamar.
    const limit = intParam(req.query.limit, { nome: 'limit', def: 10, min: 1, max: 500 });
    const t0 = Date.now();
    const { topo, candidatos, truncadoES } = await fetchTopPairs(req.query, { limit, subnet });
    const pares = topo.map((g) => {
      // Quem mandou mais bytes. A tela mostra isso para não sugerir que o par
      // conversou igual nos dois sentidos.
      const altoFalouMais = g.bytesAlto > g.bytesBaixo;
      return {
        a: g.a, b: g.b,
bytes: Math.round(g.bytes),
        // `packetDeltaCount` não existe nesta ingestão: a soma volta null.
        pacotes: Math.round(g.pacotes || 0),
        flows: g.fluxos,
        ladoPrincipal: altoFalouMais ? 'B>A' : 'A>B',
        bytesLadoPrincipal: Math.round(altoFalouMais ? g.bytesAlto : g.bytesBaixo),
        bytesLadoSecundario: Math.round(altoFalouMais ? g.bytesBaixo : g.bytesAlto),
        inicio: g.inicio, fim: g.fim,
        ...conversationDirection(g),
        protocols: [...g.protocolos].map(protocolName),
        topPorts: [...g.portas.values()].sort((x, y) => y.bytes - x.bytes).slice(0, 5)
          .map((p) => ({ port: p.port, bytes: Math.round(p.bytes) }))
      };
    });
    res.json({
      pairs: pares,
      subnet,
      limit,
      candidatos,
      // A agregação de src+dst tem teto (`lados`). Se estoura, pode faltar par
      // grande — a tela avisa em vez de apresentar ranking parcial como total.
      truncadoES,
      ms: Date.now() - t0
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha nos top pares', detail: String(e.message || e) });
  }
});

// Busca histórica de QUALQUER IP (mesmo fora do mapa/janela): primeira vez,
// última vez, peers, portas e atividade por dia. Ex: /api/lookup?ip=42.251.129.234&days=7
app.get('/api/lookup', async (req, res) => {
  try {
    const ip = (req.query.ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'Envie ?ip=IP' });
    if (!net.isIP(ip)) return res.status(400).json({ error: 'IP inválido' });
    const days = intParam(req.query.days, { nome: 'days', def: 7, min: 1, max: 7 });
    const base = [
      { range: { '@timestamp': { gte: `now-${days}d` } } },
      { bool: { should: [{ term: { [F_SRC]: ip } }, { term: { [F_DST]: ip } }], minimum_should_match: 1 } }
    ];
    const peerAggs = (field) => ({ terms: { field, size: 20 },
      aggs: { bytes: { sum: { field: 'netflow.octetDeltaCount' } } } });
    // track_total_hits: sem ele o ES para de contar em 10.000 e a tela
    // mostrava "10000 fluxos" para qualquer IP movimentado.
    const r = await searchElastic({ index: ELASTIC_INDEX, size: 0, track_total_hits: true,
      query: { bool: { filter: base } },
      aggs: {
        first: { min: { field: '@timestamp' } },
        last: { max: { field: '@timestamp' } },
        bytes: { sum: { field: 'netflow.octetDeltaCount' } },
        as_src: { filter: { term: { [F_SRC]: ip } }, aggs: { peers: peerAggs(F_DST) } },
        as_dst: { filter: { term: { [F_DST]: ip } }, aggs: { peers: peerAggs(F_SRC) } },
        dports: { terms: { field: F_DPORT, size: 15 },
          aggs: { bytes: { sum: { field: 'netflow.octetDeltaCount' } } } },
        per_day: { date_histogram: { field: '@timestamp', calendar_interval: '1d', min_doc_count: 0,
          extended_bounds: { min: `now-${days}d`, max: 'now-0d' } },
          aggs: { bytes: { sum: { field: 'netflow.octetDeltaCount' } } } }
      } });
    const a = r.aggregations;
    const peers = new Map();
    for (const b of [...(a.as_src?.peers?.buckets || []), ...(a.as_dst?.peers?.buckets || [])]) {
      const cur = peers.get(b.key) || { ip: b.key, bytes: 0, flows: 0 };
      cur.bytes += b.bytes?.value || 0; cur.flows += b.doc_count;
      peers.set(b.key, cur);
    }
    res.json({
      ip, days,
      found: (r.hits?.total?.value || 0) > 0,
      firstSeen: a.first?.value_as_string || null,
      lastSeen: a.last?.value_as_string || null,
      flows: r.hits?.total?.value || 0,
      bytes: Math.round(a.bytes?.value || 0),
      peers: [...peers.values()].map((p) => ({ ...p, bytes: Math.round(p.bytes) }))
        .sort((x, y) => y.bytes - x.bytes).slice(0, 20),
      ports: (a.dports?.buckets || []).map((b) => ({ port: b.key, bytes: Math.round(b.bytes?.value || 0), flows: b.doc_count })),
      daily: (a.per_day?.buckets || []).map((b) => ({
        day: (b.key_as_string || '').slice(0, 10),
        flows: b.doc_count, bytes: Math.round(b.bytes?.value || 0)
      }))
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha na busca', detail: String(e.message || e) });
  }
});

// Base de reputação: IPs observados no período de até sete dias, agrupados por região.
app.get('/api/reputation/db', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const days = intParam(req.query.days, { nome: 'days', def: 7, min: 1, max: 7 });
    res.json(await listReputationDb({ days, order: req.query.order, limit: req.query.limit }));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha na base de reputação', detail: String(e.message || e) });
  }
});

// Colheita manual do histórico (mesma do job diário das 06:15). Ex: POST {hours: 168}
// A tela de Regiões foi removida — quem consome esses dados é /api/reputation/db,
// mas a coleta continua: é ela que alimenta ip_sightings e a reputação de TODOS
// os IPs públicos (risco, destinos novos, país no dossiê).
app.post('/api/stats/harvest', async (req, res) => {
  try {
    if (!(await dbInit())) return res.status(503).json({ error: 'Postgres indisponível' });
    const { harvest } = require('./regions.js');
    const hours = intParam(req.body?.hours, { nome: 'hours', def: 24, min: 1, max: 24 * 7 });
    res.json(await harvest(hours));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: 'Falha na colheita', detail: String(e.message || e) });
  }
});

app.listen(PORT, () => console.log(`Backend rodando em http://localhost:${PORT} (indice ${ELASTIC_INDEX})`));
