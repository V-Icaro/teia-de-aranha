// Cliente mínimo da API de monitoramento do FortiGate.
// Endpoint usado: GET /api/v2/monitor/firewall/policy
//   -> estatísticas por política de firewall (hit_count, bytes, packets,
//      sessões, primeira/última utilização e séries históricas).
//
// Autenticação: header `Authorization: Bearer <token>` (o mesmo que funcionou
// via curl -k). O certificado do FortiGate costuma ser self-signed, então a
// validação de TLS é desligada (rejectUnauthorized:false). É uma escolha
// consciente para rede interna; ambiente com CA própria pode trocar depois.
const https = require('node:https');

const POLICY_PATH = '/api/v2/monitor/firewall/policy';
const CMDB_POLICY_PATH = '/api/v2/cmdb/firewall/policy';
const DEFAULT_TIMEOUT_MS = Math.max(1000, Number.parseInt(process.env.FORTIGATE_TIMEOUT_MS || '8000', 10));

function requestJson(host, path, token, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host,
      port: Number.parseInt(process.env.FORTIGATE_PORT || '443', 10),
      path,
      method: 'GET',
      rejectUnauthorized: false,
      headers: { Accept: 'application/json', Authorization: `Bearer ${String(token).trim()}` },
      timeout: timeoutMs
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = body ? JSON.parse(body) : null; } catch { parsed = null; }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          // O FortiGate costuma detalhar em `messages[].msg` ou `error.message`;
          // sem corpo útil, mostra o status e o começo do corpo.
          const message =
            parsed?.messages?.[0]?.msg ||
            parsed?.error?.message ||
            parsed?.error ||
            parsed?.status ||
            body.slice(0, 300);
          const status = res.statusCode === 401 || res.statusCode === 403 ? res.statusCode : 502;
          const hint =
            status === 401
              ? 'token rejeitado pelo FortiGate — confira o valor (sem espaços/linha extra) salvo em Editar, ou gere um novo no FortiGate (System > Admin > API user) e teste antes com curl'
              : status === 403
                ? 'token autentica mas não tem permissão para /api/v2/monitor/firewall/policy'
                : null;
          return reject(Object.assign(
            new Error(`FortiGate respondeu ${res.statusCode}${message ? `: ${message}` : ''}${hint ? ` (${hint})` : ''}`),
            { status }
          ));
        }
        if (parsed == null) return reject(Object.assign(new Error('Resposta do FortiGate não é JSON válido'), { status: 502 }));
        resolve(parsed);
      });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Tempo esgotado ao falar com o FortiGate'), { status: 504 })));
    req.on('error', (e) => reject(Object.assign(new Error(`Falha de conexão com o FortiGate: ${e.message}`), { status: e.status || 502 })));
    req.end();
  });
}

function toNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return 0;
}

// bytes/packets podem vir como número OU como objeto com os contadores por
// mecanismo de processamento (software/asic/nturbo). Se o objeto já tiver
// `total`, ele manda (somar os filhos duplicaria); senão soma as folhas.
function counterTotal(value) {
  if (value == null) return 0;
  if (typeof value === 'number' || typeof value === 'string') return toNumber(value);
  if (typeof value !== 'object') return 0;
  if ('total' in value) return toNumber(value.total);
  return Object.values(value).reduce((sum, item) => sum + counterTotal(item), 0);
}

// Separa os mecanismos quando existirem, para a tela poder explicar o total.
function mechanismOf(source) {
  if (!source || typeof source !== 'object') return null;
  const software = toNumber(source.software);
  const asic = toNumber(source.asic);
  const nturbo = toNumber(source.nturbo);
  if (!software && !asic && !nturbo) return null;
  return { software, asic, nturbo };
}

// Serializa a série do histórico semanal: o FortiGate pode devolver hit_count,
// bytes e packets como número ou array — a tela assume array para todas.
function historySeries(history) {
  if (!history || typeof history !== 'object') return null;
  const toArray = (v) => (Array.isArray(v) ? v.map(toNumber) : (v == null ? null : [toNumber(v)]));
  const hitCount = toArray(history.hit_count ?? history.hitCount);
  const bytes = toArray(history.bytes);
  const packets = toArray(history.packets);
  if (!hitCount && !bytes && !packets) return null;
  return { hit_count: hitCount, bytes, packets };
}

function normalizePolicy(policy, position = null) {
  const source = policy && typeof policy === 'object' ? policy : {};
  return {
    position,
    policyid: Number(source.policyid ?? source.policyId ?? 0) || 0,
    uuid: source.uuid || null,
    name: source.name || source.policy_name || null,
    hitCount: toNumber(source.hit_count),
    bytes: counterTotal(source.bytes),
    packets: counterTotal(source.packets),
    bytesMechanism: mechanismOf(source.bytes),
    packetsMechanism: mechanismOf(source.packets),
    activeSessions: toNumber(source.active_sessions),
    sessionCount: toNumber(source.session_count),
    firstUsed: toNumber(source.first_used) || null,
    lastUsed: toNumber(source.last_used) || null,
    sessionFirstUsed: toNumber(source.session_first_used) || null,
    sessionLastUsed: toNumber(source.session_last_used) || null,
    // Série do histórico semanal IPv4 (hit_count/bytes/packets por intervalo).
    history: historySeries(source['1_week_ipv4'])
  };
}

async function fetchPolicies({ host, token, vdom = 'root' }) {
  const path = `${POLICY_PATH}?vdom=${encodeURIComponent(vdom || 'root')}`;
  const json = await requestJson(host, path, token);
  const results = Array.isArray(json?.results) ? json.results : Array.isArray(json) ? json : [];
  return {
    status: json?.status || null,
    vdom: json?.vdom || null,
    version: json?.version || null,
    policies: results.map((policy, i) => normalizePolicy(policy, i + 1))
  };
}

const SORTERS = {
  hits: (a, b) => b.hitCount - a.hitCount,
  bytes: (a, b) => b.bytes - a.bytes,
  packets: (a, b) => b.packets - a.packets,
  sessions: (a, b) => b.sessionCount - a.sessionCount
};

async function topPolicies(fortigate, { limit = 20, sort = 'hits', offset = 0 } = {}) {
  const result = await fetchPolicies(fortigate);
  const compare = SORTERS[sort] || SORTERS.hits;
  const sorted = [...result.policies].sort(compare);
  const total = result.policies.length;
  const start = Math.max(0, Math.min(offset, total));
  const end = Math.min(start + limit, total);
  return {
    status: result.status,
    vdom: result.vdom,
    version: result.version,
    total,
    offset: start,
    limit,
    page: Math.floor(total ? start / limit : 0) + 1,
    pages: Math.max(1, Math.ceil(total / limit)),
    sort,
    policies: sorted.slice(start, end)
  };
}

// Campos dedicados nas seções acima; o resto vai para "avançadas" (não poluir o
// resumo com q_origin_key, ZTNA, tags etc).
const CURATED_DETAIL = new Set([
  'policyid', 'name', 'uuid', 'comments', 'status', 'action', 'schedule',
  'policy-expiry', 'policy-expiry-date-utc',
  'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'srcaddr6', 'dstaddr6',
  'srcaddr-negate', 'dstaddr-negate', 'ip-version-type', 'internet-service',
  'internet-service-name',
  'service', 'service-negate', 'nat', 'ippool', 'poolname', 'fixedport',
  'session-ttl', 'match-vip',
  'utm-status', 'inspection-mode', 'profile-type', 'profile-group',
  'profile-protocol-options', 'ssl-ssh-profile', 'av-profile',
  'webfilter-profile', 'ips-sensor', 'application-list', 'dnsfilter-profile',
  'emailfilter-profile', 'logtraffic', 'logtraffic-start', 'capture-packet',
  'auto-asic-offload', 'np-acceleration', 'dynamic-shaping', 'traffic-shaper',
  'traffic-shaper-reverse', 'per-ip-shaper', 'tcp-mss-sender', 'tcp-mss-receiver',
  'passive-wan-health-measurement'
]);
const DETAIL_NOISE = new Set([
  'q_origin_key', 'q_type', 'global-uuid', 'uuid-idx', 'fswid', 'fsso', 'fos',
  'ntlm-enabled-browsers', 'sso-identity', 'sso-groups', 'ztna-profiles',
  'ztna-emtag-based-matched', 'ztna-controls', 'zes-tag-source'
]);

// Campos da CMDB que são lista de objetos {name}; normaliza para array de nomes.
function nameArray(value) {
  if (value == null) return null;
  if (Array.isArray(value)) {
    const names = value
      .map((x) => (x && typeof x === 'object' ? x.name : x))
      .filter((x) => x != null && x !== '');
    return names.length ? names : null;
  }
  if (typeof value === 'object' && value.name) return [value.name];
  if (value === '') return null;
  return [value];
}

function normalizePolicyDetail(d) {
  const s = d && typeof d === 'object' ? d : {};
  const advanced = [];
  for (const [key, value] of Object.entries(s)) {
    if (CURATED_DETAIL.has(key) || DETAIL_NOISE.has(key)) continue;
    if (value == null || value === '') continue;
    const flat = JSON.stringify(value);
    if (flat === '{}' || flat === '[]') continue;
    advanced.push({ key, value: flat.slice(0, 160) + (flat.length > 160 ? '…' : '') });
  }
  advanced.sort((a, b) => a.key.localeCompare(b.key));
  return {
    policyid: Number(s.policyid ?? s.q_origin_key) || null,
    name: s.name || null,
    uuid: s.uuid || null,
    comments: s.comments || null,
    status: s.status || null,
    action: s.action || null,
    schedule: s.schedule || null,
    policyExpiry: s['policy-expiry'] ?? null,
    policyExpiryDateUtc: s['policy-expiry-date-utc'] ?? null,
    flow: {
      srcintf: nameArray(s.srcintf),
      dstintf: nameArray(s.dstintf),
      srcaddr: nameArray(s.srcaddr),
      dstaddr: nameArray(s.dstaddr),
      srcaddr6: nameArray(s.srcaddr6),
      dstaddr6: nameArray(s.dstaddr6),
      srcaddrNegate: s['srcaddr-negate'] ?? null,
      dstaddrNegate: s['dstaddr-negate'] ?? null,
      ipVersionType: s['ip-version-type'] ?? null,
      internetService: s['internet-service'] ?? null,
      internetServiceName: nameArray(s['internet-service-name'])
    },
    services: {
      service: nameArray(s.service),
      serviceNegate: s['service-negate'] ?? null,
      nat: s.nat ?? null,
      ippool: s.ippool ?? null,
      poolname: nameArray(s.poolname),
      fixedport: s.fixedport ?? null,
      sessionTtl: s['session-ttl'] ?? null,
      matchVip: s['match-vip'] ?? null
    },
    security: {
      utmStatus: s['utm-status'] ?? null,
      inspectionMode: s['inspection-mode'] ?? null,
      profileType: s['profile-type'] ?? null,
      profileGroup: s['profile-group'] ?? null,
      profileProtocolOptions: s['profile-protocol-options'] ?? null,
      sslSshProfile: s['ssl-ssh-profile'] ?? null,
      avProfile: s['av-profile'] ?? null,
      webfilterProfile: s['webfilter-profile'] ?? null,
      ipsSensor: s['ips-sensor'] ?? null,
      applicationList: s['application-list'] ?? null,
      dnsfilterProfile: s['dnsfilter-profile'] ?? null,
      emailfilterProfile: s['emailfilter-profile'] ?? null,
      logtraffic: s.logtraffic ?? null,
      logtrafficStart: s['logtraffic-start'] ?? null,
      capturePacket: s['capture-packet'] ?? null
    },
    performance: {
      autoAsicOffload: s['auto-asic-offload'] ?? null,
      npAcceleration: s['np-acceleration'] ?? null,
      dynamicShaping: s['dynamic-shaping'] ?? null,
      trafficShaper: s['traffic-shaper'] ?? null,
      trafficShaperReverse: s['traffic-shaper-reverse'] ?? null,
      perIpShaper: s['per-ip-shaper'] ?? null,
      tcpMssSender: s['tcp-mss-sender'] ?? null,
      tcpMssReceiver: s['tcp-mss-receiver'] ?? null,
      passiveWanHealthMeasurement: s['passive-wan-health-measurement'] ?? null
    },
    advanced
  };
}

// GET /api/v2/cmdb/firewall/policy/{id}?vdom=root — configuração completa da regra.
async function fetchPolicyDetail({ host, token, policyId, vdom = 'root' }) {
  const path = `${CMDB_POLICY_PATH}/${policyId}?vdom=${encodeURIComponent(vdom)}`;
  const json = await requestJson(host, path, token);
  const policy = Array.isArray(json?.results) ? json.results[0] : json;
  return {
    httpStatus: json?.http_status ?? null,
    status: json?.status ?? null,
    vdom: json?.vdom ?? vdom,
    revision: json?.revision ?? null,
    policy: normalizePolicyDetail(policy)
  };
}

// GET /api/v2/cmdb/firewall/policy?vdom=root — todas as políticas, na ordem
// efetiva da lista (a posição real da ACL, que o policyid NÃO representa).
async function fetchPolicyConfigs({ host, token, vdom = 'root' }) {
  const path = `${CMDB_POLICY_PATH}?vdom=${encodeURIComponent(vdom)}`;
  const json = await requestJson(host, path, token);
  const results = Array.isArray(json?.results) ? json.results : [];
  return {
    status: json?.status ?? null,
    vdom: json?.vdom ?? vdom,
    revision: json?.revision ?? null,
    configs: results.map((policy, i) => ({ ...normalizePolicyDetail(policy), position: i + 1 }))
  };
}

// Perfis de segurança na ordem em que o FortiGate os exibe na lista.
const SECURITY_PROFILE_FIELDS = [
  ['avProfile', 'AV'],
  ['webfilterProfile', 'Web'],
  ['dnsfilterProfile', 'DNS'],
  ['applicationList', 'App'],
  ['ipsSensor', 'IPS'],
  ['emailfilterProfile', 'Email'],
  ['sslSshProfile', 'SSL']
];

function profileName(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'object') return value.name || null;
  return String(value);
}

function securityProfilesOf(security) {
  if (!security || security.utmStatus !== 'enable') return [];
  if (security.profileType === 'group' && security.profileGroup) {
    return [{ type: 'Grupo', name: profileName(security.profileGroup) }];
  }
  return SECURITY_PROFILE_FIELDS
    .map(([key, type]) => ({ type, name: profileName(security[key]) }))
    .filter((p) => p.name);
}

// Visão "Interface Pair View" do FortiGate: configuração da CMDB (interfaces,
// endereços, serviço, ação, NAT, perfis, log) + contadores do monitor, na
// ordem efetiva da lista. O agrupamento por par de interfaces fica na tela.
async function fetchPolicyTable({ host, token, vdom = 'root' }) {
  const [configs, stats] = await Promise.all([
    fetchPolicyConfigs({ host, token, vdom }),
    fetchPolicies({ host, token, vdom })
  ]);
  const statsById = new Map(stats.policies.map((s) => [s.policyid, s]));
  const policies = configs.configs.map((c) => {
    const s = statsById.get(c.policyid) || {};
    const flow = c.flow || {};
    const services = c.services || {};
    const usesInternetService = flow.internetService === 'enable';
    return {
      policyid: c.policyid,
      position: c.position,
      name: c.name,
      comments: c.comments,
      status: c.status || 'enable',
      action: c.action || null,
      schedule: c.schedule || null,
      srcintf: flow.srcintf || [],
      dstintf: flow.dstintf || [],
      srcaddr: [...(flow.srcaddr || []), ...(flow.srcaddr6 || [])],
      dstaddr: usesInternetService
        ? (flow.internetServiceName || [])
        : [...(flow.dstaddr || []), ...(flow.dstaddr6 || [])],
      srcaddrNegate: flow.srcaddrNegate === 'enable',
      dstaddrNegate: flow.dstaddrNegate === 'enable',
      internetService: usesInternetService,
      service: usesInternetService ? [] : (services.service || []),
      serviceNegate: services.serviceNegate === 'enable',
      nat: services.nat === 'enable',
      ippool: services.ippool === 'enable',
      poolname: services.poolname || [],
      securityProfiles: securityProfilesOf(c.security),
      logtraffic: c.security?.logtraffic || null,
      hitCount: s.hitCount ?? 0,
      bytes: s.bytes ?? 0,
      packets: s.packets ?? 0,
      activeSessions: s.activeSessions ?? 0,
      sessionCount: s.sessionCount ?? 0,
      firstUsed: s.firstUsed ?? null,
      lastUsed: s.lastUsed ?? null,
      hasStats: statsById.has(c.policyid)
    };
  });
  return {
    vdom: configs.vdom || stats.vdom || vdom,
    version: stats.version,
    revision: configs.revision,
    total: policies.length,
    policies
  };
}

module.exports = { requestJson, fetchPolicies, topPolicies, fetchPolicyDetail, fetchPolicyConfigs, fetchPolicyTable, normalizePolicy, normalizePolicyDetail };
