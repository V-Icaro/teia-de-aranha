// Cor da aresta por protocolo
export const PROTOCOL_COLORS = {
  TCP: '#3b82f6',
  UDP: '#22c55e',
  ICMP: '#eab308',
  GRE: '#a855f7',
  ESP: '#ec4899',
  OTHER: '#94a3b8'
};

export function colorFor(protocol) {
  return PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.OTHER;
}

// Linha fina: 0.6px .. 3px por volume (escala log p/ não explodir com outliers)
export function widthFor(bytes, maxBytes) {
  if (!bytes || !maxBytes) return 0.8;
  const t = Math.log10(bytes + 1) / Math.log10(maxBytes + 1);
  return 0.6 + t * 2.4;
}

export function fmtBytes(n) {
  if (n == null) return '-';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n < 1024 ** 4) return `${(n / 1024 ** 3).toFixed(2)} GB`;
  if (n < 1024 ** 5) return `${(n / 1024 ** 4).toFixed(2)} TB`;
  return `${(n / 1024 ** 5).toFixed(2)} PB`;
}

// "agora" / "20s" / "5min" a partir de ISO (compacto p/ tabela)
export function timeAgo(iso) {
  if (!iso) return '-';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 10) return 'agora';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}min`;
  return `${Math.floor(m / 60)}h`;
}

export function fmtTime(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// /24 p/ IPv4 (igual ao backend em names.js)
export function subnetOf(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') + '::/64';
  return 'unknown';
}

export async function resolveNames(ips) {
  const r = await fetch('/api/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips })
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json(); // { names: {ip: name}, subnets: {ip: subnet} }
}

// limit = arestas de maior volume (0 = máximo do backend) · cidr/ip = recorte
// feito no backend antes do top-N · fresh = ignora o cache curto do backend.
export async function fetchGraph({ minutes, from, to, limit, cidr, ip, fresh } = {}) {
  const p = new URLSearchParams();
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  if (limit != null) p.set('limit', String(limit));
  if (ip) p.set('ip', ip);
  else if (cidr) p.set('cidr', cidr);
  if (fresh) p.set('fresh', '1');
  const r = await fetch(`/api/graph?${p.toString()}`);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}

export async function fetchHost(ip, { minutes, from, to, active }) {
  const p = new URLSearchParams();
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  if (active) p.set('active', active);
  const r = await fetch(`/api/host/${encodeURIComponent(ip)}?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function fetchAlerts({ minutes, from, to }) {
  const p = new URLSearchParams();
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/alerts?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export function isPublicIp(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a >= 224) return false;
  return true;
}

export async function checkReputation(ips) {
  const r = await fetch('/api/reputation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips })
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json(); // { rep: { ip: { verdict, sources, abuse } } }
}

// Só o que já está em memória/Postgres. NÃO chama o AbuseIPDB: serve para
// mostrar o cache na hora e decidir quantos IPs valem uma consulta de verdade.
// -> { coverage: { ip: { cached, stale, from, ageDays, result } }, quota, ttlDays }
export async function fetchRepCoverage(ips) {
  const r = await fetch('/api/reputation/coverage', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips })
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// Base de reputação do Postgres (tudo já verificado) + histórico de conexões
export async function fetchReputationDb({ days = 7, order = 'rep' } = {}) {
  const p = new URLSearchParams({ days: String(days), order });
  const r = await fetch(`/api/reputation/db?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json(); // { days, order, total, regions[], ips[] }
}

// ------------------------------------------------------------------ risco
// Exposição a IP malicioso por host. Cruzamento ES( bytes/par ) × Postgres(
// score ), então não consome cota da API externa nem trava a UI.
export async function fetchRisk({ minutes, from, to, only = '', limit = 50 } = {}) {
  const p = new URLSearchParams({ limit: String(limit) });
  if (only) p.set('only', only);
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/risk?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json(); // { hosts[], reputationCoverage, reputacao, truncated }
}

export const RISK_COLORS = {
  none: '#22c55e',
  low: '#eab308',
  med: '#f97316',
  high: '#ef4444',
  critical: '#b91c1c'
};

export const RISK_LABELS = {
  none: 'sem exposição',
  low: 'baixo',
  med: 'médio',
  high: 'alto',
  critical: 'crítico'
};

export function riskColor(level) {
  return RISK_COLORS[level] || RISK_COLORS.none;
}

// ------------------------------------------------- destinos nunca vistos
export async function fetchNewExternal({ minutes, from, to, onlyNew = true, limit = 100 } = {}) {
  const p = new URLSearchParams({ limit: String(limit) });
  if (onlyNew) p.set('onlyNew', '1');
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/new-external?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json(); // { minutes, pairs[], total, newCount, truncated }
}

// ------------------------------------------------- sessões vivas (par)
export async function fetchSessions({ minutes, from, to, activeSec = 120 } = {}) {
  const p = new URLSearchParams({ activeSec: String(activeSec) });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/sessions?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json(); // { activeSec, sessions[], count, truncated }
}

// Entrada externa para a rede privada, incluindo protocolos sem porta TCP/UDP.
export async function fetchInbound({ minutes, from, to, limit = 200 } = {}) {
  const p = new URLSearchParams({ limit: String(limit) });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/inbound?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json(); // { flows[], total, shown, truncated, window }
}

// ------------------------------------------------- periodicidade (beacon/C2)
// Só faz sentido para UM par escolhido pelo usuário: a query traz hits.
export async function fetchBeacon(src, dst, { minutes = 240 } = {}) {
  const p = new URLSearchParams({ src, dst, minutes: String(minutes) });
  const r = await fetch(`/api/beacon?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json(); // { samples, meanBytes, intervalMs, sdMs, cv, periodic }
}

export async function fetchIpInfo(ip, { minutes, from, to }) {
  const p = new URLSearchParams();
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/ip/${encodeURIComponent(ip)}?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function compareHosts(a, b, { minutes, from, to }) {
  const p = new URLSearchParams({ a, b });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/compare?${p.toString()}`);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}

export async function topPairs({ minutes, from, to, subnet }) {
  const p = new URLSearchParams();
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  if (subnet) p.set('subnet', subnet);
  const r = await fetch(`/api/top-pairs?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json(); // { pairs, subnet }
}

// Sub-redes monitoradas. A feature "Vigilância de hosts" foi removida; sobrou
// só isto, que serve ao filtro do mapa e não depende de vigiar host.
async function subnetsReq(path, opts = {}) {
  const r = await fetch(`/api/subnets${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}

// Coleta manual da base (histórico de IPs + reputação). A tela de Regiões foi
// removida; o botão vive na tela "Rep. externa", que é quem consome esses dados.
export async function harvestRegions(hours = 168) {
  const r = await fetch('/api/stats/harvest', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hours })
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export const getWatchSubnets = () => subnetsReq('');
export const addWatchSubnet = (cidr, name) => subnetsReq('', { method: 'POST', body: JSON.stringify({ cidr, name }) });
export const patchWatchSubnet = (cidr, body) => subnetsReq(`/${encodeURIComponent(cidr)}`, { method: 'PATCH', body: JSON.stringify(body) });
export const delWatchSubnet = (cidr) => subnetsReq(`/${encodeURIComponent(cidr)}`, { method: 'DELETE' });

// Inventário de máquinas/IPs/aplicações. Uma aplicação pode ter listeners em
// vários IPs da mesma máquina.
async function inventoryReq(path = '', opts = {}) {
  const r = await fetch(`/api/inventory${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}
export const fetchInventory = () => inventoryReq('');
export const createInventoryServer = (body) => inventoryReq('/servers', { method: 'POST', body: JSON.stringify(body) });
export const renameInventoryServer = (id, name) => inventoryReq(`/servers/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) });
export const deleteInventoryServer = (id) => inventoryReq(`/servers/${id}`, { method: 'DELETE' });
export const addServerIp = (serverId, ip) => inventoryReq(`/servers/${serverId}/ips`, { method: 'POST', body: JSON.stringify({ ip }) });
export const deleteServerIp = (id) => inventoryReq(`/ips/${id}`, { method: 'DELETE' });
export const createInventoryApplication = (serverId, body) => inventoryReq(`/servers/${serverId}/applications`, { method: 'POST', body: JSON.stringify(body) });
export const renameInventoryApplication = (id, name) => inventoryReq(`/applications/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) });
export const deleteInventoryApplication = (id) => inventoryReq(`/applications/${id}`, { method: 'DELETE' });
export const addApplicationListener = (applicationId, body) => inventoryReq(`/applications/${applicationId}/listeners`, { method: 'POST', body: JSON.stringify(body) });
export const deleteApplicationListener = (id) => inventoryReq(`/listeners/${id}`, { method: 'DELETE' });
export const addExpectedApplicationClient = (applicationId, ip) => inventoryReq(`/applications/${applicationId}/expected-clients`, { method: 'POST', body: JSON.stringify({ ip }) });
export const deleteExpectedApplicationClient = (id) => inventoryReq(`/expected-clients/${id}`, { method: 'DELETE' });

// Resumo de aplicações da máquina no período selecionado, ordenado por fluxos
// NetFlow (não representa requisições HTTP individuais).
export async function fetchDashboardApplications(serverId, { minutes, from, to } = {}) {
  const p = new URLSearchParams({ serverId: String(serverId) });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/dashboard/applications?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}

export async function fetchApplicationConnections(serverId, applicationId, { minutes, from, to } = {}) {
  const p = new URLSearchParams({ serverId: String(serverId) });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/dashboard/applications/${applicationId}/connections?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}

// Top 5 portas conhecidas que correspondem a tráfego nos IPs da máquina.
export async function fetchDashboardPorts(serverId, { minutes, from, to } = {}) {
  const p = new URLSearchParams({ serverId: String(serverId) });
  if (from && to) { p.set('from', from); p.set('to', to); }
  else p.set('minutes', String(minutes));
  const r = await fetch(`/api/dashboard/ports?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}

export async function fetchDashboardConversations({ top = 5, time = '1h', flowType = 'ingress' } = {}) {
  const p = new URLSearchParams({ top: String(top), time, flowType });
  const r = await fetch(`/api/dashboard/conversations?${p.toString()}`);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}

// ------------------------------------------------- firewalls FortiGate
// Cadastro guarda o token cifrado no Postgres; a API nunca devolve o valor.
async function fortigateReq(path = '', opts = {}) {
  const r = await fetch(`/api/fortigate${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}
export const fetchFortigates = () => fortigateReq('');
// Relógio do backend (é a hora usada pelo agendador de backups).
export async function fetchServerTime() {
  const r = await fetch('/api/server-time');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export const createFortigate = (body) => fortigateReq('', { method: 'POST', body: JSON.stringify(body) });
export const updateFortigate = (id, body) => fortigateReq(`/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteFortigate = (id) => fortigateReq(`/${id}`, { method: 'DELETE' });
export const testFortigate = (id) => fortigateReq(`/${id}/test`, { method: 'POST' });
export const fetchFortigatePolicies = (id, { limit = 20, sort = 'hits', offset = 0, vdom = 'root' } = {}) =>
  fortigateReq(`/${id}/policies?limit=${limit}&sort=${encodeURIComponent(sort)}&offset=${offset}&vdom=${encodeURIComponent(vdom)}`);
export const fetchFortigatePolicyTable = (id, vdom = 'root') =>
  fortigateReq(`/${id}/policy-table?vdom=${encodeURIComponent(vdom || 'root')}`);
export const fetchFortigatePolicyDetail = (id, policyId, vdom) =>
  fortigateReq(`/${id}/policy/${encodeURIComponent(policyId)}?vdom=${encodeURIComponent(vdom || 'root')}`);
export const fetchFortigateAudit = (id) => fortigateReq(`/${id}/audit`);
export const fetchFortigateAnalysis = (id, { staleDays = 90, vdom } = {}) =>
  fortigateReq(`/${id}/analysis?staleDays=${encodeURIComponent(staleDays)}${vdom ? `&vdom=${encodeURIComponent(vdom)}` : ''}`);

// true se ip pertence ao CIDR (ex. 10.190.164.5 em 10.190.164.0/26)
export function cidrContains(cidr, ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr || '');
  const o = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip || '');
  if (!m || !o) return false;
  const bits = Number(m[5]);
  if (bits < 0 || bits > 32) return false;
  const a = ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
  const b = ((+o[1] << 24) | (+o[2] << 16) | (+o[3] << 8) | +o[4]) >>> 0;
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}


export async function lookupIp(ip, days = 7) {
  const r = await fetch(`/api/lookup?ip=${encodeURIComponent(ip)}&days=${days}`);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return r.json();
}

export const VERDICTS = {
  malicious: { label: 'não confiável', dot: 'high' },
  suspicious: { label: 'não confiável', dot: 'high' },
  clean: { label: 'confiável', dot: 'ok' },
  unknown: { label: 'não verificado', dot: 'muted' },
  private: { label: 'rede interna', dot: 'muted' }
};
