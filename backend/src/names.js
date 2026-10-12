const dns = require('dns').promises;
const fs = require('fs');

// Fallback legado opcional: JSON { "172.20.20.28": "web-01", ... }.
// O inventário principal de máquinas/IPs é o PostgreSQL; o JSON é mantido como
// fonte secundária durante a migração de instalações antigas.
let inventory = {};
if (process.env.INVENTORY_FILE) {
  try {
    inventory = JSON.parse(fs.readFileSync(process.env.INVENTORY_FILE, 'utf8'));
    console.log(`[names] inventário carregado: ${Object.keys(inventory).length} hosts`);
  } catch (e) {
    console.warn(`[names] INVENTORY_FILE inválido: ${e.message}`);
  }
}

const RDNS_ENABLED = !['0', 'false', 'no'].includes(String(process.env.RDNS_ENABLED ?? '1').toLowerCase());
const RDNS_TIMEOUT = parseInt(process.env.RDNS_TIMEOUT_MS || '1500', 10);
const RDNS_TTL = parseInt(process.env.RDNS_CACHE_TTL_MS || '3600000', 10); // 1h

// DNS recursivo p/ PTR externo (o DNS interno às vezes não resolve a internet).
// Ex: RDNS_DNS_SERVERS=8.8.8.8,1.1.1.1 — vazio = usa o DNS do sistema.
if (process.env.RDNS_DNS_SERVERS) {
  dns.setServers(process.env.RDNS_DNS_SERVERS.split(',').map((s) => s.trim()).filter(Boolean));
}

// ASN/organização via Team Cymru (grátis, via DNS, sem API key) — cobre
// IPs públicos mesmo sem PTR (ex. 1.1.1.1 -> AS13335 CLOUDFLARENET).
const ASN_ENABLED = !['0', 'false', 'no'].includes(String(process.env.ASN_ENABLED ?? '1').toLowerCase());
const ASN_TTL = parseInt(process.env.ASN_CACHE_TTL_MS || '86400000', 10); // 24h
const asnCache = new Map(); // ip -> { asn, org, prefix, expires }

const cache = new Map(); // ip -> { name, source, expires }

function subnetOf(ip) {
  // /24 para IPv4; IPv6 -> /64 (primeiros 4 grupos)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') + '::/64';
  return 'unknown';
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('dns timeout')), ms))
  ]);
}

function isPrivateIp(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    if (ip === '::1') return true;
    const l = ip.toLowerCase();
    return l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

// 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com (IPv6: sem suporte, retorna null)
function cymruOriginName(ip) {
  if (ip.includes(':')) return null;
  return ip.split('.').reverse().join('.') + '.origin.asn.cymru.com';
}

async function lookupAsn(ip) {
  if (!ASN_ENABLED || isPrivateIp(ip)) return null;
  const hit = asnCache.get(ip);
  if (hit && hit.expires > Date.now()) return hit;

  try {
    const q = cymruOriginName(ip);
    if (!q) return null;
    const txts = await withTimeout(dns.resolveTxt(q), RDNS_TIMEOUT);
    // "15169 | 8.8.8.0/24 | US | arin | ..."
    const first = (txts[0] || []).join('');
    const [asn, prefix] = first.split('|').map((s) => s.trim());
    if (!asn || !/^\d+$/.test(asn)) return null;
    let org = null;
    try {
      const atxts = await withTimeout(dns.resolveTxt(`AS${asn}.asn.cymru.com`), RDNS_TIMEOUT);
      // "15169 | US | arin | 1992-12-01 | GOOGLE, US"
      const parts = (atxts[0] || []).join('').split('|').map((s) => s.trim());
      org = parts[4] || null;
    } catch { /* ASN sem nome, segue com número */ }
    const info = { asn: Number(asn), org, prefix: prefix || null, expires: Date.now() + ASN_TTL };
    asnCache.set(ip, info);
    return info;
  } catch {
    return null; // sem rota Cymru (IP reservado) ou DNS fora
  }
}

async function resolveIp(ip, { skipDbInventory = false } = {}) {
  if (!skipDbInventory) {
    try {
      const { inventoryNameFor } = require('./db.js');
      const dbName = await inventoryNameFor(ip);
      if (dbName) return { ip, name: dbName, source: 'inventory' };
    } catch { /* o inventário PostgreSQL pode estar indisponível; tenta fontes restantes */ }
  }
  if (inventory[ip]) return { ip, name: inventory[ip], source: 'inventory' };

  const hit = cache.get(ip);
  if (hit && hit.expires > Date.now()) return { ip, name: hit.name, source: hit.source };

  let name = null;
  let source = 'none';
  if (RDNS_ENABLED) {
    try {
      const hostnames = await withTimeout(dns.reverse(ip), RDNS_TIMEOUT);
      if (hostnames && hostnames.length) { name = hostnames[0].replace(/\.$/, ''); source = 'rdns'; }
    } catch {
      source = 'none'; // sem PTR, timeout ou DNS fora — normal em rede interna
    }
  }
  cache.set(ip, { name, source, expires: Date.now() + RDNS_TTL });
  const asnInfo = await lookupAsn(ip);
  return {
    ip,
    name,
    source,
    asn: asnInfo?.asn ?? null,
    org: asnInfo?.org ?? null,
    prefix: asnInfo?.prefix ?? null
  };
}

// Concorrência limitada p/ não afogar o DNS com 5000 IPs
// Retorna { names: {ip: name}, info: {ip: {asn, org, prefix}} }
async function resolveMany(ips, concurrency = 20) {
  const uniq = [...new Set(ips)].slice(0, 2000);
  const names = {};
  const info = {};
  // Lê o inventário PostgreSQL em lote: o nome manual vence rDNS e evita uma
  // consulta SQL individual para cada nó do grafo.
  try {
    const { inventoryNamesFor } = require('./db.js');
    Object.assign(names, await inventoryNamesFor(uniq));
  } catch { /* segue com o JSON legado, cache e rDNS */ }
  for (const ip of uniq) if (!names[ip] && inventory[ip]) names[ip] = inventory[ip];
  const resolve = uniq.filter((ip) => !names[ip]);
  let i = 0;
  async function worker() {
    while (i < resolve.length) {
      const ip = resolve[i++];
      try {
        const r = await resolveIp(ip, { skipDbInventory: true });
        if (r.name) names[ip] = r.name;
        if (r.asn) info[ip] = { asn: r.asn, org: r.org, prefix: r.prefix };
      } catch { /* ignora */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, resolve.length) }, worker));
  return { names, info };
}

module.exports = { inventory, subnetOf, resolveIp, resolveMany, lookupAsn };
