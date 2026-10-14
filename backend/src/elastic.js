const fs = require('fs');
const { Client } = require('@elastic/elasticsearch');

const ELASTIC_URL = process.env.ELASTIC_URL || 'http://localhost:9200';
const ELASTIC_INDEX = process.env.ELASTIC_INDEX || 'netflow-*';
// Campos text precisam do sub-campo .keyword p/ agregação
const F_SRC = process.env.ELASTIC_FIELD_SRC || 'netflow.sourceIPv4Address.keyword';
const F_DST = process.env.ELASTIC_FIELD_DST || 'netflow.destinationIPv4Address.keyword';
const F_PROTO = process.env.ELASTIC_FIELD_PROTO || 'netflow.protocolIdentifier';
const F_SPORT = process.env.ELASTIC_FIELD_SPORT || 'netflow.sourceTransportPort';
const F_DPORT = process.env.ELASTIC_FIELD_DPORT || 'netflow.destinationTransportPort';
// Início/fim do fluxo. Neste ambiente são DATE (ISO 8601), não epoch — tratar
// como número dá 0 silenciosamente, então o parsing é por Date.parse.
const F_FSTART = process.env.ELASTIC_FIELD_FLOWSTART || 'netflow.flowStartMilliseconds';
const F_FEND = process.env.ELASTIC_FIELD_FLOWEND || 'netflow.flowEndMilliseconds';
const F_TCP_FLAGS = process.env.ELASTIC_FIELD_TCP_FLAGS || 'netflow.tcpControlBits';
const F_FLOW_DIRECTION = process.env.ELASTIC_FIELD_FLOW_DIRECTION || 'netflow.flowDirection';
const F_EXPORTER = process.env.ELASTIC_FIELD_EXPORTER || 'host.ip.keyword';
const TCP_SYN_NO_ACK_VALUES = Array.from({ length: 512 }, (_, value) => value)
  .filter((value) => (value & 2) !== 0 && (value & 16) === 0);
const TCP_SYN_ACK_VALUES = Array.from({ length: 512 }, (_, value) => value)
  .filter((value) => (value & 2) !== 0 && (value & 16) !== 0);

// Aceita os dois formatos: ISO do Elastic e epoch (outro exporter). Retorna ms
// ou NaN — quem chama decide o que fazer com o NaN, nunca confiar em coerção.
function toMs(v) {
  if (v == null) return NaN;
  if (typeof v === 'number') return v;
  const n = Number(v);
  if (Number.isFinite(n) && String(v).trim() !== '') return n;
  const d = Date.parse(v);
  return Number.isNaN(d) ? NaN : d;
}

// Lê 'netflow.flowStartMilliseconds' de um _source. Precisa existir porque o
// _source é JSON aninhado: pedir ['netflow.x'] no _source devolve
// { netflow: { x } }, não { 'netflow.x': ... }. Acessar direto por índice
// retorna undefined e a query parece "sem dados" em vez de dar erro.
function srcField(source, dotted) {
  let cur = source;
  for (const part of String(dotted).split('.')) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

// true se ip pertence ao CIDR (ex. 10.190.164.5 em 10.190.164.0/26)
function cidrContains(cidr, ip) {
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
// monitoramento, web alternativa...). O resto é tratado como efêmera e vai
// para o fim da fila na exibição — nunca some, só não polui o rótulo.
const KNOWN_SERVICE_PORTS = new Set(
  String(process.env.KNOWN_SERVICE_PORTS || '1433,1521,3306,3389,5432,5601,5666,5900,5985,6379,8080,8443,9200,9300,10050,10051,1514,2055,27017').split(',').map((s) => Number(s.trim()))
);
function isServicePort(p) {
  return p != null && (p <= 1023 || KNOWN_SERVICE_PORTS.has(p));
}
// Serviço primeiro, depois maior volume, depois número — p/ rótulos e listas
function rankPorts(list) {
  return [...list].sort((a, b) => {
    const pa = typeof a === 'object' ? a.port : a;
    const pb = typeof b === 'object' ? b.port : b;
    const sa = isServicePort(pa) ? 0 : 1;
    const sb = isServicePort(pb) ? 0 : 1;
    if (sa !== sb) return sa - sb;
    const ba = (typeof a === 'object' ? a.bytes : 0) || 0;
    const bb = (typeof b === 'object' ? b.bytes : 0) || 0;
    if (bb !== ba) return bb - ba;
    return (pa ?? 999999) - (pb ?? 999999);
  });
}

function buildTlsOptions() {
  // Lab com certificado self-signed: desliga verificação por padrão,
  // a menos que o usuário force ELASTIC_TLS_REJECT_UNAUTHORIZED=1/true
  // ou forneça CA via fingerprint/arquivo.
  const forceVerify = ['1', 'true', 'yes'].includes(
    String(process.env.ELASTIC_TLS_REJECT_UNAUTHORIZED || '').toLowerCase()
  );
  const tls = { rejectUnauthorized: !forceVerify ? false : true };

  if (process.env.ELASTIC_CA_FINGERPRINT) {
    tls.caFingerprint = process.env.ELASTIC_CA_FINGERPRINT.replace(/:/g, '').toUpperCase();
    tls.rejectUnauthorized = true; // com fingerprint dá p/ verificar
  }
  if (process.env.ELASTIC_CA_FILE) {
    try {
      tls.ca = fs.readFileSync(process.env.ELASTIC_CA_FILE);
      tls.rejectUnauthorized = true;
    } catch (e) {
      console.warn(`[elastic] não consegui ler ELASTIC_CA_FILE: ${e.message}`);
    }
  }
  if (!tls.rejectUnauthorized) {
    console.warn('[elastic] TLS sem verificação (self-signed). Use CA própria em produção.');
  }
  return tls;
}

function buildClient() {
  const opts = {
    node: ELASTIC_URL,
    tls: buildTlsOptions(),
    // Evita SniffingTransport tentando descobrir outros nós com cert inválido
    sniffOnStart: false,
    sniffOnConnectionFault: false,
    maxRetries: Math.min(2, Math.max(0, Number.parseInt(process.env.ELASTIC_MAX_RETRIES || '1', 10) || 0)),
    requestTimeout: Math.max(5000, Number.parseInt(process.env.ELASTIC_REQUEST_TIMEOUT_MS || '120000', 10) || 120000)
  };
  if (process.env.ELASTIC_API_KEY) {
    opts.auth = { apiKey: process.env.ELASTIC_API_KEY };
  } else if (process.env.ELASTIC_USER) {
    opts.auth = {
      username: process.env.ELASTIC_USER,
      password: process.env.ELASTIC_PASS || ''
    };
  }
  return new Client(opts);
}

const client = buildClient();

// Limita a pressão simultânea no cluster. Aggregations paginadas continuam
// sequenciais por consulta; esta fila só controla concorrência entre rotas/jobs.
const MAX_CONCURRENT_SEARCHES = Math.max(1, Number.parseInt(process.env.ELASTIC_MAX_CONCURRENT_SEARCHES || '3', 10) || 3);
const MAX_QUEUED_SEARCHES = Math.max(1, Number.parseInt(process.env.ELASTIC_MAX_QUEUED_SEARCHES || '24', 10) || 24);
const SEARCH_QUEUE_TIMEOUT_MS = Math.max(1000, Number.parseInt(process.env.ELASTIC_SEARCH_QUEUE_TIMEOUT_MS || '15000', 10) || 15000);
const SLOW_SEARCH_WARN_MS = Math.max(1000, Number.parseInt(process.env.ELASTIC_SLOW_SEARCH_WARN_MS || '30000', 10) || 30000);
const MAX_SPORT_BUCKETS = Math.max(100, Number.parseInt(process.env.MAX_SPORT_BUCKETS || '10000', 10) || 10000);
let activeSearches = 0;
const pendingSearches = [];

function normalizeSearchError(error) {
  const statusCode = Number(error?.statusCode ?? error?.meta?.statusCode ?? 0);
  const transportFailure = statusCode === 0 && (
    error?.name === 'ConnectionError' || error?.name === 'TimeoutError'
    || ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH'].includes(error?.code)
    || String(error?.code || '').startsWith('ERR_TLS_')
    || ['CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(error?.code)
  );
  if (!transportFailure) return error;
  const reason = error.code || error.name || 'transport';
  return Object.assign(new Error(`Elasticsearch indisponível ou timeout (${reason}).`), {
    status: 503, code: 'ELASTIC_UNAVAILABLE', cause: error
  });
}

function runSearchTask(task) {
  if (task.timer) clearTimeout(task.timer);
  activeSearches += 1;
  const startedAt = Date.now();
  Promise.resolve().then(() => client.search(task.params))
    .then(task.resolve, (error) => task.reject(normalizeSearchError(error)))
    .finally(() => {
    const elapsed = Date.now() - startedAt;
    if (elapsed >= SLOW_SEARCH_WARN_MS) {
      const aggregations = task.params.aggs || task.params.body?.aggs || {};
      console.warn(`[elastic] busca lenta ${elapsed}ms index=${task.params.index || 'unknown'} aggs=${Object.keys(aggregations).join(',') || 'none'}`);
    }
    activeSearches -= 1;
    const next = pendingSearches.shift();
    if (next) runSearchTask(next);
  });
}

function searchElastic(params) {
  return new Promise((resolve, reject) => {
    const task = { params, resolve, reject, timer: null };
    if (activeSearches < MAX_CONCURRENT_SEARCHES) {
      runSearchTask(task);
      return;
    }
    if (pendingSearches.length >= MAX_QUEUED_SEARCHES) {
      reject(Object.assign(new Error('Elasticsearch está ocupado; reduza o período ou tente novamente.'), { status: 503, code: 'ELASTIC_BUSY' }));
      return;
    }
    task.timer = setTimeout(() => {
      const index = pendingSearches.indexOf(task);
      if (index < 0) return;
      pendingSearches.splice(index, 1);
      reject(Object.assign(new Error('A fila do Elasticsearch atingiu o tempo limite; tente novamente.'), { status: 503, code: 'ELASTIC_QUEUE_TIMEOUT' }));
    }, SEARCH_QUEUE_TIMEOUT_MS);
    task.timer.unref?.();
    pendingSearches.push(task);
  });
}

function elasticSearchStats() {
  return { active: activeSearches, queued: pendingSearches.length, maxConcurrent: MAX_CONCURRENT_SEARCHES };
}

// Sessões vivas: agregação por PAR interno↔externo com flowEnd recente.
// Não é "conexão aberta" (NetFlow não tem estado) — é "fluxo ainda ativo
// dentro da janela", que é o mais próximo de sessão que o formato permite.
// Retorna também intervalo médio e desvio entre inícios de fluxo: beacon/C2
// aparece como período baixo desvio. Teto de 4000 pares para não estourar o ES.
async function fetchSessions(query, { activeSec = 120, maxPairs = 4000 } = {}) {
  const baseQuery = buildBaseQuery(query);
  baseQuery.bool.filter.push({ range: { 'netflow.flowEndMilliseconds': { gte: `now-${activeSec}s` } } });
  const buckets = [];
  let after = null;
  let truncated = false;

  while (true) {
    const remaining = maxPairs - buckets.length;
    if (remaining <= 0) {
      if (after) {
        // `after_key` também aparece na última página do composite. Só uma
        // página de prova confirma que ainda havia pares depois do teto.
        const probe = await searchElastic({
          index: ELASTIC_INDEX, size: 0, query: baseQuery,
          aggs: { pares: { composite: {
            size: 1, after,
            sources: [
              { origem: { terms: { field: F_SRC } } },
              { destino: { terms: { field: F_DST } } }
            ]
          } } }
        });
        truncated = (probe.aggregations?.pares?.buckets || []).length > 0;
      }
      break;
    }

    const composite = {
      size: Math.min(2000, remaining),
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } }
      ]
    };
    if (after) composite.after = after;
    const resp = await searchElastic({
      index: ELASTIC_INDEX, size: 0, query: baseQuery,
      aggs: {
        pares: {
          composite,
          aggs: {
            bytes: { sum: { field: 'netflow.octetDeltaCount' } },
            packets: { sum: { field: 'netflow.packetDeltaCount' } },
            portas: { terms: { field: F_DPORT, size: 8 } },
            firstSeen: { min: { field: F_FSTART } },
            lastSeen: { max: { field: F_FEND } }
          }
        }
      }
    });

    const page = resp.aggregations?.pares?.buckets || [];
    if (!page.length) break;
    buckets.push(...page);
    after = resp.aggregations?.pares?.after_key;
    if (!after) break;
  }
  return { buckets, truncated, maxPairs };
}

// Desvio padrão dos intervalos entre inícios de fluxo de UM par.
// Beacon/C2 = intervalo quase constante (cv baixo). Consulta pontual, só para
// os pares que o chamador já filtrou como suspeitos — não varre o índice.
//
// Retorna os intervalos crus junto do resumo: com cv alto (que é o caso
// normal) a média esconde o que aconteceu, e o operador precisa ver se foi
// rajada, marcha-e-parou ou tráfego contínuo.
async function fetchBeaconProfile({ src, dst, minutes = 240 }) {
  const resp = await searchElastic({
    index: ELASTIC_INDEX,
    size: 2000,
    track_total_hits: true,
    query: {
      bool: {
        filter: [
          { range: { '@timestamp': { gte: `now-${minutes}m` } } },
          { term: { [F_SRC]: src } },
          { term: { [F_DST]: dst } }
        ]
      }
    },
    sort: [{ [F_FSTART]: 'asc' }],
    _source: true
  });

  const hits = resp.hits?.hits || [];
  const totalHits = typeof resp.hits?.total === 'number' ? resp.hits.total : (resp.hits?.total?.value || hits.length);
  const truncated = totalHits > hits.length;
  const starts = [];
  let bytesSum = 0;
  for (const h of hits) {
    const ms = toMs(srcField(h._source, F_FSTART));
    if (Number.isNaN(ms)) continue;
    starts.push(ms);
    bytesSum += Number(srcField(h._source, 'netflow.octetDeltaCount') || 0);
  }
  starts.sort((a, b) => a - b);
  // Duplicatas: o mesmo instante reexportado (active timeout) não é um
  // intervalo novo — zerar o gap inflaria a média à toa.
  const uniq = starts.filter((v, i) => i === 0 || v !== starts[i - 1]);

  const base = {
    samples: uniq.length,
    totalFlows: totalHits,
    truncated,
    windowMinutes: minutes,
    meanBytes: uniq.length ? Math.round(bytesSum / uniq.length) : null
  };
  if (uniq.length < 4) return { ...base, cv: null, intervalMs: null, sdMs: null, periodic: false, insufficient: true };

  const gaps = [];
  for (let i = 1; i < uniq.length; i += 1) gaps.push(uniq[i] - uniq[i - 1]);
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
  const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
  const sd = Math.sqrt(variance);
  const cv = mean > 0 ? sd / mean : null;
  return {
    ...base,
    intervalMs: Math.round(mean),
    sdMs: Math.round(sd),
    minMs: Math.min(...gaps),
    maxMs: Math.max(...gaps),
    cv: cv == null ? null : Number(cv.toFixed(3)),
    // cv < 0,35 = compatível com beacon; acima é tráfego comum. Não é veredito:
    // backup agendado e health check também são regulares.
    periodic: !truncated && cv != null && cv < 0.35,
    insufficient: false
  };
}

// Número de protocolo -> nome. Enough para colorir o mapa e o tooltip;
// o que não estiver aqui vira PROTO-<n>, nunca some.
const PROTOCOLS = {
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  89: 'OSPF',
  132: 'SCTP'
};

function protocolName(num) {
  if (num === undefined || num === null) return 'OTHER';
  return PROTOCOLS[num] || `PROTO-${num}`;
}

// Porta -> nome de serviço. Só portas com nome ESTÁVEL e reconhecível: um
// rótulo errado ("App" em 30001) é pior que rótulo nenhum, porque o operador
// lê como se soubesse o que é. Tudo fora daqui cai em "retorno · N fluxos"
// ou fica só como número.
const PORT_NAMES = {
  20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
  111: 'RPCBind', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS',
  139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS',
  445: 'SMB', 464: 'Kerberos', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP',
  636: 'LDAPS', 691: 'MSRPC', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN',
  1433: 'MSSQL', 1434: 'MSSQL-BD', 1514: 'Syslog', 1521: 'Oracle', 1701: 'L2TP',
  1723: 'PPTP', 1812: 'RADIUS', 1813: 'RADIUS', 1883: 'MQTT', 2049: 'NFS',
  2055: 'NetFlow', 2181: 'Zookeeper', 2375: 'Docker', 2376: 'Docker',
  2379: 'etcd', 2389: 'etcd', 2888: 'Zookeeper', 3128: 'Squid', 3306: 'MySQL',
  3389: 'RDP', 3690: 'SVN', 3899: 'LDAP', 4369: 'EPMD', 4444: 'Metasploit',
  4500: 'IPsec', 4567: 'AMQP', 5000: 'UPnP', 5060: 'SIP', 5061: 'SIPS',
  5222: 'XMPP', 5432: 'Postgres', 5500: 'VNC', 5601: 'Kibana', 5671: 'AMQP-TLS',
  5672: 'AMQP', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM-TLS', 6000: 'X11',
  6379: 'Redis', 6443: 'K8s-API', 6667: 'IRC', 7001: 'Cassandra', 8080: 'HTTP-Alt',
  8088: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8500: 'Consul', 8883: 'MQTT-TLS',
  9000: 'PHP-FPM', 9090: 'Prometheus', 9092: 'Kafka', 9100: 'Node-Exp',
  9200: 'Elasticsearch', 9300: 'ES-Transporte', 9418: 'Git', 10050: 'Zabbix',
  10051: 'Zabbix', 10250: 'K8s-Kubelet', 10255: 'K8s-ReadOnly', 11211: 'Memcached',
  15672: 'RabbitMQ-Mgmt', 16200: 'Elasticsearch', 16379: 'Redis',
  25565: 'Minecraft', 27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB',
  28015: 'MongoDB', 28017: 'MongoDB', 50070: 'MongoDB', 61616: 'STOMP',
  6667.5: 'IRC'
};

// 6667.5 acima é ruído de leitura: chave fracionária num mapa indexado por
// inteiro nunca casa. Remove em vez de deixar uma entrada morta que sugere
// cobertura que não existe.
delete PORT_NAMES[6667.5];

function portName(p) {
  if (p == null || Number.isNaN(p)) return null;
  return PORT_NAMES[Number(p)] || null;
}

function knownServicePorts() {
  return Object.entries(PORT_NAMES)
    .map(([port, service]) => ({ port: Number(port), service }))
    .filter(({ port }) => Number.isInteger(port))
    .sort((a, b) => a.port - b.port);
}

// Nome de serviço pro rótulo: HTTPS · 443 · 12 fluxos (nunca "retorno · N" pra porta conhecida)
function serviceLabel(port, flows) {
  const svc = portName(port);
  const num = port ?? '?';
  if (svc) return `${svc} · ${num} · ${flows} fluxos`;
  return `${num} · ${flows} fluxos`;
}

// Monta o filtro de tempo a partir dos query params.
// Suporta: ?minutes=15 | ?range=now-15m | ?from=ISO&to=ISO
function buildTimeRange(query) {
  if (query.from || query.to) {
    const from = Date.parse(query.from || '');
    const to = Date.parse(query.to || '');
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
      throw Object.assign(new Error('Informe um intervalo from/to válido.'), { status: 400 });
    }
    if (to - from > 7 * 24 * 60 * 60 * 1000) {
      throw Object.assign(new Error('O histórico disponível é de até 7 dias.'), { status: 400 });
    }
    return { '@timestamp': { gte: query.from, lte: query.to } };
  }
  if (query.range) {
    if (query.range !== 'now') {
      const match = /^now-(\d+)([smhd])$/.exec(query.range);
      if (!match) throw Object.assign(new Error('Use uma janela relativa de até 7 dias.'), { status: 400 });
      const unitMs = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[match[2]];
      if (Number(match[1]) * unitMs > 7 * 24 * 60 * 60 * 1000) {
        throw Object.assign(new Error('O histórico disponível é de até 7 dias.'), { status: 400 });
      }
    }
    return { '@timestamp': { gte: query.range } };
  }
  const minutes = Number.parseInt(query.minutes || '15', 10);
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 7 * 24 * 60) {
    throw Object.assign(new Error('O histórico disponível é de até 7 dias.'), { status: 400 });
  }
  return { '@timestamp': { gte: `now-${minutes}m` } };
}

function buildBaseQuery(query) {
  return {
    bool: {
      filter: [{ range: buildTimeRange(query) }]
    }
  };
}

// Query principal: composite origem + destino + protocolo + porta_dest.
// A porta de origem (efêmera, única por fluxo) fica DE FORA por padrão:
// incluí-la multiplica os buckets por 10-50x. Quem precisa dela (detalhe do
// host) usa withSport + filtro de IP.
// SEM TETO: pagina até esgotar o after_key — o mapa agrega por par, então o
// volume final é pequeno mesmo em janelas longas.

// Top N pares bidirecionais.
//
// POR QUE NÃO REUSA fetchConnections
// A rota anterior chamava fetchConnections, que esvazia o composite INTEIRO da
// janela (src+dst+protocolo+porta) antes de agrupar em JS. Medido aqui com o
// sample rate em 0:
//   15min = 9,9s | 1h = 51,8s | 6h = 60,3s | 12h = 68,4s | 24h = 81,1s
//   3d = 114s | 7d > 120s (abortado)      ... para devolver 10 linhas.
// O gargalo é a cardinalidade: src+dst+protocolo+porta dá 36 mil buckets em 15min
// e 190 mil em 7 dias, com 39 idas e voltas ao ES.
//
// A AGREGAÇÃO DELEVA AQUI É src+dst (sem protocolo/porta), que é o que a tela
// ordena, e ela cabe em 2-3 páginas: 468 buckets em 15min, 6.223 em 7 dias.
// Protocolo e porta saem numa segunda query, só para os `limit` pares que
// entraram no ranking. Resultado: 7 dias saiu de >120s (timeout) para ~6s.
//
// O `terms` aninhado também serve e é ainda mais barato, mas com 500 src x 1000
// dst a cardinalidade estoura max_buckets em janela longa e o ES derruba a
// consulta; composite não tem esse teto e devolve contagem exata.
//
// UMA PASSADA SÓ. Composite sobre (src,dst) já devolve os dois sentidos: o
// bucket "X→Y" E o bucket "Y→X" saem na mesma resposta. Rodar a agregação duas
// vezes (uma com os campos trocados) reenumera os mesmos buckets e dobra os
// bytes — chegou a dar 2x em toda linha do ranking, e o erro se escondia porque
// a ordem continuava certa.
function addInventoryFlowFilter(target, ips, flowType = 'both') {
  if (!ips?.length) return;
  if (flowType === 'ingress') {
    target.bool.filter.push({ terms: { [F_DST]: ips } });
  } else if (flowType === 'egress') {
    target.bool.filter.push({ terms: { [F_SRC]: ips } });
  } else {
    target.bool.filter.push({
      bool: {
        should: [
          { terms: { [F_SRC]: ips } },
          { terms: { [F_DST]: ips } }
        ],
        minimum_should_match: 1
      }
    });
  }
}

async function fetchTopPairs(query, { limit = 10, subnet = null, inventoryIps = null, flowType = 'both', pagina = 3000, maxPaginas = 12 } = {}) {
  const baseQuery = buildBaseQuery(query);
  addInventoryFlowFilter(baseQuery, inventoryIps, flowType);

  const grupos = new Map();
  let after = null;
  let paginas = 0;
  let truncadoES = false;

  do {
    const composite = {
      size: pagina,
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } }
      ]
    };
    if (after) composite.after = after;

    const r = await searchElastic({
      index: ELASTIC_INDEX, size: 0, query: baseQuery,
      aggs: {
        pares: {
          composite,
          aggs: {
            bytes: { sum: { field: 'netflow.octetDeltaCount' } },
            pacotes: { sum: { field: 'netflow.packetDeltaCount' } },
            fluxoInicio: { min: { field: F_FEND } },
            fluxoFim: { max: { field: F_FEND } },
            synNoAck: { filter: { terms: { [F_TCP_FLAGS]: TCP_SYN_NO_ACK_VALUES } } },
            synAck: { filter: { terms: { [F_TCP_FLAGS]: TCP_SYN_ACK_VALUES } } },
            flowDirections: { terms: { field: F_FLOW_DIRECTION, size: 4 } }
          }
        }
      }
    });

    const buckets = r.aggregations?.pares?.buckets || [];
    for (const bucket of buckets) {
      const s = String(bucket.key.origem);
      const d = String(bucket.key.destino);
      if (!s || !d || s === d) continue;
      const bytes = bucket.bytes?.value || 0;
      const ini = bucket.fluxoInicio?.value_as_string
        || (bucket.fluxoInicio?.value != null ? new Date(bucket.fluxoInicio.value).toISOString() : null);
      const fim = bucket.fluxoFim?.value_as_string
        || (bucket.fluxoFim?.value != null ? new Date(bucket.fluxoFim.value).toISOString() : null);

      // Chave normalizada: X→Y e Y→X caem no mesmo grupo.
      const baixoEhPrimeiro = s < d;
      const k = baixoEhPrimeiro ? `${s}|${d}` : `${d}|${s}`;
      let g = grupos.get(k);
      if (!g) {
        g = {
          a: baixoEhPrimeiro ? s : d, b: baixoEhPrimeiro ? d : s,
          bytes: 0, pacotes: 0, fluxos: 0,
          bytesBaixo: 0, bytesAlto: 0,
          inicio: null, fim: null, protocolos: new Set(), portas: new Map(),
          initiatorVotes: new Map(), flowDirections: new Map(), synNoAckFlows: 0, synAckFlows: 0
        };
        grupos.set(k, g);
      }
      g.bytes += bytes;
      g.pacotes += bucket.pacotes?.value || 0;
      g.fluxos += bucket.doc_count || 0;
      if (baixoEhPrimeiro) g.bytesBaixo += bytes; else g.bytesAlto += bytes;
      const synNoAckFlows = bucket.synNoAck?.doc_count || 0;
      const synAckFlows = bucket.synAck?.doc_count || 0;
      g.synNoAckFlows += synNoAckFlows;
      g.synAckFlows += synAckFlows;
      if (synNoAckFlows) g.initiatorVotes.set(s, (g.initiatorVotes.get(s) || 0) + synNoAckFlows);
      if (synAckFlows) g.initiatorVotes.set(d, (g.initiatorVotes.get(d) || 0) + synAckFlows);
      for (const direction of bucket.flowDirections?.buckets || []) {
        const key = Number(direction.key);
        g.flowDirections.set(key, (g.flowDirections.get(key) || 0) + (direction.doc_count || 0));
      }
      if (ini && (!g.inicio || ini < g.inicio)) g.inicio = ini;
      if (fim && (!g.fim || fim > g.fim)) g.fim = fim;
    }

    // `after_key` não distingue "terminou" de "tem mais": vem preenchido na
    // última página também. O corte é a página vir cheia com o teto de páginas.
    paginas++;
    after = r.aggregations?.pares?.after_key || null;
    if (after && paginas >= maxPaginas) {
      const probe = await searchElastic({
        index: ELASTIC_INDEX, size: 0, query: baseQuery,
        aggs: { pares: { composite: { size: 1, after, sources: composite.sources } } }
      });
      truncadoES = (probe.aggregations?.pares?.buckets || []).length > 0;
    }
  } while (after && paginas < maxPaginas);

  // A subnet filtra em JS, com o MESMO cidrContains que o resto do backend usa.
  // Havia antes um script painless equivalente na query: os campos de IP são
  // text+keyword (sem range nativo), o script quebrava em IPv6 e em `split`, e
  // manter duas cópias do mesmo teste é como os dois lados divergem em silêncio.
  // Não compensa: o composite sem protocolo/porta é barato o bastante (6.223
  // buckets em 7 dias, ~2,5s) para paginar tudo e descartar o resto aqui.
  const todos = [...grupos.values()].sort((x, y) => y.bytes - x.bytes);
  const lista = subnet
    ? todos.filter((g) => cidrContains(subnet, g.a) || cidrContains(subnet, g.b))
    : todos;

  // Só os que passam no corte recebem detalhe de protocolo/porta.
  const topo = lista.slice(0, limit);
  if (topo.length) await detalharPares(query, topo, { inventoryIps, flowType });
  return { grupos: lista, candidatos: lista.length, topo, truncadoES };
}

function conversationDirection(group) {
  const votes = [...group.initiatorVotes.entries()].sort((a, b) => b[1] - a[1]);
  const [clientIp, clientVotes] = votes[0] || [null, 0];
  const [runnerUpIp, runnerUpVotes] = votes[1] || [null, 0];
  const confident = clientIp && clientVotes > runnerUpVotes;
  const selectedClient = confident ? clientIp : null;
  const flowDirections = [...group.flowDirections.entries()].map(([code, flows]) => ({
    code,
    label: code === 0 ? 'Ingress' : code === 1 ? 'Egress' : `Direção ${code}`,
    flows
  }));
  return {
    clientIp: selectedClient,
    serverIp: selectedClient ? (selectedClient === group.a ? group.b : group.a) : null,
    directionConfidence: confident ? 'tcpControlBits' : votes.length ? 'ambiguous' : 'unavailable',
    clientToServerBytes: selectedClient == null ? null : Math.round(selectedClient === group.a ? group.bytesBaixo : group.bytesAlto),
    serverToClientBytes: selectedClient == null ? null : Math.round(selectedClient === group.a ? group.bytesAlto : group.bytesBaixo),
    synNoAckFlows: group.synNoAckFlows || 0,
    synAckFlows: group.synAckFlows || 0,
    flowDirections
  };
}

// Detalhe (protocolo + portas) dos `limit` pares do ranking, em UMA query.
// Um `should` por par, nos dois sentidos: filtrar pelos IPs soltos deixaria
// passar qualquer outro par que envolva um deles e contaminaria a linha.
async function detalharPares(query, pares, inventoryScope = {}) {
  const q = buildBaseQuery(query);
  addInventoryFlowFilter(q, inventoryScope.inventoryIps, inventoryScope.flowType);
  q.bool.filter.push({
    bool: {
      should: pares.flatMap((p) => [
        { bool: { must: [{ term: { [F_SRC]: p.a } }, { term: { [F_DST]: p.b } }] } },
        { bool: { must: [{ term: { [F_SRC]: p.b } }, { term: { [F_DST]: p.a } }] } }
      ]),
      minimum_should_match: 1
    }
  });

  const porChave = new Map(pares.map((p) => [`${p.a}|${p.b}`, p]));
  // Composite só de (src,dst) e protocolo/porta como `terms` dentro de cada par.
  // Antes eram 4 fontes no composite: ele ordena por CHAVE, não por bytes, então
  // o teto de buckets cortava as portas grandes e a linha saía sem porta nenhuma.
  // Aqui a cardinalidade é ~2x `pares`, então não há o que estourar.
  const r = await searchElastic({
    index: ELASTIC_INDEX, size: 0, query: q,
    aggs: {
      pares: {
        composite: {
          size: Math.max(100, pares.length * 2),
          sources: [
            { origem: { terms: { field: F_SRC } } },
            { destino: { terms: { field: F_DST } } }
          ]
        },
        aggs: {
          // `missing_bucket` é opção de fonte do composite, não de `terms`.
          // Sem ele, fluxo sem protocolo/porta simplesmente não entra no bucket.
          protocolos: { terms: { field: F_PROTO, size: 20 } },
          portas: {
            terms: { field: F_DPORT, size: 20 },
            aggs: { bytes: { sum: { field: 'netflow.octetDeltaCount' } } }
          }
        }
      }
    }
  });
  for (const bucket of r.aggregations?.pares?.buckets || []) {
    const s = String(bucket.key.origem);
    const d = String(bucket.key.destino);
    const k = s < d ? `${s}|${d}` : `${d}|${s}`;
    const alvo = porChave.get(k);
    if (!alvo) continue;
    for (const proto of bucket.protocolos?.buckets || []) {
      if (proto.key != null) alvo.protocolos.add(proto.key);
    }
    for (const p of bucket.portas?.buckets || []) {
      const dp = p.key ?? null;
      const cur = alvo.portas.get(dp) || { port: dp, bytes: 0 };
      cur.bytes += p.bytes?.value || 0;
      alvo.portas.set(dp, cur);
    }
  }
}

async function fetchConnections(query, { pageSize = 1000, maxEdges = 50000, ip = null, withSport = false, activeSec = null, withTimes = false }) {
  const bucketLimit = withSport ? Math.min(maxEdges, MAX_SPORT_BUCKETS) : maxEdges;
  const afterPages = [];
  let after = undefined;
  let totalBuckets = 0;
  let truncated = false;
  const baseQuery = buildBaseQuery(query);
  if (activeSec) baseQuery.bool.filter.push({ range: { [F_FEND]: { gte: `now-${activeSec}s` } } });
  if (ip) {
    baseQuery.bool.filter.push({
      bool: {
        should: [{ term: { [F_SRC]: ip } }, { term: { [F_DST]: ip } }],
        minimum_should_match: 1
      }
    });
  }

  while (totalBuckets < bucketLimit) {
    const remaining = bucketLimit - totalBuckets;
    const composite = {
      size: Math.min(pageSize, remaining),
      sources: [
        { origem: { terms: { field: F_SRC } } },
        { destino: { terms: { field: F_DST } } },
        { protocolo: { terms: { field: F_PROTO, missing_bucket: true } } },
        { porta_dest: { terms: { field: F_DPORT, missing_bucket: true } } }
      ]
    };
    if (withSport) composite.sources.push({ porta_orig: { terms: { field: F_SPORT, missing_bucket: true } } });
    if (after) composite.after = after;

    const body = {
      size: 0,
      query: baseQuery,
        aggs: {
          conexoes: {
            composite,
            aggs: {
              bytes: { sum: { field: 'netflow.octetDeltaCount' } },
              pacotes: { sum: { field: 'netflow.packetDeltaCount' } },
              // primeira/última atividade do par (p/ coluna ESTADO).
              // firstSeen = início do fluxo MAIS ANTIGO na janela (não absoluto!);
              // lastSeen = fim do fluxo MAIS RECENTE (último pacote ou export).
              ...(withTimes ? {
                firstSeen: { min: { field: 'netflow.flowStartMilliseconds' } },
                lastSeen: { max: { field: 'netflow.flowEndMilliseconds' } }
              } : {})
            }
          }
        }
    };

    const resp = await searchElastic({ index: ELASTIC_INDEX, body });
    const agg = resp.aggregations?.conexoes;
    if (!agg || !agg.buckets.length) break;

    afterPages.push(...agg.buckets);
    totalBuckets += agg.buckets.length;

    if (!agg.after_key) break;
    after = agg.after_key;
  }

  if (after && totalBuckets >= bucketLimit) {
    // O after_key pode existir também na última página. Uma página de prova
    // confirma se havia mais buckets, sem percorrer o restante do composite.
    const sources = [
      { origem: { terms: { field: F_SRC } } },
      { destino: { terms: { field: F_DST } } },
      { protocolo: { terms: { field: F_PROTO, missing_bucket: true } } },
      { porta_dest: { terms: { field: F_DPORT, missing_bucket: true } } }
    ];
    if (withSport) sources.push({ porta_orig: { terms: { field: F_SPORT, missing_bucket: true } } });
    const probe = await searchElastic({
      index: ELASTIC_INDEX, size: 0, query: baseQuery,
      aggs: { conexoes: { composite: { size: 1, after, sources } } }
    });
    truncated = (probe.aggregations?.conexoes?.buckets || []).length > 0;
  }

  const out = afterPages.slice(0, bucketLimit);
  out.truncated = truncated || totalBuckets > out.length;
  return out;
}

// Agrega por PAR (origem, destino, protocolo): portas efêmeras — de origem E
// de destino (tráfego de retorno) — não viram arestas separadas. Cada aresta
// soma bytes/pacotes/fluxos e guarda o ranking de portas destino. É isso que
// evita o "novelo" de milhares de linhas entre os mesmos hosts.
function toCytoscape(buckets) {
  const nodeSet = new Set();
  const groups = new Map(); // src|dst|proto -> agregado
  for (const b of buckets) {
    if (!b.key.origem || !b.key.destino || b.key.origem === b.key.destino) continue;
    const source = String(b.key.origem);
    const target = String(b.key.destino);
    const protoNum = b.key.protocolo ?? null;
    const k = `${source}|${target}|${protoNum}`;
    nodeSet.add(source);
    nodeSet.add(target);
    let g = groups.get(k);
    if (!g) {
      g = { source, target, protoNum, bytes: 0, packets: 0, flows: 0, dports: new Map(), srcPorts: new Set() };
      groups.set(k, g);
    }
    const bytes = b.bytes?.value || 0;
    const flowCount = b.doc_count || 0;
    g.bytes += bytes;
    g.packets += b.pacotes?.value || 0;
    g.flows += flowCount;
    const dp = b.key.porta_dest ?? null;
    const cur = g.dports.get(dp) || { port: dp, bytes: 0, flows: 0 };
    cur.bytes += bytes; cur.flows += flowCount;
    g.dports.set(dp, cur);
    if (b.key.porta_orig != null && g.srcPorts.size < 50) g.srcPorts.add(b.key.porta_orig);
  }

  const edges = [...groups.values()].map((g, i) => {
    const ranked = rankPorts([...g.dports.values()]);
    const top = ranked[0] || { port: null, bytes: 0, flows: 0 };
    const svcName = portName(top.port);
    return {
      data: {
        id: `e${i}-${g.source}-${g.target}-${g.protoNum}`,
        source: g.source,
        target: g.target,
        bytes: Math.round(g.bytes),
        packets: Math.round(g.packets),
        protocolNum: g.protoNum,
        protocol: protocolName(g.protoNum),
        srcPort: g.srcPorts.size === 1 ? [...g.srcPorts][0] : null,
        srcPorts: [...g.srcPorts],
        dstPort: top.port, // porta principal (maior volume)
        port: top.port, // compat
        dstPorts: ranked.slice(0, 15).map((d) => ({ port: d.port, service: portName(d.port), bytes: Math.round(d.bytes), flows: d.flows })),
        flows: g.flows,
        // --- Fase A1: nome do serviço + formato do tráfego (sinal, não rótulo) ---
        service: svcName, // "HTTPS", "RDP", null se efêmera/desconhecida
        servicePort: isServicePort(top.port),
        // bytes por pacote: transferência em massa (~1400) vs. beacon/túnel (<120)
        bytesPerPacket: g.packets > 0 ? Math.round(g.bytes / g.packets) : null,
        // pacotes por fluxo: volume uno (alto) vs. pulverizado (baixo)
        packetsPerFlow: g.flows > 0 ? Math.round(g.packets / g.flows) : null,
        // serviço primeiro, depois número — "HTTPS · 443 · 12 fluxos"
        portLabel: isServicePort(top.port)
          ? serviceLabel(top.port, g.flows)
          : `retorno · ${g.flows} fluxos`
      }
    };
  });

  const nodes = [...nodeSet].map((ip) => ({ data: { id: ip, label: ip } }));
  return { nodes, edges };
}

module.exports = {
  client,
  searchElastic,
  elasticSearchStats,
  ELASTIC_INDEX,
  F_SRC, F_DST, F_PROTO, F_SPORT, F_DPORT, F_FSTART, F_FEND, F_TCP_FLAGS, F_FLOW_DIRECTION, F_EXPORTER,
  TCP_SYN_NO_ACK_VALUES, TCP_SYN_ACK_VALUES, toMs, srcField,
  PROTOCOLS,
  protocolName,
  portName,
  knownServicePorts,
  serviceLabel,
  isServicePort,
  rankPorts,
  cidrContains,
  buildTimeRange,
  fetchConnections,
  fetchTopPairs,
  addInventoryFlowFilter,
  conversationDirection,
  fetchSessions,
  fetchBeaconProfile,
  toCytoscape
};
