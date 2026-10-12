// Métricas por aplicação cadastrada: um fluxo conta quando seu IP/porta/protocolo
// coincide com um listener em qualquer uma das interfaces da máquina.
const { client, ELASTIC_INDEX, F_SRC, F_DST, F_PROTO, F_SPORT, F_DPORT, F_FSTART, F_FEND, buildTimeRange, knownServicePorts, protocolName, portName, cidrContains } = require('./elastic.js');
const { pool, listInventory, listSubnets } = require('./db.js');

const F_OCTETS = 'netflow.octetDeltaCount';
const F_PACKETS = 'netflow.packetDeltaCount';

function either(clauses) {
  return clauses.length
    ? { bool: { should: clauses, minimum_should_match: 1 } }
    : { match_none: {} };
}

async function topApplications(serverId, query, limit = 5) {
  const servers = await listInventory();
  const server = servers.find((item) => item.id === Number(serverId));
  if (!server) throw Object.assign(new Error('Máquina não encontrada no inventário'), { status: 404 });
  if (!server.applications.length) {
    return { server: { id: server.id, name: server.name, ips: server.ips }, totalApplications: 0, applications: [] };
  }

  const definitions = new Map();
  const filters = {};
  const incomingFilters = {};
  const outgoingFilters = {};
  for (const application of server.applications) {
    const incoming = [];
    const outgoing = [];
    for (const listener of application.listeners) {
      const protocol = listener.protocol === 'TCP' ? 6 : 17;
      incoming.push({ bool: { filter: [
        { term: { [F_DST]: listener.ip } },
        { term: { [F_DPORT]: listener.port } },
        { term: { [F_PROTO]: protocol } }
      ] } });
      outgoing.push({ bool: { filter: [
        { term: { [F_SRC]: listener.ip } },
        { term: { [F_SPORT]: listener.port } },
        { term: { [F_PROTO]: protocol } }
      ] } });
    }
    const key = String(application.id);
    definitions.set(key, { ...application, incoming, outgoing });
    filters[key] = either([...incoming, ...outgoing]);
    incomingFilters[key] = either(incoming);
    outgoingFilters[key] = either(outgoing);
  }

  const response = await client.search({
    index: ELASTIC_INDEX,
    size: 0,
    query: { range: buildTimeRange(query) },
    aggs: {
      applications: {
        filters: { filters },
        aggs: {
          bytes: { sum: { field: F_OCTETS } },
          packets: { sum: { field: F_PACKETS } }
        }
      },
      incoming: {
        filters: { filters: incomingFilters },
        aggs: {
          bytes: { sum: { field: F_OCTETS } },
          packets: { sum: { field: F_PACKETS } }
        }
      },
      outgoing: {
        filters: { filters: outgoingFilters },
        aggs: {
          bytes: { sum: { field: F_OCTETS } },
          packets: { sum: { field: F_PACKETS } }
        }
      }
    }
  });

  const buckets = response.aggregations?.applications?.buckets || {};
  const incomingBuckets = response.aggregations?.incoming?.buckets || {};
  const outgoingBuckets = response.aggregations?.outgoing?.buckets || {};
  const applications = [...definitions.entries()].map(([key, app]) => {
    const bucket = buckets[key] || {};
    const incoming = incomingBuckets[key] || {};
    const outgoing = outgoingBuckets[key] || {};
    return {
      id: app.id,
      name: app.name,
      listeners: app.listeners,
      flows: bucket.doc_count || 0,
      bytes: Math.round(bucket.bytes?.value || 0),
      packets: Math.round(bucket.packets?.value || 0),
      incoming: {
        flows: incoming.doc_count || 0,
        bytes: Math.round(incoming.bytes?.value || 0),
        packets: Math.round(incoming.packets?.value || 0)
      },
      outgoing: {
        flows: outgoing.doc_count || 0,
        bytes: Math.round(outgoing.bytes?.value || 0),
        packets: Math.round(outgoing.packets?.value || 0)
      }
    };
  }).sort((a, b) => b.flows - a.flows || b.bytes - a.bytes);

  return {
    server: { id: server.id, name: server.name, ips: server.ips },
    totalApplications: applications.length,
    applicationsWithTraffic: applications.filter((app) => app.flows > 0).length,
    ranking: 'netflow-doc-count',
    applications: applications.slice(0, limit)
  };
}

async function topKnownPorts(serverId, query, limit = 5) {
  const servers = await listInventory();
  const server = servers.find((item) => item.id === Number(serverId));
  if (!server) throw Object.assign(new Error('Máquina não encontrada no inventário'), { status: 404 });

  const ports = knownServicePorts();
  const ips = server.ips.map((item) => item.ip);
  if (!ips.length) {
    return { server: { id: server.id, name: server.name, ips: server.ips }, totalKnownPorts: ports.length, portsWithTraffic: 0, ports: [] };
  }

  const allPortFilters = {};
  const incomingFilters = {};
  const outgoingFilters = {};
  for (const port of ports) {
    const key = String(port.port);
    // A service port must belong to the selected server, not the remote peer:
    // destination port for inbound flows, source port for outbound flows.
    const incoming = { bool: { filter: [
      { terms: { [F_DST]: ips } },
      { term: { [F_DPORT]: port.port } }
    ] } };
    const outgoing = { bool: { filter: [
      { terms: { [F_SRC]: ips } },
      { term: { [F_SPORT]: port.port } }
    ] } };
    incomingFilters[key] = incoming;
    outgoingFilters[key] = outgoing;
    allPortFilters[key] = either([incoming, outgoing]);
  }

  const metrics = {
    bytes: { sum: { field: F_OCTETS } },
    packets: { sum: { field: F_PACKETS } }
  };
  const response = await client.search({
    index: ELASTIC_INDEX,
    size: 0,
    query: { range: buildTimeRange(query) },
    aggs: {
      known_ports: {
        filters: { filters: allPortFilters },
        aggs: {
          ...metrics,
          protocols: { terms: { field: F_PROTO, size: 16 } }
        }
      },
      incoming: { filters: { filters: incomingFilters }, aggs: metrics },
      outgoing: { filters: { filters: outgoingFilters }, aggs: metrics }
    }
  });

  const buckets = response.aggregations?.known_ports?.buckets || {};
  const incomingBuckets = response.aggregations?.incoming?.buckets || {};
  const outgoingBuckets = response.aggregations?.outgoing?.buckets || {};
  const ranked = ports.map((port) => {
    const key = String(port.port);
    const bucket = buckets[key] || {};
    const incoming = incomingBuckets[key] || {};
    const outgoing = outgoingBuckets[key] || {};
    return {
      ...port,
      flows: bucket.doc_count || 0,
      bytes: Math.round(bucket.bytes?.value || 0),
      packets: Math.round(bucket.packets?.value || 0),
      protocols: (bucket.protocols?.buckets || []).map((item) => protocolName(item.key)),
      incoming: {
        flows: incoming.doc_count || 0,
        bytes: Math.round(incoming.bytes?.value || 0),
        packets: Math.round(incoming.packets?.value || 0)
      },
      outgoing: {
        flows: outgoing.doc_count || 0,
        bytes: Math.round(outgoing.bytes?.value || 0),
        packets: Math.round(outgoing.packets?.value || 0)
      }
    };
  }).filter((port) => port.flows > 0)
    .sort((a, b) => b.flows - a.flows || b.bytes - a.bytes || a.port - b.port);

  return {
    server: { id: server.id, name: server.name, ips: server.ips },
    totalKnownPorts: ports.length,
    portsWithTraffic: ranked.length,
    ranking: 'netflow-doc-count',
    ports: ranked.slice(0, limit)
  };
}

const BANDWIDTH_PERIODS = {
  '1h': { minutes: 60, interval: '1m', seconds: 60 },
  '6h': { minutes: 360, interval: '5m', seconds: 300 },
  '24h': { minutes: 1440, interval: '15m', seconds: 900 },
  '7d': { days: 7 },
  '30d': { days: 30 }
};

function summarizeBandwidth(rows, intervalSeconds) {
  const buckets = rows.map((row) => {
    const bytes = Math.round(Number(row.bytes) || 0);
    const packets = Math.round(Number(row.packets) || 0);
    const flows = Math.round(Number(row.flows) || 0);
    return {
      time: row.time,
      bytes,
      packets,
      flows,
      bitsPerSecond: Math.round((bytes * 8) / intervalSeconds)
    };
  });
  const rates = buckets.map((bucket) => bucket.bitsPerSecond).sort((a, b) => a - b);
  const totalBytes = buckets.reduce((sum, bucket) => sum + bucket.bytes, 0);
  const totalFlows = buckets.reduce((sum, bucket) => sum + bucket.flows, 0);
  const average = rates.length ? rates.reduce((sum, value) => sum + value, 0) / rates.length : 0;
  const p95 = rates.length ? rates[Math.max(0, Math.ceil(rates.length * 0.95) - 1)] : 0;
  return {
    buckets,
    summary: {
      totalBytes,
      totalFlows,
      averageBitsPerSecond: Math.round(average),
      peakBitsPerSecond: rates[rates.length - 1] || 0,
      p95BitsPerSecond: p95
    }
  };
}

function applicationTrafficFilter(application, serverIps) {
  const clauses = [];
  for (const listener of application.listeners || []) {
    const ip = listener.ip;
    const protocol = listener.protocol === 'TCP' ? 6 : 17;
    clauses.push({ bool: { filter: [
      { term: { [F_DST]: ip } },
      { term: { [F_DPORT]: listener.port } },
      { term: { [F_PROTO]: protocol } }
    ] } });
    clauses.push({ bool: { filter: [
      { term: { [F_SRC]: ip } },
      { term: { [F_SPORT]: listener.port } },
      { term: { [F_PROTO]: protocol } }
    ] } });
  }
  return either(clauses);
}

async function bandwidthForServer(serverId, period = '1h', groupBy = 'server') {
  const settings = BANDWIDTH_PERIODS[period];
  if (!settings) throw Object.assign(new Error('Período deve ser 1h, 6h, 24h, 7d ou 30d.'), { status: 400 });
  if (!['server', 'subnet', 'application', 'exporter'].includes(groupBy)) {
    throw Object.assign(new Error('Agrupamento deve ser server, subnet, application ou exporter.'), { status: 400 });
  }
  if (settings.days && ['application', 'exporter'].includes(groupBy)) {
    throw Object.assign(new Error('O histórico diário guarda pares IP, não listeners ou exporters; use o agrupamento server ou subnet.'), { status: 400 });
  }
  const servers = await listInventory();
  const server = servers.find((item) => item.id === Number(serverId));
  if (!server) throw Object.assign(new Error('Máquina não encontrada no inventário'), { status: 404 });
  const serverIps = server.ips.map((item) => item.ip);
  const serverInfo = { id: server.id, name: server.name, ips: server.ips };
  const groupDefs = [];

  if (groupBy === 'server' && serverIps.length) {
    groupDefs.push({ key: String(server.id), label: server.name, ips: serverIps });
  } else if (groupBy === 'application') {
    for (const application of server.applications) {
      groupDefs.push({
        key: String(application.id),
        label: application.name,
        filter: applicationTrafficFilter(application, serverIps)
      });
    }
  } else if (groupBy === 'subnet') {
    const watched = await listSubnets();
    const matching = watched.filter((subnet) => serverIps.some((ip) => cidrContains(subnet.cidr, ip)));
    for (const subnet of matching) {
      const ips = servers.flatMap((item) => item.ips.map((address) => address.ip))
        .filter((ip) => cidrContains(subnet.cidr, ip));
      groupDefs.push({ key: subnet.cidr, label: subnet.name || subnet.cidr, ips });
    }
  }

  const summarizeGroups = (series, intervalSeconds) => {
    let seriesWithStats = series.map((item) => ({ ...item, ...summarizeBandwidth(item.rows, intervalSeconds) }));
    if (groupBy !== 'server') {
      seriesWithStats = seriesWithStats.filter((item) => item.summary.totalFlows > 0)
        .sort((a, b) => b.summary.totalBytes - a.summary.totalBytes)
        .slice(0, 5);
    }
    const byTime = new Map();
    for (const item of seriesWithStats) for (const bucket of item.buckets) {
      const current = byTime.get(bucket.time) || { time: bucket.time, bytes: 0, packets: 0, flows: 0 };
      current.bytes += bucket.bytes;
      current.packets += bucket.packets;
      current.flows += bucket.flows;
      byTime.set(bucket.time, current);
    }
    const combined = summarizeBandwidth([...byTime.values()].sort((a, b) => a.time.localeCompare(b.time)), intervalSeconds);
    return {
      series: seriesWithStats.map(({ key, label, buckets, summary }) => ({ key, label, buckets, summary })),
      summary: combined.summary
    };
  };

  let source = 'elasticsearch';
  let series = [];
  if (settings.days) {
    source = 'pair_daily';
    for (const group of groupDefs) {
      const { rows } = await pool.query(
        `select days.day::date::text as time,
                coalesce(sum(pair.bytes), 0)::bigint as bytes,
                coalesce(sum(pair.packets), 0)::bigint as packets,
                coalesce(sum(pair.flows), 0)::bigint as flows
         from generate_series(current_date - $1::int, current_date - interval '1 day', interval '1 day') as days(day)
         left join pair_daily pair on pair.day = days.day::date
           and (pair.src = any($2::text[]) or pair.dst = any($2::text[]))
         group by days.day order by days.day`,
        [settings.days, group.ips]
      );
      series.push({ key: group.key, label: group.label, rows });
    }
  } else if (groupBy === 'exporter' && serverIps.length) {
    const response = await client.search({
      index: ELASTIC_INDEX,
      size: 0,
      query: { bool: { filter: [
        { range: buildTimeRange({ minutes: settings.minutes }) },
        either([
          { terms: { [F_SRC]: serverIps } },
          { terms: { [F_DST]: serverIps } }
        ])
      ] } },
      aggs: {
        exporters: {
          terms: { field: 'host.ip.keyword', size: 5, order: { total_bytes: 'desc' } },
          aggs: {
            total_bytes: { sum: { field: F_OCTETS } },
            over_time: {
              date_histogram: {
                field: '@timestamp', fixed_interval: settings.interval, min_doc_count: 0,
                extended_bounds: { min: `now-${settings.minutes}m`, max: 'now' }
              },
              aggs: { bytes: { sum: { field: F_OCTETS } }, packets: { sum: { field: F_PACKETS } } }
            }
          }
        }
      }
    });
    series = (response.aggregations?.exporters?.buckets || []).map((bucket) => ({
      key: String(bucket.key), label: String(bucket.key),
      rows: (bucket.over_time?.buckets || []).map((point) => ({
        time: point.key_as_string || new Date(point.key).toISOString(),
        bytes: point.bytes?.value || 0, packets: point.packets?.value || 0, flows: point.doc_count || 0
      }))
    }));
  } else if (groupDefs.length) {
    const filters = Object.fromEntries(groupDefs.map((group) => [
      group.key,
      group.filter || either([
        { terms: { [F_SRC]: group.ips } },
        { terms: { [F_DST]: group.ips } }
      ])
    ]));
    const response = await client.search({
      index: ELASTIC_INDEX,
      size: 0,
      query: { range: buildTimeRange({ minutes: settings.minutes }) },
      aggs: {
        groups: {
          filters: { filters },
          aggs: {
            over_time: {
              date_histogram: {
                field: '@timestamp', fixed_interval: settings.interval, min_doc_count: 0,
                extended_bounds: { min: `now-${settings.minutes}m`, max: 'now' }
              },
              aggs: { bytes: { sum: { field: F_OCTETS } }, packets: { sum: { field: F_PACKETS } } }
            }
          }
        }
      }
    });
    const buckets = response.aggregations?.groups?.buckets || {};
    series = groupDefs.map((group) => ({
      key: group.key,
      label: group.label,
      rows: (buckets[group.key]?.over_time?.buckets || []).map((point) => ({
        time: point.key_as_string || new Date(point.key).toISOString(),
        bytes: point.bytes?.value || 0, packets: point.packets?.value || 0, flows: point.doc_count || 0
      }))
    }));
  }

  const intervalSeconds = settings.seconds || 86400;
  const summarized = summarizeGroups(series, intervalSeconds);
  return {
    server: serverInfo,
    period,
    groupBy,
    source,
    ...summarized
  };
}

const CRITICAL_SERVICE_PORTS = [22, 445, 1433, 3389, 5985];

function isoField(aggregation) {
  if (aggregation?.value_as_string) return aggregation.value_as_string;
  return aggregation?.value != null ? new Date(aggregation.value).toISOString() : null;
}

async function criticalServiceAccess(days = 30, { maxClients = 1000, maxPages = 50 } = {}) {
  if (![30, 90, 365].includes(Number(days))) {
    throw Object.assign(new Error('Período deve ser 30, 90 ou 365 dias.'), { status: 400 });
  }
  const historyDays = Number(days);
  const todayUtc = new Date().toISOString().slice(0, 10);
  const windowStartDate = new Date(`${todayUtc}T00:00:00.000Z`);
  windowStartDate.setUTCDate(windowStartDate.getUTCDate() - (historyDays - 1));
  const windowStartDay = windowStartDate.toISOString().slice(0, 10);
  const todayStart = `${todayUtc}T00:00:00.000Z`;
  const servers = await listInventory();
  const serverByIp = new Map();
  const applicationsByEndpoint = new Map();
  for (const server of servers) {
    for (const address of server.ips) serverByIp.set(address.ip, server.name);
    for (const application of server.applications) for (const listener of application.listeners) {
      const key = `${listener.ip}|${listener.protocol === 'TCP' ? 6 : 17}|${listener.port}`;
      const apps = applicationsByEndpoint.get(key) || [];
      apps.push({ name: application.name, expectedClients: application.expectedClients || [] });
      applicationsByEndpoint.set(key, apps);
    }
  }
  const serverIps = [...serverByIp.keys()];
  if (!serverIps.length) return { days: historyDays, criticalPorts: CRITICAL_SERVICE_PORTS, inventoryIps: 0, truncated: false, clients: [] };

  const { rows: dailyRows } = await pool.query(
    `select src, dst, proto, dport,
            min(day)::text as first_day, max(day)::text as last_day,
            coalesce(sum(bytes) filter (where day >= $3::date and day < $4::date), 0)::bigint as period_bytes,
            coalesce(sum(flows) filter (where day >= $3::date and day < $4::date), 0)::bigint as period_flows
       from pair_daily
      where dst = any($1::text[]) and dport = any($2::int[])
      group by src, dst, proto, dport
     having max(day) >= $3::date`,
    [serverIps, CRITICAL_SERVICE_PORTS, windowStartDay, todayUtc]
  );
  const clientsByKey = new Map();
  const makeKey = (src, dst, proto, port) => `${src}|${dst}|${proto}|${port}`;
  for (const row of dailyRows) {
    clientsByKey.set(makeKey(row.src, row.dst, row.proto, row.dport), {
      source: row.src,
      target: row.dst,
      protocol: Number(row.proto),
      port: Number(row.dport),
      firstSeen: row.first_day,
      lastSeen: row.last_day,
      periodBytes: Number(row.period_bytes) || 0,
      periodFlows: Number(row.period_flows) || 0
    });
  }

  let after = null;
  let pages = 0;
  let truncated = false;
  do {
    const composite = {
      size: 2000,
      sources: [
        { src: { terms: { field: F_SRC } } },
        { dst: { terms: { field: F_DST } } },
        { proto: { terms: { field: F_PROTO } } },
        { dport: { terms: { field: F_DPORT } } }
      ]
    };
    if (after) composite.after = after;
    const response = await client.search({
      index: ELASTIC_INDEX,
      size: 0,
      query: { bool: { filter: [
        { range: buildTimeRange({ from: todayStart }) },
        { terms: { [F_DST]: serverIps } },
        { terms: { [F_DPORT]: CRITICAL_SERVICE_PORTS } },
        { term: { [F_PROTO]: 6 } }
      ] } },
      aggs: {
        critical_pairs: {
          composite,
          aggs: {
            bytes: { sum: { field: F_OCTETS } },
            flowsStart: { min: { field: F_FSTART } },
            flowsEnd: { max: { field: F_FEND } }
          }
        }
      }
    });
    const page = response.aggregations?.critical_pairs?.buckets || [];
    for (const bucket of page) {
      const source = String(bucket.key.src);
      const target = String(bucket.key.dst);
      const protocol = Number(bucket.key.proto);
      const port = Number(bucket.key.dport);
      const key = makeKey(source, target, protocol, port);
      const current = clientsByKey.get(key) || {
        source, target, protocol, port, firstSeen: null, lastSeen: null, periodBytes: 0, periodFlows: 0
      };
      const firstSeen = isoField(bucket.flowsStart);
      const lastSeen = isoField(bucket.flowsEnd);
      if (firstSeen && (!current.firstSeen || firstSeen.slice(0, 10) < current.firstSeen.slice(0, 10))) current.firstSeen = firstSeen;
      if (lastSeen && (!current.lastSeen || lastSeen > current.lastSeen)) current.lastSeen = lastSeen;
      current.periodBytes += Math.round(bucket.bytes?.value || 0);
      current.periodFlows += bucket.doc_count || 0;
      clientsByKey.set(key, current);
    }
    after = response.aggregations?.critical_pairs?.after_key || null;
    pages += 1;
    if (after && pages >= maxPages) truncated = true;
  } while (after && pages < maxPages);

  const cutoffDay = windowStartDay;
  const clients = [...clientsByKey.values()].filter((item) => item.periodFlows > 0).map((item) => {
    const endpointKey = `${item.target}|${item.protocol}|${item.port}`;
    const apps = applicationsByEndpoint.get(endpointKey) || [];
    const expectedClients = [...new Set(apps.flatMap((app) => app.expectedClients.map((client) => client.ip)))];
    const baselineConfigured = expectedClients.length > 0;
    const applicationNames = [...new Set(apps.map((app) => app.name))];
    return {
      source: item.source,
      sourceName: serverByIp.get(item.source) || item.source,
      target: item.target,
      targetName: serverByIp.get(item.target) || item.target,
      protocol: protocolName(item.protocol),
      port: item.port,
      service: portName(item.port) || `Porta ${item.port}`,
      applications: applicationNames,
      expectedStatus: !baselineConfigured ? 'unconfigured' : expectedClients.includes(item.source) ? 'expected' : 'unexpected',
      baselineConfigured,
      isNew: Boolean(item.firstSeen && item.firstSeen.slice(0, 10) >= cutoffDay),
      firstSeen: item.firstSeen,
      lastSeen: item.lastSeen,
      flows: item.periodFlows,
      bytes: Math.round(item.periodBytes)
    };
  }).sort((a, b) => Number(b.isNew) - Number(a.isNew)
    || Number(b.expectedStatus === 'unexpected') - Number(a.expectedStatus === 'unexpected')
    || b.bytes - a.bytes)
    .slice(0, maxClients);

  return { days: historyDays, windowStart: windowStartDay, criticalPorts: CRITICAL_SERVICE_PORTS, inventoryIps: serverIps.length, truncated, clients };
}

module.exports = { topApplications, topKnownPorts, bandwidthForServer, criticalServiceAccess };
