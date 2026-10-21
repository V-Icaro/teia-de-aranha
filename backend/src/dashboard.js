// Métricas por aplicação cadastrada: um fluxo conta quando seu IP/porta/protocolo
// coincide com um listener em qualquer uma das interfaces da máquina.
const { searchElastic, ELASTIC_INDEX, F_SRC, F_DST, F_PROTO, F_SPORT, F_DPORT, F_FSTART, F_FEND, buildTimeRange, knownServicePorts, protocolName, portName } = require('./elastic.js');
const { listInventory } = require('./db.js');

const F_OCTETS = 'netflow.octetDeltaCount';
const F_PACKETS = 'netflow.packetDeltaCount';
const MAX_APPLICATION_PEERS = 10000;

function either(clauses) {
  return clauses.length
    ? { bool: { should: clauses, minimum_should_match: 1 } }
    : { match_none: {} };
}

// Janela + restrição de topo. Antes a query era só o range de tempo e os
// filtros ficavam nas agregações: o ES avaliava dezenas (aplicações) ou
// centenas (portas conhecidas) de filtros em CADA fluxo da janela, inclusive
// os que não têm nada a ver com a máquina. Com o filtro no topo, ele usa o
// índice para pegar só os fluxos da máquina e as agregações rodam sobre eles.
function scopedQuery(query, scope) {
  return { bool: { filter: [{ range: buildTimeRange(query) }, scope] } };
}

async function topApplications(serverId, query) {
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
  const allClauses = [];
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
    allClauses.push(...incoming, ...outgoing);
  }

  const response = await searchElastic({
    index: ELASTIC_INDEX,
    size: 0,
    query: scopedQuery(query, either(allClauses)),
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
    applications
  };
}

async function applicationConnections(serverId, applicationId, query) {
  const servers = await listInventory();
  const server = servers.find((item) => item.id === Number(serverId));
  if (!server) throw Object.assign(new Error('Máquina não encontrada no inventário'), { status: 404 });
  const application = server.applications.find((item) => item.id === Number(applicationId));
  if (!application) throw Object.assign(new Error('Aplicação não encontrada nesta máquina'), { status: 404 });

  const incomingMatches = [];
  const outgoingMatches = [];
  for (const listener of application.listeners || []) {
    const protocol = listener.protocol === 'TCP' ? 6 : 17;
    incomingMatches.push({ bool: { filter: [
      { term: { [F_DST]: listener.ip } },
      { term: { [F_DPORT]: listener.port } },
      { term: { [F_PROTO]: protocol } }
    ] } });
    outgoingMatches.push({ bool: { filter: [
      { term: { [F_SRC]: listener.ip } },
      { term: { [F_SPORT]: listener.port } },
      { term: { [F_PROTO]: protocol } }
    ] } });
  }

  if (!incomingMatches.length) {
    return { application: { id: application.id, name: application.name }, connections: [], truncated: false };
  }

  const peerMetrics = {
    bytes: { sum: { field: F_OCTETS } },
    packets: { sum: { field: F_PACKETS } },
    protocols: { terms: { field: F_PROTO, size: 8 } },
    firstSeen: { min: { field: F_FSTART } },
    lastSeen: { max: { field: F_FEND } }
  };
  const response = await searchElastic({
    index: ELASTIC_INDEX,
    size: 0,
    query: scopedQuery(query, either([...incomingMatches, ...outgoingMatches])),
    aggs: {
      incoming: {
        filter: either(incomingMatches),
        aggs: { peers: { terms: { field: F_SRC, size: MAX_APPLICATION_PEERS, order: { _key: 'asc' } }, aggs: peerMetrics } }
      },
      outgoing: {
        filter: either(outgoingMatches),
        aggs: { peers: { terms: { field: F_DST, size: MAX_APPLICATION_PEERS, order: { _key: 'asc' } }, aggs: peerMetrics } }
      }
    }
  });

  const peers = new Map();
  const timestamp = (value) => value?.value_as_string
    || (value?.value != null ? new Date(value.value).toISOString() : null);
  for (const [side, direction] of [['incoming', 'entrada'], ['outgoing', 'saída']]) {
    const aggregation = response.aggregations?.[side]?.peers || {};
    for (const bucket of aggregation.buckets || []) {
      const ip = String(bucket.key);
      const peer = peers.get(ip) || { ip, flows: 0, packets: 0, bytes: 0, directions: new Set(), protocols: new Set(), firstSeen: null, lastSeen: null };
      peer.flows += bucket.doc_count || 0;
      peer.packets += Math.round(bucket.packets?.value || 0);
      peer.bytes += Math.round(bucket.bytes?.value || 0);
      peer.directions.add(direction);
      for (const protocol of bucket.protocols?.buckets || []) peer.protocols.add(protocolName(protocol.key));
      const firstSeen = timestamp(bucket.firstSeen);
      const lastSeen = timestamp(bucket.lastSeen);
      if (firstSeen && (!peer.firstSeen || firstSeen < peer.firstSeen)) peer.firstSeen = firstSeen;
      if (lastSeen && (!peer.lastSeen || lastSeen > peer.lastSeen)) peer.lastSeen = lastSeen;
      peers.set(ip, peer);
    }
  }
  const connections = [...peers.values()].map((peer) => ({
    ...peer,
    directions: [...peer.directions],
    direction: peer.directions.size > 1 ? 'bidirecional' : peer.directions.values().next().value,
    protocols: [...peer.protocols].sort()
  })).sort((a, b) => b.flows - a.flows || b.bytes - a.bytes || a.ip.localeCompare(b.ip));
  const truncated = Boolean(response.aggregations?.incoming?.peers?.sum_other_doc_count
    || response.aggregations?.outgoing?.peers?.sum_other_doc_count);

  return {
    application: { id: application.id, name: application.name },
    connections,
    truncated
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
  const response = await searchElastic({
    index: ELASTIC_INDEX,
    size: 0,
    // Só fluxos da máquina: os ~100 filtros de porta deixam de rodar na janela inteira.
    query: scopedQuery(query, either([{ terms: { [F_DST]: ips } }, { terms: { [F_SRC]: ips } }])),
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

module.exports = { topApplications, applicationConnections, topKnownPorts };
