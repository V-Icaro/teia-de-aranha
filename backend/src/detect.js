// Ranking de maiores falantes (top talkers) por bytes totais na janela.
const TOP_N = parseInt(process.env.ALERT_TOP_N || '10', 10);

function bytesOf(b) { return b.bytes?.value || 0; }
function pktsOf(b) { return b.pacotes?.value || 0; }

// bytes por IP (entrada/saída)
function summarize(buckets) {
  const map = {};
  for (const b of buckets) {
    const src = String(b.key.origem);
    const dst = String(b.key.destino);
    const bytes = bytesOf(b);
    const pkts = pktsOf(b);
    map[src] = map[src] || { ip: src, inBytes: 0, outBytes: 0, inPackets: 0, outPackets: 0, peers: new Set() };
    map[dst] = map[dst] || { ip: dst, inBytes: 0, outBytes: 0, inPackets: 0, outPackets: 0, peers: new Set() };
    map[src].outBytes += bytes; map[src].outPackets += pkts; map[src].peers.add(dst);
    map[dst].inBytes += bytes; map[dst].inPackets += pkts; map[dst].peers.add(src);
  }
  return Object.values(map).map((m) => ({
    ...m,
    totalBytes: Math.round(m.inBytes + m.outBytes),
    inBytes: Math.round(m.inBytes),
    outBytes: Math.round(m.outBytes),
    peerCount: m.peers.size,
    peers: undefined
  }));
}

function topTalkers(buckets, n = TOP_N) {
  return summarize(buckets).sort((a, b) => b.totalBytes - a.totalBytes).slice(0, n);
}

module.exports = { TOP_N, summarize, topTalkers };
