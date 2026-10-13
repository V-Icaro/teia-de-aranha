export default function MapScreen({
  view, setView, focusSubnet, setFocusSubnet, focusHost, setFocusHost,
  selected, setSelected, setEdgeInfo, setHostDetail, watchSubnets,
  showNames, setShowNames, search, setSearch, focusSearch, protoFilter,
  setProtoFilter, protos, minBytes, setMinBytes, graph, layoutName,
  setLayoutName, spacing, setSpacing, showPorts, setShowPorts, isolate,
  setIsolate, NODE_COLORS, REP_COLORS, error, InventoryContext, cyRef,
  tip, perfMode, edgeInfo, subnetEmpty, topPortsLabel, portsShort,
  hostDetail, inventoryNameForIp, isPublicIp, openIpModal, repMap,
  repColorForScore, checkRep, repLoading, fmtBytes, dirArrow, fmtTime,
  timeAgo, repDot
}) {
  return (
    <>
      <aside className="sidebar">
        <section className="card">
          <h3>Visão</h3>
          <div className="seg">
            <button className={view === 'hosts' ? 'active' : ''} onClick={() => { setView('hosts'); setFocusSubnet(null); setFocusHost(null); }}>Hosts</button>
            <button className={view === 'subnets' ? 'active' : ''} onClick={() => { setView('subnets'); setFocusSubnet(null); setFocusHost(null); setSelected(null); setHostDetail(null); }}>Sub-redes /24</button>
          </div>
          {watchSubnets?.length > 0 && <label className="field"><span>Sub-rede monitorada</span><select value={focusSubnet || ''} onChange={(e) => { setFocusSubnet(e.target.value || null); setFocusHost(null); if (e.target.value) setView('hosts'); }}><option value="">Todas</option>{watchSubnets.map((s) => <option key={s.cidr} value={s.cidr}>{s.name ? `${s.name} (${s.cidr})` : s.cidr}{s.is_default ? ' ★' : ''}</option>)}</select></label>}
          <label className="chk"><input type="checkbox" checked={showNames} onChange={(e) => setShowNames(e.target.checked)} /> mostrar nomes do inventário</label>
          {focusSubnet && <div className="focus"><span>Sub-rede <b>{focusSubnet}</b></span><button className="ghost" onClick={() => { setFocusSubnet(null); setView('subnets'); }}>ver tudo</button></div>}
          {focusHost && <div className="focus"><span>Host <b className="mono">{focusHost}</b></span><button className="ghost" onClick={() => setFocusHost(null)}>ver tudo</button></div>}
        </section>

        <section className="card">
          <h3>Filtros</h3>
          <label className="field"><span>Buscar IP</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="172.20.20.28" onKeyDown={(e) => e.key === 'Enter' && focusSearch()} /></label>
          <button onClick={focusSearch} className="ghost">Localizar</button>
          <label className="field"><span>Protocolo</span><select value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)}><option value="ALL">Todos</option>{protos.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
          <label className="field"><span>Bytes mínimos <b>{fmtBytes(minBytes)}</b></span><input type="range" min="0" max={Math.max(1000, ...graph.edges.map((e) => e.data.bytes || 0))} value={minBytes} onChange={(e) => setMinBytes(Number(e.target.value))} /></label>
        </section>

        <section className="card">
          <h3>Mapa</h3>
          <label className="field"><span>Layout</span><select value={layoutName} onChange={(e) => setLayoutName(e.target.value)}><option value="cose">Força (espalhado)</option><option value="concentric">Concêntrico (centraliza hubs)</option><option value="circle">Círculo</option><option value="grid">Grade</option></select></label>
          <label className="field"><span>Distância <b>{spacing}px</b></span><input type="range" min="120" max="1000" step="20" value={spacing} onChange={(e) => setSpacing(Number(e.target.value))} /></label>
          <label className="chk"><input type="checkbox" checked={showPorts} onChange={(e) => setShowPorts(e.target.checked)} /> mostrar portas nas linhas</label>
          <label className="chk"><input type="checkbox" checked={isolate} onChange={(e) => setIsolate(e.target.checked)} /> isolar vizinhos ao selecionar</label>
          <p className="hint">Se ainda embolar: aumente a distância, use Concêntrico ou suba o filtro de bytes mínimos.</p>
        </section>

        <section className="card">
          <h3>Legenda</h3>
          <div className="legend-panel">
            <div className="legend-group"><p className="legend-title">Nós — cor = reputação</p><ul className="legend">
              <li title="Host da sua rede"><i style={{ background: NODE_COLORS.private }} /> Host interno</li>
              <li title="AbuseIPDB score acima de 70"><i style={{ background: REP_COLORS.bad }} /> Público: score &gt; 70</li>
              <li title="AbuseIPDB score acima de 50 até 70"><i style={{ background: REP_COLORS.orange }} /> Score 51–70</li>
              <li title="AbuseIPDB score de 20 a 50"><i style={{ background: REP_COLORS.yellow }} /> Score 20–50</li>
              <li title="AbuseIPDB score abaixo de 20"><i style={{ background: REP_COLORS.good }} /> Score &lt; 20</li>
              <li title="Sem score disponível"><i style={{ background: REP_COLORS.unknown }} /> sem avaliação</li>
              <li title="Agregado de uma /24"><i className="hex" style={{ background: NODE_COLORS.subnet }} /> Sub-rede</li>
            </ul><p className="hint">IPs públicos aparecem sublinhados; selecione o nó para abrir o dossiê no painel.</p></div>
            <div className="legend-group"><p className="legend-title">Arestas — cor = protocolo</p><ul className="legend"><li><i className="line" style={{ background: '#3b82f6' }} /> TCP</li><li><i className="line" style={{ background: '#22c55e' }} /> UDP</li><li><i className="line" style={{ background: '#eab308' }} /> ICMP</li><li><i className="line" style={{ background: '#94a3b8' }} /> Outros</li></ul></div>
            <details className="howto"><summary>Como ler</summary><p><b>Tamanho do nó</b> = bytes que o host troca (escala log).<br /><b>Espessura da linha</b> = volume entre o par.<br /><b>Rótulo</b> = porta de serviço · nº de fluxos ("retorno" = só efêmeras).</p></details>
          </div>
          <div className="stats-row"><span className={`status-dot ${graph.nodes?.length ? 'ok' : ''}`} /><p className="stats" style={{ margin: 0 }}>{graph.nodes?.length || 0} hosts <small>· {graph.edges?.length || 0} conexões</small></p></div>
          {error && <p className="error">{error}</p>}
        </section>
      </aside>

      <main className="canvas-wrap">
        <div className="canvas" ref={cyRef} />
        {tip && <div className={`map-tip ${tip.flip ? 'flip' : ''}`} style={{ left: tip.x, top: tip.y }}><b>{tip.title}</b>{tip.badge && <span className="map-tip-badge">{tip.badge}</span>}{tip.rows.map(([k, v]) => <div className="map-tip-row" key={k}><span>{k}</span><i>{v}</i></div>)}</div>}
        <div className="canvas-status"><b>{view === 'subnets' && !focusSubnet ? 'Sub-redes' : 'Hosts'}</b><span className="sep">·</span><span>{graph.nodes?.length || 0} hosts · {graph.edges?.length || 0} fluxos</span>{perfMode && <><span className="sep">·</span><span>modo desempenho</span></>}{graph.meta?.truncated && <><span className="sep">·</span><span className="badge med" title="O limite de buckets foi atingido; reduza o período ou eleve MAX_EDGES.">resultado parcial</span></>}</div>
        {!selected && !edgeInfo && !subnetEmpty && <div className="canvas-tip">Clique num nó para detalhes · clique numa linha para ver portas · arraste para mover</div>}
        {subnetEmpty && <div className="canvas-alert"><span>Sub-rede <b>{subnetEmpty}</b> sem tráfego nesta janela — mostrando todas</span><button className="ghost" onClick={() => setFocusSubnet(null)}>ver todas</button></div>}
      </main>

      <aside className={`detail ${selected || edgeInfo ? 'open' : ''}`}>
        {edgeInfo && !selected && <div className="detail-inner">
          <div className="detail-head"><h2>Conexão</h2><div className="sub">{edgeInfo.source} <b>→</b> {edgeInfo.target}</div></div>
          <div className="kpis"><div><b>{fmtBytes(edgeInfo.bytes)}</b><span>bytes</span></div><div><b>{edgeInfo.packets ?? '-'}</b><span>pacotes</span></div><div><b>{edgeInfo.flows ?? 1}</b><span>fluxos</span></div></div>
          <div className="table-wrap"><table><tbody><tr><td>Protocolo</td><td>{edgeInfo.protocol ?? '-'}</td></tr><tr><td>Portas destino</td><td className="mono">{topPortsLabel(edgeInfo)}</td></tr>{((edgeInfo.srcPorts || []).length > 0 || edgeInfo.srcPort != null) && <tr><td>Portas origem</td><td className="mono">{portsShort(edgeInfo.srcPorts || [edgeInfo.srcPort])}</td></tr>}</tbody></table></div>
          <p className="hint">Clique no fundo para fechar. Clique num IP p/ ver todas as conexões.</p>
        </div>}
        {!selected && !edgeInfo && <div className="detail-inner"><div className="empty">Clique em um IP para ver conexões, portas e tráfego.<br />Clique numa linha para ver as portas daquela conexão.</div></div>}
        {selected && !hostDetail && <div className="detail-inner"><p>Carregando…</p></div>}
        {hostDetail?.loading && <div className="detail-inner"><p>Carregando {hostDetail.ip}…</p></div>}
        {hostDetail && !hostDetail.loading && !hostDetail.error && <div className="detail-inner">
          <div className="detail-head"><h2>{inventoryNameForIp(hostDetail.ip)}</h2><div className="sub">{hostDetail.ip} · {hostDetail.connections.length} conexões no período</div></div>
          <InventoryContext data={hostDetail.inventory} />
          {isPublicIp(hostDetail.ip) && <div className="rep-line"><button className="linklike" onClick={() => openIpModal(hostDetail.ip)} title="Abrir dossiê completo">Ver dossiê ⧉</button>{repMap[hostDetail.ip]?.abuse?.score != null ? <b style={{ color: repColorForScore(repMap[hostDetail.ip].abuse.score) }}>Score {repMap[hostDetail.ip].abuse.score}</b> : <button className="ghost" onClick={() => checkRep([hostDetail.ip])} disabled={repLoading}>{repLoading ? 'Verificando…' : 'Verificar reputação'}</button>}</div>}
          <div className="kpis"><div><b>{fmtBytes(hostDetail.totalOutBytes)}</b><span>saída</span></div><div><b>{fmtBytes(hostDetail.totalInBytes)}</b><span>entrada</span></div><div><b>{hostDetail.totalOutPackets + hostDetail.totalInPackets}</b><span>pacotes</span></div></div>
          {hostDetail.truncated && <p className="error">A consulta atingiu o limite de buckets; a lista de conexões pode estar incompleta. Reduza o período para detalhar este host.</p>}
          <h3 style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--mut)' }}>Conexões ({hostDetail.connections.length})</h3>
          <div className="table-wrap"><table><thead><tr><th>Peer</th><th>Bytes</th><th>Estado</th><th>Proto</th></tr></thead><tbody>{hostDetail.connections.map((c) => {
            const d = dirArrow(c);
            const pairLines = (list) => list?.length ? list.map((x, j) => <div className="pline" key={j}><span>{x.sport ?? '?'}→{x.dport ?? '?'}</span><span className="dim">{fmtBytes(x.bytes)}</span></div>) : <div className="dim">-</div>;
            return <>
              <tr key={c.ip} className="peer-row"><td className="mono"><span className="dir" title={d.t} style={{ color: d.color }}>{d.s}</span> {isPublicIp(c.ip) ? <span className="ip-link" title="Ver dossiê" onClick={() => openIpModal(c.ip)}>{c.ip}</span> : c.ip}{isPublicIp(c.ip) && repDot(c.ip)}</td><td>{fmtBytes(c.bytes)}</td><td title={`desde ${fmtTime(c.firstSeen)} · último pacote ${fmtTime(c.lastSeen)} (na janela)`}><span className={`pill ${c.active ? 'on' : ''}`}>{c.active ? '🟢' : '⚪'} {timeAgo(c.lastSeen)}</span></td><td><span className="proto-chip">{c.protocols.join(', ') || '-'}</span></td></tr>
              <tr key={`${c.ip}-ports`} className="subrow"><td colSpan={4}><div className="flows2"><div><b className="flow-h out">HOST → PEER</b><div className="mono">{pairLines(c.outTop)}</div></div><div><b className="flow-h in">PEER → HOST</b><div className="mono">{pairLines(c.inTop)}</div></div></div></td></tr>
            </>;
          })}</tbody></table></div>
          <div className="tlegend"><span><b style={{ color: 'var(--acc)' }}>↑</b> saiu deste host</span><span><b style={{ color: 'var(--ok)' }}>↓</b> entrou</span><span><b style={{ color: 'var(--vio)' }}>⇄</b> ambos</span><span>🟢 pacote recente</span><span>⚪ ocioso</span></div>
        </div>}
        {hostDetail?.error && <div className="detail-inner"><p className="error">{hostDetail.error}</p></div>}
      </aside>
    </>
  );
}
