// Atalhos do filtro de bytes mínimos (o slider é logarítmico: com uma aresta
// de GB, a escala linear não deixava escolher nada abaixo de alguns MB).
const BYTE_PRESETS = [
  { label: 'Todos', value: 0 },
  { label: '1 KB', value: 1024 },
  { label: '100 KB', value: 100 * 1024 },
  { label: '1 MB', value: 1024 ** 2 },
  { label: '10 MB', value: 10 * 1024 ** 2 },
  { label: '100 MB', value: 100 * 1024 ** 2 },
  { label: '1 GB', value: 1024 ** 3 }
];
const FLOW_PRESETS = [1, 2, 5, 10, 50, 100, 1000];
const TRAFFIC_OPTIONS = [
  { value: 'all', label: 'Todo o tráfego' },
  { value: 'internal', label: 'Interno ↔ interno' },
  { value: 'external', label: 'Interno ↔ externo' },
  { value: 'inbound', label: 'Entrada (externo → interno)' },
  { value: 'outbound', label: 'Saída (interno → externo)' }
];
const SLIDER_STEPS = 1000;

function Card({ id, title, badge, collapsed, onToggle, children }) {
  return (
    <section className={`card map-card${collapsed ? ' collapsed' : ''}`}>
      <button type="button" className="map-card-head" onClick={() => onToggle(id)} aria-expanded={!collapsed}>
        <span className="map-card-caret" aria-hidden="true">{collapsed ? '▸' : '▾'}</span>
        <h3>{title}</h3>
        {badge != null && <span className="map-card-badge">{badge}</span>}
      </button>
      {!collapsed && <div className="map-card-body">{children}</div>}
    </section>
  );
}

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
  timeAgo, repDot, maxEdgeBytes, edgeLimit, changeEdgeLimit, useWebgl,
  changeWebgl, layoutNote, loading,
  portFilter, setPortFilter, portOptions, trafficFilter, setTrafficFilter,
  minFlows, setMinFlows, highlightRisk, setHighlightRisk, riskCount,
  legendOpen, setLegendOpen, collapsedCards, toggleCard, mapNotice, setMapNotice,
  mapZoom, mapFit, mapCenterSelected, mapExportPng
}) {
  const meta = graph.meta || {};
  const num = (v) => Number(v || 0).toLocaleString('pt-BR');
  const cards = collapsedCards || {};

  // Slider logarítmico de bytes mínimos
  const logMax = Math.log10(Math.max(1024, maxEdgeBytes || 0) + 1);
  const sliderValue = minBytes > 0 ? Math.min(SLIDER_STEPS, Math.round((Math.log10(minBytes + 1) / logMax) * SLIDER_STEPS)) : 0;
  const fromSlider = (v) => (v <= 0 ? 0 : Math.round(10 ** ((v / SLIDER_STEPS) * logMax)));

  const activeFilters = [
    protoFilter !== 'ALL', portFilter !== '', trafficFilter !== 'all', minFlows > 1, minBytes > 0
  ].filter(Boolean).length;
  function clearFilters() {
    setProtoFilter('ALL'); setPortFilter(''); setTrafficFilter('all'); setMinFlows(1); setMinBytes(0);
  }

  return (
    <>
      <aside className="sidebar">
        <Card id="view" title="Visão" collapsed={cards.view} onToggle={toggleCard}>
          <div className="seg">
            <button className={view === 'hosts' ? 'active' : ''} onClick={() => { setView('hosts'); setFocusSubnet(null); setFocusHost(null); }}>Hosts</button>
            <button className={view === 'subnets' ? 'active' : ''} onClick={() => { setView('subnets'); setFocusSubnet(null); setFocusHost(null); setSelected(null); setHostDetail(null); }}>Sub-redes /24</button>
          </div>
          {watchSubnets?.length > 0 && <label className="field"><span>Sub-rede monitorada</span><select value={focusSubnet || ''} onChange={(e) => { setFocusSubnet(e.target.value || null); setFocusHost(null); if (e.target.value) setView('hosts'); }}><option value="">Todas</option>{watchSubnets.map((s) => <option key={s.cidr} value={s.cidr}>{s.name ? `${s.name} (${s.cidr})` : s.cidr}{s.is_default ? ' ★' : ''}</option>)}</select></label>}
          {focusSubnet && <div className="focus"><span>Sub-rede <b>{focusSubnet}</b></span><button className="ghost" onClick={() => { setFocusSubnet(null); setView('subnets'); }}>ver tudo</button></div>}
          {focusHost && <div className="focus"><span>Host <b className="mono">{focusHost}</b></span><button className="ghost" onClick={() => setFocusHost(null)}>ver tudo</button></div>}
          <label className="chk"><input type="checkbox" checked={showNames} onChange={(e) => setShowNames(e.target.checked)} /> mostrar nomes do inventário</label>
          <label className="chk"><input type="checkbox" checked={highlightRisk} onChange={(e) => setHighlightRisk(e.target.checked)} /> destacar IPs com reputação ruim</label>
          {highlightRisk && <p className="hint">{riskCount ? `${num(riskCount)} IP(s) públicos com score ≥ 20 em destaque, com seus vizinhos.` : 'Nenhum IP com reputação ruim conhecida neste mapa (só contam IPs já verificados ou em cache).'}</p>}
          <div className="stats-row"><span className={`status-dot ${graph.nodes?.length ? 'ok' : ''}`} /><p className="stats" style={{ margin: 0 }}>{num(graph.nodes?.length)} hosts <small>· {num(graph.edges?.length)} conexões</small></p></div>
          {error && <p className="error">{error}</p>}
        </Card>

        <Card id="filters" title="Filtros" badge={activeFilters || null} collapsed={cards.filters} onToggle={toggleCard}>
          <label className="field"><span>Buscar IP</span>
            <div className="map-search">
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="172.20.20.28" onKeyDown={(e) => e.key === 'Enter' && focusSearch()} />
              <button onClick={focusSearch} className="ghost" disabled={!search.trim()}>Localizar</button>
            </div>
          </label>
          <p className="hint map-hint-tight">Se o IP não estiver desenhado, o mapa foca nele e busca só as conexões dele.</p>
          <label className="field"><span>Protocolo</span><select value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)}><option value="ALL">Todos</option>{protos.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
          <label className="field"><span>Serviço / porta</span>
            <select value={portFilter} onChange={(e) => setPortFilter(e.target.value)}>
              <option value="">Todos</option>
              {portOptions.map((p) => <option key={p.port} value={String(p.port)}>{p.service} · {p.port}</option>)}
            </select>
          </label>
          <label className="field"><span>Tráfego</span>
            <select value={trafficFilter} onChange={(e) => setTrafficFilter(e.target.value)}>
              {TRAFFIC_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </label>
          <label className="field"><span>Fluxos mínimos por conexão</span>
            <select value={minFlows} onChange={(e) => setMinFlows(Number(e.target.value))}>
              {FLOW_PRESETS.map((n) => <option key={n} value={n}>{n === 1 ? 'Qualquer' : `${num(n)}+`}</option>)}
            </select>
          </label>
          <div className="field"><span>Bytes mínimos <b>{minBytes ? fmtBytes(minBytes) : 'todos'}</b></span>
            <div className="map-presets">
              {BYTE_PRESETS.map((p) => (
                <button key={p.label} type="button" className={minBytes === p.value ? 'on' : ''} onClick={() => setMinBytes(p.value)} disabled={p.value > (maxEdgeBytes || 0) && p.value !== 0}>{p.label}</button>
              ))}
            </div>
            <input type="range" min="0" max={SLIDER_STEPS} value={sliderValue} onChange={(e) => setMinBytes(fromSlider(Number(e.target.value)))} aria-label="Bytes mínimos (escala logarítmica)" />
          </div>
          {activeFilters > 0 && <button type="button" className="map-link" onClick={clearFilters}>Limpar {activeFilters} filtro{activeFilters > 1 ? 's' : ''}</button>}
        </Card>

        <Card id="layout" title="Mapa" collapsed={cards.layout} onToggle={toggleCard}>
          <label className="field"><span>Layout</span><select value={layoutName} onChange={(e) => setLayoutName(e.target.value)}><option value="cose">Força (espalhado)</option><option value="concentric">Concêntrico (centraliza hubs)</option><option value="circle">Círculo</option><option value="grid">Grade</option></select></label>
          <label className="field"><span>Distância <b>{spacing}px</b></span><input type="range" min="120" max="1000" step="20" value={spacing} onChange={(e) => setSpacing(Number(e.target.value))} /></label>
          <label className="chk"><input type="checkbox" checked={showPorts} onChange={(e) => setShowPorts(e.target.checked)} /> mostrar portas nas linhas</label>
          <label className="chk"><input type="checkbox" checked={isolate} onChange={(e) => setIsolate(e.target.checked)} /> isolar vizinhos ao selecionar</label>
          {layoutNote && <p className="map-perf-note">{layoutNote}</p>}
          <p className="hint">Se ainda embolar: aumente a distância, use Concêntrico ou suba os filtros de bytes/fluxos.</p>
        </Card>

        <Card id="perf" title="Desempenho" badge={meta.limited ? 'top' : null} collapsed={cards.perf} onToggle={toggleCard}>
          <label className="field"><span>Conexões exibidas</span>
            <select value={edgeLimit} onChange={(e) => changeEdgeLimit(Number(e.target.value))} disabled={loading}>
              <option value={1000}>1.000 maiores</option>
              <option value={3000}>3.000 maiores</option>
              <option value={5000}>5.000 maiores</option>
              <option value={10000}>10.000 maiores</option>
              <option value={20000}>20.000 maiores</option>
              <option value={0}>Máximo permitido</option>
            </select>
          </label>
          {meta.limited && <p className="map-perf-note">Mostrando as {num(meta.edges)} conexões de maior volume de {num(meta.totalEdges)} ({num(meta.totalNodes)} hosts). Foque uma sub-rede ou host para ver o resto dentro dele.</p>}
          <label className="chk"><input type="checkbox" checked={useWebgl} onChange={(e) => changeWebgl(e.target.checked)} /> aceleração WebGL (experimental)</label>
          <p className="hint">Acima de {num(10000)} conexões a renderização WebGL costuma ser bem mais fluida. Se algo aparecer estranho, desligue.</p>
          {meta.queryMs != null && <p className="hint">Consulta: {num(meta.pairs)} pares em {(meta.queryMs / 1000).toFixed(1)}s{meta.cached ? ' · cache' : ''}</p>}
        </Card>
        <p className="hint map-shortcuts">Atalho: <kbd>Esc</kbd> limpa a seleção, depois o foco.</p>
      </aside>

      <main className="canvas-wrap">
        <div className="canvas" ref={cyRef} />
        {tip && <div className={`map-tip ${tip.flip ? 'flip' : ''}`} style={{ left: tip.x, top: tip.y }}><b>{tip.title}</b>{tip.badge && <span className="map-tip-badge">{tip.badge}</span>}{tip.rows.map(([k, v]) => <div className="map-tip-row" key={k}><span>{k}</span><i>{v}</i></div>)}</div>}
        <div className="canvas-status"><b>{view === 'subnets' && !focusSubnet ? 'Sub-redes' : 'Hosts'}</b><span className="sep">·</span><span>{num(graph.nodes?.length)} hosts · {num(graph.edges?.length)} fluxos</span>{meta.limited && <><span className="sep">·</span><span className="badge low" title="O backend devolve só as conexões de maior volume. Ajuste em Desempenho → Conexões exibidas.">top {num(meta.edges)} de {num(meta.totalEdges)}</span></>}{activeFilters > 0 && <><span className="sep">·</span><span className="badge med">{activeFilters} filtro{activeFilters > 1 ? 's' : ''}</span></>}{perfMode && <><span className="sep">·</span><span>modo desempenho</span></>}{loading && <><span className="sep">·</span><span>atualizando…</span></>}{meta.truncated && <><span className="sep">·</span><span className="badge med" title="A janela tem mais pares do que o teto MAP_MAX_PAIRS do backend; reduza o período ou eleve o teto.">resultado parcial</span></>}</div>

        <div className="map-toolbar" role="toolbar" aria-label="Controles do mapa">
          <button type="button" onClick={() => mapZoom(1.3)} title="Aproximar">+</button>
          <button type="button" onClick={() => mapZoom(1 / 1.3)} title="Afastar">−</button>
          <button type="button" onClick={mapFit} title="Enquadrar tudo">⤢</button>
          <button type="button" onClick={mapCenterSelected} disabled={!selected && !edgeInfo} title="Centralizar no selecionado">◎</button>
          <span className="map-toolbar-sep" />
          <button type="button" onClick={mapExportPng} title="Exportar o mapa como PNG">PNG</button>
        </div>

        <div className={`map-legend${legendOpen ? ' open' : ''}`}>
          <button type="button" className="map-legend-head" onClick={() => setLegendOpen(!legendOpen)} aria-expanded={legendOpen}>
            <span>Legenda</span><span aria-hidden="true">{legendOpen ? '▾' : '▴'}</span>
          </button>
          {legendOpen && (
            <div className="map-legend-body">
              <p className="legend-title">Nós — cor = reputação</p>
              <ul className="map-legend-list">
                <li><i style={{ background: NODE_COLORS.private }} /> Host interno</li>
                <li><i style={{ background: REP_COLORS.bad }} /> Score &gt; 70</li>
                <li><i style={{ background: REP_COLORS.orange }} /> Score 51–70</li>
                <li><i style={{ background: REP_COLORS.yellow }} /> Score 20–50</li>
                <li><i style={{ background: REP_COLORS.good }} /> Score &lt; 20</li>
                <li><i style={{ background: REP_COLORS.unknown }} /> Sem avaliação</li>
                <li><i className="hex" style={{ background: NODE_COLORS.subnet }} /> Sub-rede</li>
              </ul>
              <p className="legend-title">Linhas — cor = protocolo</p>
              <ul className="map-legend-list">
                <li><i className="line" style={{ background: '#3b82f6' }} /> TCP</li>
                <li><i className="line" style={{ background: '#22c55e' }} /> UDP</li>
                <li><i className="line" style={{ background: '#eab308' }} /> ICMP</li>
                <li><i className="line" style={{ background: '#94a3b8' }} /> Outros</li>
              </ul>
              <p className="map-legend-note">Tamanho do nó = bytes do host (log) · espessura = volume do par · IP público sublinhado · rótulo = serviço · fluxos ("retorno" = só portas efêmeras).</p>
            </div>
          )}
        </div>

        {!selected && !edgeInfo && !subnetEmpty && !mapNotice && <div className="canvas-tip">Clique num nó para detalhes · clique numa linha para ver portas · arraste para mover</div>}
        {subnetEmpty && <div className="canvas-alert"><span>Sub-rede <b>{subnetEmpty}</b> sem tráfego nesta janela — mostrando todas</span><button className="ghost" onClick={() => setFocusSubnet(null)}>ver todas</button></div>}
        {mapNotice && <div className={`canvas-alert${subnetEmpty ? ' second' : ''}`}><span>{mapNotice}</span><button className="ghost" onClick={() => setMapNotice('')}>ok</button></div>}
      </main>

      <aside className={`detail ${selected || edgeInfo ? 'open' : ''}`}>
        {edgeInfo && !selected && <div className="detail-inner">
          <div className="detail-head"><h2>Conexão</h2><div className="sub">{edgeInfo.source} <b>→</b> {edgeInfo.target}</div></div>
          <div className="kpis"><div><b>{fmtBytes(edgeInfo.bytes)}</b><span>bytes</span></div><div><b>{edgeInfo.packets ?? '-'}</b><span>pacotes</span></div><div><b>{edgeInfo.flows ?? 1}</b><span>fluxos</span></div></div>
          <div className="table-wrap"><table><tbody><tr><td>Protocolo</td><td>{edgeInfo.protocol ?? '-'}</td></tr><tr><td>Portas destino</td><td className="mono">{topPortsLabel(edgeInfo)}</td></tr>{((edgeInfo.srcPorts || []).length > 0 || edgeInfo.srcPort != null) && <tr><td>Portas origem</td><td className="mono">{portsShort(edgeInfo.srcPorts || [edgeInfo.srcPort])}</td></tr>}</tbody></table></div>
          <p className="hint">Clique no fundo (ou Esc) para fechar. Clique num IP p/ ver todas as conexões.</p>
        </div>}
        {!selected && !edgeInfo && <div className="detail-inner"><div className="empty">Clique em um IP para ver conexões, portas e tráfego.<br />Clique numa linha para ver as portas daquela conexão.</div></div>}
        {selected && !hostDetail && <div className="detail-inner"><p>Carregando…</p></div>}
        {hostDetail?.loading && <div className="detail-inner"><p>Carregando {hostDetail.ip}…</p></div>}
        {hostDetail && !hostDetail.loading && !hostDetail.error && <div className="detail-inner">
          <div className="detail-head"><h2>{inventoryNameForIp(hostDetail.ip)}</h2><div className="sub">{hostDetail.ip} · {num(hostDetail.peerCount ?? hostDetail.connections.length)} peers no período</div></div>
          <div className="map-detail-actions">
            {focusHost !== hostDetail.ip
              ? <button className="ghost" onClick={() => setFocusHost(hostDetail.ip)} title="Mostrar no mapa só este host e os vizinhos">Focar no mapa</button>
              : <button className="ghost" onClick={() => setFocusHost(null)}>Sair do foco</button>}
          </div>
          <InventoryContext key={hostDetail.ip} data={hostDetail.inventory} />
          {isPublicIp(hostDetail.ip) && <div className="rep-line"><button className="linklike" onClick={() => openIpModal(hostDetail.ip)} title="Abrir dossiê completo">Ver dossiê ⧉</button>{repMap[hostDetail.ip]?.abuse?.score != null ? <b style={{ color: repColorForScore(repMap[hostDetail.ip].abuse.score) }}>Score {repMap[hostDetail.ip].abuse.score}</b> : <button className="ghost" onClick={() => checkRep([hostDetail.ip])} disabled={repLoading}>{repLoading ? 'Verificando…' : 'Verificar reputação'}</button>}</div>}
          <div className="kpis"><div><b>{fmtBytes(hostDetail.totalOutBytes)}</b><span>saída</span></div><div><b>{fmtBytes(hostDetail.totalInBytes)}</b><span>entrada</span></div><div><b>{num(hostDetail.totalOutPackets + hostDetail.totalInPackets)}</b><span>pacotes</span></div></div>
          {hostDetail.truncated && <p className="map-perf-note">Este host tem pares demais na janela para listar todos: alguns peers pequenos podem faltar na lista. Os totais acima são exatos.</p>}
          <h3 style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--mut)' }}>Conexões ({hostDetail.peerCount > hostDetail.connections.length ? `${num(hostDetail.connections.length)} maiores de ${num(hostDetail.peerCount)}` : num(hostDetail.connections.length)})</h3>
          <div className="table-wrap"><table><thead><tr><th>Peer</th><th>Bytes</th><th>Estado</th><th>Proto</th></tr></thead><tbody>{hostDetail.connections.map((c) => {
            const d = dirArrow(c);
            const pairLines = (list) => list?.length ? list.map((x, j) => <div className="pline" key={j}><span>{x.sport ?? '?'}→{x.dport ?? '?'}</span><span className="dim">{fmtBytes(x.bytes)}</span></div>) : <div className="dim">-</div>;
            return [
              <tr key={c.ip} className="peer-row"><td className="mono"><span className="dir" title={d.t} style={{ color: d.color }}>{d.s}</span> {isPublicIp(c.ip) ? <span className="ip-link" title="Ver dossiê" onClick={() => openIpModal(c.ip)}>{c.ip}</span> : c.ip}{isPublicIp(c.ip) && repDot(c.ip)}</td><td>{fmtBytes(c.bytes)}</td><td title={`desde ${fmtTime(c.firstSeen)} · último pacote ${fmtTime(c.lastSeen)} (na janela)`}><span className={`pill ${c.active ? 'on' : ''}`}>{c.active ? '🟢' : '⚪'} {timeAgo(c.lastSeen)}</span></td><td><span className="proto-chip">{c.protocols.join(', ') || '-'}</span></td></tr>,
              <tr key={`${c.ip}-ports`} className="subrow"><td colSpan={4}><div className="flows2"><div><b className="flow-h out">HOST → PEER</b><div className="mono">{pairLines(c.outTop)}</div></div><div><b className="flow-h in">PEER → HOST</b><div className="mono">{pairLines(c.inTop)}</div></div></div></td></tr>
            ];
          })}</tbody></table></div>
          <div className="tlegend"><span><b style={{ color: 'var(--acc)' }}>↑</b> saiu deste host</span><span><b style={{ color: 'var(--ok)' }}>↓</b> entrou</span><span><b style={{ color: 'var(--vio)' }}>⇄</b> ambos</span><span>🟢 pacote recente</span><span>⚪ ocioso</span></div>
        </div>}
        {hostDetail?.error && <div className="detail-inner"><p className="error">{hostDetail.error}</p></div>}
      </aside>
    </>
  );
}
