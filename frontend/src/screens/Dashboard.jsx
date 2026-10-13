export default function DashboardScreen({
  dashboardTab,
  closeDashboard,
  topTalkersConfig,
  bandwidthPeriod,
  criticalAccessDays,
  fmtWindow,
  useCustom,
  custom,
  minutes,
  loadInventory,
  setDashboardRefresh,
  inventoryLoading,
  dashboardLoading,
  dashboardPortsLoading,
  dashboardConversationsLoading,
  dashboardBandwidthLoading,
  criticalAccessLoading,
  setDashboardTab,
  inventoryData,
  inventoryError,
  openInventory,
  dashboardServerId,
  setDashboardServerId,
  dashboardData,
  dashboardError,
  fmtBytes,
  dashboardPortsData,
  dashboardPortsError,
  bandwidthGroup,
  setBandwidthGroup,
  setBandwidthPeriod,
  watchSubnets,
  dashboardBandwidthData,
  dashboardBandwidthError,
  fmtRate,
  criticalAccessData,
  criticalAccessError,
  setCriticalAccessDays,
  conversationEndpoint,
  topTalkersForm,
  setTopTalkersForm,
  setTopTalkersConfig,
  dashboardConversationsData,
  dashboardConversationsError,
  fmtAccessTime
}) {
  return (
    <main className="page-dashboard">
      <div className="page-head">
        <div className="page-title">
          <button className="ghost" onClick={closeDashboard} title="Voltar ao mapa">← mapa</button>
          <div><h2>Dashboard</h2><span className="hint">visão de tráfego por máquina</span></div>
        </div>
        <div className="page-actions">
          <span className="badge low">{dashboardTab === 'topTalkers' ? topTalkersConfig.time : dashboardTab === 'bandwidth' ? bandwidthPeriod : dashboardTab === 'criticalAccess' ? `${criticalAccessDays}d` : fmtWindow(useCustom, custom, minutes)}</span>
          <button className="ghost" onClick={() => { loadInventory(); setDashboardRefresh((n) => n + 1); }} disabled={inventoryLoading || dashboardLoading || dashboardPortsLoading || dashboardConversationsLoading || dashboardBandwidthLoading || criticalAccessLoading} title="Atualizar inventário e dados">↻</button>
        </div>
      </div>
      <div className="page-bar dashboard-page-bar">
        <div className="seg dashboard-tabs">
          <button className={dashboardTab === 'applications' ? 'active' : ''} onClick={() => setDashboardTab('applications')}>Aplicações</button>
          <button className={dashboardTab === 'ports' ? 'active' : ''} onClick={() => setDashboardTab('ports')}>Portas</button>
          <button className={dashboardTab === 'bandwidth' ? 'active' : ''} onClick={() => setDashboardTab('bandwidth')}>Banda</button>
          <button className={dashboardTab === 'criticalAccess' ? 'active' : ''} onClick={() => setDashboardTab('criticalAccess')}>Acessos críticos</button>
          <button className={dashboardTab === 'topTalkers' ? 'active' : ''} onClick={() => setDashboardTab('topTalkers')}>Tráfego</button>
        </div>
        <span className="hint">{dashboardTab === 'applications' ? 'Ranking por fluxos NetFlow · volume em bytes' : dashboardTab === 'ports' ? 'Ranking por fluxos em portas conhecidas de aplicações' : dashboardTab === 'bandwidth' ? 'Série temporal e capacidade da máquina' : dashboardTab === 'criticalAccess' ? 'Clientes de serviços críticos das máquinas do inventário' : 'Conversas que envolvem IPs do inventário'}</span>
      </div>
      <div className={`dashboard-grid${['topTalkers','criticalAccess'].includes(dashboardTab) ? ' dashboard-wide-grid' : ''}`}>
        <aside className="dashboard-machines">
          <div className="dashboard-section-head">
            <h3>Máquinas</h3>
            <span className="badge low">{inventoryData.length}</span>
          </div>
          {inventoryError && <p className="error">{inventoryError}</p>}
          {inventoryLoading && <p className="hint">Carregando inventário…</p>}
          {!inventoryLoading && !inventoryData.length && (
            <div className="empty">Nenhuma máquina cadastrada.<br /><button className="ghost" onClick={openInventory} style={{ marginTop: 10 }}>Abrir inventário</button></div>
          )}
          <div className="dashboard-machine-list">
            {inventoryData.map((server) => (
              <button key={server.id} className={`dashboard-machine${dashboardServerId === server.id ? ' active' : ''}`} onClick={() => setDashboardServerId(server.id)}>
                <span className="dashboard-machine-name">{server.name}</span>
                <span className="hint">{server.ips.map((x) => x.ip).join(' · ') || 'sem IP'}</span>
                <span className="dashboard-machine-meta">{server.applications.length} aplicações · {server.ips.length} IPs</span>
              </button>
            ))}
          </div>
        </aside>

        {dashboardTab === 'applications' ? (
          <section className="dashboard-applications">
            {!dashboardServerId ? (
              <div className="empty">Selecione uma máquina cadastrada para ver suas aplicações.</div>
            ) : dashboardLoading ? (
              <p className="hint">Consultando NetFlow para esta máquina…</p>
            ) : dashboardError ? (
              <p className="error">Falha ao carregar o dashboard: {dashboardError}</p>
            ) : !dashboardData ? (
              <p className="hint">Aguardando consulta de aplicações…</p>
            ) : (
              <>
                <div className="dashboard-section-head">
                  <div>
                    <h3>{dashboardData.server.name}</h3>
                    <span className="hint">{dashboardData.server.ips.map((x) => x.ip).join(' · ')}</span>
                  </div>
                  <span className="badge low">{dashboardData.applicationsWithTraffic} de {dashboardData.totalApplications} com tráfego</span>
                </div>
                <p className="hint">Top 5 por registros NetFlow que coincidem com IP, protocolo e porta do listener. Um fluxo NetFlow não representa necessariamente uma requisição de aplicação.</p>
                {!dashboardData.applications.length ? (
                  <div className="empty">Esta máquina ainda não tem aplicações cadastradas.<br /><button className="ghost" onClick={openInventory} style={{ marginTop: 10 }}>Cadastrar aplicações</button></div>
                ) : dashboardData.applications[0].flows === 0 ? (
                  <p className="hint">Nenhum fluxo corresponde aos listeners cadastrados nesta janela.</p>
                ) : null}
                <div className="table-wrap dashboard-table-wrap">
                  <table className="dashboard-data-table" aria-label="Aplicações mais acessadas">
                    <thead><tr><th>Aplicação</th><th>Tráfego</th><th>Utilização</th><th>Entrada / saída</th><th>Listeners</th></tr></thead>
                    <tbody>
                      {dashboardData.applications.map((application, index) => {
                        const maxFlows = Math.max(1, ...dashboardData.applications.map((app) => app.flows));
                        const utilization = Math.round((application.flows / maxFlows) * 100);
                        return (
                          <tr key={application.id}>
                            <td><span className="dashboard-rank">{index + 1}</span><b className="dashboard-row-name">{application.name}</b></td>
                            <td><b>{application.flows} fluxos</b><small>{fmtBytes(application.bytes)}</small></td>
                            <td><div className="dashboard-utilization"><div className="bar"><i style={{ width: `${Math.max(application.flows ? 2 : 0, utilization)}%` }} /></div><span>{utilization}%</span></div></td>
                            <td><span className="dashboard-direction">↓ {fmtBytes(application.incoming.bytes)} <i>·</i> ↑ {fmtBytes(application.outgoing.bytes)}</span></td>
                            <td className="dashboard-listeners">{application.listeners.map((l) => `${l.protocol}/${l.port}`).join(' · ') || 'nenhum configurado'}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </section>
        ) : dashboardTab === 'ports' ? (
          <section className="dashboard-applications">
            {!dashboardServerId ? (
              <div className="empty">Selecione uma máquina cadastrada para ver suas portas.</div>
            ) : dashboardPortsLoading ? (
              <p className="hint">Consultando portas conhecidas no NetFlow…</p>
            ) : dashboardPortsError ? (
              <p className="error">Falha ao carregar as portas: {dashboardPortsError}</p>
            ) : !dashboardPortsData ? (
              <p className="hint">Aguardando consulta de portas…</p>
            ) : (
              <>
                <div className="dashboard-section-head">
                  <div><h3>{dashboardPortsData.server.name}</h3><span className="hint">{dashboardPortsData.server.ips.map((x) => x.ip).join(' · ')}</span></div>
                  <span className="badge low">{dashboardPortsData.portsWithTraffic} portas com tráfego</span>
                </div>
                <p className="hint">Top 5 por registros NetFlow nas portas locais do servidor: destino na entrada e origem na saída. A porta do peer remoto é ignorada. Um fluxo NetFlow não representa necessariamente uma requisição de aplicação.</p>
                {!dashboardPortsData.ports.length ? (
                  <div className="empty">Nenhuma porta conhecida com tráfego nesta janela.</div>
                ) : (
                  <div className="table-wrap dashboard-table-wrap">
                    <table className="dashboard-data-table dashboard-ports-table" aria-label="Portas de serviço mais acessadas">
                      <thead><tr><th>Serviço / porta</th><th>Tráfego</th><th>Utilização</th><th>Entrada / saída</th><th>Protocolo</th></tr></thead>
                      <tbody>{dashboardPortsData.ports.map((port, index) => {
                        const maxFlows = Math.max(1, ...dashboardPortsData.ports.map((item) => item.flows));
                        const utilization = Math.round((port.flows / maxFlows) * 100);
                        return (
                          <tr key={port.port}>
                            <td><span className="dashboard-rank">{index + 1}</span><b className="dashboard-row-name">{port.service} · {port.port}</b></td>
                            <td><b>{port.flows} fluxos</b><small>{fmtBytes(port.bytes)}</small></td>
                            <td><div className="dashboard-utilization"><div className="bar"><i style={{ width: `${Math.max(2, utilization)}%` }} /></div><span>{utilization}%</span></div></td>
                            <td><span className="dashboard-direction">↓ {fmtBytes(port.incoming.bytes)} <i>·</i> ↑ {fmtBytes(port.outgoing.bytes)}</span></td>
                            <td>{port.protocols.join(' · ') || 'não identificados'}</td>
                          </tr>
                        );
                      })}</tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </section>
        ) : dashboardTab === 'bandwidth' ? (
          <section className="dashboard-applications dashboard-bandwidth">
            {!dashboardServerId ? (
              <div className="empty">Selecione uma máquina cadastrada para ver sua banda.</div>
            ) : dashboardBandwidthLoading ? (
              <p className="hint">Agregando tráfego ao longo do tempo…</p>
            ) : dashboardBandwidthError ? (
              <p className="error">Falha ao carregar a série de banda: {dashboardBandwidthError}</p>
            ) : !dashboardBandwidthData ? (
              <p className="hint">Aguardando série de banda…</p>
            ) : (
              <>
                <div className="dashboard-section-head bandwidth-heading">
                  <div>
                    <h3>{dashboardBandwidthData.server.name}</h3>
                    <span className="hint">{dashboardBandwidthData.server.ips.map((item) => item.ip).join(' · ')} · {dashboardBandwidthData.groupBy === 'application' ? 'por aplicação' : dashboardBandwidthData.groupBy === 'exporter' ? 'por exporter' : dashboardBandwidthData.groupBy === 'subnet' ? 'por sub-rede (IPs inventariados)' : 'por máquina'} · fonte {dashboardBandwidthData.source === 'pair_daily' ? 'pair_daily' : 'NetFlow em tempo real'}</span>
                  </div>
                  <div className="dashboard-bandwidth-controls">
                    <label className="dashboard-period-select"><span>Agrupar por</span><select value={bandwidthGroup} onChange={(event) => setBandwidthGroup(event.target.value)}>
                      <option value="server">Máquina</option><option value="subnet" disabled={!watchSubnets?.length}>Sub-rede</option>
                      <option value="application" disabled={!inventoryData.find((item) => item.id === dashboardServerId)?.applications.length || ['7d','30d'].includes(bandwidthPeriod)}>Aplicação</option>
                      <option value="exporter" disabled={['7d','30d'].includes(bandwidthPeriod)}>Exporter</option>
                    </select></label>
                    <label className="dashboard-period-select"><span>Período</span><select value={bandwidthPeriod} onChange={(event) => {
                      const period = event.target.value;
                      setBandwidthPeriod(period);
                      if (['7d','30d'].includes(period) && ['application','exporter'].includes(bandwidthGroup)) setBandwidthGroup('server');
                    }}><option value="1h">1h</option><option value="6h">6h</option><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option></select></label>
                  </div>
                </div>
                <div className="kpis dashboard-bandwidth-kpis">
                  <div><b>{fmtBytes(dashboardBandwidthData.summary.totalBytes)}</b><span>volume total</span></div>
                  <div><b>{fmtRate(dashboardBandwidthData.summary.averageBitsPerSecond)}</b><span>média</span></div>
                  <div><b>{fmtRate(dashboardBandwidthData.summary.peakBitsPerSecond)}</b><span>pico</span></div>
                  <div><b>{fmtRate(dashboardBandwidthData.summary.p95BitsPerSecond)}</b><span>percentil 95</span></div>
                </div>
                {!dashboardBandwidthData.series.length || dashboardBandwidthData.summary.totalFlows === 0 ? (
                  <div className="empty">Sem fluxos para este agrupamento no período.</div>
                ) : (() => {
                  const series = dashboardBandwidthData.series;
                  const buckets = series[0]?.buckets || [];
                  const maxRate = Math.max(1, ...series.flatMap((line) => line.buckets.map((bucket) => bucket.bitsPerSecond)));
                  const labelStep = Math.max(1, Math.ceil(buckets.length / 8));
                  const seriesColors = ['#21b875', '#3478c8', '#8b65ba', '#ec8b32', '#1a9e9b'];
                  return (
                    <>
                      <div className="bandwidth-chart-wrap">
                        <div className="bandwidth-y-axis"><span>{fmtRate(maxRate)}</span><span>{fmtRate(maxRate / 2)}</span><span>0</span></div>
                        <div className="bandwidth-plot" role="img" aria-label={`Banda de ${dashboardBandwidthData.server.name} ao longo de ${bandwidthPeriod}`}>
                          {buckets.map((bucket, index) => {
                            const time = new Date(bucket.time);
                            const label = bandwidthPeriod.endsWith('d')
                              ? time.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })
                              : time.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
                            return (
                              <div className="bandwidth-time-group" key={bucket.time}>
                                <div className="bandwidth-series-bars">{series.map((line, lineIndex) => {
                                  const point = line.buckets[index] || { bitsPerSecond: 0, bytes: 0 };
                                  const height = Math.round((point.bitsPerSecond / maxRate) * 100);
                                  return <i key={line.key} title={`${line.label} · ${fmtRate(point.bitsPerSecond)} · ${fmtBytes(point.bytes)}`} style={{ height: `${point.bitsPerSecond ? Math.max(2, height) : 0}%`, background: seriesColors[lineIndex % seriesColors.length] }} />;
                                })}</div>
                                {index % labelStep === 0 && <small>{label}</small>}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                      {series.length > 1 && <div className="bandwidth-legend">{series.map((line, index) => <span key={line.key}><i style={{ background: seriesColors[index % seriesColors.length] }} />{line.label}</span>)}</div>}
                    </>
                  );
                })()}
                <p className="hint">Banda estimada por bucket: bytes NetFlow × 8 ÷ duração do intervalo. P95 é calculado sobre os pontos da série. O vDS pode exportar o mesmo tráfego em mais de um ponto; valide interfaces e direção antes de usar os totais para cobrança.</p>
              </>
            )}
          </section>
        ) : dashboardTab === 'criticalAccess' ? (
          <section className="dashboard-applications dashboard-critical-access">
            <div className="dashboard-section-head">
              <div><h3>Quem acessa serviços críticos</h3><span className="hint">TCP 22, 445, 1433, 3389 e 5985 · histórico diário mais fluxos recentes</span></div>
              <label className="dashboard-period-select"><span>Período</span><select value={criticalAccessDays} onChange={(event) => setCriticalAccessDays(Number(event.target.value))}><option value={30}>30 dias</option><option value={90}>90 dias</option><option value={365}>365 dias</option></select></label>
            </div>
            {criticalAccessLoading ? <p className="hint">Consultando acessos às portas críticas…</p>
              : criticalAccessError ? <p className="error">Falha ao carregar acessos críticos: {criticalAccessError}</p>
                : !criticalAccessData ? <p className="hint">Aguardando consulta de acessos…</p>
                  : criticalAccessData.inventoryIps === 0 ? <div className="empty">Nenhum IP cadastrado no inventário.</div>
                    : !criticalAccessData.clients.length ? <div className="empty">Nenhum acesso a essas portas no período selecionado.</div>
                      : <>
                        <div className="dashboard-summary"><span className="badge low">{criticalAccessData.clients.length} acessos · {criticalAccessData.days} dias</span><span className="hint">“Novo” indica primeira aparição no período. “Fora do esperado” depende da allowlist cadastrada na aplicação; sem allowlist o estado fica sem baseline.</span></div>
                        {criticalAccessData.truncated && <p className="error">A consulta excedeu o limite de páginas; a lista pode estar incompleta.</p>}
                        <div className="table-wrap dashboard-table-wrap"><table className="dashboard-data-table dashboard-critical-access-table" aria-label="Clientes que acessaram serviços críticos do inventário">
                          <thead><tr><th>Serviço</th><th>Servidor</th><th>Cliente</th><th>Classificação</th><th>Primeiro acesso</th><th>Último acesso</th><th>Fluxos</th><th>Bytes</th></tr></thead>
                          <tbody>{criticalAccessData.clients.map((access) => (
                            <tr key={`${access.source}|${access.target}|${access.protocol}|${access.port}`}>
                              <td><b>{access.service} · {access.port}</b><small>{access.applications.join(' · ') || access.protocol}</small></td>
                              <td>{conversationEndpoint(access.target)}</td><td>{conversationEndpoint(access.source)}</td>
                              <td><div className="critical-access-status">{access.isNew && <span className="badge med">Novo</span>}{access.expectedStatus === 'expected' && <span className="badge low">Esperado</span>}{access.expectedStatus === 'unexpected' && <span className="badge high">Fora do esperado</span>}{access.expectedStatus === 'unconfigured' && <span className="badge med">Sem baseline</span>}</div></td>
                              <td>{fmtAccessTime(access.firstSeen)}</td><td>{fmtAccessTime(access.lastSeen)}</td><td>{access.flows}</td><td>{fmtBytes(access.bytes)}</td>
                            </tr>
                          ))}</tbody>
                        </table></div>
                      </>}
          </section>
        ) : (
          <section className="dashboard-applications dashboard-conversations">
            <form className="dashboard-conversation-form" onSubmit={(event) => {
              event.preventDefault();
              setTopTalkersConfig({ top: Number(topTalkersForm.top), time: topTalkersForm.time, flowType: topTalkersForm.flowType });
              setDashboardRefresh((n) => n + 1);
            }}>
              <label><span>Top</span><select value={topTalkersForm.top} onChange={(event) => setTopTalkersForm((current) => ({ ...current, top: event.target.value }))}>{Array.from({ length: 20 }, (_, index) => <option key={index + 1} value={index + 1}>{index + 1}</option>)}</select></label>
              <label><span>Time</span><select value={topTalkersForm.time} onChange={(event) => setTopTalkersForm((current) => ({ ...current, time: event.target.value }))}><option value="1h">1h</option><option value="6h">6h</option><option value="24h">24h</option></select></label>
              <label><span>Flow type</span><select value={topTalkersForm.flowType} onChange={(event) => setTopTalkersForm((current) => ({ ...current, flowType: event.target.value }))}><option value="ingress">Ingress</option><option value="egress">Egress</option><option value="both">Both</option></select></label>
              <button type="submit" disabled={dashboardConversationsLoading}>{dashboardConversationsLoading ? 'Consultando…' : 'Aplicar'}</button>
            </form>
            {dashboardConversationsLoading ? <p className="hint">Consultando conversas dos IPs inventariados…</p>
              : dashboardConversationsError ? <p className="error">Falha ao carregar tráfego: {dashboardConversationsError}</p>
                : !dashboardConversationsData ? <p className="hint">Aguardando consulta de conversas…</p>
                  : dashboardConversationsData.inventoryIps === 0 ? <div className="empty">Nenhum IP cadastrado no inventário.<br /><button className="ghost" onClick={openInventory} style={{ marginTop: 10 }}>Abrir inventário</button></div>
                    : !dashboardConversationsData.pairs.length ? <div className="empty">Nenhuma conversa encontrada para os IPs do inventário neste período.</div>
                      : <>
                        <div className="dashboard-section-head"><h3>Top {dashboardConversationsData.top} conversas</h3><span className="badge low">{dashboardConversationsData.inventoryIps} IPs · {dashboardConversationsData.time} · {dashboardConversationsData.flowType}</span></div>
                        <div className="table-wrap dashboard-table-wrap"><table className="dashboard-data-table dashboard-conversation-table" aria-label="Top conversas entre máquinas do inventário e seus peers">
                          <thead><tr><th>Conversação</th><th>Total</th><th>Fluxos</th><th>Cliente → servidor</th><th>Servidor → cliente</th><th>Direção exportador</th><th>Protocolos</th><th>Portas</th></tr></thead>
                          <tbody>{dashboardConversationsData.pairs.map((pair, index) => (
                            <tr key={`${pair.a}|${pair.b}`}>
                              <td><span className="dashboard-rank">{index + 1}</span><span className="conversation-peers">{pair.clientIp ? <>{conversationEndpoint(pair.clientIp)}<i>→</i>{conversationEndpoint(pair.serverIp)}</> : <>{conversationEndpoint(pair.a)}<i>↔</i>{conversationEndpoint(pair.b)}</>}</span>{!pair.clientIp && <small>{pair.directionConfidence === 'ambiguous' ? 'iniciador ambíguo' : 'sem SYN observado'}</small>}</td>
                              <td><b>{fmtBytes(pair.bytes)}</b></td><td><b>{pair.flows}</b><small>{pair.packets} pacotes</small></td>
                              <td>{pair.clientToServerBytes == null ? '—' : fmtBytes(pair.clientToServerBytes)}</td><td>{pair.serverToClientBytes == null ? '—' : fmtBytes(pair.serverToClientBytes)}</td>
                              <td>{pair.flowDirections.map((direction) => `${direction.label} (${direction.flows})`).join(' · ') || '—'}</td><td>{pair.protocols.join(' · ') || '—'}</td><td>{pair.topPorts.map((port) => port.port).join(' · ') || '—'}</td>
                            </tr>
                          ))}</tbody>
                        </table></div>
                      </>}
          </section>
        )}
      </div>
    </main>
  );
}
