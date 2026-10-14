import { useEffect, useRef, useState } from 'react';

const APPLICATIONS_PER_PAGE = 5;

export default function DashboardScreen({
  dashboardTab,
  closeDashboard,
  topTalkersConfig,
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
  setDashboardTab,
  inventoryData,
  inventoryError,
  openInventory,
  dashboardServerId,
  setDashboardServerId,
  dashboardData,
  dashboardError,
  fetchApplicationConnections,
  fmtBytes,
  dashboardPortsData,
  dashboardPortsError,
  conversationEndpoint,
  topTalkersForm,
  setTopTalkersForm,
  setTopTalkersConfig,
  dashboardConversationsData,
  dashboardConversationsError
}) {
  const [applicationConnectionsDialog, setApplicationConnectionsDialog] = useState(null);
  const [applicationConnectionsPage, setApplicationConnectionsPage] = useState(0);
  const applicationConnectionsRequest = useRef(0);
  const applicationConnections = applicationConnectionsDialog?.data?.connections || [];
  const applicationConnectionsPages = Math.ceil(applicationConnections.length / APPLICATIONS_PER_PAGE);
  const currentApplicationConnectionsPage = Math.min(applicationConnectionsPage, Math.max(0, applicationConnectionsPages - 1));
  const visibleApplicationConnections = applicationConnections.slice(
    currentApplicationConnectionsPage * APPLICATIONS_PER_PAGE,
    (currentApplicationConnectionsPage + 1) * APPLICATIONS_PER_PAGE
  );
  const [applicationsPage, setApplicationsPage] = useState(0);
  const applications = dashboardData?.applications || [];
  const applicationsPages = Math.ceil(applications.length / APPLICATIONS_PER_PAGE);
  const currentApplicationsPage = Math.min(applicationsPage, Math.max(0, applicationsPages - 1));
  const visibleApplications = applications.slice(
    currentApplicationsPage * APPLICATIONS_PER_PAGE,
    (currentApplicationsPage + 1) * APPLICATIONS_PER_PAGE
  );
  const maxApplicationFlows = Math.max(1, ...applications.map((application) => application.flows));

  useEffect(() => {
    setApplicationsPage(0);
  }, [dashboardData]);

  async function loadApplicationConnections(application) {
    const requestId = applicationConnectionsRequest.current + 1;
    applicationConnectionsRequest.current = requestId;
    setApplicationConnectionsDialog({ application, loading: true, data: null, error: '' });
    const query = useCustom && custom.from && custom.to
      ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
      : { minutes };
    try {
      const data = await fetchApplicationConnections(dashboardServerId, application.id, query);
      if (applicationConnectionsRequest.current === requestId) {
        setApplicationConnectionsDialog({ application, loading: false, data, error: '' });
      }
    } catch (error) {
      if (applicationConnectionsRequest.current === requestId) {
        setApplicationConnectionsDialog({ application, loading: false, data: null, error: String(error.message || error) });
      }
    }
  }

  function openApplicationConnections(application) {
    setApplicationConnectionsPage(0);
    loadApplicationConnections(application);
  }

  function closeApplicationConnections() {
    applicationConnectionsRequest.current += 1;
    setApplicationConnectionsDialog(null);
    setApplicationConnectionsPage(0);
  }

  const formatConnectionTime = (value) => value ? new Date(value).toLocaleString('pt-BR') : '—';

  return (
    <main className="page-dashboard">
      <div className="page-head">
        <div className="page-title">
          <button className="ghost" onClick={closeDashboard} title="Voltar ao mapa">← mapa</button>
          <div><h2>Dashboard</h2><span className="hint">visão de tráfego por máquina</span></div>
        </div>
        <div className="page-actions">
          <span className="badge low">{dashboardTab === 'topTalkers' ? topTalkersConfig.time : fmtWindow(useCustom, custom, minutes)}</span>
          <button className="ghost" onClick={() => { loadInventory(); setDashboardRefresh((n) => n + 1); }} disabled={inventoryLoading || dashboardLoading || dashboardPortsLoading || dashboardConversationsLoading} title="Atualizar inventário e dados">↻</button>
        </div>
      </div>
      <div className="page-bar dashboard-page-bar">
        <div className="seg dashboard-tabs">
          <button className={dashboardTab === 'applications' ? 'active' : ''} onClick={() => setDashboardTab('applications')}>Aplicações</button>
          <button className={dashboardTab === 'ports' ? 'active' : ''} onClick={() => setDashboardTab('ports')}>Portas</button>
          <button className={dashboardTab === 'topTalkers' ? 'active' : ''} onClick={() => setDashboardTab('topTalkers')}>Tráfego</button>
        </div>
        <span className="hint">{dashboardTab === 'applications' ? 'Ranking por fluxos NetFlow · volume em bytes' : dashboardTab === 'ports' ? 'Ranking por fluxos em portas conhecidas de aplicações' : 'Conversas que envolvem IPs do inventário'}</span>
      </div>
      <div className={`dashboard-grid${dashboardTab === 'topTalkers' ? ' dashboard-wide-grid' : ''}`}>
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
               <p className="hint">Aplicações ordenadas por registros NetFlow que coincidem com IP, protocolo e porta do listener. A lista é exibida de cinco em cinco; um fluxo NetFlow não representa necessariamente uma requisição de aplicação.</p>
                {!dashboardData.applications.length ? (
                  <div className="empty">Esta máquina ainda não tem aplicações cadastradas.<br /><button className="ghost" onClick={openInventory} style={{ marginTop: 10 }}>Cadastrar aplicações</button></div>
                ) : dashboardData.applications[0].flows === 0 ? (
                  <p className="hint">Nenhum fluxo corresponde aos listeners cadastrados nesta janela.</p>
                ) : null}
                <div className="table-wrap dashboard-table-wrap">
                  <table className="dashboard-data-table" aria-label="Aplicações mais acessadas">
                    <thead><tr><th>Aplicação</th><th>Tráfego</th><th>Utilização</th><th>Entrada / saída</th><th>Listeners</th></tr></thead>
                    <tbody>
                      {visibleApplications.map((application, index) => {
                        const utilization = Math.round((application.flows / maxApplicationFlows) * 100);
                        return (
                          <tr key={application.id}>
                            <td><span className="dashboard-rank">{currentApplicationsPage * APPLICATIONS_PER_PAGE + index + 1}</span><button type="button" className="linklike dashboard-application-link" onClick={() => openApplicationConnections(application)} title="Ver conexões que correspondem aos listeners desta aplicação">{application.name}</button></td>
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
                {applicationsPages > 1 && <div className="pager dashboard-applications-pager" aria-label="Paginação das aplicações">
                  <span>{currentApplicationsPage * APPLICATIONS_PER_PAGE + 1}–{Math.min((currentApplicationsPage + 1) * APPLICATIONS_PER_PAGE, applications.length)} de {applications.length}</span>
                  <button className="ghost" disabled={currentApplicationsPage === 0} onClick={() => setApplicationsPage(currentApplicationsPage - 1)}>Anterior</button>
                  <span>{currentApplicationsPage + 1} / {applicationsPages}</span>
                  <button className="ghost" disabled={currentApplicationsPage >= applicationsPages - 1} onClick={() => setApplicationsPage(currentApplicationsPage + 1)}>Próxima</button>
                </div>}
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
      {applicationConnectionsDialog && <div className="modal-backdrop" onClick={closeApplicationConnections}>
        <div className="modal modal-wide dashboard-application-connections" role="dialog" aria-modal="true" aria-labelledby="application-connections-title" onClick={(event) => event.stopPropagation()}>
          <div className="modal-head">
            <div><h2 id="application-connections-title">Conexões · {applicationConnectionsDialog.application.name}</h2><span className="hint">Fluxos que correspondem aos listeners cadastrados · {fmtWindow(useCustom, custom, minutes)}</span></div>
            <div className="page-actions"><button className="ghost" onClick={() => loadApplicationConnections(applicationConnectionsDialog.application)} disabled={applicationConnectionsDialog.loading} title="Atualizar conexões">↻</button><button className="ghost" onClick={closeApplicationConnections} aria-label="Fechar conexões">✕</button></div>
          </div>
          <div className="modal-body">
            <p className="hint">Listeners: {applicationConnectionsDialog.application.listeners.map((listener) => `${listener.ip} · ${listener.protocol}/${listener.port}`).join(' · ') || 'nenhum cadastrado'}</p>
            {applicationConnectionsDialog.loading && <p className="hint">Consultando conexões no NetFlow…</p>}
            {applicationConnectionsDialog.error && <p className="error">Falha ao consultar conexões: {applicationConnectionsDialog.error}</p>}
            {!applicationConnectionsDialog.loading && !applicationConnectionsDialog.error && applicationConnectionsDialog.data && (
              applicationConnections.length ? <>
                {applicationConnectionsDialog.data.truncated && <p className="error">A agregação atingiu o limite de 10.000 IPs por direção; a lista pode estar incompleta.</p>}
                <div className="table-wrap"><table className="dashboard-data-table dashboard-application-connections-table">
                  <thead><tr><th>IP remoto único</th><th>Direção</th><th>Protocolos</th><th>Fluxos</th><th>Pacotes</th><th>Bytes</th><th>Primeiro fluxo</th><th>Último fluxo</th></tr></thead>
                  <tbody>{visibleApplicationConnections.map((connection) => <tr key={connection.ip}>
                    <td className="mono">{conversationEndpoint(connection.ip)}</td>
                    <td>{connection.direction}</td>
                    <td>{connection.protocols.join(' · ') || '—'}</td><td>{connection.flows}</td><td>{connection.packets}</td><td>{fmtBytes(connection.bytes)}</td>
                    <td>{formatConnectionTime(connection.firstSeen)}</td><td>{formatConnectionTime(connection.lastSeen)}</td>
                  </tr>)}</tbody>
                </table></div>
                <div className="pager dashboard-application-connections-pager" aria-label="Paginação das conexões">
                  <span>{currentApplicationConnectionsPage * APPLICATIONS_PER_PAGE + 1}–{Math.min((currentApplicationConnectionsPage + 1) * APPLICATIONS_PER_PAGE, applicationConnections.length)} de {applicationConnections.length} IPs</span>
                  <button className="ghost" onClick={() => setApplicationConnectionsPage((page) => Math.max(0, page - 1))} disabled={currentApplicationConnectionsPage === 0}>Anterior</button>
                  <span>Página {currentApplicationConnectionsPage + 1} / {applicationConnectionsPages}</span>
                  <button className="ghost" onClick={() => setApplicationConnectionsPage((page) => Math.min(applicationConnectionsPages - 1, page + 1))} disabled={currentApplicationConnectionsPage >= applicationConnectionsPages - 1}>Próxima</button>
                </div>
              </> : <p className="empty">Nenhum fluxo correspondente aos listeners desta aplicação no período.</p>
            )}
          </div>
        </div>
      </div>}
    </main>
  );
}
