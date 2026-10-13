export default function InventoryScreen({
  closeInventory,
  inventoryData,
  loadInventory,
  inventoryLoading,
  inventoryError,
  newServerName,
  setNewServerName,
  newServerIp,
  setNewServerIp,
  addInventoryServer,
  inventoryBusy,
  inventoryEdit,
  setInventoryEdit,
  saveInventoryEdit,
  inventorySelectedId,
  setInventorySelectedId,
  removeInventoryServer,
  setApplicationDrafts,
  applicationDrafts,
  inventoryNewApplicationRef,
  selectedInventoryServer,
  openIpModal,
  newServerIps,
  setNewServerIps,
  addInventoryIp,
  removeInventoryIp,
  setApplicationDraft,
  addInventoryApplication,
  removeInventoryApplication,
  expectedClientDrafts,
  setExpectedClientDrafts,
  removeExpectedClient,
  addExpectedClient,
  listenerDrafts,
  setListenerDraft,
  removeInventoryListener,
  addInventoryListener
}) {
  return (
    <main className="page-inventory">
      <div className="page-head inventory-page-head">
        <div className="page-title">
          <button className="ghost" onClick={closeInventory} title="Voltar para a tela anterior">← voltar</button>
          <div><h2>Inventário</h2><span className="hint">máquinas, endereços IP, aplicações e listeners</span></div>
        </div>
        <div className="page-actions">
          <span className="badge low">{inventoryData.length} máquinas</span>
          <button className="ghost" onClick={loadInventory} disabled={inventoryLoading} title="Atualizar inventário">↻</button>
        </div>
      </div>
      <div className="inventory-page-body">
        {inventoryError && <p className="error">{inventoryError}</p>}
        <section className="inventory-add-panel">
          <div className="inventory-add-heading">
            <h3>Adicionar máquina</h3>
            <p className="hint">Cadastre um nome e o primeiro IP. Outros endereços, aplicações e listeners podem ser adicionados em cada máquina.</p>
          </div>
          <div className="cmp-form inventory-create-form">
            <input value={newServerName} onChange={(e) => setNewServerName(e.target.value)} placeholder="Nome — ex. DNS01" />
            <input value={newServerIp} onChange={(e) => setNewServerIp(e.target.value)} placeholder="IP — ex. 10.1.0.10" onKeyDown={(e) => e.key === 'Enter' && addInventoryServer()} />
            <button onClick={addInventoryServer} disabled={inventoryBusy === 'server-new'}>{inventoryBusy === 'server-new' ? 'Salvando…' : 'Adicionar'}</button>
          </div>
        </section>
        {inventoryLoading && <p className="hint">Carregando inventário…</p>}
        {!inventoryLoading && !inventoryData.length && <p className="empty">Nenhuma máquina cadastrada ainda.</p>}
        {!!inventoryData.length && (
          <div className="inventory-workspace">
            <section className="inventory-machine-panel">
              <div className="inventory-panel-head"><h3>Máquinas</h3><span className="badge low">{inventoryData.length}</span></div>
              <div className="inventory-machine-list">
                {inventoryData.map((server) => {
                  const serverEditing = inventoryEdit?.kind === 'server' && inventoryEdit.id === server.id;
                  return (
                    <article key={server.id} className={`inventory-machine-row${inventorySelectedId === server.id ? ' active' : ''}`} onClick={() => setInventorySelectedId(server.id)}>
                      <div className="inventory-machine-summary">
                        {serverEditing ? (
                          <input autoFocus value={inventoryEdit.name} onChange={(e) => setInventoryEdit({ ...inventoryEdit, name: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && saveInventoryEdit()} />
                        ) : (
                          <><b>{server.name}</b><span className="hint">ID {server.id}</span></>
                        )}
                      </div>
                      <div className="inventory-machine-ips">{server.ips.map((address) => address.ip).join(' · ') || 'sem IP'}</div>
                      <div className="inventory-machine-meta">{server.applications.length} aplicações · {server.ips.length} IPs</div>
                      <div className="inventory-actions" onClick={(e) => e.stopPropagation()}>
                        {serverEditing ? (
                          <>
                            <button className="ghost" onClick={saveInventoryEdit} disabled={inventoryBusy === `rename-server-${server.id}`}>Salvar</button>
                            <button className="ghost" onClick={() => setInventoryEdit(null)}>Cancelar</button>
                          </>
                        ) : (
                          <>
                            <button className="ghost" onClick={() => setInventoryEdit({ kind: 'server', id: server.id, name: server.name })}>Editar</button>
                            <button className="ghost" onClick={() => removeInventoryServer(server)}>Remover</button>
                            <button className="inventory-add-app" onClick={() => {
                              setInventorySelectedId(server.id);
                              setApplicationDrafts((all) => ({ ...all, [server.id]: all[server.id] || { name: '', serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '' } }));
                              requestAnimationFrame(() => {
                                inventoryNewApplicationRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                inventoryNewApplicationRef.current?.querySelector('input')?.focus({ preventScroll: true });
                              });
                            }}>Adicionar aplicação</button>
                          </>
                        )}
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="inventory-machine-detail" id="inventory-machine-detail">
              <div className="inventory-list">
                {[selectedInventoryServer].filter(Boolean).map((server) => {
                  const appDraft = {
                    name: '', serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '',
                    ...(applicationDrafts[server.id] || {})
                  };
                  if (!appDraft.serverIpId) appDraft.serverIpId = String(server.ips[0]?.id || '');
                  return (
                    <section className="inventory-server" key={server.id}>
                      <div className="inventory-server-head">
                        <div><b>{server.name}</b><span className="hint">{server.ips.length} IPs · {server.applications.length} aplicações</span></div>
                      </div>

                      <div className="inventory-ip-list">
                        {server.ips.map((address) => (
                          <div className="inventory-ip" key={address.id}>
                            <span className="mono ip-link" title="Abrir dossiê do IP" onClick={() => openIpModal(address.ip)}>{address.ip}</span>
                            <button className="ghost" title="Remover IP (e seus listeners)" onClick={() => removeInventoryIp(address)}>×</button>
                          </div>
                        ))}
                      </div>
                      <div className="cmp-form inventory-add-ip">
                        <input value={newServerIps[server.id] || ''} onChange={(e) => setNewServerIps((all) => ({ ...all, [server.id]: e.target.value }))} placeholder="Adicionar outro IP" onKeyDown={(e) => e.key === 'Enter' && addInventoryIp(server)} />
                        <button className="ghost" onClick={() => addInventoryIp(server)} disabled={inventoryBusy === `ip-new-${server.id}`}>{inventoryBusy === `ip-new-${server.id}` ? 'Salvando…' : 'Adicionar IP'}</button>
                      </div>

                      <h4>Aplicações ({server.applications.length})</h4>
                      <div className="cmp-form inventory-new-application" ref={inventoryNewApplicationRef}>
                        <input value={appDraft.name} onChange={(e) => setApplicationDraft(server.id, 'name', e.target.value)} placeholder="Nome da aplicação" />
                        <select value={appDraft.serverIpId} onChange={(e) => setApplicationDraft(server.id, 'serverIpId', e.target.value)} disabled={!server.ips.length}>
                          {server.ips.map((address) => <option key={address.id} value={address.id}>{address.ip}</option>)}
                        </select>
                        <select value={appDraft.protocol} onChange={(e) => setApplicationDraft(server.id, 'protocol', e.target.value)}>
                          <option value="TCP">TCP</option><option value="UDP">UDP</option>
                        </select>
                        <input type="number" min="1" max="65535" value={appDraft.port} onChange={(e) => setApplicationDraft(server.id, 'port', e.target.value)} placeholder="Porta" />
                        <button onClick={() => addInventoryApplication(server)} disabled={!server.ips.length || inventoryBusy === `app-new-${server.id}`}>{inventoryBusy === `app-new-${server.id}` ? 'Salvando…' : 'Adicionar aplicação'}</button>
                      </div>
                      {!server.applications.length && <p className="hint">Nenhuma aplicação cadastrada.</p>}
                      {server.applications.map((application) => {
                        const appEditing = inventoryEdit?.kind === 'application' && inventoryEdit.id === application.id;
                        const listenerDraft = {
                          serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '',
                          ...(listenerDrafts[application.id] || {})
                        };
                        if (!listenerDraft.serverIpId) listenerDraft.serverIpId = String(server.ips[0]?.id || '');
                        return (
                          <div className="inventory-application" key={application.id}>
                            <div className="inventory-application-head">
                              {appEditing ? (
                                <input autoFocus value={inventoryEdit.name} onChange={(e) => setInventoryEdit({ ...inventoryEdit, name: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && saveInventoryEdit()} />
                              ) : <b>{application.name}</b>}
                              <div className="inventory-actions">
                                {appEditing ? (
                                  <>
                                    <button className="ghost" onClick={saveInventoryEdit} disabled={inventoryBusy === `rename-application-${application.id}`}>Salvar</button>
                                    <button className="ghost" onClick={() => setInventoryEdit(null)}>Cancelar</button>
                                  </>
                                ) : (
                                  <>
                                    <button className="ghost" onClick={() => setInventoryEdit({ kind: 'application', id: application.id, name: application.name })}>Renomear</button>
                                    <button className="ghost" onClick={() => removeInventoryApplication(application)}>Remover</button>
                                  </>
                                )}
                              </div>
                            </div>
                            <div className="inventory-expected-clients">
                              <div className="inventory-expected-head"><b>Clientes esperados</b><span className="hint">Allowlist usada no relatório de acessos críticos</span></div>
                              <div className="inventory-expected-list">
                                {(application.expectedClients || []).map((client) => (
                                  <span className="inventory-expected-client mono" key={client.id}>
                                    {client.ip}<button className="ghost" title="Remover cliente esperado" onClick={() => removeExpectedClient(client)}>×</button>
                                  </span>
                                ))}
                                {!application.expectedClients?.length && <span className="hint">Sem baseline: acessos aparecem como não classificados.</span>}
                              </div>
                              <div className="cmp-form inventory-expected-form">
                                <input value={expectedClientDrafts[application.id] || ''} onChange={(e) => setExpectedClientDrafts((all) => ({ ...all, [application.id]: e.target.value }))} placeholder="IP cliente permitido" onKeyDown={(e) => e.key === 'Enter' && addExpectedClient(application)} />
                                <button className="ghost" onClick={() => addExpectedClient(application)} disabled={inventoryBusy === `expected-client-new-${application.id}`}>{inventoryBusy === `expected-client-new-${application.id}` ? 'Salvando…' : 'Adicionar esperado'}</button>
                              </div>
                            </div>
                            {application.listeners.map((listener) => (
                              <div className="inventory-listener" key={listener.id}>
                                <span className="mono">{listener.ip} · {listener.protocol}/{listener.port}</span>
                                <button className="ghost" title="Remover listener" onClick={() => removeInventoryListener(listener)}>×</button>
                              </div>
                            ))}
                            <div className="cmp-form inventory-listener-form">
                              <select value={listenerDraft.serverIpId} onChange={(e) => setListenerDraft(application.id, 'serverIpId', e.target.value)} disabled={!server.ips.length}>
                                {server.ips.map((address) => <option key={address.id} value={address.id}>{address.ip}</option>)}
                              </select>
                              <select value={listenerDraft.protocol} onChange={(e) => setListenerDraft(application.id, 'protocol', e.target.value)}>
                                <option value="TCP">TCP</option><option value="UDP">UDP</option>
                              </select>
                              <input type="number" min="1" max="65535" value={listenerDraft.port} onChange={(e) => setListenerDraft(application.id, 'port', e.target.value)} placeholder="Porta" />
                              <button className="ghost" onClick={() => addInventoryListener(server, application)} disabled={!server.ips.length || inventoryBusy === `listener-new-${application.id}`}>Adicionar listener</button>
                            </div>
                          </div>
                        );
                      })}

                    </section>
                  );
                })}
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}
