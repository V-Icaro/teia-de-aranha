import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import DashboardScreen from './screens/Dashboard.jsx';
import InventoryScreen from './screens/Inventory.jsx';
import ReputationScreen from './screens/Reputation.jsx';
import ExposureScreen from './screens/Exposure.jsx';
import MapScreen from './screens/Map.jsx';
import { colorFor, widthFor, fmtBytes, timeAgo, fmtTime, fetchGraph, fetchHost, fetchIpInfo, compareHosts, topPairs, lookupIp, harvestRegions, fetchReputationDb, fetchRisk, fetchNewExternal, fetchSessions, fetchInbound, fetchBeacon, fetchDashboardApplications, fetchApplicationConnections, fetchDashboardPorts, fetchDashboardConversations, fetchFortigates, createFortigate, updateFortigate, deleteFortigate, testFortigate, fetchFortigatePolicies, fetchFortigatePolicyDetail, fetchFortigateAnalysis, getWatchSubnets, addWatchSubnet, patchWatchSubnet, delWatchSubnet, fetchInventory, createInventoryServer, renameInventoryServer, deleteInventoryServer, addServerIp, deleteServerIp, createInventoryApplication, renameInventoryApplication, deleteInventoryApplication, addApplicationListener, deleteApplicationListener, addExpectedApplicationClient, deleteExpectedApplicationClient, isPublicIp, checkReputation, fetchRepCoverage, VERDICTS, subnetOf, cidrContains } from './api.js';

const PRESETS = [
  { label: 'Últimos 5 min', minutes: 5 },
  { label: 'Últimos 15 min', minutes: 15 },
  { label: 'Últimos 30 min', minutes: 30 },
  { label: 'Última hora', minutes: 60 },
  { label: 'Últimas 6 horas', minutes: 360 },
  { label: 'Últimas 12 horas', minutes: 720 },
  { label: 'Últimas 24 horas', minutes: 1440 }
];

// Teto de IPs por consulta ao AbuseIPDB. Tem de bater com o `slice(0, 100)` do
// checkMany no backend: passar mais só gasta requisição e o excesso volta sem
// veredito, mas o front marcava a fila toda como "em cache".
const MAX_CHECK_REP = 100;

// Texto da janela ativa, usado nos modais que seguem o seletor da barra.
function fmtWindow(useCustom, custom, minutes) {
  if (useCustom && custom.from && custom.to) {
    const f = new Date(custom.from);
    const t = new Date(custom.to);
    const horas = Math.max(0, Math.round((t - f) / 3600000));
    return `personalizado (${f.toLocaleString('pt-BR')} → ${t.toLocaleString('pt-BR')}, ${horas}h)`;
  }
  return (PRESETS.find((p) => p.minutes === minutes) || { label: `Últimos ${minutes} min` }).label.toLowerCase();
}

function InventoryContext({ data }) {
  if (!data) return null;
  return (
    <section className="inventory-context">
      <div className="talker-top">
        <b>{data.serverName}</b>
        <span className="badge low">Inventário</span>
      </div>
      {!data.applications?.length ? <p className="hint">Nenhuma aplicação cadastrada para esta máquina.</p> : (
        <div className="inventory-context-apps">
          {data.applications.map((app) => (
            <div key={app.id}>
              <b>{app.name}</b>
              {app.listeners?.length ? (
                <div className="tlegend">
                  {app.listeners.map((listener) => <span key={listener.id}>{listener.ip} · {listener.protocol}/{listener.port}</span>)}
                </div>
              ) : <p className="hint">Sem listener configurado.</p>}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// Cor do nó: internos ciano; IP público usa a faixa numérica de reputação.
const NODE_COLORS = { private: '#22d3ee', subnet: '#7c3aed' };
const REP_COLORS = { bad: '#ef4444', orange: '#f97316', yellow: '#eab308', good: '#22c55e', unknown: '#94a3b8' };
const RISK_COLORS = { none: '#22c55e', low: '#eab308', med: '#f97316', high: '#ef4444', critical: '#b91c1c', parcial: '#94a3b8', indisponivel: '#64748b' };
const RISK_LABELS = { none: 'sem risco nos avaliados', low: 'baixo', med: 'médio', high: 'alto', critical: 'crítico', parcial: 'avaliação parcial', indisponivel: 'indisponível' };

function repColorForScore(score) {
  if (score == null || score === '') return REP_COLORS.unknown;
  const value = Number(score);
  if (!Number.isFinite(value)) return REP_COLORS.unknown;
  if (value > 70) return REP_COLORS.bad;
  if (value > 50) return REP_COLORS.orange;
  if (value >= 20) return REP_COLORS.yellow;
  return REP_COLORS.good;
}

function FortigatePage() {
  const [firewalls, setFirewalls] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState({ name: '', host: '', vdom: 'root', token: '' });
  const [policiesData, setPoliciesData] = useState(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState('');
  const [sort, setSort] = useState('hits');
  const [offset, setOffset] = useState(0);
  const [detail, setDetail] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analysisTarget, setAnalysisTarget] = useState(null);
  const analysisRequestRef = useRef(0);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState('');
  const [staleDays, setStaleDays] = useState(90);
  const [analysisSeverity, setAnalysisSeverity] = useState('todas');
  const [expandedFindingId, setExpandedFindingId] = useState(null);

  const selected = firewalls.find((item) => item.id === selectedId) || null;

  async function loadFirewalls(preferredId = selectedId) {
    setLoading(true);
    setError('');
    try {
      const result = await fetchFortigates();
      const items = result.firewalls || [];
      setFirewalls(items);
      setSelectedId(items.some((item) => item.id === preferredId) ? preferredId : items[0]?.id ?? null);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadFirewalls(null); }, []);

  useEffect(() => {
    if (!selectedId) {
      setPoliciesData(null);
      return undefined;
    }
    let cancelled = false;
    setPolicyLoading(true);
    setPolicyError('');
    fetchFortigatePolicies(selectedId, { limit: 20, sort, offset, vdom: firewalls.find((item) => item.id === selectedId)?.vdom || 'root' })
      .then((data) => { if (!cancelled) setPoliciesData(data); })
      .catch((e) => { if (!cancelled) setPolicyError(String(e.message || e)); })
      .finally(() => { if (!cancelled) setPolicyLoading(false); });
    return () => { cancelled = true; };
  }, [selectedId, sort, offset, firewalls]);

  function resetForm() {
    setEditingId(null);
    setForm({ name: '', host: '', vdom: 'root', token: '' });
  }

  async function saveFirewall(event) {
    event.preventDefault();
    setBusy('save');
    setError('');
    setMessage('');
    try {
      if (editingId) {
        const result = await updateFortigate(editingId, form);
        await loadFirewalls(result.firewall?.id || editingId);
        setMessage('FortiGate atualizado.');
      } else {
        const result = await createFortigate(form);
        await loadFirewalls(result.firewall?.id);
        setMessage('FortiGate cadastrado.');
      }
      resetForm();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy('');
    }
  }

  async function runTest(firewall) {
    setBusy(`test-${firewall.id}`);
    setMessage('');
    setError('');
    try {
      const result = await testFortigate(firewall.id);
      setMessage(`Conexão OK · ${result.policies} políticas${result.version ? ` · FortiOS ${result.version}` : ''}.`);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy('');
    }
  }

  async function removeFirewall(firewall) {
    if (!confirm(`Remover ${firewall.name} (${firewall.host}) do inventário?`)) return;
    setBusy(`delete-${firewall.id}`);
    try {
      await deleteFortigate(firewall.id);
      if (analysisTarget?.id === firewall.id) {
        setAnalysis(null);
        setAnalysisTarget(null);
      }
      resetForm();
      await loadFirewalls(null);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy('');
    }
  }

  async function showPolicy(policyId, firewallId = selectedId, vdom = selected?.vdom || 'root') {
    setDetail({ loading: true, policyId });
    try {
      const result = await fetchFortigatePolicyDetail(firewallId, policyId, vdom);
      setDetail({ policyId, policy: result.policy, revision: result.revision });
    } catch (e) {
      setDetail({ policyId, error: String(e.message || e) });
    }
  }

  async function runAnalysis(firewall) {
    if (!firewall) return;
    const requestId = analysisRequestRef.current + 1;
    analysisRequestRef.current = requestId;
    setSelectedId(firewall.id);
    setAnalysisTarget({ id: firewall.id, name: firewall.name, host: firewall.host, vdom: firewall.vdom || 'root' });
    setAnalysis({ loading: true });
    setAnalysisError('');
    setAnalysisLoading(true);
    try {
      const result = await fetchFortigateAnalysis(firewall.id, { staleDays, vdom: firewall.vdom || 'root' });
      if (analysisRequestRef.current === requestId) setAnalysis(result);
    } catch (e) {
      if (analysisRequestRef.current === requestId) {
        setAnalysis(null);
        setAnalysisError(String(e.message || e));
      }
    } finally {
      if (analysisRequestRef.current === requestId) setAnalysisLoading(false);
    }
  }

  function closeAnalysis() {
    analysisRequestRef.current += 1;
    setAnalysis(null);
    setAnalysisTarget(null);
    setAnalysisError('');
    setAnalysisLoading(false);
  }

  const dateValue = (value) => {
    if (value == null || value === 0) return '—';
    const n = Number(value);
    const date = new Date(n > 1e12 ? n : n * 1000);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('pt-BR');
  };
  const severityLabel = (value) => ({ alta: 'Alta', media: 'Média', baixa: 'Baixa' }[value] || value || '—');
  const findingClass = (value) => ({ alta: 'high', media: 'med', baixa: 'low' }[value] || 'low');
  const shownFindings = (analysis?.findings || []).filter((finding) => analysisSeverity === 'todas' || finding.severity === analysisSeverity);
  const detailValue = (value) => Array.isArray(value) ? value.join(', ') : (typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value));

  return (
    <main className="page-fortigate">
      <div className="page-head fortigate-page-head">
        <div className="page-title">
          <span className="fortigate-page-icon" aria-hidden="true">FG</span>
          <div><h2>FortiGate</h2><span className="hint">Gestão de firewalls e análise consultiva de políticas</span></div>
        </div>
        <div className="page-actions">
          <span className="fortigate-count"><b>{firewalls.length}</b><span>firewalls cadastrados</span></span>
          <button className="ghost" onClick={() => loadFirewalls()} disabled={loading} aria-label="Atualizar lista">↻ Atualizar</button>
        </div>
      </div>
      <div className="page-body fortigate-body">
        {error && <p className="error">{error}</p>}
        {message && <p className="hint">{message}</p>}
        <section className="inventory-add-panel fortigate-add-panel">
          <div className="inventory-add-heading">
            <span className="fortigate-step">{editingId ? 'CONFIGURAÇÃO' : 'NOVO EQUIPAMENTO'}</span>
            <h3>{editingId ? `Editar ${form.name || 'FortiGate'}` : 'Adicionar firewall'}</h3>
            <p className="hint">Credenciais protegidas com AES-256-GCM. O token não é mostrado após salvar.</p>
          </div>
          <form className="cmp-form inventory-create-form" onSubmit={saveFirewall}>
            <label className="fortigate-field"><span>Nome de identificação</span><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Ex.: FGT-Matriz" required /></label>
            <label className="fortigate-field"><span>Endereço do equipamento</span><input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="IP ou hostname" required /></label>
            <label className="fortigate-field"><span>{editingId ? 'Substituir token (opcional)' : 'Token de API'}</span><input type="password" value={form.token} onChange={(e) => setForm({ ...form, token: e.target.value })} placeholder={editingId ? 'Deixe vazio para manter o atual' : 'Token API'} required={!editingId} autoComplete="new-password" /></label>
            <button className="fortigate-submit" type="submit" disabled={busy === 'save'}>{busy === 'save' ? 'Salvando…' : editingId ? 'Salvar alterações' : 'Cadastrar'}</button>
            {editingId && <button type="button" className="ghost" onClick={resetForm}>Cancelar</button>}
          </form>
        </section>
        {loading && <p className="hint">Carregando firewalls…</p>}
        {!loading && !firewalls.length && <p className="empty">Nenhum FortiGate cadastrado.</p>}
        {!!firewalls.length && (
          <div className="inventory-workspace fortigate-workspace">
            <section className="inventory-machine-panel fortigate-list-panel">
              <div className="inventory-panel-head"><div><h3>Equipamentos</h3><span className="hint">Selecione um firewall para ver as políticas</span></div><span className="badge low">{firewalls.length}</span></div>
              <div className="inventory-machine-list fortigate-list">
                {firewalls.map((firewall) => (
                  <article key={firewall.id} className={`fortigate-card${selectedId === firewall.id ? ' active' : ''}`} onClick={() => setSelectedId(firewall.id)}>
                    <div className="fortigate-card-head">
                      <span className="fortigate-device-icon" aria-hidden="true">▣</span>
                      <div className="fortigate-device-info"><b>{firewall.name}</b><span className="mono">{firewall.host}</span></div>
                      <span className="fortigate-vdom">{firewall.vdom || 'root'}</span>
                    </div>
                    <div className="fortigate-card-meta"><span><i className={`fortigate-token-dot${firewall.hasToken ? ' on' : ''}`} />{firewall.hasToken ? 'Token configurado' : 'Token ausente'}</span><span>ID {firewall.id}</span></div>
                    <div className="fortigate-card-actions" onClick={(e) => e.stopPropagation()}>
                      <button className="fortigate-analyze-button" onClick={() => runAnalysis(firewall)} disabled={analysisLoading}>{analysisLoading && analysisTarget?.id === firewall.id ? 'Analisando…' : 'Análise inteligente'}</button>
                      <button className="ghost" onClick={() => runTest(firewall)} disabled={busy === `test-${firewall.id}`}>{busy === `test-${firewall.id}` ? 'Testando…' : 'Testar'}</button>
                      <button className="ghost" onClick={() => { setEditingId(firewall.id); setForm({ name: firewall.name, host: firewall.host, vdom: firewall.vdom || 'root', token: '' }); }}>Editar</button>
                      <button className="ghost fortigate-remove-button" onClick={() => removeFirewall(firewall)} disabled={busy === `delete-${firewall.id}`}>Remover</button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
            <section className="inventory-machine-panel fortigate-policies">
              <div className="dashboard-section-head">
                <div><h3>{selected?.name || 'Políticas'}</h3><span className="hint">{selected?.host || ''} · VDOM {selected?.vdom || 'root'}</span></div>
                <div className="page-actions">
                  <label className="dashboard-period-select"><span>Ordenar</span><select value={sort} onChange={(e) => { setSort(e.target.value); setOffset(0); }}><option value="hits">Hits</option><option value="bytes">Bytes</option><option value="packets">Pacotes</option><option value="sessions">Sessões</option></select></label>
                </div>
              </div>
              <p className="hint">Hits, bytes e pacotes são os contadores atuais retornados pelo FortiGate; primeira e última utilização são os timestamps informados pelo próprio equipamento.</p>
              {policyError && <p className="error">{policyError}</p>}
              {policyLoading ? <p className="hint">Consultando políticas no FortiGate…</p> : !selected ? <p className="hint">Selecione um firewall.</p> : !policiesData ? <p className="hint">Sem dados de política.</p> : (
                <>
                  <div className="table-wrap">
                    <table className="dashboard-data-table">
                      <thead><tr><th>Política</th><th>Posição</th><th>Hits</th><th>Bytes</th><th>Pacotes</th><th>Sessões</th><th>Primeiro uso</th><th>Último uso</th></tr></thead>
                      <tbody>{(policiesData.policies || []).map((policy) => (
                        <tr key={policy.policyid} className="fgt-policy-row" onClick={() => showPolicy(policy.policyid)}>
                          <td><b>{policy.name || `Policy ${policy.policyid}`}</b><small>{policy.policyid}</small></td>
                          <td>{policy.position ?? '—'}</td><td>{policy.hitCount ?? 0}</td><td>{fmtBytes(policy.bytes || 0)}</td><td>{policy.packets ?? 0}</td><td>{policy.activeSessions ?? policy.sessionCount ?? 0}</td>
                          <td>{dateValue(policy.firstUsed)}</td><td>{dateValue(policy.lastUsed)}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                  <div className="pager">
                    <span>{policiesData.total ?? 0} políticas · página {policiesData.page ?? 1} de {policiesData.pages ?? 1}</span>
                    <button className="ghost" disabled={offset <= 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Anterior</button>
                    <button className="ghost" disabled={offset + 20 >= (policiesData.total || 0)} onClick={() => setOffset(offset + 20)}>Próxima</button>
                  </div>
                </>
              )}
            </section>
          </div>
        )}
      </div>
      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal modal-wide fgt-detail" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head"><div><h2>Política {detail.policyId}</h2><span className="hint">{detail.policy?.name || 'Detalhes da configuração'}</span></div><button className="ghost" onClick={() => setDetail(null)}>✕</button></div>
            <div className="modal-body">
              {detail.loading ? <p className="hint">Lendo configuração…</p> : detail.error ? <p className="error">{detail.error}</p> : detail.policy && (() => {
                const policy = detail.policy;
                const sections = [
                  ['Geral', { policyid: policy.policyid, uuid: policy.uuid, comments: policy.comments, status: policy.status, action: policy.action, schedule: policy.schedule, policyExpiry: policy.policyExpiry, policyExpiryDateUtc: policy.policyExpiryDateUtc }],
                  ['Fluxo', policy.flow], ['Serviços e NAT', policy.services], ['Segurança e inspeção', policy.security], ['Performance', policy.performance]
                ];
                return <>{sections.map(([title, values]) => (
                  <section className="fgt-sec" key={title}><h4>{title}</h4><div className="fgt-g">{Object.entries(values || {}).filter(([, value]) => value != null && value !== '').map(([key, value]) => (
                    <div className="fgt-kv" key={key}><span>{key}</span><b className="mono">{detailValue(value)}</b></div>
                  ))}</div></section>
                ))}{policy.advanced?.length > 0 && <section className="fgt-sec fgt-adv"><h4>Campos avançados</h4><div className="fgt-g">{policy.advanced.map((item) => <div className="fgt-kv" key={item.key}><span>{item.key}</span><b className="mono">{item.value}</b></div>)}</div></section>}</>;
              })()}
            </div>
          </div>
        </div>
      )}
      {(analysis || analysisError) && (
        <div className="modal-backdrop" onClick={closeAnalysis}>
          <div className="modal modal-wide fgt-analysis" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head"><div><h2>Análise inteligente · {analysisTarget?.name}</h2><span className="hint">{analysisTarget?.host} · VDOM {analysisTarget?.vdom} · análise somente leitura</span></div><button className="ghost" onClick={closeAnalysis}>✕</button></div>
            <div className="modal-body">
              <div className="fgt-an-toolbar"><label className="field"><span>Inatividade para regra obsoleta</span><select value={staleDays} onChange={(e) => setStaleDays(Number(e.target.value))}><option value={30}>30 dias</option><option value={60}>60 dias</option><option value={90}>90 dias</option><option value={180}>180 dias</option></select></label><label className="field"><span>Severidade</span><select value={analysisSeverity} onChange={(e) => setAnalysisSeverity(e.target.value)}><option value="todas">Todas</option><option value="alta">Alta</option><option value="media">Média</option><option value="baixa">Baixa</option></select></label><button className="ghost" onClick={() => runAnalysis(analysisTarget)} disabled={analysisLoading}>Recalcular</button></div>
              {analysisError && <p className="error">{analysisError}</p>}
              {analysis?.loading && <p className="hint">Analisando configuração e uso…</p>}
              {analysis?.summary && <div className="fgt-an-summary"><span className="badge low">{analysis.summary.totalPolicies} políticas</span><span className="badge low">{analysis.summary.policiesWithStats} com estatística</span><span className="badge med">{analysis.summary.findings} achados</span></div>}
              {!!analysis?.findings?.length && <div className="fgt-an-list">{shownFindings.map((finding, index) => {
                const findingId = finding.id || `${finding.rule}-${finding.policyid}-${index}`;
                const expanded = expandedFindingId === findingId;
                return (
                <article className="inventory-machine-row" key={findingId} onClick={() => setExpandedFindingId(expanded ? null : findingId)}>
                  <i className={`fgt-an-sev ${findingClass(finding.severity)}`} />
                  <div className="fgt-an-title"><b>{finding.category || finding.rule}</b><small>{finding.policyName || `Policy ${finding.policyid}`} · posição {finding.position || '—'} · {finding.rule}</small><p className="hint">{finding.problem}</p>
                    {expanded && <div className="fgt-an-block">
                      <h5>Recomendação</h5><p>{finding.recommendation}</p>
                      <div className="fgt-an-badges"><span className="badge low">Impacto: {finding.impact}</span><span className="badge med">Risco da mudança: {finding.changeRisk}</span></div>
                      {!!finding.evidence?.length && <><h5>Evidências</h5><ul>{finding.evidence.map((line, i) => <li key={i}>{line}</li>)}</ul></>}
                      {finding.validation && <div className="fgt-an-validate"><h5>Validar antes de mudar</h5><p>{finding.validation}</p></div>}
                      <button className="ghost" onClick={(event) => { event.stopPropagation(); closeAnalysis(); showPolicy(finding.policyid, analysisTarget?.id, analysisTarget?.vdom); }}>Ver política</button>
                    </div>}
                  </div>
                  <div className="fgt-an-badges"><span className={`badge ${findingClass(finding.severity)}`}>{severityLabel(finding.severity)}</span>{finding.confidence && <span className="badge low">Confiança: {finding.confidence}</span>}<span className="fgt-an-caret">{expanded ? '▾' : '▸'}</span></div>
                </article>
              );})}</div>}
              {!analysis?.loading && !analysisError && analysis && !shownFindings.length && <p className="hint">Nenhum achado para este filtro com os dados disponíveis.</p>}
              {!!analysis?.limitations?.length && <details className="howto"><summary>Limitações da análise</summary><ul>{analysis.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details>}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

export default function App() {
  const cyRef = useRef(null);
  const cy = useRef(null);
  // Espelho p/ as funções de estilo do Cytoscape lerem valores frescos
  // sem reconstruir o grafo (é isso que impede o mapa de se mexer sozinho)
  const uiRef = useRef({ showNames: false, inventoryNames: {}, showPorts: true, repMap: {} });
  // Maior volume (bytes) entre os nós da janela: normaliza o tamanho dos nós
  const volRef = useRef({ max: 1 });
  // Desregistra o listener de mouseleave do canvas a cada recriação do grafo
  const tipAbortRef = useRef(null);
  // Container do Cytoscape mudou de tamanho / nasceu degenerado
  const roRef = useRef(null);
  const [minutes, setMinutes] = useState(15);
  const [custom, setCustom] = useState({ from: '', to: '' });
  const [useCustom, setUseCustom] = useState(false);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [hostDetail, setHostDetail] = useState(null);
  const [edgeInfo, setEdgeInfo] = useState(null);
  const [minBytes, setMinBytes] = useState(0);
  const [protoFilter, setProtoFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [spacing, setSpacing] = useState(420);
  const [layoutName, setLayoutName] = useState('cose');
  const [showPorts, setShowPorts] = useState(true);
  const [view, setView] = useState('hosts'); // hosts | subnets
  const [showNames, setShowNames] = useState(true);
  const [focusSubnet, setFocusSubnet] = useState(null);
  const [focusHost, setFocusHost] = useState(null); // mapa mostra só este host + vizinhos
  const [subnetEmpty, setSubnetEmpty] = useState(''); // sub-rede escolhida sem tráfego na janela
  const [repMap, setRepMap] = useState({});
  const [repLoading, setRepLoading] = useState(false);
  // De onde veio o veredito: memória | postgres (X dias) | agora | sem cache.
  const [repCov, setRepCov] = useState({});
  const [repMsg, setRepMsg] = useState(null);
  const [repQuota, setRepQuota] = useState(null);
const [perfMode, setPerfMode] = useState(false);
  const [tip, setTip] = useState(null); // tooltip do mapa: { x, y, flip, title, badge, rows }
  const [isolate, setIsolate] = useState(true); // apagar o resto ao selecionar um host
  const [ipModal, setIpModal] = useState(null); // { loading, ip } | dossiê | { ip, error }
  const [cmpOpen, setCmpOpen] = useState(false);
  const [pairsOpen, setPairsOpen] = useState(false);

  // Página "Reputação": base e cobertura do cache.
  const [repDbOpen, setRepDbOpen] = useState(false);
  const repReturnDashboardRef = useRef(true);
  const [repTab, setRepTab] = useState('base'); // base | cobertura
  const [repDb, setRepDb] = useState(null);
  const [repDbLoading, setRepDbLoading] = useState(false);
  const [repHarvesting, setRepHarvesting] = useState(false);
  const [repHarvestMsg, setRepHarvestMsg] = useState(null);
  const [repDbDays, setRepDbDays] = useState(7); // janela máxima de 7 dias
  const [repDbOrder, setRepDbOrder] = useState('rep');
  const [repDbCountry, setRepDbCountry] = useState(null);
  const [repDbIp, setRepDbIp] = useState(null);

  const PERIODOS = [
    { v: 1, label: '24 horas' },
    { v: 7, label: '7 dias' }
  ];

  async function loadRepDb(days = repDbDays, order = repDbOrder) {
    // A lista e a ordenação mudam: a página 7 da ordenação anterior não
    // significa nada na nova.
    setPgBase(0); setRepDbCountry(null); setRepDbIp(null);
    setRepDbLoading(true);
    try {
      setRepDb(await fetchReputationDb({ days, order }));
    } catch {
      setRepDb({ error: true });
    } finally {
      setRepDbLoading(false);
    }
  }

  // A tela de reputação limita a base à retenção disponível no ES.
  async function setPeriodo(days) {
    setRepDbDays(days);
    setRepDbCountry(null);
    setRepDbIp(null);
    await loadRepDb(days, repDbOrder);
  }

  // Abre a base e carrega a cobertura para que o botão mostre quantos IPs faltam.
  function openRep(tab = 'base') {
    setFortigateOpen(false);
    if (!repDbOpen) repReturnDashboardRef.current = dashboardOpen;
    setDashboardOpen(false);
    setRepDbOpen(true);
    setRepTab(tab);
    loadRepDb(repDbDays, repDbOrder);
    loadRepCoverage(publicIps);
  }

  // Sair da página devolve o mapa. O relayout é explícito porque o cytoscape
  // ficou com container de tamanho zero enquanto a página estava aberta — sem
  // isso o grafo volta achatado.
  function closeRep() {
    setRepDbOpen(false);
    const returnToDashboard = repReturnDashboardRef.current;
    setDashboardOpen(returnToDashboard);
    setSelected(null);
    setEdgeInfo(null);
    if (!returnToDashboard) requestAnimationFrame(() => {
      cy.current?.resize();
      relayout();
    });
}

  function openDashboard(tab = 'applications') {
    setFortigateOpen(false);
    setRepDbOpen(false);
    setDashboardOpen(true);
    setDashboardTab(tab);
    if (!inventoryLoading) loadInventory();
  }

  function closeDashboard() {
    setDashboardOpen(false);
    setDashboardData(null);
    requestAnimationFrame(() => {
      cy.current?.resize();
      relayout();
    });
  }

  function openMap() {
    setFortigateOpen(false);
    setRepDbOpen(false);
    closeDashboard();
  }

  // Exposição a risco (IP malicioso) por host interno
  const [riskMap, setRiskMap] = useState({});

  // Tela "Exposição": indicadores de risco, entrada, novidade e atividade recente.
  const [expOpen, setExpOpen] = useState(false);
  const [expTab, setExpTab] = useState('risk'); // risk | inbound | new | sessions
  const [expData, setExpData] = useState({ risk: null, inbound: null, newExt: null, sessions: null });
  const [expLoading, setExpLoading] = useState(false);
  const [expIp, setExpIp] = useState(null);
  const [beacon, setBeacon] = useState(null); // { src, dst, data }

  // Carrega as quatro visões em paralelo. Uma falha não derruba as outras:
  // cada aba mostra o próprio erro e as demais continuam utilizáveis.
  async function loadExposure() {
    setExpLoading(true);
    setExpData({ risk: null, inbound: null, newExt: null, sessions: null });
    setExpIp(null);
    setRiskMap({});
    setBeacon(null);
    const win = useCustom && custom.from && custom.to
      ? { from: custom.from, to: custom.to }
      : { minutes };
    const jobs = {
      risk: fetchRisk({ ...win, only: 'withbad', limit: 200 }).then((d) => { setRiskMap(Object.fromEntries((d.hosts || []).map((h) => [h.ip, h]))); return d; }),
      inbound: fetchInbound({ ...win, limit: 500 }),
      newExt: fetchNewExternal({ ...win, onlyNew: true, limit: 200 }),
      sessions: fetchSessions({ ...win, activeSec: 120 })
    };
    const settled = await Promise.allSettled(Object.values(jobs));
    const keys = Object.keys(jobs);
    const out = {};
    settled.forEach((s, i) => { out[keys[i]] = s.status === 'fulfilled' ? s.value : { error: String(s.reason?.message || s.reason) }; });
    setExpData((prev) => ({ ...prev, ...out }));
    setExpLoading(false);
  }

  // Periodicidade de UM par — só dispara quando o usuário escolhe o par,
  // porque a query traz hits e não pode varrer o índice.
  async function loadBeacon(src, dst) {
    setBeacon({ src, dst, data: null });
    try {
      setBeacon({ src, dst, data: await fetchBeacon(src, dst, { minutes: 240 }) });
    } catch (e) {
      setBeacon({ src, dst, error: String(e.message || e) });
    }
  }

  // Lista os IPs de uma região com os vereditos mais problemáticos primeiro.
  function repDbIpsOf(country) {
    const list = (repDb?.ips || []).filter((x) => (x.country || '??') === country);
    const rank = (v) => ({ malicious: 0, suspicious: 0, unknown: 1, clean: 2 }[v] ?? 1);
    return list.sort((a, b) => rank(a.verdict) - rank(b.verdict)
      || (b.score || 0) - (a.score || 0) || (b.reports || 0) - (a.reports || 0));
  }

  const [pairsData, setPairsData] = useState(null);
  const [pairsLoading, setPairsLoading] = useState(false);
  const [pairsSubnet, setPairsSubnet] = useState('');
  const [pairsMinutes, setPairsMinutes] = useState(60);

  // Sub-redes monitoradas (🗺 Subnets). Sobreviveu à remoção da feature de
  // vigilância: serve ao filtro do mapa e ao "abre junto com o sistema".
  const [watchSubnets, setWatchSubnets] = useState(null);
  const [subnetsOpen, setSubnetsOpen] = useState(false);
  const [newCidr, setNewCidr] = useState('');
  const [newCidrName, setNewCidrName] = useState('');
  const [watchBusy, setWatchBusy] = useState('');
  const [watchError, setWatchError] = useState('');
  const defaultAppliedRef = useRef(false);

  // Inventário manual de servidores e listeners. IDs são do Postgres; o
  // formulário pede apenas nome/IP e os detalhes de aplicação.
  const [inventoryOpen, setInventoryOpen] = useState(false);
  const [fortigateOpen, setFortigateOpen] = useState(false);
  const inventoryReturnMapRef = useRef(false);
  const inventoryNewApplicationRef = useRef(null);
  const [inventoryData, setInventoryData] = useState([]);
  const [inventorySelectedId, setInventorySelectedId] = useState(null);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [inventoryBusy, setInventoryBusy] = useState('');
  const [inventoryError, setInventoryError] = useState('');
  const [newServerName, setNewServerName] = useState('');
  const [newServerIp, setNewServerIp] = useState('');
  const [newServerIps, setNewServerIps] = useState({});
  const [applicationDrafts, setApplicationDrafts] = useState({});
  const [listenerDrafts, setListenerDrafts] = useState({});
  const [expectedClientDrafts, setExpectedClientDrafts] = useState({});
  const [inventoryEdit, setInventoryEdit] = useState(null);
  const [dashboardOpen, setDashboardOpen] = useState(true);
  const [dashboardTab, setDashboardTab] = useState('applications');
  const [dashboardServerId, setDashboardServerId] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState('');
  const [dashboardPortsData, setDashboardPortsData] = useState(null);
  const [dashboardPortsLoading, setDashboardPortsLoading] = useState(false);
  const [dashboardPortsError, setDashboardPortsError] = useState('');
  const [dashboardConversationsData, setDashboardConversationsData] = useState(null);
  const [dashboardConversationsLoading, setDashboardConversationsLoading] = useState(false);
  const [dashboardConversationsError, setDashboardConversationsError] = useState('');
  const [topTalkersForm, setTopTalkersForm] = useState({ top: '5', time: '1h', flowType: 'ingress' });
  const [topTalkersConfig, setTopTalkersConfig] = useState({ top: 5, time: '1h', flowType: 'ingress' });
  const [dashboardRefresh, setDashboardRefresh] = useState(0);

  function pairsSubnetOptions() {
    // SOMENTE sub-redes cadastradas (nada de /24 automática de IP público)
    return (watchSubnets || [])
      .map((s) => [s.cidr, s.name ? `${s.name} (${s.cidr})` : s.cidr])
      .sort((a, b) => (a[0] < b[0] ? -1 : 1));
  }

  const [lkOpen, setLkOpen] = useState(false);
  const [lkIp, setLkIp] = useState('');
  const [lkDays, setLkDays] = useState(7);
  const [lkData, setLkData] = useState(null);
  const [lkLoading, setLkLoading] = useState(false);
  const [lkError, setLkError] = useState('');

  async function runLookup(ip, days) {
    if (!ip?.trim()) { setLkError('Informe um IP.'); return; }
    setLkLoading(true); setLkError(''); setLkData(null);
    try {
      setLkData(await lookupIp(ip.trim(), days));
    } catch (e) {
      setLkError(String(e.message || e));
    } finally {
      setLkLoading(false);
    }
  }

  // Só as sub-redes: a parte de vigiar host foi removida.
  async function loadWatch() {
    setWatchError('');
    try {
      const n = await getWatchSubnets();
      if (n.subnets !== null) setWatchSubnets(n.subnets);
    } catch (e) {
      setWatchError(String(e.message || e));
    }
  }

  // Subnet default na abertura: aplica 1x quando os dados chegam.
  // NÃO espera o grafo: se esperasse, o primeiro layout rodaria com "Todas" e a
  // aplicação do default viraria uma segunda montagem no meio da animação,
  // herdando as posições pela metade (mapa em branco ou pilhado).
  useEffect(() => {
    if (defaultAppliedRef.current || !watchSubnets || focusSubnet || focusHost) return;
    const def = watchSubnets.find((s) => s.is_default && s.cidr);
    if (def) {
      defaultAppliedRef.current = true;
      setView('hosts');
      setFocusSubnet(def.cidr);
    }
  }, [watchSubnets, focusSubnet, focusHost]);

  async function doWatch(fn, busy) {
    setWatchBusy(busy); setWatchError('');
    try { await fn(); await loadWatch(); }
    catch (e) { setWatchError(String(e.message || e)); }
    finally { setWatchBusy(''); }
  }

  async function loadInventory() {
    setInventoryLoading(true);
    setInventoryError('');
    try {
      const data = await fetchInventory();
      const servers = data.servers || [];
      setInventoryData(servers);
      setInventorySelectedId((current) => current && servers.some((server) => server.id === current)
        ? current : servers[0]?.id ?? null);
      setDashboardServerId((current) => current && servers.some((s) => s.id === current)
        ? current : servers[0]?.id ?? null);
    } catch (e) {
      setInventoryError(String(e.message || e));
    } finally {
      setInventoryLoading(false);
    }
  }

  useEffect(() => { loadInventory(); }, []);

  useEffect(() => {
    if (!dashboardOpen || inventoryLoading) return;
    if (!inventoryData.length) {
      if (dashboardServerId !== null) setDashboardServerId(null);
      return;
    }
    if (!inventoryData.some((server) => server.id === dashboardServerId)) {
      setDashboardServerId(inventoryData[0].id);
    }
  }, [dashboardOpen, inventoryLoading, inventoryData, dashboardServerId]);

  useEffect(() => {
    if (!dashboardOpen || dashboardTab !== 'applications' || inventoryLoading || !dashboardServerId) {
      setDashboardData(null);
      setDashboardLoading(false);
      return;
    }
    let cancelled = false;
    setDashboardLoading(true);
    setDashboardError('');
    setDashboardData(null);
    const params = useCustom && custom.from && custom.to
      ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
      : { minutes };
    fetchDashboardApplications(dashboardServerId, params)
      .then((data) => { if (!cancelled) setDashboardData(data); })
      .catch((error) => { if (!cancelled) setDashboardError(String(error.message || error)); })
      .finally(() => { if (!cancelled) setDashboardLoading(false); });
    return () => { cancelled = true; };
  }, [dashboardOpen, dashboardTab, inventoryLoading, dashboardServerId, minutes, useCustom, custom.from, custom.to, dashboardRefresh]);

  useEffect(() => {
    if (!dashboardOpen || dashboardTab !== 'ports' || inventoryLoading || !dashboardServerId) {
      setDashboardPortsData(null);
      setDashboardPortsLoading(false);
      return;
    }
    let cancelled = false;
    setDashboardPortsLoading(true);
    setDashboardPortsError('');
    setDashboardPortsData(null);
    const params = useCustom && custom.from && custom.to
      ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
      : { minutes };
    fetchDashboardPorts(dashboardServerId, params)
      .then((data) => { if (!cancelled) setDashboardPortsData(data); })
      .catch((error) => { if (!cancelled) setDashboardPortsError(String(error.message || error)); })
      .finally(() => { if (!cancelled) setDashboardPortsLoading(false); });
    return () => { cancelled = true; };
  }, [dashboardOpen, dashboardTab, inventoryLoading, dashboardServerId, minutes, useCustom, custom.from, custom.to, dashboardRefresh]);

  useEffect(() => {
    if (!dashboardOpen || dashboardTab !== 'topTalkers' || inventoryLoading) {
      setDashboardConversationsData(null);
      setDashboardConversationsLoading(false);
      return;
    }
    let cancelled = false;
    setDashboardConversationsLoading(true);
    setDashboardConversationsError('');
    setDashboardConversationsData(null);
    fetchDashboardConversations(topTalkersConfig)
      .then((data) => {
        if (cancelled) return;
        setDashboardConversationsData(data);
        const publicEndpoints = data.pairs.flatMap((pair) => [pair.a, pair.b]).filter(isPublicIp);
        if (publicEndpoints.length) loadRepCoverage(publicEndpoints);
      })
      .catch((error) => { if (!cancelled) setDashboardConversationsError(String(error.message || error)); })
      .finally(() => { if (!cancelled) setDashboardConversationsLoading(false); });
    return () => { cancelled = true; };
  }, [dashboardOpen, dashboardTab, inventoryLoading, topTalkersConfig.top, topTalkersConfig.time, topTalkersConfig.flowType, dashboardRefresh]);

  async function doInventoryAction(key, action) {
    setInventoryBusy(key);
    setInventoryError('');
    try {
      await action();
      await loadInventory();
    } catch (e) {
      setInventoryError(String(e.message || e));
    } finally {
      setInventoryBusy('');
    }
  }

  function openInventory() {
    setFortigateOpen(false);
    if (!inventoryOpen) inventoryReturnMapRef.current = !dashboardOpen && !repDbOpen;
    setInventoryOpen(true);
    if (!inventoryLoading) loadInventory();
  }

  function closeInventory() {
    setInventoryOpen(false);
    if (inventoryReturnMapRef.current) requestAnimationFrame(() => {
      cy.current?.resize();
      relayout();
    });
  }

  async function addInventoryServer() {
    const name = newServerName.trim();
    const ip = newServerIp.trim();
    await doInventoryAction('server-new', async () => {
      const { server } = await createInventoryServer({ name, ips: [ip] });
      setInventorySelectedId(server.id);
      setNewServerName('');
      setNewServerIp('');
    });
  }

  async function addInventoryIp(server) {
    const ip = String(newServerIps[server.id] || '').trim();
    await doInventoryAction(`ip-new-${server.id}`, async () => {
      await addServerIp(server.id, ip);
      setNewServerIps((all) => ({ ...all, [server.id]: '' }));
    });
  }

  async function removeInventoryServer(server) {
    if (!confirm(`Remover ${server.name}, seus IPs, aplicações e listeners? O histórico NetFlow não será apagado.`)) return;
    await doInventoryAction(`server-delete-${server.id}`, () => deleteInventoryServer(server.id));
  }

  async function removeInventoryIp(ip) {
    if (!confirm(`Remover o IP ${ip.ip}? Listeners associados a esse IP também serão removidos.`)) return;
    await doInventoryAction(`ip-delete-${ip.id}`, () => deleteServerIp(ip.id));
  }

  async function addInventoryApplication(server) {
    const draft = applicationDrafts[server.id] || { name: '', serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '' };
    const serverIpId = Number(draft.serverIpId || server.ips[0]?.id || 0);
    if (!serverIpId) { setInventoryError('Adicione um IP à máquina antes de cadastrar uma aplicação.'); return; }
    await doInventoryAction(`app-new-${server.id}`, async () => {
      await createInventoryApplication(server.id, {
        name: draft.name,
        listeners: [{ serverIpId, protocol: draft.protocol || 'TCP', port: Number(draft.port) }]
      });
      setApplicationDrafts((all) => ({ ...all, [server.id]: { name: '', serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '' } }));
    });
  }

  async function addInventoryListener(server, application) {
    const draft = listenerDrafts[application.id] || { serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '' };
    const serverIpId = Number(draft.serverIpId || server.ips[0]?.id || 0);
    if (!serverIpId) { setInventoryError('Adicione um IP à máquina antes de cadastrar um listener.'); return; }
    await doInventoryAction(`listener-new-${application.id}`, async () => {
      await addApplicationListener(application.id, {
        serverIpId, protocol: draft.protocol || 'TCP', port: Number(draft.port)
      });
      setListenerDrafts((all) => ({ ...all, [application.id]: { serverIpId: String(server.ips[0]?.id || ''), protocol: 'TCP', port: '' } }));
    });
  }

  async function removeInventoryApplication(application) {
    if (!confirm(`Remover a aplicação ${application.name} e seus listeners?`)) return;
    await doInventoryAction(`app-delete-${application.id}`, () => deleteInventoryApplication(application.id));
  }

  async function removeInventoryListener(listener) {
    if (!confirm(`Remover o listener ${listener.protocol}/${listener.port} em ${listener.ip}?`)) return;
    await doInventoryAction(`listener-delete-${listener.id}`, () => deleteApplicationListener(listener.id));
  }

  async function addExpectedClient(application) {
    const ip = String(expectedClientDrafts[application.id] || '').trim();
    await doInventoryAction(`expected-client-new-${application.id}`, async () => {
      await addExpectedApplicationClient(application.id, ip);
      setExpectedClientDrafts((all) => ({ ...all, [application.id]: '' }));
    });
  }

  async function removeExpectedClient(client) {
    await doInventoryAction(`expected-client-delete-${client.id}`, () => deleteExpectedApplicationClient(client.id));
  }

  async function saveInventoryEdit() {
    if (!inventoryEdit) return;
    const edit = inventoryEdit;
    await doInventoryAction(`rename-${edit.kind}-${edit.id}`, async () => {
      if (edit.kind === 'server') await renameInventoryServer(edit.id, edit.name);
      else await renameInventoryApplication(edit.id, edit.name);
      setInventoryEdit(null);
    });
  }

  function setApplicationDraft(serverId, field, value) {
    const firstIpId = String(inventoryData.find((s) => s.id === serverId)?.ips[0]?.id || '');
    setApplicationDrafts((all) => ({
      ...all,
      [serverId]: { ...(all[serverId] || { name: '', serverIpId: firstIpId, protocol: 'TCP', port: '' }), [field]: value }
    }));
  }

  function setListenerDraft(applicationId, field, value) {
    const owner = inventoryData.find((s) => s.applications.some((a) => a.id === applicationId));
    const firstIpId = String(owner?.ips[0]?.id || '');
    setListenerDrafts((all) => ({
      ...all,
      [applicationId]: { ...(all[applicationId] || { serverIpId: firstIpId, protocol: 'TCP', port: '' }), [field]: value }
    }));
  }

  const [cmpA, setCmpA] = useState('');
  const [cmpB, setCmpB] = useState('');
  const [cmpMinutes, setCmpMinutes] = useState(60);
  const [cmpData, setCmpData] = useState(null);
  const [cmpLoading, setCmpLoading] = useState(false);
  const [cmpError, setCmpError] = useState('');

  async function runCompare(a, b) {
    if (!a?.trim() || !b?.trim()) { setCmpError('Informe os dois IPs.'); return; }
    setCmpLoading(true); setCmpError(''); setCmpData(null);
    try {
      setCmpData(await compareHosts(a.trim(), b.trim(), { minutes: cmpMinutes }));
    } catch (e) {
      setCmpError(String(e.message || e));
    } finally {
      setCmpLoading(false);
    }
  }
  // Paginação padrão das listas curtas; a base de reputação usa páginas maiores.
  const PAGE = 5;
  const PAGE_REP = 25;
  const [pgRep, setPgRep] = useState(0);
  // Página da lista de IPs dentro de uma região, na aba Base. Estado separado do
  // pgRep porque é outra lista: avançar aqui não pode mexer no painel.
  const [pgBase, setPgBase] = useState(0);

  function pager(page, setPage, total, porPagina = PAGE) {
    const pages = Math.ceil(total / porPagina);
    if (pages <= 1) return null;
    return (
      <div className="pager">
        <button className="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>◀</button>
        <span>{page + 1}/{pages}</span>
        <button className="ghost" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>▶</button>
      </div>
    );
  }

  function lookupModal() {
    if (!lkOpen) return null;
    return (
        <div className="modal-backdrop" style={{ zIndex: 60 }} onClick={() => setLkOpen(false)}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>Buscar IP no histórico</h2><span className="hint">mesmo fora do mapa · conforme retenção do índice</span></div>
              <button className="ghost" onClick={() => setLkOpen(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="cmp-form">
                <input value={lkIp} onChange={(e) => setLkIp(e.target.value)} placeholder="IP — ex. 42.251.129.234" onKeyDown={(e) => e.key === 'Enter' && runLookup(lkIp, lkDays)} />
                <select value={lkDays} onChange={(e) => setLkDays(Number(e.target.value))} style={{ maxWidth: 110 }}>
                  <option value={7}>7 dias</option>
                </select>
                <button onClick={() => runLookup(lkIp, lkDays)} disabled={lkLoading}>{lkLoading ? '…' : 'Buscar'}</button>
              </div>
              {lkError && <p className="error">{lkError}</p>}
              {lkData && !lkData.found && <p className="hint">Nenhum fluxo desse IP nos últimos {lkData.days} dias (ou fora da retenção).</p>}
              {lkData?.found && (
                <>
                  <div className="kpis kpis-2">
                    <div><b>{new Date(lkData.firstSeen).toLocaleString('pt-BR')}</b><span>primeira vez</span></div>
                    <div><b>{new Date(lkData.lastSeen).toLocaleString('pt-BR')}</b><span>última vez</span></div>
                  </div>
                  <div className="kpis" style={{ marginTop: 8 }}>
                    <div><b>{fmtBytes(lkData.bytes)}</b><span>bytes</span></div>
                    <div><b>{lkData.flows}</b><span>fluxos</span></div>
                    <div><b>{lkData.peers.length}</b><span>peers</span></div>
                  </div>
                  <h3>Atividade por dia</h3>
                  <div className="tl">
                    {(() => {
                      const max = Math.max(1, ...lkData.daily.map((d) => d.bytes));
                      return lkData.daily.map((d, i) => (
                        <div key={i} className="tl-col" title={`${d.day} · ${fmtBytes(d.bytes)} · ${d.flows} fluxos`}>
                          <i className="tl-up" style={{ height: `${Math.max(3, (d.bytes / max) * 100)}%` }} />
                        </div>
                      ));
                    })()}
                  </div>
                  <p className="hint">dias: {lkData.daily.filter((d) => d.flows > 0).map((d) => d.day.slice(5)).join(', ') || '-'}</p>
                  <h3>Top peers</h3>
                  <div className="table-wrap"><table><thead><tr><th>Peer</th><th>Bytes</th><th>Fluxos</th></tr></thead>
                    <tbody>{lkData.peers.slice(0, 10).map((p) => (
                      <tr key={p.ip} className="clickable" onClick={() => { setLkIp(p.ip); runLookup(p.ip, lkDays); }}>
                        <td className="mono">{p.ip}</td><td>{fmtBytes(p.bytes)}</td><td>{p.flows}</td>
                      </tr>
                    ))}</tbody></table></div>
                  <h3>Portas envolvidas</h3>
                  <p className="mono" style={{ fontSize: 12 }}>{lkData.ports.map((p) => `${p.port ?? '?'} (${p.flows})`).join(', ') || '-'}</p>
                  <span>
                    <button className="ghost" onClick={() => openIpModal(lkData.ip)}>Dossiê</button>{' '}
                    <button className="ghost" onClick={() => { setLkOpen(false); focusIp(lkData.ip); }}>Localizar no mapa</button>
                  </span>
                </>
              )}
            </div>
          </div>
        </div>
    );
}

  // Ordem da lista: não confiáveis primeiro, depois o resto
  const VERDICT_RANK = { malicious: 0, suspicious: 0, unknown: 1, clean: 2, private: 3 };
  function sortedRepIps() {
    return publicIps
      .filter((ip) => repMap[ip])
      .sort((a, b) => {
        const ra = VERDICT_RANK[repMap[a]?.verdict] ?? 1;
        const rb = VERDICT_RANK[repMap[b]?.verdict] ?? 1;
        if (ra !== rb) return ra - rb;
        return (repMap[b]?.abuse?.score || 0) - (repMap[a]?.abuse?.score || 0) || (a < b ? -1 : 1);
      });
  }

  async function openIpModal(ip) {
    setIpModal({ loading: true, ip });
    try {
      const details = await fetchIpInfo(ip, timeParams());
      setIpModal(details);
      if (isPublicIp(ip)) {
        if (details.reputation) setRepMap((current) => ({ ...current, [ip]: details.reputation }));
        await loadRepCoverage([ip]);
      }
    } catch (e) {
      setIpModal({ ip, error: String(e.message || e) });
    }
  }

  // Esc fecha os modais
  useEffect(() => {
    if (!ipModal && !cmpOpen && !pairsOpen && !lkOpen && !subnetsOpen && !inventoryOpen && !repDbOpen && !dashboardOpen && !expOpen) return;
    const h = (e) => {
      if (e.key !== 'Escape') return;
      if (ipModal) { setIpModal(null); return; } // dossiê sobreposto: volta pro que estava atrás
      if (repDbIp) { setRepDbIp(null); return; } // fecha primeiro o detalhe do IP
      if (expIp) { setExpIp(null); return; } // idem na tela de exposição
      if (inventoryOpen) { closeInventory(); return; }
      if (dashboardOpen) { closeDashboard(); return; }
      setIpModal(null); setCmpOpen(false); setPairsOpen(false);
      setLkOpen(false); setSubnetsOpen(false); setInventoryOpen(false);
      if (repDbOpen) { closeRep(); return; } // página de reputação: Esc devolve o mapa
      setExpOpen(false); setBeacon(null);
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [ipModal, cmpOpen, pairsOpen, lkOpen, subnetsOpen, inventoryOpen, repDbOpen, repDbIp, dashboardOpen, expOpen, expIp]);

  async function loadPairs(minutes = pairsMinutes, subnet = pairsSubnet) {
    setPairsLoading(true);
    try {
      setPairsData(await topPairs({ minutes, subnet: subnet || undefined }));
    } catch {
      setPairsData({ error: true });
    } finally {
      setPairsLoading(false);
    }
  }

  function openCompare(a, b) {
    setPairsOpen(false);
    setCmpA(a); setCmpB(b); setCmpData(null); setCmpError('');
    setCmpOpen(true);
    runCompare(a, b);
  }

  // Só leitura: o que o backend já tem em memória/Postgres, sem gastar cota.
// Também preenche repMap com o que achar — é o que faz a lista aparecer sozinha.
async function loadRepCoverage(ips) {
  const list = [...new Set(ips)].filter(isPublicIp).slice(0, 300);
  if (!list.length) return {};
  try {
    const { coverage, quota } = await fetchRepCoverage(list);
    setRepCov((c) => ({ ...c, ...coverage }));
    if (quota) setRepQuota(quota);
    const cached = {};
    for (const [ip, c] of Object.entries(coverage)) if (c.result) cached[ip] = c.result;
    if (Object.keys(cached).length) setRepMap((m) => ({ ...m, ...cached }));
    return coverage;
  } catch {
    return {}; // sem cobertura: o botão continua funcionando como antes
  }
}

// IP público que ainda vale uma consulta de verdade (fora do TTL de 7 dias).
function pendingRep(ips) {
  return [...new Set(ips)].filter(isPublicIp).filter((ip) => !repCov[ip]?.cached);
}

function repSource(ip) {
  const c = repCov[ip];
  if (!c) return 'sem cache';
  if (c.from === 'agora') return 'consultado agora';
  if (c.from === 'memoria') return 'cache (memória)';
  if (c.from === 'postgres') return c.stale ? `cache velho (${c.ageDays}d)` : `cache (${c.ageDays}d)`;
  if (c.from === 'privado') return 'privado';
  return 'sem cache';
}

async function checkRep(ips) {
  const base = [...new Set(ips)].filter(isPublicIp);
  if (!base.length) return;
  // 1) o que já está em cache sai de graça e some da fila
  const coverage = await loadRepCoverage(base.filter((ip) => !(ip in repMap)));
  const pendentes = base.filter((ip) => !(ip in repMap) && !coverage?.[ip]?.cached);
  if (!pendentes.length) return;
  // O AbuseIPDB é consultado em lotes de 100 (limite do checkMany no backend).
  // Mandar mais não traz veredito: o excesso é ignorado. E o erro antigo era
  // marcar a fila INTEIRA como "em cache" — o botão passava a dizer "Tudo em
  // cache" e os ~700 restantes nunca mais eram consultados, nem em outra janela.
  const lote = pendentes.slice(0, MAX_CHECK_REP);
  setRepLoading(true);
  setRepMsg(null);
  try {
    const { rep } = await checkReputation(lote);
    setRepMap((m) => ({ ...m, ...rep }));
    setRepCov((c) => {
      const n = { ...c };
      // Só o que veio de verdade conta como cache.
      for (const ip of Object.keys(rep)) n[ip] = { cached: true, from: 'agora', result: rep[ip] || null };
      return n;
    });
    setRepMsg(lote.length < pendentes.length
      ? `Verificados ${lote.length} de ${pendentes.length}. O AbuseIPDB aceita ${MAX_CHECK_REP} IPs por consulta: aperte de novo para os ${pendentes.length - lote.length} restantes.`
      : null);
  } catch (e) {
    // Antes o catch era { /* mantém o que já tem */ } e o POST estourando o
    // limite de corpo da API (413) não aparecia em lugar nenhum: o botão
    // piscava e nada acontecia.
    setRepMsg(`Falha ao consultar o AbuseIPDB: ${e?.message || 'erro desconhecido'}. Nada foi marcado como verificado.`);
  }
  finally { setRepLoading(false); }
}

  const publicIps = [...new Set(graph.nodes.map((n) => n.data.id))].filter(isPublicIp);
  const publicIpsKey = publicIps.join('|');
  const inventoryNames = Object.fromEntries(inventoryData.flatMap((server) =>
    (server.ips || []).map((item) => [item.ip, server.name])
  ));

  useEffect(() => {
    const missingCoverage = publicIps.filter((ip) => !repCov[ip]);
    if (missingCoverage.length) loadRepCoverage(missingCoverage);
  }, [publicIpsKey]); // eslint-disable-line

  function inventoryNameForIp(ip) {
    return inventoryNames[ip] || ip;
  }

  function conversationEndpoint(ip) {
    const label = inventoryNameForIp(ip);
    if (!isPublicIp(ip)) return <span className="conversation-host" title={label !== ip ? ip : undefined}>{label}</span>;
    const score = repMap[ip]?.abuse?.score;
    return (
      <button
        type="button"
        className="conversation-public ip-link"
        style={{ color: repColorForScore(score) }}
        title={`Abrir dossiê de ${ip}${score != null ? ` · score ${score}` : ''}`}
        onClick={() => openIpModal(ip)}
      >{label}</button>
    );
  }

  function repDot(ip) {
    const r = repMap[ip];
    if (!r) return null;
    const v = VERDICTS[r.verdict] || VERDICTS.unknown;
    return <button className="dot-btn" title={`${v.label}${r.abuse ? ` (score ${r.abuse.score})` : ''} — clique p/ dossiê`}
      onClick={(e) => { e.stopPropagation(); openIpModal(ip); }}><i className={`dot ${v.dot}`} /></button>;
  }

  function repBadge(ip) {
    const r = repMap[ip];
    if (!r) return null;
    const v = VERDICTS[r.verdict] || VERDICTS.unknown;
    const extra = r.abuse ? ` score ${r.abuse.score}` : '';
    return <span><i className={`dot ${v.dot}`} /> {v.label}{extra}</span>;
  }

  function timeParams() {
    return useCustom && custom.from && custom.to
      ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
      : { minutes };
  }

  function buildLayout(fast = false) {
    const noAnim = fast ? { animate: false, animationDuration: 0 } : { animate: true, animationDuration: 600 };
    if (layoutName === 'circle') return { name: 'circle', padding: 60, ...noAnim };
    if (layoutName === 'grid') return { name: 'grid', padding: 60, ...noAnim };
    if (layoutName === 'concentric') {
      return {
        name: 'concentric', padding: 60, ...noAnim,
        concentric: (n) => n.degree(), levelWidth: () => 2, minNodeSpacing: spacing / 2
      };
    }
    // cose (força): quanto maior spacing, mais longe os nós ficam;
    // em modo rápido, sem animação e com menos iterações p/ não travar a aba
    return {
      name: 'cose', ...noAnim,
      idealEdgeLength: () => spacing,
      nodeOverlap: 90,
      nodeRepulsion: () => 30000 + spacing * 150,
      nodeDimensionsIncludeLabels: true,
      componentSpacing: spacing,
      edgeElasticity: 80,
      nestingFactor: 1.2,
      gravity: 0.35,
      numIter: fast ? 250 : 1500,
      refresh: fast ? 30 : 20,
      padding: 60
    };
  }

  async function load() {
    setLoading(true);
    setError('');
    try {
      const params = useCustom && custom.from && custom.to
        ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
        : { minutes };
      const data = await fetchGraph(params);
      setGraph(data);
      setSelected(null);
      setHostDetail(null);
      setEdgeInfo(null);
    } catch (e) {
      setError('Falha ao carregar grafo. Verifique se o backend (porta 3001) e o Elasticsearch estão no ar. ' + e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); loadWatch(); }, []); // eslint-disable-line

  function underlineMapLabel(text) {
    return Array.from(String(text)).map((character) => /\s/.test(character) ? character : `${character}\u0332`).join('');
  }

  function nodeLabel(id) {
    const { showNames, inventoryNames: names } = uiRef.current;
    const label = showNames && names[id] ? names[id] : id;
    return isPublicIp(id) ? underlineMapLabel(label) : label;
  }

  // Volume do nó (bytes somados das arestas incidentes) em escala log 0..1
  function nodeScale(el) {
    const b = el.data('bytes') || 0;
    if (!b) return 0;
    return Math.min(1, Math.log10(b + 1) / Math.log10((volRef.current.max || 1) + 1));
  }

  // Diâmetro: host 16→42px, sub-rede 30→64px (hub fica evidente sem clicar)
  function nodeDiameter(el) {
    const sub = !!el.data('isSubnet');
    return (sub ? 30 : 16) + Math.round(nodeScale(el) * (sub ? 34 : 26));
  }

  // Borda = reputação numérica disponível; sem dado fica neutra.
  function repBorderColor(el) {
    const r = uiRef.current.repMap?.[el.id()];
    if (!r) return '#38bdf8';
    if (r.abuse?.score != null) return repColorForScore(r.abuse.score);
    if (r.verdict === 'malicious' || r.verdict === 'suspicious') return REP_COLORS.bad;
    if (r.verdict === 'clean') return REP_COLORS.good;
    return REP_COLORS.unknown;
  }

  // Nó público = círculo comum, mas pintado com a reputação.
  function isPublicHost(el) {
    return !el.data('isSubnet') && isPublicIp(el.id());
  }

  function repFillFor(el) {
    const r = uiRef.current.repMap?.[el.id()];
    if (!r) return REP_COLORS.unknown;
    if (r.abuse?.score != null) return repColorForScore(r.abuse.score);
    if (r.verdict === 'malicious' || r.verdict === 'suspicious') return REP_COLORS.bad;
    if (r.verdict === 'clean') return REP_COLORS.good;
    return REP_COLORS.unknown;
  }

  // Isola o 1º nível do host selecionado, sem reconstruir o grafo
  function applyIsolate() {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass('unfocused');
    if (!isolate || !selected) return;
    const n = c.getElementById(selected);
    if (!n.length) return;
    const keep = new Set([n.id()]);
    n.connectedEdges().forEach((e) => { keep.add(e.data('source')); keep.add(e.data('target')); });
    c.nodes().forEach((x) => { if (!keep.has(x.id())) x.addClass('unfocused'); });
    c.edges().forEach((x) => {
      if (!keep.has(x.data('source')) || !keep.has(x.data('target'))) x.addClass('unfocused');
    });
  }

  // Direção em relação ao host selecionado: ↑ saiu de você · ↓ entrou · ⇄ ambos
  function dirArrow(c) {
    const out = c.outBytes || 0;
    const inn = c.inBytes || 0;
    if (out > 0 && inn === 0) return { s: '↑', t: 'saída: este host → peer', color: 'var(--acc)' };
    if (inn > 0 && out === 0) return { s: '↓', t: 'entrada: peer → este host', color: 'var(--ok)' };
    return { s: '⇄', t: 'ambos os sentidos', color: 'var(--vio)' };
  }

  // Listas de portas podem ter centenas de efêmeras — mostra amostra + total
  function portsShort(list, max = 8) {
    if (!list || !list.length) return '-';
    const head = list.slice(0, max).join(', ');
    return list.length > max ? `${head} +${list.length - max}` : head;
  }

  // Top portas destino da aresta com volume: "443·12MB, 80·3KB +2"
  function topPortsLabel(e, max = 5) {
    const list = e.dstPorts || (e.dstPort != null || e.port != null ? [{ port: e.dstPort ?? e.port }] : []);
    if (!list.length) return '-';
    const head = list.slice(0, max).map((d) => (d.bytes != null ? `${d.port ?? '?'}·${fmtBytes(d.bytes)}` : `${d.port ?? '?'}`)).join(', ');
    return list.length > max ? `${head} +${list.length - max}` : head;
  }

  // Agrega o grafo filtrado por par de sub-redes (visão recolhida)
  function aggregateSubnets(nodes, edges) {
    const subOf = {};
    nodes.forEach((n) => { subOf[n.data.id] = n.data.subnet || subnetOf(n.data.id); });
    const groups = {};
    nodes.forEach((n) => {
      const s = subOf[n.data.id];
      groups[s] = groups[s] || { id: s, hosts: new Set(), bytes: 0 };
      groups[s].hosts.add(n.data.id);
    });
    const agg = {};
    edges.forEach((e) => {
      const a = subOf[e.data.source];
      const b = subOf[e.data.target];
      if (!a || !b) return;
      const k = `${a}||${b}||${e.data.protocol}`;
      agg[k] = agg[k] || { source: a, target: b, protocol: e.data.protocol, bytes: 0, packets: 0, flows: 0 };
      agg[k].bytes += e.data.bytes || 0;
      agg[k].packets += e.data.packets || 0;
      agg[k].flows += 1;
      groups[a].bytes += e.data.bytes || 0;
      groups[b].bytes += e.data.bytes || 0;
    });
    const snodes = Object.values(groups).map((g) => ({
      data: { id: g.id, label: `${g.id}\n${g.hosts.size} hosts`, hosts: [...g.hosts], hostCount: g.hosts.size, bytes: g.bytes, isSubnet: true }
    }));
    const sedges = Object.values(agg).map((a, i) => ({
      data: { id: `s${i}`, source: a.source, target: a.target, bytes: a.bytes, packets: a.packets, protocol: a.protocol, flows: a.flows, portLabel: `${a.flows} fluxos` }
    }));
    return { snodes, sedges };
  }

  // (re)cria o Cytoscape SÓ em mudança estrutural (dados, filtros, visão).
  // Cosmético (nomes, rótulos) atualiza via style().update() no efeito abaixo,
  // sem destruir nada — por isso o mapa não se reorganiza sozinho.
  useEffect(() => {
if (!cyRef.current) return;
    uiRef.current = { showNames, inventoryNames, showPorts, repMap };
    const savedPos = {};
    let savedView = null;
if (cy.current) {
      cy.current.nodes().forEach((n) => { savedPos[n.id()] = { ...n.position() }; });
      try { savedView = { pan: { ...cy.current.pan() }, zoom: cy.current.zoom() }; } catch { /* ignore */ }
      // Trava o layout ANTES de destruir: um rAF de animação que sobrevive ao
      // destroy() estoura em endBatch ("Cannot read properties of null
      // (reading 'notify')") e mata o loop de render do canvas — era isso que
      // deixava o mapa em branco quando a sub-rede padrão chegava no meio da
      // animação do 1º carregamento.
      try { cy.current.layout()?.stop(); } catch { /* ignore */ }
      try { cy.current.animations().forEach((a) => a.stop()); } catch { /* ignore */ }
      cy.current.destroy();
      cy.current = null;
    }

    const maxBytes = Math.max(1, ...graph.edges.map((e) => e.data.bytes || 0));
    let filteredEdges = graph.edges.filter((e) => {
      if ((e.data.bytes || 0) < minBytes) return false;
      if (protoFilter !== 'ALL' && e.data.protocol !== protoFilter) return false;
      return true;
    });
let filteredNodes = graph.nodes.filter((n) =>
      filteredEdges.some((e) => e.data.source === n.data.id || e.data.target === n.data.id)
    );

    // Volume por nó (bytes das arestas incidentes) p/ dimensionar os nós
    const nodeBytes = new Map();
    for (const e of filteredEdges) {
      const b = e.data.bytes || 0;
      nodeBytes.set(e.data.source, (nodeBytes.get(e.data.source) || 0) + b);
      nodeBytes.set(e.data.target, (nodeBytes.get(e.data.target) || 0) + b);
    }
    volRef.current = { max: Math.max(1, ...nodeBytes.values()) };

    // Drill-down: sub-rede/CIDR em foco + vizinhos, ou host em foco + vizinhos
    if (focusHost) {
      filteredEdges = filteredEdges.filter((e) => e.data.source === focusHost || e.data.target === focusHost);
      const keep = new Set();
      filteredEdges.forEach((e) => { keep.add(e.data.source); keep.add(e.data.target); });
      filteredNodes = filteredNodes.filter((n) => keep.has(n.data.id));
} else if (focusSubnet) {
      const members = new Set(filteredNodes.filter((n) => cidrContains(focusSubnet, n.data.id)).map((n) => n.data.id));
      if (members.size) {
        filteredEdges = filteredEdges.filter((e) => members.has(e.data.source) || members.has(e.data.target));
        const keep = new Set();
        filteredEdges.forEach((e) => { keep.add(e.data.source); keep.add(e.data.target); });
        filteredNodes = filteredNodes.filter((n) => keep.has(n.data.id));
        setSubnetEmpty('');
      } else {
        // Sub-rede sem nenhum host na janela: filtrar deixaria o mapa vazio e
        // silencioso. Mantém a visão completa e avisa (evita o "mapa em branco"
        // de quando a sub-rede padrão abre junto com o sistema).
        setSubnetEmpty(focusSubnet);
      }
    } else {
      setSubnetEmpty('');
    }

    let elements;
    let isSubnetView = view === 'subnets' && !focusSubnet && !focusHost;
if (isSubnetView) {
      const { snodes, sedges } = aggregateSubnets(filteredNodes, filteredEdges);
      elements = [...snodes, ...sedges];
    } else {
      // copia os nós para poder gravar o volume sem mutar o estado do grafo
      const withVol = filteredNodes.map((n) => ({ ...n, data: { ...n.data, bytes: nodeBytes.get(n.data.id) || 0 } }));
      elements = [...withVol, ...filteredEdges];
    }

    // Grafos grandes (>1200 elementos) travam a aba com animação/texturas:
    // liga o modo desempenho automaticamente
    const fast = elements.length > 1200;
    setPerfMode(fast);

    cy.current = cytoscape({
      container: cyRef.current,
      elements,
      layout: { name: 'preset' }, // sem animação automática; física decidida abaixo
      textureOnViewport: fast,
      motionBlur: fast,
      hideEdgesOnViewport: false,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (el) => {
              // Interno = ciano. Público = faixa do score; sub-rede = violeta.
              if (el.data('isSubnet')) return NODE_COLORS.subnet;
              if (isPublicHost(el)) return repFillFor(el);
              return NODE_COLORS.private;
            },
label: (el) => el.data('isSubnet') ? el.data('label') : nodeLabel(el.id()),
            color: '#334155',
            'font-size': (el) => (el.data('isSubnet') ? 10 : 9) + Math.round(nodeScale(el) * 3),
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-wrap': 'wrap',
            width: (el) => nodeDiameter(el),
            height: (el) => nodeDiameter(el),
            shape: (el) => el.data('isSubnet') ? 'hexagon' : 'ellipse',
            // Público já é colorido pela reputação: borda seria redundante.
            'border-width': (el) => isPublicHost(el) ? 0 : (uiRef.current.repMap?.[el.id()] ? 2.5 : 2),
            'border-color': (el) => repBorderColor(el),
            'overlay-color': (el) => repBorderColor(el),
            'overlay-opacity': (el) => (uiRef.current.repMap?.[el.id()] ? 0.16 : 0),
            'overlay-padding': 8
          }
        },
        {
selector: 'node:selected',
          style: { 'border-color': '#148853', 'border-width': 3 }
        },
        {
          selector: 'edge',
          style: {
            width: (el) => widthFor(el.data('bytes'), maxBytes),
            'line-color': (el) => colorFor(el.data('protocol')),
            'target-arrow-color': (el) => colorFor(el.data('protocol')),
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.7,
            'curve-style': 'bezier',
            opacity: 0.7,
            // rótulo origem→destino em cada conexão (desligável p/ limpar o mapa)
            label: (el) => {
              if (!uiRef.current.showPorts) return '';
              return el.data('portLabel') || `${el.data('srcPort') ?? '?'}→${el.data('dstPort') ?? el.data('port') ?? '?'}`;
            },            'font-size': 7,
            color: '#64748b',
            'text-rotation': 'autorotate',
            'text-margin-y': -6
          }
        },
{
          selector: 'edge:selected',
          style: { opacity: 1, 'font-size': 9, color: '#fff' }
        },
        // Isolamento: o que não é vizinho do host selecionado some
        {
          selector: 'node.unfocused',
          style: { opacity: 0.1, 'text-opacity': 0.08 }
        },
        {
          selector: 'edge.unfocused',
          style: { opacity: 0.04 }
        }
      ]
    });

    // Volta aos lugares conhecidos p/ transição suave (sem randomizar);
    // primeira carga não tem onde voltar e usa o layout cheio
    const cyInst = cy.current;
    let restored = 0;
    Object.entries(savedPos).forEach(([id, p]) => {
      const n = cyInst.getElementById(id);
      if (n.length) { n.position(p); restored++; }
    });
if (restored > 0) {
      cyInst.layout({ ...buildLayout(fast), randomize: false, animate: false }).run();
      if (savedView) { try { cyInst.viewport({ zoom: savedView.zoom, pan: savedView.pan }); } catch { /* ignore */ } }
    } else {
      // Conteúdo novo: layout SEM animação (ver comentário do destroy) e
      // enquadramento depois que a física termina.
      cyInst.one('layoutstop', () => { try { cyInst.fit(undefined, 40); } catch { /* ignore */ } });
      cyInst.layout({ ...buildLayout(fast), animate: false }).run();
    }

    cy.current.on('tap', 'node', async (evt) => {
      const el = evt.target;
      // seleção única: só o último clicado fica amarelo
      cy.current.elements(':selected').unselect();
      el.select();
      // Visão sub-redes: clique entra na sub-rede (drill-down)
      if (el.data('isSubnet')) {
        setFocusSubnet(el.id());
        setFocusHost(null);
        setView('hosts');
        setSelected(null);
        setHostDetail(null);
        setEdgeInfo(null);
        return;
      }
      const ip = el.id();
      setSelected(ip);
      setEdgeInfo(null);
      await reloadHost(ip);
    });
    cy.current.on('tap', 'edge', (evt) => {
      cy.current.elements(':selected').unselect();
      evt.target.select();
      const d = evt.target.data();
      setEdgeInfo(d);
      setSelected(null);
      setHostDetail(null);
    });
cy.current.on('tap', (evt) => {
      if (evt.target === cy.current) { cy.current.elements(':selected').unselect(); setSelected(null); setHostDetail(null); setEdgeInfo(null); }
    });

    // Tooltip no hover: leitura do elemento sem sair do mapa
    const hideTip = () => setTip(null);
    const tipBox = (evt, title, rows, badge) => {
      const p = evt.renderedPosition;
      setTip({
        x: p.x, y: p.y,
        flip: p.x > cyInst.container().clientWidth - 300,
        title, rows, badge
      });
    };
    cyInst.on('mouseover', 'node', (evt) => {
      const el = evt.target;
      const sub = !!el.data('isSubnet');
      const ip = el.id();
      const r = uiRef.current.repMap?.[ip];
      const v = r ? (VERDICTS[r.verdict] || VERDICTS.unknown) : null;
      tipBox(evt,
        sub ? el.id() : (uiRef.current.inventoryNames?.[ip] || ip),
        sub
          ? [['hosts', String(el.data('hostCount') ?? '-')], ['bytes', fmtBytes(el.data('bytes'))]]
          : [
            ['ip', ip],
            ['bytes', fmtBytes(el.data('bytes'))],
            ['conexões', String(el.degree())]
          ],
        v ? `${v.label}${r.abuse?.score != null ? ` · score ${r.abuse.score}` : ''}` : null);
    });
    cyInst.on('mouseover', 'edge', (evt) => {
      const d = evt.target.data();
      const nm = uiRef.current.inventoryNames || {};
      tipBox(evt,
        `${nm[d.source] || d.source} → ${nm[d.target] || d.target}`,
        [['protocolo', d.protocol || '-'], ['bytes', fmtBytes(d.bytes)],
         ['pacotes', String(d.packets ?? '-')], ['fluxos', String(d.flows ?? 1)],
         ...(d.portLabel ? [['portas', d.portLabel]] : []),
         // formato do tráfego: sinal de bulk vs. beacon/túnel
         ...(d.bytesPerPacket ? [['bytes/pacote', String(d.bytesPerPacket)]] : []),
         ...(d.packetsPerFlow ? [['pacotes/fluxo', String(d.packetsPerFlow)]] : [])]);
    });
    cyInst.on('mouseout', 'node edge', hideTip);
    cyInst.on('mouseover', (evt) => { if (evt.target === cyInst) hideTip(); });
    cyInst.on('pan zoom', hideTip); // o tooltip fica preso ao elemento, some ao mover

    // O Cytoscape mede o container UMA vez, na criação. Se a primeira montagem
    // acontece antes do grid CSS resolver o tamanho, ele fica com viewport 0x0
    // e o mapa nasce invisível (o layout roda contra uma caixa degenerada).
    // O ResizeObserver corrige; a relatagem só acontece nesse caso patológico.
    const cont = cyInst.container();
    if (roRef.current) roRef.current.disconnect();
    const ro = new ResizeObserver(() => { try { cyInst.resize(); } catch { /* ignore */ } });
    ro.observe(cont);
    roRef.current = ro;
    const box = cont.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) {
      const ro2 = new ResizeObserver(() => {
        const b = cont.getBoundingClientRect();
        if (b.width < 2 || b.height < 2) return;
        try {
          cyInst.resize();
          // posições nasceram contra uma caixa 0x0: refaz a física e enquadra
          cyInst.layout({ ...buildLayout(fast), randomize: true, animate: false }).run();
          cyInst.fit(undefined, 40);
        } catch { /* ignore */ }
        ro2.disconnect();
      });
      ro2.observe(cont);
    }
    // Rede de segurança: conteúdo novo cujas posições colapsaram ou ficaram fora
    // do enquadramento (container medido antes do layout, remontagem no meio da
    // animação) → refaz a física e enquadra.
    requestAnimationFrame(() => {
      try {
        if (!elements.length) return;
        const ext = cyInst.extent();
        // região visível em coordenadas de modelo (Cytoscape não expõe
        // renderedViewport): x_modelo = (x_render - pan) / zoom
        const pan = cyInst.pan();
        const z = cyInst.zoom() || 1;
        const vp = {
          x1: -pan.x / z, y1: -pan.y / z,
          x2: (cont.clientWidth - pan.x) / z, y2: (cont.clientHeight - pan.y) / z
        };
        const visivel = !(ext.x2 < vp.x1 || ext.x1 > vp.x2 || ext.y2 < vp.y1 || ext.y1 > vp.y2);
        const pilhado = elements.length >= 3 && ext.w < 20 && ext.h < 20;
        if (!visivel || pilhado) {
          console.warn('[mapa] posições inválidas — refazendo a física', {
            visivel, pilhado, elementos: elements.length, ext, vp
          });
          cyInst.layout({ ...buildLayout(fast), randomize: true, animate: false }).run();
          cyInst.fit(undefined, 40);
        }
      } catch (e) { console.warn('[mapa] falha ao corrigir o viewport', e); }
    });
    // O Cytoscape não emite mouseout em alguns caminhos de saída, então o
    // mousemove é a fonte da verdade: se o ponteiro não está sobre elemento, some.
    cyInst.on('mousemove', (evt) => { if (evt.target === cyInst) hideTip(); });
    // ...e sair do canvas de vez não chega ao Cytoscape: cobre no DOM
    if (tipAbortRef.current) tipAbortRef.current.abort();
    tipAbortRef.current = new AbortController();
    cyInst.container().addEventListener('mouseleave', hideTip, { signal: tipAbortRef.current.signal });

    applyIsolate();
  }, [graph, minBytes, protoFilter, spacing, layoutName, view, focusSubnet, focusHost]); // eslint-disable-line

  // Cosmético (nomes resolvidos, rótulos de porta, reputação): só reavalia
  // estilos, sem destruir o grafo — o mapa fica parado
  useEffect(() => {
    uiRef.current = { showNames, inventoryNames, showPorts, repMap };
    if (cy.current) cy.current.style().update();
  }, [showNames, inventoryData, showPorts, repMap]);

  // Reaplica o isolamento quando a seleção muda (o grafo não é reconstruído)
  useEffect(() => { applyIsolate(); }, [selected, isolate]);

  function relayout() {
    // Reorganizar é explícito: física completa com animação
    cy.current?.layout({ ...buildLayout(perfMode), randomize: true, animate: true }).run();
  }

  // (Re)carrega o painel do host (sempre janela cheia; ESTADO distingue ativas)
  async function reloadHost(ip) {
    try {
      const params = useCustom && custom.from && custom.to
        ? { from: new Date(custom.from).toISOString(), to: new Date(custom.to).toISOString() }
        : { minutes };
      setHostDetail({ loading: true, ip });
      const d = await fetchHost(ip, params);
      setHostDetail(d);
      // reputação automática do próprio host + peers públicos (com cache)
      checkRep([ip, ...d.connections.map((c) => c.ip)].filter(isPublicIp));
    } catch (e) {
      setHostDetail({ ip, error: String(e.message) });
    }
  }

  function focusSearch() {
    if (!search || !cy.current) return;
    focusIp(search.trim());
  }

  // Centraliza e abre o detalhe de um IP (usado pela busca e pelos alertas)
  function focusIp(ip) {
    if (!ip || !cy.current) return;
    if (view === 'subnets') { setView('hosts'); setFocusSubnet(null); }
    setFocusHost(null);
    // espera o grafo de hosts remontar antes de procurar o nó
    setTimeout(() => {
      const node = cy.current.getElementById(ip);
      if (node && node.length) {
        cy.current.center(node);
        node.select();
        node.trigger('tap');
      } else {
        alert(`IP ${ip} não encontrado no grafo atual.`);
      }
    }, view === 'subnets' ? 700 : 0);
  }

  const protos = [...new Set(graph.edges.map((e) => e.data.protocol))].sort();
  const selectedInventoryServer = inventoryData.find((server) => server.id === inventorySelectedId) || inventoryData[0] || null;
  const dashboardScreenProps = {
    dashboardTab, closeDashboard, topTalkersConfig,
    fmtWindow, useCustom, custom, minutes, loadInventory, setDashboardRefresh,
    inventoryLoading, dashboardLoading, dashboardPortsLoading, dashboardConversationsLoading,
    setDashboardTab, inventoryData,
    inventoryError, openInventory, dashboardServerId, setDashboardServerId,
    dashboardData, dashboardError, fetchApplicationConnections, fmtBytes, dashboardPortsData, dashboardPortsError,
    conversationEndpoint,
    topTalkersForm, setTopTalkersForm, setTopTalkersConfig,
    dashboardConversationsData, dashboardConversationsError
  };
  const inventoryScreenProps = {
    closeInventory, inventoryData, loadInventory, inventoryLoading, inventoryError,
    newServerName, setNewServerName, newServerIp, setNewServerIp, addInventoryServer,
    inventoryBusy, inventoryEdit, setInventoryEdit, saveInventoryEdit,
    inventorySelectedId, setInventorySelectedId, removeInventoryServer,
    setApplicationDrafts, applicationDrafts, inventoryNewApplicationRef,
    selectedInventoryServer, openIpModal, newServerIps, setNewServerIps,
    addInventoryIp, removeInventoryIp, setApplicationDraft,
    addInventoryApplication, removeInventoryApplication, expectedClientDrafts,
    setExpectedClientDrafts, removeExpectedClient, addExpectedClient,
    listenerDrafts, setListenerDraft, removeInventoryListener, addInventoryListener
  };
  const reputationScreenProps = {
    closeRep, setRepHarvesting, setRepHarvestMsg, harvestRegions, loadRepDb,
    repDbLoading, repHarvesting, repHarvestMsg, PERIODOS, repDbDays,
    setPeriodo, repTab, setRepTab, fmtBytes, setPgRep, setPgBase,
    setRepDbCountry, setRepDbIp, publicIps, fmtWindow, useCustom, custom, minutes, checkRep, repLoading,
    pendingRep, repQuota, repMsg, sortedRepIps, pgRep, PAGE_REP, openIpModal,
    repMap, repBadge, repSource, pager, setRepDbOrder, repDbOrder, repDb,
    repDbIp, repDbCountry, repDbIpsOf, pgBase, VERDICTS, timeAgo, setLkIp,
    setLkOpen, runLookup, focusIp
  };
  const exposureScreenProps = {
    setExpOpen, fmtWindow, useCustom, custom, minutes, loadExposure, expLoading,
    expTab, setExpTab, expData, expIp, setExpIp, riskMap, RISK_COLORS,
    RISK_LABELS, fmtBytes, openIpModal, focusIp, timeAgo, loadBeacon, beacon
  };
  const mapScreenProps = {
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
  };

  return (
    <div className={`layout${repDbOpen ? ' rep-page' : ''}${dashboardOpen ? ' dashboard-page' : ''}${inventoryOpen ? ' inventory-page' : ''}${fortigateOpen ? ' fortigate-page' : ''}`}>
<header className="topbar">
        <div className="topbar-row">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true">
              <svg viewBox="0 0 32 32" fill="none">
                <path d="M16 4v24M5.6 10l20.8 12M5.6 22l20.8-12M8 5.8l16 20.4M24 5.8 8 26.2" stroke="currentColor" strokeWidth="1.4" />
                <circle cx="16" cy="16" r="3.3" fill="currentColor" />
                <circle cx="16" cy="4" r="1.8" fill="currentColor" />
                <circle cx="5.6" cy="10" r="1.8" fill="currentColor" />
                <circle cx="26.4" cy="10" r="1.8" fill="currentColor" />
                <circle cx="5.6" cy="22" r="1.8" fill="currentColor" />
                <circle cx="26.4" cy="22" r="1.8" fill="currentColor" />
                <circle cx="16" cy="28" r="1.8" fill="currentColor" />
              </svg>
            </span>
            <h1>Teia de Aranha<span>NetFlow · VMware → Elasticsearch</span></h1>
          </div>
          <span className="status-chip" title={error ? String(error) : 'Estado da coleta'}>
            <span className={`status-dot ${error ? 'err' : loading ? 'busy' : graph.nodes?.length ? 'ok' : ''}`} />
            {error ? 'erro' : loading ? 'carregando…' : graph.nodes?.length ? 'ao vivo' : 'sem dados'}
          </span>
          <div className="controls">
            {!useCustom ? (
              <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                {PRESETS.map((p) => <option key={p.minutes} value={p.minutes}>{p.label}</option>)}
              </select>
            ) : (
              <span className="custom-range">
                <input type="datetime-local" value={custom.from} onChange={(e) => setCustom({ ...custom, from: e.target.value })} />
                <input type="datetime-local" value={custom.to} onChange={(e) => setCustom({ ...custom, to: e.target.value })} />
              </span>
            )}
            <label className="chk"><input type="checkbox" checked={useCustom} onChange={(e) => setUseCustom(e.target.checked)} /> personalizado</label>
            <button onClick={load} disabled={loading}>{loading ? 'Carregando…' : 'Atualizar'}</button>
          </div>
        </div>
        <div className="topbar-row">
          <div className="tools">
            <div className="tool-group" aria-label="Página principal">
              <button className={`tool${dashboardOpen && !inventoryOpen && dashboardTab !== 'topTalkers' ? ' active' : ''}`} onClick={() => { setInventoryOpen(false); openDashboard('applications'); }} title="Dashboard de aplicações, portas e conversas"><span className="ti" aria-hidden="true">▦</span>Dashboard</button>
            </div>
            <div className="tool-group" aria-label="Análise do tráfego">
              <button className="tool" onClick={relayout} title="Refazer a física do grafo (animado)"><span className="ti" aria-hidden="true">↻</span>Reorganizar</button>
              <button className={`tool${cmpOpen ? ' active' : ''}`} onClick={() => { setCmpA(selected || ''); setCmpB(''); setCmpData(null); setCmpError(''); setCmpOpen(true); }} title="Analisar tráfego entre dois hosts"><span className="ti" aria-hidden="true">⇄</span>Comparar</button>
              <button className={`tool${pairsOpen ? ' active' : ''}`} onClick={() => { setPairsSubnet(''); setPairsOpen(true); loadPairs(); }} title="Top pares que mais conversam"><span className="ti" aria-hidden="true">⋈</span>Pares</button>
            </div>
            <div className="tool-group" aria-label="Segurança e exposição">
              <button className={`tool${repDbOpen && !inventoryOpen ? ' active' : ''}${(repDb?.regions || []).some((r) => r.bad > 0) ? ' danger' : ''}`} onClick={() => { setInventoryOpen(false); setRepDbIp(null); openRep('base'); }} title="Reputação: base de IPs e verificação de cache">
                <span className="ti" aria-hidden="true">◉</span>Reputação
              </button>
             <button className={`tool${expOpen ? ' active' : ''}`} onClick={() => { setFortigateOpen(false); setInventoryOpen(false); setExpOpen(true); loadExposure(); }} title="Exposição externa: risco por host, tráfego de entrada, destinos novos e sessões vivas">
                <span className="ti" aria-hidden="true">⬡</span>Exposição
              </button>
            </div>
            <div className="tool-group" aria-label="Investigação">
              <button className={`tool${inventoryOpen ? ' active' : ''}`} onClick={openInventory} title="Cadastro de máquinas, IPs e aplicações"><span className="ti" aria-hidden="true">▤</span>Inventário</button>
              <button className={`tool${subnetsOpen ? ' active' : ''}`} onClick={() => setSubnetsOpen(true)} title="Sub-redes monitoradas"><span className="ti" aria-hidden="true">▦</span>Subnets</button>
              <button className="tool" onClick={() => { setLkIp(''); setLkData(null); setLkError(''); setLkOpen(true); }} title="Buscar qualquer IP no histórico (mesmo fora do mapa)"><span className="ti" aria-hidden="true">⌕</span>Buscar IP</button>
              <button className={`tool${dashboardOpen && !inventoryOpen && dashboardTab === 'topTalkers' ? ' active' : ''}`} onClick={() => { setInventoryOpen(false); openDashboard('topTalkers'); }} title="Conversas dos IPs cadastrados no inventário">
                <span className="ti" aria-hidden="true">≋</span>Tráfego
              </button>
               <button className={`tool${!inventoryOpen && !dashboardOpen && !repDbOpen && !fortigateOpen ? ' active' : ''}`} onClick={() => { setInventoryOpen(false); openMap(); }} title="Abrir mapa de conexões"><span className="ti" aria-hidden="true">⌖</span>Mapa</button>
              <button className={`tool${fortigateOpen ? ' active' : ''}`} onClick={() => { setFortigateOpen(true); setInventoryOpen(false); setRepDbOpen(false); setDashboardOpen(false); setExpOpen(false); }} title="Firewalls FortiGate e análise de políticas"><span className="ti" aria-hidden="true">▣</span>FortiGate</button>
            </div>
          </div>
        </div>
        <div className={`loadbar ${loading ? 'on' : ''}`}><i /></div>
      </header>

      {fortigateOpen && <FortigatePage />}

      {dashboardOpen && <DashboardScreen {...dashboardScreenProps} />}

      <MapScreen {...mapScreenProps} />

      {ipModal && (
        <div className="modal-backdrop" style={{ zIndex: 60 }} onClick={() => setIpModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            {ipModal.loading && <><div className="modal-head"><h2 className="mono">{ipModal.ip}</h2></div><div className="modal-body"><p>Montando dossiê…</p></div></>}
            {ipModal.error && <><div className="modal-head"><h2 className="mono">{ipModal.ip}</h2><button className="ghost" onClick={() => setIpModal(null)}>✕</button></div><div className="modal-body"><p className="error">{ipModal.error}</p></div></>}
            {!ipModal.loading && !ipModal.error && (() => {
              const v = VERDICTS[ipModal.reputation?.verdict] || VERDICTS.unknown;
              const a = ipModal.reputation?.abuse;
              return (<>
                <div className="modal-head">
                  <div>
                    <h2 className="mono">{ipModal.ip}</h2>
                    <span className="hint">{ipModal.public ? 'IP público' : 'rede interna'} · {ipModal.subnet}</span>
                  </div>
                  <span>
                    <button className="ghost" onClick={() => { setIpModal(null); focusIp(ipModal.ip); }}>Localizar</button>{' '}
                    <button className="ghost" onClick={() => { const ip = ipModal.ip; setIpModal(null); setSelected(ip); setEdgeInfo(null); reloadHost(ip); }}>Conexões</button>{' '}
                    <button className="ghost" onClick={() => setIpModal(null)}>✕</button>
                  </span>
                </div>
                <div className="modal-body">
                  <h3>Identidade</h3>
                  <div className="kv">
                    <span>Nome (PTR/inventário)</span><b>{ipModal.name || '-'}</b>
                    <span>Domínio (AbuseIPDB)</span><b>{a?.domain || '-'}</b>
                    <span>Hostnames</span><b>{a?.hostnames?.join(', ') || '-'}</b>
                    <span>Organização (ASN)</span><b>{ipModal.org ? `AS${ipModal.asn} ${ipModal.org}` : '-'}</b>
                    <span>Prefixo</span><b className="mono">{ipModal.prefix || '-'}</b>
                    <span>País / ISP</span><b>{[a?.countryName || a?.country, a?.isp].filter(Boolean).join(' · ') || '-'}</b>
                    <span>Uso</span><b>{a?.usageType || '-'}</b>
                  </div>
                  <InventoryContext data={ipModal.inventory} />

                  <h3>Reputação <i className={`dot ${v.dot}`} /> {v.label}{a ? ` · score ${a.score}` : ''}</h3>
                  {a && (
                    <div className="scorebar"><i style={{ width: `${Math.min(100, a.score)}%`, background: a.score > 0 ? 'var(--bad)' : 'var(--ok)' }} /></div>
                  )}
                  <div className="kv">
                    <span>Reportes</span><b>{a?.reports ?? '-'}{a?.distinctUsers != null ? ` (${a.distinctUsers} usuários)` : ''}</b>
                    <span>Último reporte</span><b>{a?.lastReported || '-'}</b>
                    <span>Whitelist AbuseIPDB</span><b>{a?.whitelisted == null ? '-' : a.whitelisted ? 'sim' : 'não'}</b>
                    <span>Fontes</span><b>{ipModal.reputation?.sources?.join(', ') || '-'}</b>
                  </div>

                  <h3>Tráfego na janela</h3>
                  {ipModal.truncated && <p className="error">A consulta atingiu o limite de buckets; este dossiê pode estar incompleto. Reduza o período.</p>}
                  <div className="kpis">
                    <div><b>{fmtBytes(ipModal.traffic.outBytes)}</b><span>saída</span></div>
                    <div><b>{fmtBytes(ipModal.traffic.inBytes)}</b><span>entrada</span></div>
                    <div><b>{ipModal.traffic.flows}</b><span>fluxos</span></div>
                  </div>
                  <div className="kv">
                    <span>Pacotes out/in</span><b>{ipModal.traffic.outPackets} / {ipModal.traffic.inPackets}</b>
                    <span>Top portas</span><b className="mono">{ipModal.traffic.topPorts.map((p) => `${p.port ?? '?'}·${fmtBytes(p.bytes)}`).join(', ') || '-'}</b>
                  </div>
                  {ipModal.traffic.topPeers.length > 0 && (
                    <div className="table-wrap">
                      <table>
                        <thead><tr><th>Peer local</th><th>Bytes</th><th>Fluxos</th><th>Portas</th></tr></thead>
                        <tbody>
                          {ipModal.traffic.topPeers.map((p) => (
                            <tr key={p.ip}>
                              <td className="mono">{p.ip}</td>
                              <td>{fmtBytes(p.bytes)}</td>
                              <td>{p.flows}</td>
                              <td className="mono">{p.ports.join(', ') || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </>);
            })()}
          </div>
        </div>
      )}
      {cmpOpen && (
        <div className="modal-backdrop" onClick={() => setCmpOpen(false)}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>Comparar hosts</h2><span className="hint">tráfego entre dois IPs no período escolhido</span></div>
              <button className="ghost" onClick={() => setCmpOpen(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="cmp-form">
                <input value={cmpA} onChange={(e) => setCmpA(e.target.value)} placeholder="IP A — ex. 10.190.164.2" onKeyDown={(e) => e.key === 'Enter' && runCompare(cmpA, cmpB)} />
                <span className="hint">⇄</span>
                <input value={cmpB} onChange={(e) => setCmpB(e.target.value)} placeholder="IP B — ex. 10.190.164.12" onKeyDown={(e) => e.key === 'Enter' && runCompare(cmpA, cmpB)} />
              </div>
              <div className="cmp-form" style={{ marginTop: 8 }}>
                <select value={cmpMinutes} onChange={(e) => setCmpMinutes(Number(e.target.value))} style={{ maxWidth: 220 }}>
                  {PRESETS.map((p) => <option key={p.minutes} value={p.minutes}>{p.label}</option>)}
                </select>
                <button onClick={() => runCompare(cmpA, cmpB)} disabled={cmpLoading}>{cmpLoading ? '…' : 'Analisar'}</button>
              </div>
              {cmpError && <p className="error">{cmpError}</p>}
              {cmpData && (
                <>
                  {cmpData.truncated && <p className="error">A consulta atingiu o limite de buckets; a comparação pode estar incompleta. Reduza o período.</p>}
                  <div className="kpis kpis-2">
                    <div><b>{cmpData.a}</b><span>→ {fmtBytes(cmpData.aToB.bytes)} · {cmpData.aToB.flows} fluxos</span></div>
                    <div><b>{cmpData.b}</b><span>→ {fmtBytes(cmpData.bToA.bytes)} · {cmpData.bToA.flows} fluxos</span></div>
                  </div>
                  <h3>Timeline ({cmpData.interval}) <span className="hint">■ A→B ■ B→A</span></h3>
                  <div className="tl">
                    {(() => {
                      const max = Math.max(1, ...cmpData.timeline.map((t) => Math.max(t.aToB, t.bToA)));
                      return cmpData.timeline.map((t, i) => (
                        <div key={i} className="tl-col" title={`${t.t.slice(11, 16)} · A→B ${fmtBytes(t.aToB)} · B→A ${fmtBytes(t.bToA)}`}>
                          <i className="tl-up" style={{ height: `${Math.max(2, (t.aToB / max) * 100)}%` }} />
                          <i className="tl-dn" style={{ height: `${Math.max(2, (t.bToA / max) * 100)}%` }} />
                        </div>
                      ));
                    })()}
                  </div>
                  <h3>Top portas A→B</h3>
                  <div className="table-wrap"><table><thead><tr><th>Porta</th><th>Bytes</th><th>Fluxos</th></tr></thead>
                    <tbody>{cmpData.aToB.topPorts.map((p) => (
                      <tr key={p.port ?? 'null'}><td className="mono">{p.port ?? '-'}</td><td>{fmtBytes(p.bytes)}</td><td>{p.flows}</td></tr>
                    ))}</tbody></table></div>
                  <h3>Top portas B→A</h3>
                  <div className="table-wrap"><table><thead><tr><th>Porta</th><th>Bytes</th><th>Fluxos</th></tr></thead>
                    <tbody>{cmpData.bToA.topPorts.map((p) => (
                      <tr key={p.port ?? 'null'}><td className="mono">{p.port ?? '-'}</td><td>{fmtBytes(p.bytes)}</td><td>{p.flows}</td></tr>
                    ))}</tbody></table></div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      {pairsOpen && (
        <div className="modal-backdrop" onClick={() => setPairsOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>Top pares</h2><span className="hint">quem mais conversa entre si · clique p/ comparar</span></div>
              <button className="ghost" onClick={() => setPairsOpen(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="cmp-form">
                <select value={pairsSubnet} onChange={(e) => { setPairsSubnet(e.target.value); loadPairs(pairsMinutes, e.target.value); }} style={{ flex: 1 }}>
                  <option value="">Todas as sub-redes</option>
                  {pairsSubnetOptions().map(([cidr, label]) => <option key={cidr} value={cidr}>{label}</option>)}
                </select>
                <select value={pairsMinutes} onChange={(e) => { setPairsMinutes(Number(e.target.value)); loadPairs(Number(e.target.value), pairsSubnet); }} style={{ maxWidth: 150 }}>
                  {PRESETS.map((p) => <option key={p.minutes} value={p.minutes}>{p.label}</option>)}
                </select>
              </div>
              {(watchSubnets && !watchSubnets.length) && <p className="hint">Cadastre sub-redes em 🗺 Subnets para filtrar.</p>}
              {!pairsData || pairsLoading ? <p>Calculando…</p> : pairsData.error ? (
                <p className="error">Falha ao carregar.</p>
              ) : !pairsData.pairs.length ? (
                <p className="hint">Nenhum par{pairsSubnet ? ' nesta sub-rede' : ''} no período.</p>
              ) : (
                <>
                  {pairsData.truncadoES && (
                    <p className="hint">⚠️ Volume muito alto para a janela pedida: o ranking pode estar
                      incompleto. Reduza o período para ver o topo real.</p>
                  )}
                  {pairsData.pairs.map((p, i) => (
                    <div key={`${p.a}-${p.b}`} className="talker" onClick={() => openCompare(p.a, p.b)} title="Abrir comparador">
                      <div className="talker-top">
                        <span className="talker-ip">#{i + 1} {p.a} ⇄ {p.b}</span>
                        <span className="talker-bytes">{fmtBytes(p.bytes)}</span>
                      </div>
                      <div className="bar"><i style={{ width: `${Math.round((p.bytes / (pairsData.pairs[0].bytes || 1)) * 100)}%` }} /></div>
                      <span className="hint">{p.flows} fluxos · {(p.protocols || []).join('/')} · portas {(p.topPorts || []).map((x) => x.port ?? '?').join(', ')}</span>
                      {p.ladoPrincipal && p.bytesLadoSecundario != null && (
                        <span className="hint">
                          {p.ladoPrincipal === 'A>B' ? `${p.a} → ${p.b}` : `${p.b} → ${p.a}`} {'transmitiu '}
                          {fmtBytes(p.bytesLadoPrincipal)}
                          {p.bytesLadoSecundario > 0
                            ? ` · o outro sentido ${fmtBytes(p.bytesLadoSecundario)}`
                            : ' · sem retorno'}
                        </span>
                      )}
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
        </div>
      )}
      {inventoryOpen && <InventoryScreen {...inventoryScreenProps} />}
      {subnetsOpen && (
        <div className="modal-backdrop" onClick={() => setSubnetsOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>Sub-redes monitoradas</h2><span className="hint">★ abre junto com o sistema</span></div>
              <button className="ghost" onClick={() => setSubnetsOpen(false)}>✕</button>
            </div>
            <div className="modal-body">
              {watchError && <p className="error">{watchError}</p>}
              <div className="cmp-form">
                <input value={newCidr} onChange={(e) => setNewCidr(e.target.value)} placeholder="CIDR — ex. 10.190.164.0/26" onKeyDown={(e) => e.key === 'Enter' && doWatch(() => addWatchSubnet(newCidr.trim(), newCidrName.trim()), 'sadd')} />
                <input value={newCidrName} onChange={(e) => setNewCidrName(e.target.value)} placeholder="Nome (opcional)" onKeyDown={(e) => e.key === 'Enter' && doWatch(() => addWatchSubnet(newCidr.trim(), newCidrName.trim()), 'sadd')} />
                <button onClick={() => doWatch(async () => { await addWatchSubnet(newCidr.trim(), newCidrName.trim()); setNewCidr(''); setNewCidrName(''); }, 'sadd')} disabled={watchBusy === 'sadd'}>Adicionar</button>
              </div>
              {(watchSubnets || []).map((s) => (
                <div key={s.cidr} className="talker" onClick={() => { setSubnetsOpen(false); setView('hosts'); setFocusHost(null); setFocusSubnet(s.cidr); }} title="Ver no mapa">
                  <div className="talker-top">
                    <span className="talker-ip">{s.is_default ? '★ ' : ''}{s.cidr}{s.name ? ` · ${s.name}` : ''}</span>
                    <span onClick={(e) => e.stopPropagation()}>
                      <button className="ghost" style={{ padding: '2px 8px', fontSize: 11 }} title="Abrir junto com o sistema" onClick={() => doWatch(() => patchWatchSubnet(s.cidr, { is_default: !s.is_default }), `s-${s.cidr}`)}>{s.is_default ? '★ padrão' : 'tornar padrão'}</button>{' '}
                      <button className="ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => { if (confirm(`Remover ${s.cidr}?`)) doWatch(() => delWatchSubnet(s.cidr), `sd-${s.cidr}`); }}>✕</button>
                    </span>
                  </div>
                  <span className="hint">{s.is_default ? 'abre junto com o sistema' : 'clique para ver no mapa'}</span>
                </div>
              ))}
              {watchSubnets && !watchSubnets.length && <p className="hint">Nenhuma sub-rede — adicione acima.</p>}
            </div>
          </div>
        </div>
      )}
      {repDbOpen && <ReputationScreen {...reputationScreenProps} />}
      {expOpen && <ExposureScreen {...exposureScreenProps} />}
      {lookupModal()}
    </div>
  );
}
