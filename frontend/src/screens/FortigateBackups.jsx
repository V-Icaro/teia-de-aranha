import { useEffect, useMemo, useState } from 'react';
import { fmtBytes, fetchFortigates } from '../api.js';
import { listFortigateBackupPolicies, createFortigateBackupPolicy, updateFortigateBackupPolicy, deleteFortigateBackupPolicy, runFortigateBackupPolicy, runFortigateBackupNow, listFortigateBackups, getFortigateBackupContent, deleteFortigateBackup } from '../fortigateBackupsApi';

const DAYS = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
const STATUS = {
  success: { label: 'Sucesso', cls: 'ok' },
  error: { label: 'Erro', cls: 'err' },
  running: { label: 'Executando', cls: 'run' }
};
const EMPTY_FORM = { name: '', description: '', enabled: true, hour: 2, minute: 0, runAllDays: true, daysOfWeek: [], retentionDays: 7, targetFortigateIds: [] };

const pad = (n) => String(n).padStart(2, '0');
const fmtDate = (v) => (v ? new Date(v).toLocaleString('pt-BR') : '—');

function fmtDuration(start, end) {
  if (!start || !end) return null;
  const s = Math.max(0, Math.round((new Date(end) - new Date(start)) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}min ${s % 60}s`;
}

// Próxima execução prevista a partir de hora/minuto/dias (hora local do navegador).
function nextRun(policy) {
  if (!policy.enabled) return null;
  const days = policy.runAllDays ? [0, 1, 2, 3, 4, 5, 6] : (policy.daysOfWeek || []);
  if (!days.length) return null;
  const now = new Date();
  for (let i = 0; i < 8; i += 1) {
    const d = new Date(now);
    d.setDate(now.getDate() + i);
    d.setHours(policy.hour, policy.minute, 0, 0);
    if (d > now && days.includes(d.getDay())) return d;
  }
  return null;
}

function StatusBadge({ status }) {
  const s = STATUS[status] || { label: status || '—', cls: '' };
  return <span className={`fgb-status ${s.cls}`}>{s.label}</span>;
}

export default function FortigateBackupsScreen({ firewalls: firewallsProp = [] }) {
  const [tab, setTab] = useState('policies');
  const [firewalls, setFirewalls] = useState(firewallsProp);
  const [policies, setPolicies] = useState([]);
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [view, setView] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [histFortigate, setHistFortigate] = useState('');
  const [histStatus, setHistStatus] = useState('');

  async function loadPolicies() { try { const r = await listFortigateBackupPolicies(); setPolicies(r.policies || []); } catch (e) { setError(String(e.message || e)); } }
  async function loadBackups() { try { const r = await listFortigateBackups(); setBackups(r.backups || []); } catch (e) { setError(String(e.message || e)); } }
  async function loadFirewalls() { try { const r = await fetchFortigates(); setFirewalls(r.firewalls || []); } catch { /* mantém a lista recebida */ } }
  async function loadAll() { setLoading(true); await Promise.all([loadPolicies(), loadBackups(), loadFirewalls()]); setLoading(false); }

  useEffect(() => { loadAll(); }, []);

  // Enquanto houver backup em execução, atualiza o histórico sozinho.
  const hasRunning = backups.some((b) => b.status === 'running');
  useEffect(() => {
    if (!hasRunning) return undefined;
    const t = setInterval(loadBackups, 4000);
    return () => clearInterval(t);
  }, [hasRunning]);

  function flash(text) { setError(''); setMsg(text); setTimeout(() => setMsg((m) => (m === text ? '' : m)), 5000); }
  async function act(key, fn) {
    setBusy(key); setError('');
    try { await fn(); } catch (ex) { setError(String(ex.message || ex)); } finally { setBusy(''); }
  }

  function openNew() { setEditing(null); setForm({ ...EMPTY_FORM, targetFortigateIds: firewalls.length === 1 ? [firewalls[0].id] : [] }); setShowForm(true); setError(''); }
  function openEdit(p) {
    setEditing(p);
    setForm({ name: p.name, description: p.description || '', enabled: p.enabled, hour: p.hour, minute: p.minute, runAllDays: p.runAllDays, daysOfWeek: p.daysOfWeek || [], retentionDays: p.retentionDays, targetFortigateIds: (p.targets || []).map((t) => t.id) });
    setShowForm(true); setError('');
  }

  function save(e) {
    e.preventDefault();
    if (!form.runAllDays && !form.daysOfWeek.length) return setError('Selecione ao menos um dia da semana.');
    act('save', async () => {
      if (editing) await updateFortigateBackupPolicy(editing.id, form); else await createFortigateBackupPolicy(form);
      setShowForm(false);
      await loadPolicies();
      flash(editing ? 'Política atualizada.' : 'Política criada.');
    });
  }

  const togglePolicy = (p) => act(`toggle-${p.id}`, async () => { await updateFortigateBackupPolicy(p.id, { enabled: !p.enabled }); await loadPolicies(); });
  const removePolicy = (p) => { if (confirm(`Remover a política "${p.name}"? Os backups já feitos são mantidos.`)) act(`del-${p.id}`, async () => { await deleteFortigateBackupPolicy(p.id); await Promise.all([loadPolicies(), loadBackups()]); flash('Política removida.'); }); };
  const runPolicy = (p) => act(`run-${p.id}`, async () => { const r = await runFortigateBackupPolicy(p.id); flash(`Backup iniciado em ${r.started ?? (p.targets || []).length} FortiGate(s).`); setTimeout(loadBackups, 1500); });
  const runNow = (f) => act(`now-${f.id}`, async () => { await runFortigateBackupNow(f.id); flash(`Backup de ${f.name} iniciado.`); setTimeout(loadBackups, 1500); });
  const viewBackup = (b) => act(`view-${b.id}`, async () => { const r = await getFortigateBackupContent(b.id); setView({ ...r, id: b.id, fileName: r.fileName || b.fileName, sizeBytes: b.sizeBytes, fortigateName: b.fortigateName, createdAt: b.createdAt }); });
  const delBackup = (b) => { if (confirm(`Remover o backup ${b.fileName || `#${b.id}`}?`)) act(`delb-${b.id}`, async () => { await deleteFortigateBackup(b.id); await loadBackups(); }); };
  const download = (id) => { window.location.href = `/api/fortigate-backups/${id}/download`; };

  function toggleDay(d) { setForm((f) => ({ ...f, daysOfWeek: f.daysOfWeek.includes(d) ? f.daysOfWeek.filter((x) => x !== d) : [...f.daysOfWeek, d].sort() })); }
  function toggleFg(id) { setForm((f) => ({ ...f, targetFortigateIds: f.targetFortigateIds.includes(id) ? f.targetFortigateIds.filter((x) => x !== id) : [...f.targetFortigateIds, id] })); }
  const allSelected = firewalls.length > 0 && firewalls.every((f) => form.targetFortigateIds.includes(f.id));

  const stats = useMemo(() => {
    const success = backups.filter((b) => b.status === 'success');
    return {
      activePolicies: policies.filter((p) => p.enabled).length,
      success: success.length,
      errors: backups.filter((b) => b.status === 'error').length,
      lastSuccess: success[0]?.createdAt || null,
      storage: success.reduce((sum, b) => sum + (b.sizeBytes || 0), 0)
    };
  }, [policies, backups]);

  const lastByFortigate = useMemo(() => {
    const map = new Map();
    for (const b of backups) if (!map.has(b.fortigateId)) map.set(b.fortigateId, b);
    return map;
  }, [backups]);

  const lastSuccessByFortigate = useMemo(() => {
    const map = new Map();
    for (const b of backups) if (b.status === 'success' && !map.has(b.fortigateId)) map.set(b.fortigateId, b);
    return map;
  }, [backups]);

  const shownBackups = backups.filter((b) => (!histFortigate || String(b.fortigateId) === histFortigate) && (!histStatus || b.status === histStatus));

  return (
    <main className="page-fortigate fgb-page">
      <div className="fgt-head">
        <div className="page-title">
          <span className="fortigate-page-icon fgb-icon" aria-hidden="true">BK</span>
          <div><h2>Backups</h2><span className="hint">Cópias da configuração dos FortiGates, agendadas ou manuais</span></div>
        </div>
        <div className="page-actions">
          <button className="ghost" onClick={loadAll} disabled={loading}>{loading ? 'Atualizando…' : '↻ Atualizar'}</button>
          <button onClick={openNew}>+ Nova política</button>
        </div>
      </div>

      <section className="fgb-stats">
        <div><span>Políticas ativas</span><b>{stats.activePolicies}<small>/ {policies.length}</small></b></div>
        <div><span>Backups com sucesso</span><b className="ok">{stats.success}</b></div>
        <div><span>Falhas</span><b className={stats.errors ? 'err' : ''}>{stats.errors}</b></div>
        <div><span>Último backup</span><b className="fgb-stat-date">{fmtDate(stats.lastSuccess)}</b></div>
        <div><span>Armazenamento</span><b>{fmtBytes(stats.storage)}</b></div>
      </section>

      {error && <p className="error">{error}</p>}
      {msg && <p className="fgt-flash">{msg}</p>}

      <section className="fgt-card fgb-panel">
        <div className="fgb-tabs" role="tablist">
          <button role="tab" className={tab === 'policies' ? 'active' : ''} onClick={() => setTab('policies')}>Políticas<span>{policies.length}</span></button>
          <button role="tab" className={tab === 'backups' ? 'active' : ''} onClick={() => { setTab('backups'); loadBackups(); }}>Histórico<span>{backups.length}</span>{hasRunning && <i className="fgb-pulse" title="Backup em execução" />}</button>
          <button role="tab" className={tab === 'manual' ? 'active' : ''} onClick={() => setTab('manual')}>Execução manual<span>{firewalls.length}</span></button>
        </div>

        {tab === 'policies' && (
          policies.length ? (
            <div className="table-wrap">
              <table className="fgb-table">
                <colgroup><col style={{ width: '24%' }} /><col style={{ width: '9%' }} /><col style={{ width: '20%' }} /><col style={{ width: '9%' }} /><col style={{ width: '18%' }} /><col style={{ width: '20%' }} /></colgroup>
                <thead><tr><th>Política</th><th>Status</th><th>Agendamento</th><th>Retenção</th><th>FortiGates</th><th className="right">Ações</th></tr></thead>
                <tbody>
                  {policies.map((p) => {
                    const next = nextRun(p);
                    const targets = p.targets || [];
                    return (
                      <tr key={p.id} className={p.enabled ? '' : 'fgb-off'}>
                        <td><b>{p.name}</b>{p.description && <small>{p.description}</small>}</td>
                        <td>
                          <button className={`fgb-switch${p.enabled ? ' on' : ''}`} onClick={() => togglePolicy(p)} disabled={busy === `toggle-${p.id}`} title={p.enabled ? 'Pausar política' : 'Ativar política'}>
                            <i />{p.enabled ? 'Ativa' : 'Pausada'}
                          </button>
                        </td>
                        <td>
                          <div className="fgb-sched"><b className="mono">{pad(p.hour)}:{pad(p.minute)}</b>
                            {p.runAllDays ? <span className="fgb-chip">Todos os dias</span> : <span className="fgb-days">{DAYS.map((d, i) => <i key={d} className={(p.daysOfWeek || []).includes(i) ? 'on' : ''}>{d[0]}</i>)}</span>}
                          </div>
                          <small>{next ? `Próxima: ${next.toLocaleString('pt-BR', { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}` : 'Sem próxima execução'}</small>
                        </td>
                        <td>{p.retentionDays} dias</td>
                        <td>
                          {targets.length ? (
                            <div className="fgb-targets" title={targets.map((t) => t.name).join(', ')}>
                              {targets.slice(0, 3).map((t) => <span key={t.id} className="fgb-chip">{t.name}</span>)}
                              {targets.length > 3 && <span className="fgb-chip more">+{targets.length - 3}</span>}
                            </div>
                          ) : <span className="fgt-muted">Nenhum</span>}
                        </td>
                        <td className="right">
                          <div className="fgb-actions">
                            <button className="ghost" onClick={() => runPolicy(p)} disabled={busy === `run-${p.id}` || !targets.length}>{busy === `run-${p.id}` ? 'Iniciando…' : 'Executar'}</button>
                            <button className="ghost" onClick={() => openEdit(p)}>Editar</button>
                            <button className="ghost fgt-btn-danger" onClick={() => removePolicy(p)} disabled={busy === `del-${p.id}`}>Excluir</button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="fgb-empty">
              <b>Nenhuma política de backup</b>
              <span>Crie uma política para copiar a configuração dos FortiGates automaticamente.</span>
              <button onClick={openNew}>+ Nova política</button>
            </div>
          )
        )}

        {tab === 'backups' && (
          <>
            <div className="fgb-filters">
              <label className="dashboard-period-select"><span>FortiGate</span>
                <select value={histFortigate} onChange={(e) => setHistFortigate(e.target.value)}>
                  <option value="">Todos</option>
                  {firewalls.map((f) => <option key={f.id} value={String(f.id)}>{f.name}</option>)}
                </select>
              </label>
              <label className="dashboard-period-select"><span>Status</span>
                <select value={histStatus} onChange={(e) => setHistStatus(e.target.value)}>
                  <option value="">Todos</option>
                  <option value="success">Sucesso</option>
                  <option value="error">Erro</option>
                  <option value="running">Executando</option>
                </select>
              </label>
              <span className="hint fgb-filters-count">{shownBackups.length} de {backups.length} backups</span>
            </div>
            <div className="table-wrap">
              <table className="fgb-table">
                <colgroup><col style={{ width: '15%' }} /><col style={{ width: '15%' }} /><col style={{ width: '13%' }} /><col style={{ width: '13%' }} /><col style={{ width: '9%' }} /><col style={{ width: '17%' }} /><col style={{ width: '18%' }} /></colgroup>
                <thead><tr><th>Data/hora</th><th>FortiGate</th><th>Origem</th><th>Status</th><th>Tamanho</th><th>Arquivo</th><th className="right">Ações</th></tr></thead>
                <tbody>
                  {shownBackups.map((b) => (
                    <tr key={b.id}>
                      <td>{fmtDate(b.createdAt)}{fmtDuration(b.startedAt, b.finishedAt) && <small>em {fmtDuration(b.startedAt, b.finishedAt)}</small>}</td>
                      <td><b>{b.fortigateName || '—'}</b>{b.fortigateHost && <small className="mono">{b.fortigateHost}</small>}</td>
                      <td>{b.policyName ? <span className="fgb-chip">{b.policyName}</span> : <span className="fgb-chip manual">Manual</span>}</td>
                      <td><StatusBadge status={b.status} />{b.status === 'error' && b.errorMsg && <small className="fgb-errmsg" title={b.errorMsg}>{b.errorMsg}</small>}</td>
                      <td>{b.sizeBytes ? fmtBytes(b.sizeBytes) : '—'}</td>
                      <td><span className="mono fgb-file" title={b.fileName || ''}>{b.fileName || '—'}</span></td>
                      <td className="right">
                        <div className="fgb-actions">
                          {b.status === 'success' && <>
                            <button className="ghost" onClick={() => viewBackup(b)} disabled={busy === `view-${b.id}`}>Ver</button>
                            <button className="ghost" onClick={() => download(b.id)}>Baixar</button>
                          </>}
                          <button className="ghost fgt-btn-danger" onClick={() => delBackup(b)} disabled={busy === `delb-${b.id}` || b.status === 'running'}>Excluir</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {!shownBackups.length && <tr><td colSpan={7} className="empty">{backups.length ? 'Nenhum backup para este filtro.' : 'Nenhum backup realizado ainda.'}</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === 'manual' && (
          firewalls.length ? (
            <div className="fgb-manual">
              {firewalls.map((f) => {
                const last = lastByFortigate.get(f.id);
                const lastOk = lastSuccessByFortigate.get(f.id);
                const running = last?.status === 'running';
                return (
                  <article key={f.id} className="fgb-manual-card">
                    <div className="fgt-device-top">
                      <span className="fortigate-device-icon" aria-hidden="true">▣</span>
                      <div className="fgt-device-info"><b>{f.name}</b><span className="mono">{f.host}</span></div>
                      {last && <StatusBadge status={last.status} />}
                    </div>
                    <dl className="fgb-manual-meta">
                      <div><dt>Último backup OK</dt><dd>{lastOk ? fmtDate(lastOk.createdAt) : 'Nunca'}</dd></div>
                      <div><dt>Tamanho</dt><dd>{lastOk?.sizeBytes ? fmtBytes(lastOk.sizeBytes) : '—'}</dd></div>
                    </dl>
                    {last?.status === 'error' && last.errorMsg && <p className="fgb-errmsg" title={last.errorMsg}>{last.errorMsg}</p>}
                    <div className="fgb-manual-actions">
                      {lastOk && <button className="ghost" onClick={() => download(lastOk.id)}>Baixar último</button>}
                      <button onClick={() => runNow(f)} disabled={running || busy === `now-${f.id}`}>{running || busy === `now-${f.id}` ? 'Executando…' : 'Fazer backup agora'}</button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : <div className="fgb-empty"><b>Nenhum FortiGate cadastrado</b><span>Cadastre um firewall na aba "Firewalls e políticas".</span></div>
        )}
      </section>

      {showForm && (
        <div className="modal-backdrop" onClick={() => setShowForm(false)}>
          <div className="modal fgb-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head"><div><h2>{editing ? 'Editar política' : 'Nova política de backup'}</h2><span className="hint">Define quando e de quais FortiGates a configuração é copiada</span></div><button className="ghost" onClick={() => setShowForm(false)}>✕</button></div>
            <form className="modal-body fgb-form" onSubmit={save}>
              <div className="fgb-form-row">
                <label className="fortigate-field fgb-grow"><span>Nome</span><input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Ex.: Backup diário" required /></label>
                <div className="fortigate-field"><span>Status</span>
                  <button type="button" className={`fgb-switch${form.enabled ? ' on' : ''}`} onClick={() => setForm((f) => ({ ...f, enabled: !f.enabled }))}><i />{form.enabled ? 'Ativa' : 'Pausada'}</button>
                </div>
              </div>
              <label className="fortigate-field"><span>Descrição (opcional)</span><input value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} placeholder="Para que serve esta política" /></label>

              <fieldset className="fgb-fieldset">
                <legend>Agendamento</legend>
                <div className="fgb-form-row">
                  <label className="fortigate-field"><span>Horário</span>
                    <input type="time" value={`${pad(form.hour)}:${pad(form.minute)}`} onChange={(e) => { const [h, m] = e.target.value.split(':').map(Number); setForm((f) => ({ ...f, hour: h || 0, minute: m || 0 })); }} required />
                  </label>
                  <label className="fortigate-field"><span>Retenção (dias)</span><input type="number" min="1" max="3650" value={form.retentionDays} onChange={(e) => setForm((f) => ({ ...f, retentionDays: Number(e.target.value) }))} /></label>
                </div>
                <div className="fortigate-field"><span>Dias da semana</span>
                  <div className="fgb-daypick">
                    <button type="button" className={form.runAllDays ? 'on' : ''} onClick={() => setForm((f) => ({ ...f, runAllDays: true }))}>Todos os dias</button>
                    {DAYS.map((d, i) => <button type="button" key={d} className={!form.runAllDays && form.daysOfWeek.includes(i) ? 'on' : ''} onClick={() => { setForm((f) => ({ ...f, runAllDays: false })); toggleDay(i); }}>{d}</button>)}
                  </div>
                </div>
              </fieldset>

              <fieldset className="fgb-fieldset">
                <legend>FortiGates <span className="hint">({form.targetFortigateIds.length} selecionados)</span></legend>
                {firewalls.length ? <>
                  <label className="chk fgb-selall"><input type="checkbox" checked={allSelected} onChange={() => setForm((f) => ({ ...f, targetFortigateIds: allSelected ? [] : firewalls.map((x) => x.id) }))} /> Selecionar todos</label>
                  <div className="fgb-fglist">
                    {firewalls.map((f) => (
                      <label key={f.id} className={`fgb-fgitem${form.targetFortigateIds.includes(f.id) ? ' on' : ''}`}>
                        <input type="checkbox" checked={form.targetFortigateIds.includes(f.id)} onChange={() => toggleFg(f.id)} />
                        <span><b>{f.name}</b><small className="mono">{f.host}</small></span>
                      </label>
                    ))}
                  </div>
                </> : <p className="hint">Nenhum FortiGate cadastrado.</p>}
              </fieldset>

              <div className="fgb-form-footer">
                <button type="button" className="ghost" onClick={() => setShowForm(false)}>Cancelar</button>
                <button type="submit" disabled={busy === 'save'}>{busy === 'save' ? 'Salvando…' : editing ? 'Salvar alterações' : 'Criar política'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {view && (
        <div className="modal-backdrop" onClick={() => setView(null)}>
          <div className="modal modal-wide fgb-view" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div><h2>{view.fortigateName || 'Backup'}</h2><span className="hint mono">{view.fileName || ''} · {fmtDate(view.createdAt)}{view.sizeBytes ? ` · ${fmtBytes(view.sizeBytes)}` : ''} · {(view.content || '').split('\n').length} linhas</span></div>
              <div className="page-actions">
                <button className="ghost" onClick={() => navigator.clipboard?.writeText(view.content || '').then(() => flash('Configuração copiada.'))}>Copiar</button>
                <button className="ghost" onClick={() => download(view.id)}>Baixar</button>
                <button className="ghost" onClick={() => setView(null)}>✕</button>
              </div>
            </div>
            <div className="modal-body"><pre className="fgb-pre">{view.content || ''}</pre></div>
          </div>
        </div>
      )}
    </main>
  );
}
