import { Fragment, useEffect, useMemo, useState } from 'react';
import FortigatePortMap from './FortigatePortMap.jsx';
import { fmtBytes, fetchFortigates, fetchFortigateAudit, fetchFortigateEvents, collectFortigateEvents } from '../api.js';

// Auditoria de usuários e interfaces do FortiGate (somente leitura):
// administradores e tokens de API (trusted hosts, 2FA), usuários locais e
// grupos, quem está autenticado agora e interfaces/VLANs com serviços de
// gerência perigosos.

const SEV = { alta: { label: 'Alta', cls: 'high' }, media: { label: 'Média', cls: 'med' }, baixa: { label: 'Baixa', cls: 'low' } };
const KIND_LABEL = { local: 'Local', remoto: 'Remoto', api: 'Token de API' };
const AUTH_LABEL = { password: 'Senha local', ldap: 'LDAP', radius: 'RADIUS', 'tacacs+': 'TACACS+' };
const ROLE_LABEL = { wan: 'WAN', lan: 'LAN', dmz: 'DMZ', undefined: '—' };
const ERROR_LABEL = {
  admins: 'Administradores', apiUsers: 'Tokens de API', interfaces: 'Interfaces', interfaceStats: 'Estatísticas das interfaces',
  localUsers: 'Usuários locais', userGroups: 'Grupos de usuários', authUsers: 'Usuários autenticados',
  ipsecPhase1: 'VPN IPsec (fase 1)', ipsecPhase2: 'VPN IPsec (fase 2)', ipsecMonitor: 'Status dos túneis IPsec',
  sslSettings: 'Configuração da SSL-VPN', sslMonitor: 'Sessões SSL-VPN', adminEvents: 'Eventos de administradores',
  currentAdmins: 'Sessões administrativas', userLogins: 'Logins de usuários (log)'
};
// Cor dos grupos DH: fraco (1/2/5) · desaconselhado (22–26) · forte (ECDH) · MODP aceitável.
const dhClass = (g) => ([1, 2, 5].includes(g) ? 'high' : [22, 23, 24, 25, 26].includes(g) ? 'med' : g >= 19 ? 'low' : '');

function CryptoChips({ proposals, dh }) {
  return (
    <div className="fau-chips">
      {proposals.map((p) => <span key={p.token} className={`fau-svc ${p.severity ? SEV[p.severity].cls : 'low'}`} title={p.severity ? `Fraca (${SEV[p.severity].label})` : 'Adequada'}>{p.token}</span>)}
      {dh.map((g) => <span key={`dh${g}`} className={`fau-svc fau-dh ${dhClass(g)}`} title="Grupo Diffie-Hellman">DH {g}</span>)}
    </div>
  );
}

function fmtUptime(sec) {
  if (!sec) return null;
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  return d ? `${d}d ${h}h` : `${h}h ${Math.floor((sec % 3600) / 60)}min`;
}
const num = (v) => (v == null ? '—' : Number(v).toLocaleString('pt-BR'));

function fmtDuration(sec) {
  if (sec == null) return '—';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h ? `${h}h ${m}min` : `${m}min`;
}

// Eventos de administradores: login/logout, mudanças de configuração, download
// de backup. Lidos do log em memória do FortiGate (volátil) e persistidos no
// Postgres pelo backend (coleta periódica + a cada auditoria), sem duplicar.
// Esta seção consulta o histórico do banco, com filtros.
const EVENT_ACTION_LABEL = { login: 'Login', logout: 'Logout', download: 'Download', Edit: 'Alteração', Add: 'Criação', Delete: 'Exclusão', outro: 'Outro' };
const EVENT_ACTION_CLS = { login: 'ok', logout: '', download: 'warn', Edit: 'warn', Add: 'warn', Delete: 'bad' };
const EVENT_PAGE = 50;
const EVENT_PERIODS = [
  { value: '24h', label: 'Últimas 24 h', ms: 24 * 3600e3 },
  { value: '7d', label: 'Últimos 7 dias', ms: 7 * 86400e3 },
  { value: '30d', label: 'Últimos 30 dias', ms: 30 * 86400e3 },
  { value: '90d', label: 'Últimos 90 dias', ms: 90 * 86400e3 },
  { value: 'all', label: 'Tudo', ms: 0 }
];
const fmtWhen = (v) => (v ? new Date(v).toLocaleString('pt-BR') : '—');
const isFail = (e) => e.status === 'failure' || /failed|falh/i.test(e.description || '');

function AdminEvents({ fortigateId, refreshKey }) {
  const [user, setUser] = useState('');
  const [action, setAction] = useState('');
  const [status, setStatus] = useState('');
  const [period, setPeriod] = useState('30d');
  const [q, setQ] = useState('');
  const [qApplied, setQApplied] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [collecting, setCollecting] = useState(false);
  const [note, setNote] = useState('');

  // Busca de texto com atraso para não consultar a cada tecla.
  useEffect(() => { const t = setTimeout(() => setQApplied(q.trim()), 350); return () => clearTimeout(t); }, [q]);
  useEffect(() => { setPage(0); }, [user, action, status, period, qApplied, fortigateId]);
  useEffect(() => { setUser(''); setAction(''); }, [fortigateId]);

  useEffect(() => {
    if (!fortigateId) return undefined;
    let alive = true;
    setLoading(true); setError('');
    const p = EVENT_PERIODS.find((x) => x.value === period);
    const from = p?.ms ? new Date(Date.now() - p.ms).toISOString() : '';
    fetchFortigateEvents({ fortigateId, user, action, status, from, q: qApplied, limit: EVENT_PAGE, offset: page * EVENT_PAGE })
      .then((r) => { if (alive) setData(r); })
      .catch((e) => { if (alive) { setData(null); setError(String(e.message || e)); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [fortigateId, user, action, status, period, qApplied, page, refreshKey]);

  async function collectNow() {
    setCollecting(true); setNote('');
    try {
      const r = await collectFortigateEvents(fortigateId);
      const me = (r.results || [])[0];
      setNote(me?.error ? `Falha: ${me.error}` : `${me?.inserted ?? 0} novo(s) de ${me?.read ?? 0} lidos no FortiGate.`);
      const p = EVENT_PERIODS.find((x) => x.value === period);
      const from = p?.ms ? new Date(Date.now() - p.ms).toISOString() : '';
      setData(await fetchFortigateEvents({ fortigateId, user, action, status, from, q: qApplied, limit: EVENT_PAGE, offset: page * EVENT_PAGE }));
    } catch (e) { setNote(`Falha: ${e.message || e}`); }
    finally { setCollecting(false); setTimeout(() => setNote(''), 6000); }
  }

  const events = data?.events || [];
  const total = data?.total || 0;
  const pages = Math.max(1, Math.ceil(total / EVENT_PAGE));
  const actionLabel = (a) => EVENT_ACTION_LABEL[a] || a || 'Outro';
  const filtersOn = !!(user || action || status || q || period !== '30d');
  function clearFilters() { setUser(''); setAction(''); setStatus(''); setQ(''); setQApplied(''); setPeriod('30d'); setPage(0); }

  // Última passagem do coletor: alerta se atrasou mais que o dobro do intervalo.
  const lastCollected = data?.lastCollectedAt ? new Date(data.lastCollectedAt) : null;
  const everyMin = data?.collectEveryMin || 0;
  const lateMs = lastCollected ? Date.now() - lastCollected.getTime() : null;
  const collectLate = everyMin > 0 && lateMs != null && lateMs > everyMin * 2 * 60000;

  return (
    <>
      <div className="fau-subtitle fau-events-head">
        <h4>Eventos de administradores <span className="hint">({num(total)}{loading ? ' · consultando…' : ''})</span></h4>
        <div className="fau-events-filters">
          <label className="dashboard-period-select"><span>Período</span>
            <select value={period} onChange={(e) => setPeriod(e.target.value)}>
              {EVENT_PERIODS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </label>
          <label className="dashboard-period-select"><span>Usuário</span>
            <select value={user} onChange={(e) => setUser(e.target.value)}>
              <option value="">Todos</option>
              {(data?.users || []).map((u) => <option key={u.user} value={u.user}>{u.user} ({u.count})</option>)}
            </select>
          </label>
          <label className="dashboard-period-select"><span>Ação</span>
            <select value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="">Todas</option>
              {(data?.actions || []).map((a) => <option key={a.action} value={a.action}>{actionLabel(a.action)} ({a.count})</option>)}
            </select>
          </label>
          <label className="dashboard-period-select"><span>Resultado</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Todos</option>
              <option value="success">Sucesso</option>
              <option value="failure">Falha</option>
            </select>
          </label>
          <label className="dashboard-period-select fgt-psearch"><span>Buscar</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, objeto, mensagem…" />
          </label>
          <button className="ghost" onClick={clearFilters} disabled={!filtersOn} title="Volta aos filtros padrão (últimos 30 dias)">Limpar filtros</button>
          <button className="ghost" onClick={collectNow} disabled={collecting || !fortigateId} title="Lê o log do FortiGate agora e guarda o que ainda não existe no banco">{collecting ? 'Coletando…' : '↓ Coletar agora'}</button>
        </div>
      </div>
      <p className="hint fau-events-status">
        <span className={collectLate ? 'late' : ''} title={collectLate ? `A última passagem do coletor foi há mais de ${everyMin * 2} min: verifique se o backend está no ar.` : 'O coletor roda no backend, independentemente de alguém estar com a tela aberta.'}>
          Última coleta: <b>{lastCollected ? lastCollected.toLocaleString('pt-BR') : 'nunca'}</b>
          {everyMin > 0 ? ` · automática a cada ${everyMin} min` : ' · coleta automática desligada'}
          {collectLate && <b className="fau-late-tag">ATRASADA</b>}
        </span>
        {data?.lastEventAt && <span> · evento mais recente guardado: <b>{new Date(data.lastEventAt).toLocaleString('pt-BR')}</b></span>}
        {note && <b className="fau-events-note"> {note}</b>}
      </p>
      <p className="hint">Histórico guardado no banco a partir do log em memória do FortiGate (subtype <code>system</code>, só registros com <code>user</code>). O equipamento descarta os antigos; aqui ficam todos, sem duplicar.</p>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap">
        <table className="fgb-table fau-table fau-events">
          <colgroup><col style={{ width: '13%' }} /><col style={{ width: '13%' }} /><col style={{ width: '9%' }} /><col style={{ width: '15%' }} /><col style={{ width: '38%' }} /><col style={{ width: '12%' }} /></colgroup>
          <thead><tr><th>Quando</th><th>Usuário</th><th>Ação</th><th>Origem</th><th>Detalhe</th><th>Objeto</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className={isFail(e) ? 'fau-event-fail' : ''}>
                <td className="mono">{fmtWhen(e.when)}</td>
                <td><b>{e.user}</b>{e.profile && <small>{e.profile}</small>}</td>
                <td><span className={`fau-tag ${isFail(e) ? 'bad' : EVENT_ACTION_CLS[e.action] || ''}`}>{actionLabel(e.action)}{isFail(e) ? ' (falha)' : ''}</span></td>
                <td className="mono">{e.srcip || e.ui || '—'}{e.method && e.srcip && <small>{e.method}</small>}</td>
                <td><span title={e.message || ''}>{e.description || '—'}</span>{e.message && e.message !== e.description && <small>{e.message}</small>}</td>
                <td className="mono">{e.config ? <span title={e.configAttr || ''}>{e.config}</span> : <span className="fgt-muted">—</span>}{e.configAttr && <small>{e.configAttr}</small>}</td>
              </tr>
            ))}
            {!events.length && !loading && <tr><td colSpan={6} className="empty">{error ? 'Histórico não lido.' : filtersOn ? <>Nenhum evento para este filtro. <button className="fga-link" onClick={clearFilters}>Limpar filtros</button></> : 'Nenhum evento guardado ainda. Clique em "Coletar agora".'}</td></tr>}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="fau-events-more">
          <button className="ghost" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>‹ Anterior</button>
          <span className="hint">página {page + 1} de {pages}</span>
          <button className="ghost" onClick={() => setPage((p) => Math.min(pages - 1, p + 1))} disabled={page >= pages - 1}>Próxima ›</button>
        </div>
      )}
    </>
  );
}


// Último login (admins: log system + sessão ativa; locais: log vpn/user +
// sessão autenticada). Sem FortiAnalyzer a fonte é o log em memória, que gira:
// "—" significa "nada no log atual", não "nunca".
function LastLogin({ value }) {
  if (!value?.when) return <span className="fgt-muted" title="Sem registro no log em memória do FortiGate (o log é volátil)">—</span>;
  const when = new Date(value.when);
  const title = [`${when.toLocaleString('pt-BR')}`, value.from && `de ${value.from}`, value.method && `via ${value.method}`, value.source === 'sessao' ? 'sessão ativa agora' : 'do log em memória'].filter(Boolean).join(' · ');
  return (
    <span className="fau-lastlogin" title={title}>
      <b>{value.active && <i className="fau-online" title="Logado agora" />}{when.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} {when.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</b>
      {value.from && <small className="mono">{value.from}</small>}
    </span>
  );
}

function SevPill({ severity }) {
  if (!severity) return <span className="fau-ok">OK</span>;
  const s = SEV[severity];
  return <span className={`fga-sev-pill ${s.cls}`}>{s.label}</span>;
}

function Chips({ items, max = 4, className = '' }) {
  if (!items?.length) return <span className="fgt-muted">—</span>;
  return (
    <div className="fau-chips" title={items.join(', ')}>
      {items.slice(0, max).map((x) => <span key={x} className={`fgb-chip ${className}`}>{x}</span>)}
      {items.length > max && <span className="fgb-chip more">+{items.length - max}</span>}
    </div>
  );
}

function FindingsRow({ findings, colSpan }) {
  return (
    <tr className="fau-findings-row">
      <td colSpan={colSpan}>
        {findings.length ? findings.map((f, i) => (
          <div key={i} className={`fau-finding ${SEV[f.severity].cls}`}>
            <SevPill severity={f.severity} />
            <div><b>{f.title}</b><p>{f.detail}</p><p className="fau-rec"><span>Recomendação:</span> {f.recommendation}</p></div>
          </div>
        )) : <p className="hint">Nenhum achado.</p>}
      </td>
    </tr>
  );
}

function FindingsCell({ findings, open }) {
  if (!findings.length) return <span className="fgt-muted">—</span>;
  return <span className="fau-count">{findings.length} {findings.length === 1 ? 'achado' : 'achados'} <i>{open ? '▾' : '▸'}</i></span>;
}

function exportCsv(audit) {
  const rows = [];
  const push = (area, item, f) => rows.push([area, item, f.severity, f.title, f.detail, f.recommendation]);
  for (const u of audit.admins || []) for (const f of u.findings) push(`Administrador (${KIND_LABEL[u.kind]})`, u.name, f);
  for (const u of audit.localUsers || []) if (u.enabled) for (const f of u.findings) push('Usuário local', u.name, f);
  for (const g of audit.groups || []) for (const f of g.findings) push('Grupo', g.name, f);
  for (const i of audit.interfaces || []) for (const f of i.findings) push('Interface', i.name, f);
  for (const t of audit.vpn?.ipsec || []) {
    for (const f of t.findings) push('VPN IPsec (fase 1)', t.name, f);
    for (const p of t.phase2) for (const f of p.findings) push('VPN IPsec (fase 2)', `${t.name} / ${p.name}`, f);
  }
  for (const f of audit.vpn?.sslvpn?.findings || []) push('SSL-VPN', 'configuração', f);
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = ['\ufeff' + ['Área', 'Item', 'Severidade', 'Achado', 'Detalhe', 'Recomendação'].map(esc).join(';'), ...rows.map((r) => r.map(esc).join(';'))].join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `auditoria-${(audit.firewall?.name || 'fortigate').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function FortigateAuditScreen({ firewalls: firewallsProp = [] }) {
  const [firewalls, setFirewalls] = useState(firewallsProp);
  const [fwId, setFwId] = useState(firewallsProp[0]?.id ?? null);
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('admins');
  const [search, setSearch] = useState('');
  const [onlyIssues, setOnlyIssues] = useState(false);
  const [ifaceKind, setIfaceKind] = useState('all'); // all | physical | vlan | exposed
  const [model, setModel] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());

  useEffect(() => {
    fetchFortigates().then((r) => {
      const list = r.firewalls || [];
      setFirewalls(list);
      setFwId((cur) => (list.some((f) => f.id === cur) ? cur : list[0]?.id ?? null));
    }).catch(() => {});
  }, []);

  async function runAudit(id = fwId) {
    if (!id) return;
    setLoading(true); setError('');
    try {
      setAudit(await fetchFortigateAudit(id));
      setExpanded(new Set());
    } catch (e) {
      setAudit(null);
      setError(String(e.message || e));
    } finally { setLoading(false); }
  }
  useEffect(() => { if (fwId) runAudit(fwId); }, [fwId]); // eslint-disable-line
  useEffect(() => {
    if (!fwId) return;
    fetch(`/api/fortigate/${fwId}/system-status`, { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setModel(d.model || ''))
      .catch(() => setModel(''));
  }, [fwId]);

  const toggle = (key) => setExpanded((prev) => { const n = new Set(prev); if (n.has(key)) n.delete(key); else n.add(key); return n; });
  const term = search.trim().toLowerCase();
  const match = (...vals) => !term || vals.flat().filter(Boolean).join(' ').toLowerCase().includes(term);

  const admins = useMemo(() => (audit?.admins || []).filter((u) => (!onlyIssues || u.findings.length) && match(u.name, u.profile, u.trustedHosts, u.comments)), [audit, onlyIssues, term]); // eslint-disable-line
  const localUsers = useMemo(() => (audit?.localUsers || []).filter((u) => (!onlyIssues || (u.enabled && u.findings.length)) && match(u.name, u.groups, u.type, u.server)), [audit, onlyIssues, term]); // eslint-disable-line
  const groups = useMemo(() => (audit?.groups || []).filter((g) => (!onlyIssues || g.findings.length) && match(g.name, g.members, g.remoteServers)), [audit, onlyIssues, term]); // eslint-disable-line
  const sessions = useMemo(() => (audit?.sessions || []).filter((s) => match(s.username, s.ip, s.groups, s.type)), [audit, term]); // eslint-disable-line
  const interfaces = useMemo(() => (audit?.interfaces || []).filter((i) => {
    if (onlyIssues && !i.findings.length) return false;
    if (ifaceKind === 'vlan' && i.vlanId == null) return false;
    if (ifaceKind === 'physical' && i.type !== 'physical') return false;
    if (ifaceKind === 'exposed' && !i.exposed) return false;
    return match(i.name, i.alias, i.description, i.ip, i.parent, i.vlanId != null ? `vlan ${i.vlanId}` : '', i.services.map((s) => s.label));
  }), [audit, onlyIssues, ifaceKind, term]); // eslint-disable-line

  const tunnels = useMemo(() => (audit?.vpn?.ipsec || []).filter((t) => (!onlyIssues || t.findingCount) && match(
    t.name, t.comments, t.remoteGw, t.interface, t.proposals.map((p) => p.token), t.phase2.map((p) => [p.name, p.src, p.dst])
  )), [audit, onlyIssues, term]); // eslint-disable-line

  const s = audit?.summary;
  const sectionErrors = Object.entries(audit?.errors || {}).filter(([, v]) => v);
  const fw = firewalls.find((f) => f.id === fwId);

  return (
    <main className="page-fortigate fau-page">
      <div className="fgt-head">
        <div className="page-title">
          <span className="fortigate-page-icon fau-icon" aria-hidden="true">AU</span>
          <div><h2>Auditoria</h2><span className="hint">Administradores, usuários, sessões autenticadas e serviços expostos nas interfaces · somente leitura</span></div>
        </div>
        <div className="page-actions fau-head-actions">
          <label className="dashboard-period-select"><span>Firewall</span>
            <select value={fwId ?? ''} onChange={(e) => setFwId(Number(e.target.value))} disabled={!firewalls.length}>
              {firewalls.map((f) => <option key={f.id} value={f.id}>{f.name} · {f.host}</option>)}
            </select>
          </label>
          <button className="ghost" onClick={() => runAudit()} disabled={loading || !fwId}>{loading ? 'Auditando…' : '↻ Auditar'}</button>
          <button className="ghost" onClick={() => exportCsv(audit)} disabled={!audit}>Exportar CSV</button>
        </div>
      </div>

      {!firewalls.length && <div className="fgb-empty"><b>Nenhum FortiGate cadastrado</b><span>Cadastre um firewall na aba "Firewalls e políticas".</span></div>}
      {error && <p className="error">{error}</p>}
      {loading && !audit && <div className="fga-loading"><i />Lendo a configuração de {fw?.name || 'FortiGate'}…</div>}

      <FortigatePortMap model={model} interfaces={audit?.interfaces || []} />

      {audit && (
        <>
          <section className={`fau-stats${loading ? ' dim' : ''}`}>
            <div className="fau-stat sev">
              <span>Achados</span>
              <div className="fau-sevline">
                <b className="high">{s.bySeverity.alta}</b><small>alta</small>
                <b className="med">{s.bySeverity.media}</b><small>média</small>
                <b className="low">{s.bySeverity.baixa}</b><small>baixa</small>
              </div>
            </div>
            {audit.adminsHidden ? (
              <>
                <div className="fau-stat warn"><span>Admins de qualquer lugar</span><b className="fau-hidden">oculto</b></div>
                <div className="fau-stat warn"><span>Admins locais sem 2FA</span><b className="fau-hidden">oculto</b></div>
              </>
            ) : (
              <>
                <div className={`fau-stat${s.adminsAnywhere ? ' bad' : ''}`}><span>Admins de qualquer lugar</span><b>{s.adminsAnywhere}<small>/ {s.admins}</small></b></div>
                <div className={`fau-stat${s.adminsWithout2fa ? ' warn' : ''}`}><span>Admins locais sem 2FA</span><b>{s.adminsWithout2fa}</b></div>
              </>
            )}
            <div className={`fau-stat${s.localUsersWithout2fa ? ' warn' : ''}`}><span>Usuários locais sem 2FA</span><b>{s.localUsersWithout2fa}<small>/ {s.localUsersEnabled} ativos</small></b></div>
            <div className={`fau-stat${s.exposedWithAdmin ? ' bad' : ''}`}><span>Interfaces expostas c/ gerência</span><b>{s.exposedWithAdmin}</b></div>
            <div className={`fau-stat${s.vpnWeak ? ' warn' : ''}`}><span>VPNs com config. fraca</span><b>{s.vpnWeak}<small>/ {s.vpnTunnels} túneis</small></b></div>
            <div className="fau-stat"><span>Autenticados agora</span><b>{s.authenticated}</b></div>
          </section>
          <p className="hint fau-meta">{audit.firewall?.name} · {audit.firewall?.host}{audit.version ? ` · FortiOS ${audit.version}` : ''} · auditado em {new Date(audit.generatedAt).toLocaleString('pt-BR')}</p>
          {!!sectionErrors.length && (
            <div className="map-perf-note fau-errors">
              <b>Algumas tabelas não puderam ser lidas:</b>
              <ul>{sectionErrors.map(([k, v]) => <li key={k}>{ERROR_LABEL[k] || k}: {v}</li>)}</ul>
            </div>
          )}

          <section className="fgt-card fgb-panel">
            <div className="fgb-tabs" role="tablist">
              <button className={tab === 'admins' ? 'active' : ''} onClick={() => setTab('admins')}>Administradores<span>{s.admins}</span></button>
              <button className={tab === 'local' ? 'active' : ''} onClick={() => setTab('local')}>Usuários locais<span>{s.localUsers}</span></button>
              <button className={tab === 'sessions' ? 'active' : ''} onClick={() => setTab('sessions')}>Autenticados<span>{s.authenticated}</span></button>
              <button className={tab === 'interfaces' ? 'active' : ''} onClick={() => setTab('interfaces')}>Interfaces<span>{s.interfaces}</span>{s.interfacesDangerous > 0 && <i className="fau-dot" title={`${s.interfacesDangerous} com serviço perigoso`} />}</button>
              <button className={tab === 'vpn' ? 'active' : ''} onClick={() => setTab('vpn')}>VPNs<span>{s.vpnTunnels}</span>{s.vpnWeak > 0 && <i className="fau-dot" title={`${s.vpnWeak} túnel(is) com configuração fraca`} />}</button>
            </div>

            <div className="fgb-filters">
              <input className="fau-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Buscar por nome, IP, grupo, serviço…" />
              {tab === 'interfaces' && (
                <label className="dashboard-period-select"><span>Tipo</span>
                  <select value={ifaceKind} onChange={(e) => setIfaceKind(e.target.value)}>
                    <option value="all">Todas</option>
                    <option value="physical">Físicas</option>
                    <option value="vlan">VLANs ({s.vlans})</option>
                    <option value="exposed">Expostas (WAN / IP público)</option>
                  </select>
                </label>
              )}
              {tab !== 'sessions' && <label className="chk"><input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} /> só com achados</label>}
            </div>

            {tab === 'admins' && audit.adminsHidden && (
              <div className="fau-hidden-note">
                <b>Sem acesso aos administradores</b>
                <p>O perfil do token cadastrado não permite listar os administradores deste FortiGate.</p>
              </div>
            )}

            {tab === 'admins' && !audit.adminsHidden && (
              <div className="table-wrap">
                <table className="fgb-table fau-table">
                  <colgroup><col style={{ width: '7%' }} /><col style={{ width: '14%' }} /><col style={{ width: '9%' }} /><col style={{ width: '11%' }} /><col style={{ width: '20%' }} /><col style={{ width: '9%' }} /><col style={{ width: '7%' }} /><col style={{ width: '12%' }} /><col style={{ width: '11%' }} /></colgroup>
                  <thead><tr><th>Risco</th><th>Usuário</th><th>Tipo</th><th>Perfil</th><th>Trusted hosts</th><th>2FA</th><th>VDOMs</th><th>Último login</th><th>Achados</th></tr></thead>
                  <tbody>
                    {admins.map((u) => {
                      const key = `a-${u.kind}-${u.name}`;
                      const open = expanded.has(key);
                      return (
                        <Fragment key={key}>
                          <tr className={`fau-row${open ? ' open' : ''}`} onClick={() => toggle(key)}>
                            <td><SevPill severity={u.severity} /></td>
                            <td><b>{u.name}</b>{u.comments && <small>{u.comments}</small>}</td>
                            <td>{KIND_LABEL[u.kind]}</td>
                            <td>{u.profile || '—'}{u.superAdmin && <small className="fau-public">privilégio total</small>}</td>
                            <td>{u.anywhere ? <span className="fau-tag bad">Qualquer lugar</span> : <Chips items={u.trustedHosts} className="mono" />}</td>
                            <td>{u.kind === 'api' ? <span className="fgt-muted">n/a</span> : u.twoFactor ? <span className="fau-tag ok">{u.twoFactor}</span> : <span className="fau-tag warn">Desabilitado</span>}</td>
                            <td><Chips items={u.vdoms} max={2} /></td>
                            <td><LastLogin value={u.lastLogin} /></td>
                            <td><FindingsCell findings={u.findings} open={open} /></td>
                          </tr>
                          {open && <FindingsRow findings={u.findings} colSpan={9} />}
                        </Fragment>
                      );
                    })}
                    {!admins.length && <tr><td colSpan={9} className="empty">{audit.errors?.admins ? 'Tabela não lida (veja o aviso acima).' : 'Nenhum administrador para este filtro.'}</td></tr>}
                  </tbody>
                </table>
              </div>
            )}

            {tab === 'admins' && <AdminEvents fortigateId={fwId} refreshKey={audit.generatedAt} />}

            {tab === 'local' && (
              <>
                <div className="table-wrap">
                  <table className="fgb-table fau-table">
                    <colgroup><col style={{ width: '7%' }} /><col style={{ width: '18%' }} /><col style={{ width: '9%' }} /><col style={{ width: '14%' }} /><col style={{ width: '10%' }} /><col style={{ width: '19%' }} /><col style={{ width: '12%' }} /><col style={{ width: '11%' }} /></colgroup>
                    <thead><tr><th>Risco</th><th>Usuário</th><th>Status</th><th>Autenticação</th><th>2FA</th><th>Grupos</th><th>Último login</th><th>Achados</th></tr></thead>
                    <tbody>
                      {localUsers.map((u) => {
                        const key = `l-${u.name}`;
                        const open = expanded.has(key);
                        return (
                          <Fragment key={key}>
                            <tr className={`fau-row${open ? ' open' : ''}${u.enabled ? '' : ' fgb-off'}`} onClick={() => toggle(key)}>
                              <td><SevPill severity={u.severity} /></td>
                              <td><b>{u.name}</b>{u.email && <small>{u.email}</small>}</td>
                              <td>{u.enabled ? <span className="fau-tag ok">Ativo</span> : <span className="fau-tag">Desativado</span>}</td>
                              <td>{AUTH_LABEL[u.type] || u.type}{u.server && <small>{u.server}</small>}</td>
                              <td>{u.type !== 'password' ? <span className="fgt-muted">no servidor</span> : u.twoFactor ? <span className="fau-tag ok">{u.twoFactor}</span> : <span className="fau-tag warn">Desabilitado</span>}</td>
                              <td><Chips items={u.groups} max={3} /></td>
                              <td><LastLogin value={u.lastLogin} /></td>
                              <td><FindingsCell findings={u.enabled ? u.findings : []} open={open} /></td>
                            </tr>
                            {open && <FindingsRow findings={u.enabled ? u.findings : []} colSpan={8} />}
                          </Fragment>
                        );
                      })}
                      {!localUsers.length && <tr><td colSpan={8} className="empty">{audit.errors?.localUsers ? 'Tabela não lida (veja o aviso acima).' : 'Nenhum usuário local para este filtro.'}</td></tr>}
                    </tbody>
                  </table>
                </div>
                <h4 className="fau-subtitle">Grupos de usuários <span className="hint">({num(groups.length)})</span></h4>
                <div className="table-wrap fau-groups">
                  <table className="fgb-table fau-table">
                    <colgroup><col style={{ width: '8%' }} /><col style={{ width: '20%' }} /><col style={{ width: '12%' }} /><col style={{ width: '38%' }} /><col style={{ width: '22%' }} /></colgroup>
                    <thead><tr><th>Risco</th><th>Grupo</th><th>Tipo</th><th>Membros</th><th>Servidores remotos</th></tr></thead>
                    <tbody>
                      {groups.map((g) => (
                        <tr key={g.name} title={g.findings.map((f) => `${f.title}: ${f.detail}`).join('\n')}>
                          <td><SevPill severity={g.severity} /></td>
                          <td><b>{g.name}</b>{g.findings[0] && <small>{g.findings[0].title}</small>}</td>
                          <td>{g.type}</td>
                          <td><Chips items={g.members} max={6} /></td>
                          <td>{g.remoteMatches ? <Chips items={g.remoteServers.length ? g.remoteServers : [`${g.remoteMatches} regra(s)`]} max={3} /> : <span className="fgt-muted">—</span>}</td>
                        </tr>
                      ))}
                      {!groups.length && <tr><td colSpan={5} className="empty">{audit.errors?.userGroups ? 'Tabela não lida (veja o aviso acima).' : 'Nenhum grupo para este filtro.'}</td></tr>}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {tab === 'sessions' && (
              <div className="table-wrap">
                <table className="fgb-table fau-table">
                  <colgroup><col style={{ width: '18%' }} /><col style={{ width: '14%' }} /><col style={{ width: '12%' }} /><col style={{ width: '12%' }} /><col style={{ width: '20%' }} /><col style={{ width: '12%' }} /><col style={{ width: '12%' }} /></colgroup>
                  <thead><tr><th>Usuário</th><th>IP</th><th>Tipo</th><th>Método</th><th>Grupos</th><th>Conectado há</th><th className="right">Tráfego</th></tr></thead>
                  <tbody>
                    {sessions.map((x, i) => (
                      <tr key={`${x.username}-${x.ip}-${i}`}>
                        <td><b>{x.username}</b>{x.server && <small>{x.server}</small>}</td>
                        <td className="mono">{x.ip || '—'}</td>
                        <td>{x.type || '—'}</td>
                        <td>{x.method || '—'}</td>
                        <td><Chips items={x.groups} max={2} /></td>
                        <td>{fmtDuration(x.durationSec)}</td>
                        <td className="right">{x.bytes != null ? fmtBytes(x.bytes) : '—'}</td>
                      </tr>
                    ))}
                    {!sessions.length && <tr><td colSpan={7} className="empty">{audit.errors?.authUsers ? 'Não foi possível consultar as sessões (veja o aviso acima).' : 'Ninguém autenticado no momento.'}</td></tr>}
                  </tbody>
                </table>
              </div>
            )}

            {tab === 'interfaces' && (
              <div className="table-wrap">
                <table className="fgb-table fau-table fau-ifaces">
                  <colgroup><col style={{ width: '7%' }} /><col style={{ width: '15%' }} /><col style={{ width: '11%' }} /><col style={{ width: '6%' }} /><col style={{ width: '13%' }} /><col style={{ width: '8%' }} /><col style={{ width: '10%' }} /><col style={{ width: '20%' }} /><col style={{ width: '10%' }} /></colgroup>
                  <thead><tr><th>Risco</th><th>Interface</th><th>Tipo</th><th>Papel</th><th>IP</th><th>Link</th><th>Tráfego ↓/↑</th><th>Serviços de gerência</th><th>Achados</th></tr></thead>
                  <tbody>
                    {interfaces.map((i) => {
                      const key = `i-${i.name}`;
                      const open = expanded.has(key);
                      const link = i.status === 'down' ? 'desligada' : i.stats?.link || null;
                      return (
                        <Fragment key={key}>
                          <tr className={`fau-row${open ? ' open' : ''}${i.status === 'down' ? ' fgb-off' : ''}`} onClick={() => toggle(key)}>
                            <td><SevPill severity={i.severity} /></td>
                            <td><b className="fgt-upper">{i.name}</b>{(i.alias || i.description) && <small>{i.alias || i.description}</small>}</td>
                            <td>{i.vlanId != null ? <><span className="fau-tag vlan">VLAN {i.vlanId}</span><small className="fgt-upper">em {i.parent}</small></> : (i.type || '—')}</td>
                            <td>{i.role === 'wan' ? <span className="fau-tag bad">WAN</span> : ROLE_LABEL[i.role] || i.role}</td>
                            <td className="mono">{i.ip || '—'}{i.publicIp && <small className="fau-public">IP público</small>}</td>
                            <td>{link === 'up' ? <span className="fau-link up">up</span> : link === 'down' ? <span className="fau-link down">down</span> : link ? <span className="fau-link down">{link}</span> : <span className="fgt-muted">—</span>}{i.stats?.speed ? <small>{i.stats.speed >= 1000 ? `${i.stats.speed / 1000} Gbps` : `${i.stats.speed} Mbps`}</small> : null}</td>
                            <td>{i.stats ? <><span>{fmtBytes(i.stats.rxBytes || 0)}</span><small>↑ {fmtBytes(i.stats.txBytes || 0)}</small></> : <span className="fgt-muted">—</span>}</td>
                            <td>{i.services.length ? (
                              <div className="fau-chips">{i.services.map((sv) => <span key={sv.service} className={`fau-svc ${sv.severity ? SEV[sv.severity].cls : ''}`} title={sv.severity ? `Risco ${SEV[sv.severity].label.toLowerCase()}` : 'Sem risco relevante aqui'}>{sv.label}</span>)}</div>
                            ) : <span className="fgt-muted">nenhum</span>}</td>
                            <td><FindingsCell findings={i.findings} open={open} /></td>
                          </tr>
                          {open && <FindingsRow findings={i.findings} colSpan={9} />}
                        </Fragment>
                      );
                    })}
                    {!interfaces.length && <tr><td colSpan={9} className="empty">{audit.errors?.interfaces ? 'Tabela não lida (veja o aviso acima).' : 'Nenhuma interface para este filtro.'}</td></tr>}
                  </tbody>
                </table>
              </div>
            )}
            {tab === 'vpn' && (
              <>
                <h4 className="fau-subtitle">Túneis IPsec <span className="hint">({num(s.vpnTunnelsUp)} de {num(s.vpnTunnels)} ativos)</span></h4>
                <div className="table-wrap">
                  <table className="fgb-table fau-table">
                    <colgroup><col style={{ width: '7%' }} /><col style={{ width: '15%' }} /><col style={{ width: '13%' }} /><col style={{ width: '8%' }} /><col style={{ width: '9%' }} /><col style={{ width: '22%' }} /><col style={{ width: '9%' }} /><col style={{ width: '9%' }} /><col style={{ width: '8%' }} /></colgroup>
                    <thead><tr><th>Risco</th><th>Túnel</th><th>Peer</th><th>IKE</th><th>Autenticação</th><th>Criptografia da fase 1</th><th>Status</th><th>Tráfego ↓/↑</th><th>Achados</th></tr></thead>
                    <tbody>
                      {tunnels.map((t) => {
                        const key = `v-${t.name}`;
                        const open = expanded.has(key);
                        return (
                          <Fragment key={key}>
                            <tr className={`fau-row${open ? ' open' : ''}${t.status === 'down' ? ' fgb-off' : ''}`} onClick={() => toggle(key)}>
                              <td><SevPill severity={t.severity} /></td>
                              <td><b>{t.name}</b>{t.comments && <small>{t.comments}</small>}</td>
                              <td><span className="mono">{t.remoteGw}</span>{t.interface && <small className="fgt-upper">via {t.interface}</small>}</td>
                              <td>{t.ikeVersion === '1' ? <span className="fau-tag warn">IKEv1{t.mode === 'aggressive' ? ' agressivo' : ''}</span> : <span className="fau-tag ok">IKEv2</span>}</td>
                              <td>{t.authMethod}{t.dialup && <small className="fau-public">dial-up</small>}</td>
                              <td><CryptoChips proposals={t.proposals} dh={t.dh} /></td>
                              <td>{t.status === 'up' ? <span className="fau-link up">up</span> : t.status === 'down' ? <span className="fau-link down">down</span> : <span className="fgt-muted">—</span>}<small>{t.p2Up}/{t.p2Total} fase 2{t.uptimeSec ? ` · ${fmtUptime(t.uptimeSec)}` : ''}</small></td>
                              <td>{t.inBytes != null ? <><span>{fmtBytes(t.inBytes)}</span><small>↑ {fmtBytes(t.outBytes || 0)}</small></> : <span className="fgt-muted">—</span>}</td>
                              <td>{t.findingCount ? <span className="fau-count">{t.findingCount} <i>{open ? '▾' : '▸'}</i></span> : <span className="fgt-muted">—</span>}</td>
                            </tr>
                            {open && (
                              <tr className="fau-findings-row">
                                <td colSpan={9}>
                                  {t.findings.map((f, i) => (
                                    <div key={i} className={`fau-finding ${SEV[f.severity].cls}`}>
                                      <SevPill severity={f.severity} />
                                      <div><b>Fase 1 · {f.title}</b><p>{f.detail}</p><p className="fau-rec"><span>Recomendação:</span> {f.recommendation}</p></div>
                                    </div>
                                  ))}
                                  <div className="fau-p2">
                                    <table className="fgb-table">
                                      <colgroup><col style={{ width: '17%' }} /><col style={{ width: '27%' }} /><col style={{ width: '22%' }} /><col style={{ width: '8%' }} /><col style={{ width: '8%' }} /><col style={{ width: '18%' }} /></colgroup>
                                      <thead><tr><th>Fase 2</th><th>Origem → destino</th><th>Criptografia (PFS)</th><th>Status</th><th>Tráfego</th><th>Achados</th></tr></thead>
                                      <tbody>
                                        {t.phase2.map((p) => (
                                          <tr key={p.name} className={p.status === 'down' ? 'fgb-off' : ''}>
                                            <td><b>{p.name}</b>{p.keylifeSec != null && <small>vida {Math.round(p.keylifeSec / 3600)} h{p.replay ? '' : ' · sem replay'}</small>}</td>
                                            <td className="mono fau-sel">{p.src} → {p.dst}</td>
                                            <td><CryptoChips proposals={p.proposals} dh={p.dh} />{!p.pfs && <span className="fau-tag bad">sem PFS</span>}</td>
                                            <td>{p.status === 'up' ? <span className="fau-link up">up</span> : p.status === 'down' ? <span className="fau-link down">down</span> : <span className="fgt-muted">—</span>}</td>
                                            <td>{p.status ? <><span>{fmtBytes(p.inBytes)}</span><small>↑ {fmtBytes(p.outBytes)}</small></> : '—'}</td>
                                            <td>{p.findings.length ? <div className="fau-chips">{p.findings.map((f) => <span key={f.title} className={`fau-svc ${SEV[f.severity].cls}`} title={`${f.detail}\n\nRecomendação: ${f.recommendation}`}>{f.title}</span>)}</div> : <span className="fgt-muted">—</span>}</td>
                                          </tr>
                                        ))}
                                        {!t.phase2.length && <tr><td colSpan={6} className="empty">Sem fase 2.</td></tr>}
                                      </tbody>
                                    </table>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                      {!tunnels.length && <tr><td colSpan={9} className="empty">{audit.errors?.ipsecPhase1 ? 'Tabela não lida (veja o aviso acima).' : 'Nenhum túnel IPsec para este filtro.'}</td></tr>}
                    </tbody>
                  </table>
                </div>
                {audit.vpn?.orphanPhase2?.length > 0 && <p className="map-perf-note fau-inline-note">Fase 2 sem fase 1 correspondente: {audit.vpn.orphanPhase2.map((o) => `${o.name} (→ ${o.phase1name})`).join(', ')}.</p>}

                <h4 className="fau-subtitle">SSL-VPN</h4>
                {!audit.vpn?.sslvpn ? (
                  <p className="hint fau-inline-note">{audit.errors?.sslSettings ? `Configuração não lida: ${audit.errors.sslSettings}` : 'Sem dados de SSL-VPN.'}</p>
                ) : (
                  <div className="fau-ssl">
                    <div className="fau-ssl-status">
                      {audit.vpn.sslvpn.active
                        ? <span className="fau-tag bad">Ativa · escutando em {audit.vpn.sslvpn.listenInterfaces.join(', ').toUpperCase()} :{audit.vpn.sslvpn.port}</span>
                        : audit.vpn.sslvpn.enabled
                          ? <span className="fau-tag ok">Habilitada, mas sem interface de escuta (sem exposição)</span>
                          : <span className="fau-tag ok">Desativada</span>}
                      <SevPill severity={audit.vpn.sslvpn.severity} />
                    </div>
                    <dl className="fau-kv">
                      <div><dt>TLS</dt><dd>{audit.vpn.sslvpn.minTls || '—'} a {audit.vpn.sslvpn.maxTls || '—'}</dd></div>
                      <div><dt>Cifras</dt><dd>{audit.vpn.sslvpn.algorithm || '—'}</dd></div>
                      <div><dt>Inatividade</dt><dd>{audit.vpn.sslvpn.idleTimeout != null ? `${audit.vpn.sslvpn.idleTimeout}s` : '—'}</dd></div>
                      <div><dt>Sessão máx.</dt><dd>{audit.vpn.sslvpn.authTimeout != null ? `${Math.round(audit.vpn.sslvpn.authTimeout / 3600)} h` : '—'}</dd></div>
                      <div><dt>Tentativas / bloqueio</dt><dd>{audit.vpn.sslvpn.loginAttemptLimit ?? '—'} / {audit.vpn.sslvpn.loginBlockTime != null ? `${audit.vpn.sslvpn.loginBlockTime}s` : '—'}</dd></div>
                      <div><dt>Origem permitida</dt><dd>{audit.vpn.sslvpn.sourceAddress.length ? audit.vpn.sslvpn.sourceAddress.join(', ') : 'qualquer'}</dd></div>
                    </dl>
                    {audit.vpn.sslvpn.findings.map((f, i) => (
                      <div key={i} className={`fau-finding ${SEV[f.severity].cls}`}>
                        <SevPill severity={f.severity} />
                        <div><b>{f.title}</b><p>{f.detail}</p><p className="fau-rec"><span>Recomendação:</span> {f.recommendation}</p></div>
                      </div>
                    ))}
                    {audit.vpn.sslvpn.sessions.length > 0 ? (
                      <div className="table-wrap fau-ssl-sessions">
                        <table className="fgb-table">
                          <thead><tr><th>Usuário</th><th>Origem</th><th>IP no túnel</th><th>Login</th><th className="right">Tráfego</th></tr></thead>
                          <tbody>{audit.vpn.sslvpn.sessions.map((x, i) => (
                            <tr key={`${x.username}-${i}`}><td><b>{x.username}</b></td><td className="mono">{x.remoteHost || '—'}</td><td className="mono">{x.tunnelIp || '—'}</td><td>{x.loginTime ? new Date(x.loginTime).toLocaleString('pt-BR') : '—'}</td><td className="right">{x.bytes != null ? fmtBytes(x.bytes) : '—'}</td></tr>
                          ))}</tbody>
                        </table>
                      </div>
                    ) : <p className="hint">Nenhuma sessão SSL-VPN ativa.</p>}
                  </div>
                )}
              </>
            )}
          </section>
          <p className="hint fau-legend">Serviços: <span className="fau-svc high">vermelho</span> risco alto · <span className="fau-svc med">amarelo</span> médio · <span className="fau-svc low">verde</span> baixo · <span className="fau-svc">cinza</span> normal nesta interface. "Exposta" = papel WAN ou IP público. Trusted hosts "0.0.0.0/0" equivalem a não configurado.</p>
        </>
      )}
    </main>
  );
}
