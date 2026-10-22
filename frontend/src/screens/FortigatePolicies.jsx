import { Fragment, useEffect, useMemo, useState } from 'react';
import { fmtBytes, fetchFortigatePolicyTable } from '../api.js';

// Lista de políticas no formato "Interface Pair View" do FortiGate:
// agrupada por interface de origem → interface de destino, com os objetos de
// cada regra (origem, destino, agenda, serviço, ação, NAT, perfis, log) e os
// contadores de uso do equipamento.

const SORTS = {
  position: { label: 'Sequência', compare: (a, b) => a.position - b.position },
  hits: { label: 'Hits', compare: (a, b) => b.hitCount - a.hitCount, metric: (p) => p.hitCount },
  bytes: { label: 'Bytes', compare: (a, b) => b.bytes - a.bytes, metric: (p) => p.bytes },
  sessions: { label: 'Sessões', compare: (a, b) => b.activeSessions - a.activeSessions, metric: (p) => p.activeSessions },
  lastUsed: { label: 'Último uso', compare: (a, b) => (b.lastUsed || 0) - (a.lastUsed || 0), metric: (p) => p.lastUsed || 0 }
};

const LOG_LABELS = { all: 'Todas as sessões', utm: 'Eventos de segurança', disable: 'Desabilitado' };
const ACTION_LABELS = { accept: 'ACEITAR', deny: 'NEGAR', ipsec: 'IPsec' };
const COLUMNS = 11;
const MAX_OBJECTS = 5;

const intf = (list) => (list?.length ? list.join(', ') : '—');
const num = (value) => Number(value || 0).toLocaleString('pt-BR');

// Interface com alias: "port2 (REDE-ESCRITORIO)". Sem alias, só o nome.
const intfLabel = (name, aliases) => (aliases?.[name] ? `${name} (${aliases[name]})` : name);

function IntfList({ names, aliases }) {
  if (!names?.length) return <span className="fgt-intf">—</span>;
  return (
    <span className="fgt-intf">
      {names.map((name, i) => (
        <Fragment key={name}>
          {i > 0 && ', '}
          {name}
          {aliases?.[name] && <small className="fgt-alias"> ({aliases[name]})</small>}
        </Fragment>
      ))}
    </span>
  );
}

function dateValue(value) {
  if (!value) return '—';
  const n = Number(value);
  const date = new Date(n > 1e12 ? n : n * 1000);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('pt-BR');
}

function matchesSearch(policy, term, aliases) {
  if (!term) return true;
  const intfNames = [...policy.srcintf, ...policy.dstintf];
  const haystack = [
    policy.name, policy.policyid, policy.comments, policy.schedule, policy.action,
    ...intfNames, ...intfNames.map((n) => aliases?.[n]), ...policy.srcaddr, ...policy.dstaddr,
    ...policy.service, ...policy.securityProfiles.map((p) => p.name)
  ].filter((v) => v != null).join(' ').toLowerCase();
  return haystack.includes(term);
}

function ObjList({ items, negate = false, empty = '—' }) {
  if (!items?.length) return <span className="fgt-muted">{empty}</span>;
  const shown = items.slice(0, MAX_OBJECTS);
  const rest = items.length - shown.length;
  return (
    <div className={`fgt-objs${negate ? ' negate' : ''}`} title={items.join('\n')}>
      {negate && <span className="fgt-negate">NÃO</span>}
      {shown.map((item) => <span key={item} className="fgt-obj">{item}</span>)}
      {rest > 0 && <span className="fgt-muted">+{rest} mais</span>}
    </div>
  );
}

export default function FortigatePolicyTable({ firewall, onOpenPolicy }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadKey, setReloadKey] = useState(0);
  const [sort, setSort] = useState('position');
  const [srcFilter, setSrcFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState(''); // '' | 'enable' | 'disable'
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());

  const firewallId = firewall?.id ?? null;
  const vdom = firewall?.vdom || 'root';

  // Troca de firewall: zera filtros e grupos abertos (as interfaces mudam).
  useEffect(() => {
    setSrcFilter('');
    setStatusFilter('');
    setSearch('');
    setExpanded(new Set());
  }, [firewallId]);

  useEffect(() => {
    if (!firewallId) {
      setData(null);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    fetchFortigatePolicyTable(firewallId, vdom)
      .then((result) => { if (!cancelled) setData(result); })
      .catch((e) => { if (!cancelled) { setData(null); setError(String(e.message || e)); } })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [firewallId, vdom, reloadKey]);

  const policies = data?.policies || [];
  const aliases = data?.interfaceAliases || {};

  // Interfaces de origem presentes na lista, com a quantidade de regras.
  const srcInterfaces = useMemo(() => {
    const counts = new Map();
    for (const policy of policies) {
      for (const name of policy.srcintf) counts.set(name, (counts.get(name) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0], 'pt-BR', { sensitivity: 'base' }));
  }, [policies]);

  const term = search.trim().toLowerCase();

  const groups = useMemo(() => {
    const sorter = SORTS[sort] || SORTS.position;
    const map = new Map();
    for (const policy of policies) {
      if (srcFilter && !policy.srcintf.includes(srcFilter)) continue;
      if (statusFilter === 'disable' && policy.status !== 'disable') continue;
      if (statusFilter === 'enable' && policy.status === 'disable') continue;
      if (!matchesSearch(policy, term, aliases)) continue;
      const src = intf(policy.srcintf);
      const dst = intf(policy.dstintf);
      const key = `${src}\u0000${dst}`;
      if (!map.has(key)) map.set(key, { key, src, dst, srcNames: policy.srcintf, dstNames: policy.dstintf, rows: [], disabled: 0, hits: 0, bytes: 0, metric: 0 });
      const group = map.get(key);
      group.rows.push(policy);
      if (policy.status === 'disable') group.disabled += 1;
      group.hits += policy.hitCount;
      group.bytes += policy.bytes;
      if (sorter.metric) group.metric = sort === 'lastUsed' ? Math.max(group.metric, sorter.metric(policy)) : group.metric + sorter.metric(policy);
    }
    const list = [...map.values()];
    for (const group of list) group.rows.sort(sorter.compare);
    // Sequência: pares em ordem alfabética, como o FortiGate. Métrica: maior primeiro.
    const byName = (a, b) => a.src.localeCompare(b.src, 'pt-BR', { sensitivity: 'base' }) || a.dst.localeCompare(b.dst, 'pt-BR', { sensitivity: 'base' });
    list.sort(sorter.metric ? (a, b) => (b.metric - a.metric) || byName(a, b) : byName);
    return list;
  }, [policies, srcFilter, statusFilter, term, sort, aliases]);

  const shownCount = groups.reduce((sum, group) => sum + group.rows.length, 0);
  // Com busca ativa, todos os grupos encontrados ficam abertos.
  const isOpen = (key) => !!term || expanded.has(key);

  function toggle(key) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  if (!firewall) return <p className="hint">Selecione um firewall.</p>;

  return (
    <>
      <div className="fgt-policies-head">
        <div>
          <h3>Políticas de firewall <span className="fgt-policies-fw">{firewall.name}</span></h3>
          <span className="hint">{firewall.host} · VDOM {vdom}{data?.version ? ` · FortiOS ${data.version}` : ''}</span>
        </div>
        <div className="fgt-policies-stats">
          {data && <>
            <span><b>{policies.length}</b>políticas</span>
            <span><b>{srcInterfaces.length}</b>interfaces de origem</span>
            <span role="button" tabIndex={0} style={{ cursor: 'pointer' }} title="Filtrar desabilitadas" onClick={() => setStatusFilter((s) => (s === 'disable' ? '' : 'disable'))}><b>{policies.filter((p) => p.status === 'disable').length}</b>desabilitadas</span>
            <span><b>{policies.filter((p) => !p.hitCount).length}</b>sem hits</span>
          </>}
          <button className="ghost" onClick={() => setReloadKey((k) => k + 1)} disabled={loading}>{loading ? 'Atualizando…' : '↻ Atualizar'}</button>
        </div>
      </div>

      <div className="fgt-ptoolbar">
        <label className="dashboard-period-select">
          <span>Interface de origem</span>
          <select value={srcFilter} onChange={(e) => setSrcFilter(e.target.value)}>
            <option value="">Todas ({policies.length})</option>
            {srcInterfaces.map(([name, count]) => <option key={name} value={name}>{name.toUpperCase()}{aliases[name] ? ` (${aliases[name]})` : ''} ({count})</option>)}
          </select>
        </label>
        <label className="dashboard-period-select">
          <span>Status</span>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">Todas</option>
            <option value="enable">Ativas ({policies.filter((p) => p.status !== 'disable').length})</option>
            <option value="disable">Desabilitadas ({policies.filter((p) => p.status === 'disable').length})</option>
          </select>
        </label>
        <label className="dashboard-period-select">
          <span>Ordenar</span>
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            {Object.entries(SORTS).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}
          </select>
        </label>
        <label className="dashboard-period-select fgt-psearch">
          <span>Buscar</span>
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Nome, ID, endereço, serviço…" />
        </label>
        <div className="fgt-ptoolbar-actions">
          <button className="ghost" onClick={() => setExpanded(new Set(groups.map((g) => g.key)))} disabled={!groups.length}>Expandir tudo</button>
          <button className="ghost" onClick={() => setExpanded(new Set())} disabled={!expanded.size}>Recolher tudo</button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {loading && !data && <p className="hint">Consultando políticas no FortiGate…</p>}

      {data && (
        <>
          <p className="hint fgt-psummary">
            {shownCount} de {policies.length} políticas em {groups.length} pares de interface
            {srcFilter && <> · origem <b className="fgt-upper">{srcFilter}</b>{aliases[srcFilter] && <> ({aliases[srcFilter]})</>}</>}
            {loading && ' · atualizando…'}
          </p>
          <div className="table-wrap fgt-ptable-wrap">
            <table className="fgt-ptable">
              <thead>
                <tr>
                  <th className="fgt-col-name">Nome</th>
                  <th>Origem</th>
                  <th>Destino</th>
                  <th>Agenda</th>
                  <th>Serviço</th>
                  <th>Ação</th>
                  <th>NAT</th>
                  <th>Perfis de segurança</th>
                  <th>Log</th>
                  <th className="num">Hits</th>
                  <th className="num">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => {
                  const open = isOpen(group.key);
                  return (
                    <Fragment key={group.key}>
                      <tr className={`fgt-group-row${open ? ' open' : ''}`} onClick={() => toggle(group.key)}>
                        <td colSpan={COLUMNS - 2}>
                          <span className="fgt-toggle" aria-hidden="true">{open ? '−' : '+'}</span>
                          <IntfList names={group.srcNames} aliases={aliases} />
                          <span className="fgt-arrow" aria-hidden="true">→</span>
                          <IntfList names={group.dstNames} aliases={aliases} />
                          <span className="fgt-count">{group.rows.length}</span>
                          {group.disabled > 0 && (
                            <span className="fgt-group-off" title={`${group.disabled} política(s) desabilitada(s) neste par`}>
                              {group.disabled === group.rows.length ? 'DESABILITADA' : `${group.disabled} DESABILITADA${group.disabled > 1 ? 'S' : ''}`}
                            </span>
                          )}
                        </td>
                        <td className="num">{num(group.hits)}</td>
                        <td className="num">{fmtBytes(group.bytes)}</td>
                      </tr>
                      {open && group.rows.map((policy) => {
                        const disabled = policy.status === 'disable';
                        return (
                          <tr key={policy.policyid} className={`fgt-prow${disabled ? ' disabled' : ''}`} onClick={() => onOpenPolicy?.(policy.policyid)}>
                            <td className="fgt-col-name">
                              <b>{policy.name || `Policy ${policy.policyid}`}</b>
                              <small>ID {policy.policyid} · seq {policy.position}{disabled && <span className="fgt-tag off">Desabilitada</span>}</small>
                            </td>
                            <td><ObjList items={policy.srcaddr} negate={policy.srcaddrNegate} /></td>
                            <td><ObjList items={policy.dstaddr} negate={policy.dstaddrNegate} /></td>
                            <td>{policy.schedule || '—'}</td>
                            <td>{policy.internetService ? <span className="fgt-muted">Internet Service</span> : <ObjList items={policy.service} negate={policy.serviceNegate} />}</td>
                            <td><span className={`fgt-action ${policy.action || ''}`}>{ACTION_LABELS[policy.action] || policy.action || '—'}</span></td>
                            <td>{policy.nat ? <span className="fgt-tag on">{policy.ippool && policy.poolname.length ? policy.poolname.join(', ') : 'NAT'}</span> : <span className="fgt-muted">Desabilitado</span>}</td>
                            <td>{policy.securityProfiles.length ? (
                              <div className="fgt-objs">{policy.securityProfiles.map((p) => <span key={`${p.type}-${p.name}`} className="fgt-obj profile" title={p.type}><i>{p.type}</i>{p.name}</span>)}</div>
                            ) : <span className="fgt-muted">—</span>}</td>
                            <td>{LOG_LABELS[policy.logtraffic] || policy.logtraffic || '—'}</td>
                            <td className="num" title={`Sessões ativas: ${num(policy.activeSessions)}\nPrimeiro uso: ${dateValue(policy.firstUsed)}\nÚltimo uso: ${dateValue(policy.lastUsed)}`}>{num(policy.hitCount)}</td>
                            <td className="num" title={`Pacotes: ${num(policy.packets)}`}>{fmtBytes(policy.bytes || 0)}</td>
                          </tr>
                        );
                      })}
                    </Fragment>
                  );
                })}
                {!groups.length && <tr><td colSpan={COLUMNS} className="empty">Nenhuma política para este filtro.</td></tr>}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
