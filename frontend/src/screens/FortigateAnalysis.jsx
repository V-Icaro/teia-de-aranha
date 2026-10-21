import { Fragment, useMemo, useState } from 'react';
import { fmtBytes } from '../api.js';

// Análise inteligente das políticas de um FortiGate: visão geral (nota,
// severidades, números), filtros por categoria/impacto/severidade, busca,
// agrupamento por política e exportação CSV. Somente leitura.

const SEV = {
  alta: { label: 'Alta', cls: 'high', order: 3 },
  media: { label: 'Média', cls: 'med', order: 2 },
  baixa: { label: 'Baixa', cls: 'low', order: 1 }
};
const IMPACT = { seguranca: 'Segurança', organizacao: 'Organização', desempenho: 'Desempenho', auditoria: 'Auditoria' };
const RISK = { baixo: 'Baixo', medio: 'Médio', alto: 'Alto' };
const CONF = { alta: 'Alta', media: 'Média', baixa: 'Baixa' };
const STALE_OPTIONS = [30, 60, 90, 180, 365];

const intfLabel = (p) => `${(p?.srcintf || []).join(', ') || '—'} → ${(p?.dstintf || []).join(', ') || '—'}`;
const policyLabel = (f) => f.policyName || `Policy ${f.policyid}`;
const num = (v) => (v == null ? '—' : Number(v).toLocaleString('pt-BR'));

function scoreLevel(score) {
  if (score == null) return { label: '—', cls: '' };
  if (score >= 80) return { label: 'Boa', cls: 'good' };
  if (score >= 60) return { label: 'Atenção', cls: 'warn' };
  return { label: 'Crítica', cls: 'bad' };
}

function findingText(f) {
  return [
    `[${SEV[f.severity]?.label || f.severity}] ${f.category}`,
    `Política: ${policyLabel(f)} (ID ${f.policyid}, seq ${f.position ?? '—'}) · ${intfLabel(f.policy).toUpperCase()}`,
    `Problema: ${f.problem}`,
    `Recomendação: ${f.recommendation}`,
    f.evidence?.length ? `Evidências: ${f.evidence.join(' | ')}` : null,
    f.validation ? `Validar antes de mudar: ${f.validation}` : null,
    `Impacto: ${IMPACT[f.impact] || f.impact} · Risco da mudança: ${RISK[f.changeRisk] || f.changeRisk} · Confiança: ${CONF[f.confidence] || f.confidence}`
  ].filter(Boolean).join('\n');
}

function exportCsv(findings, target) {
  const head = ['Severidade', 'Categoria', 'ID', 'Política', 'Seq', 'Interfaces', 'Ação', 'Hits', 'Impacto', 'Risco da mudança', 'Confiança', 'Problema', 'Recomendação', 'Evidências', 'Validação'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = findings.map((f) => [
    SEV[f.severity]?.label || f.severity, f.category, f.policyid, policyLabel(f), f.position ?? '',
    intfLabel(f.policy).toUpperCase(), f.policy?.action || '', f.policy?.hitCount ?? '',
    IMPACT[f.impact] || f.impact, RISK[f.changeRisk] || f.changeRisk, CONF[f.confidence] || f.confidence,
    f.problem, f.recommendation, (f.evidence || []).join(' | '), f.validation
  ].map(esc).join(';'));
  // BOM + ";" para o Excel em pt-BR abrir com acentos e colunas certas.
  const blob = new Blob(['\ufeff' + [head.map(esc).join(';'), ...lines].join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `analise-${(target?.name || 'fortigate').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function ScoreRing({ score }) {
  const level = scoreLevel(score);
  const r = 34;
  const c = 2 * Math.PI * r;
  const value = score == null ? 0 : Math.max(0, Math.min(100, score));
  return (
    <div className={`fga-score ${level.cls}`}>
      <svg viewBox="0 0 84 84" aria-hidden="true">
        <circle cx="42" cy="42" r={r} className="track" />
        <circle cx="42" cy="42" r={r} className="value" strokeDasharray={`${(value / 100) * c} ${c}`} transform="rotate(-90 42 42)" />
      </svg>
      <div className="fga-score-num"><b>{score ?? '—'}</b><span>/100</span></div>
      <div className="fga-score-label"><span>Saúde das políticas</span><b>{level.label}</b></div>
    </div>
  );
}

function FindingBody({ finding, onOpenPolicy, onCopy }) {
  return (
    <div className="fga-detail">
      <div className="fga-detail-grid">
        <div className="fga-box rec"><h5>Recomendação</h5><p>{finding.recommendation}</p></div>
        {finding.validation && <div className="fga-box val"><h5>Validar antes de mudar</h5><p>{finding.validation}</p></div>}
      </div>
      {!!finding.evidence?.length && (
        <div className="fga-evidence"><h5>Evidências</h5><ul>{finding.evidence.map((line, i) => <li key={i}>{line}</li>)}</ul></div>
      )}
      <div className="fga-detail-foot">
        <div className="fga-tags">
          <span>Impacto <b>{IMPACT[finding.impact] || finding.impact}</b></span>
          <span>Risco da mudança <b className={`risk-${finding.changeRisk}`}>{RISK[finding.changeRisk] || finding.changeRisk}</b></span>
          <span>Confiança da detecção <b>{CONF[finding.confidence] || finding.confidence}</b></span>
        </div>
        <div className="fga-detail-actions">
          <button className="ghost" onClick={() => onCopy(finding)}>Copiar</button>
          <button className="ghost" onClick={() => onOpenPolicy(finding.policyid)}>Ver política</button>
        </div>
      </div>
    </div>
  );
}

export default function FortigateAnalysis({ target, analysis, loading, error, staleDays, onChangeStaleDays, onRerun, onClose, onOpenPolicy }) {
  const [severity, setSeverity] = useState('');
  const [impact, setImpact] = useState('');
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const [groupBy, setGroupBy] = useState('finding');
  const [expanded, setExpanded] = useState(() => new Set());
  const [flash, setFlash] = useState('');

  const summary = analysis?.summary || null;
  const findings = useMemo(() => analysis?.findings || [], [analysis]);

  // Categorias com a maior severidade presente (para a cor do marcador).
  const categories = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      const cur = map.get(f.category) || { name: f.category, count: 0, sev: 'baixa' };
      cur.count += 1;
      if ((SEV[f.severity]?.order || 0) > (SEV[cur.sev]?.order || 0)) cur.sev = f.severity;
      map.set(f.category, cur);
    }
    return [...map.values()].sort((a, b) => (SEV[b.sev].order - SEV[a.sev].order) || (b.count - a.count));
  }, [findings]);

  const term = search.trim().toLowerCase();
  const shown = useMemo(() => findings.filter((f) => {
    if (severity && f.severity !== severity) return false;
    if (impact && f.impact !== impact) return false;
    if (category && f.category !== category) return false;
    if (!term) return true;
    return [f.policyName, f.policyid, f.category, f.problem, ...(f.policy?.srcintf || []), ...(f.policy?.dstintf || [])]
      .filter((v) => v != null).join(' ').toLowerCase().includes(term);
  }), [findings, severity, impact, category, term]);

  const byPolicy = useMemo(() => {
    const map = new Map();
    for (const f of shown) {
      if (!map.has(f.policyid)) map.set(f.policyid, { key: `p-${f.policyid}`, head: f, items: [], top: 0 });
      const g = map.get(f.policyid);
      g.items.push(f);
      g.top = Math.max(g.top, SEV[f.severity]?.order || 0);
    }
    return [...map.values()].sort((a, b) => (b.top - a.top) || (b.items.length - a.items.length) || ((a.head.position || 0) - (b.head.position || 0)));
  }, [shown]);

  const filtersOn = !!(severity || impact || category || term);

  function toggle(key) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }
  function expandAll() { setExpanded(new Set(groupBy === 'policy' ? byPolicy.map((g) => g.key) : shown.map((f) => f.id))); }
  function clearFilters() { setSeverity(''); setImpact(''); setCategory(''); setSearch(''); }
  function copy(finding) {
    navigator.clipboard?.writeText(findingText(finding)).then(() => { setFlash('Achado copiado.'); setTimeout(() => setFlash(''), 2500); });
  }

  const renderFinding = (f, { showPolicy = true } = {}) => {
    const open = expanded.has(f.id);
    const sev = SEV[f.severity] || SEV.baixa;
    return (
      <article key={f.id} className={`fga-item ${sev.cls}${open ? ' open' : ''}`}>
        <button className="fga-item-head" onClick={() => toggle(f.id)} aria-expanded={open}>
          <span className={`fga-sev-pill ${sev.cls}`}>{sev.label}</span>
          <span className="fga-item-title">
            <b>{f.category}</b>
            {showPolicy && (
              <span className="fga-item-policy">
                {policyLabel(f)} <i>ID {f.policyid} · seq {f.position ?? '—'}</i>
                <em className="fgt-upper">{intfLabel(f.policy)}</em>
              </span>
            )}
          </span>
          <span className="fga-item-meta">
            <span className="fga-impact">{IMPACT[f.impact] || f.impact}</span>
            <span className="fga-caret" aria-hidden="true">{open ? '▾' : '▸'}</span>
          </span>
        </button>
        <p className="fga-problem">{f.problem}</p>
        {open && <FindingBody finding={f} onOpenPolicy={onOpenPolicy} onCopy={copy} />}
      </article>
    );
  };

  const level = scoreLevel(summary?.score);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal fga" onClick={(e) => e.stopPropagation()}>
        <header className="fga-head">
          <div className="fga-head-title">
            <span className="fortigate-page-icon fga-icon" aria-hidden="true">AI</span>
            <div>
              <h2>Análise inteligente · {target?.name}</h2>
              <span className="hint">{target?.host} · VDOM {target?.vdom}{analysis?.generatedAt ? ` · gerada em ${new Date(analysis.generatedAt).toLocaleString('pt-BR')}` : ''} · somente leitura</span>
            </div>
          </div>
          <div className="fga-head-actions">
            <label className="dashboard-period-select"><span>Sem uso há mais de</span>
              <select value={staleDays} onChange={(e) => onChangeStaleDays(Number(e.target.value))} disabled={loading}>
                {STALE_OPTIONS.map((d) => <option key={d} value={d}>{d} dias</option>)}
              </select>
            </label>
            <button className="ghost" onClick={onRerun} disabled={loading}>{loading ? 'Analisando…' : '↻ Recalcular'}</button>
            <button className="ghost" onClick={() => exportCsv(shown, target)} disabled={!shown.length}>Exportar CSV</button>
            <button className="ghost" onClick={onClose} aria-label="Fechar">✕</button>
          </div>
        </header>

        <div className="fga-body">
          {error && <p className="error">{error}</p>}
          {loading && !summary && <div className="fga-loading"><i />Analisando configuração e uso das políticas…</div>}

          {summary && (
            <>
              <section className={`fga-overview${loading ? ' dim' : ''}`}>
                <ScoreRing score={summary.score} />
                <div className="fga-sevcards">
                  {Object.entries(SEV).map(([key, s]) => (
                    <button key={key} className={`fga-sevcard ${s.cls}${severity === key ? ' active' : ''}`} onClick={() => setSeverity(severity === key ? '' : key)}>
                      <span>Severidade {s.label.toLowerCase()}</span>
                      <b>{summary.bySeverity?.[key] || 0}</b>
                    </button>
                  ))}
                </div>
                <dl className="fga-facts">
                  <div><dt>Políticas analisadas</dt><dd>{summary.totalPolicies}</dd></div>
                  <div><dt>Com estatística</dt><dd>{summary.policiesWithStats}</dd></div>
                  <div><dt>Políticas com achados</dt><dd>{summary.affectedPolicies ?? '—'}</dd></div>
                  <div><dt>Desabilitadas</dt><dd>{summary.disabledPolicies ?? '—'}</dd></div>
                </dl>
              </section>
              {summary.score != null && level.cls === 'bad' && (
                <p className="fga-callout">Nota baixa: comece pelos achados de severidade alta e confiança alta. Eles costumam ter o maior ganho com o menor esforço de validação.</p>
              )}

              <div className="fga-main">
                <aside className="fga-side">
                  <h4>Categorias</h4>
                  <button className={`fga-facet${!category ? ' active' : ''}`} onClick={() => setCategory('')}><span>Todas</span><b>{findings.length}</b></button>
                  {categories.map((c) => (
                    <button key={c.name} className={`fga-facet${category === c.name ? ' active' : ''}`} onClick={() => setCategory(category === c.name ? '' : c.name)}>
                      <i className={`fga-dot ${SEV[c.sev].cls}`} /><span>{c.name}</span><b>{c.count}</b>
                    </button>
                  ))}
                  <h4>Impacto</h4>
                  {Object.entries(IMPACT).filter(([key]) => summary.byImpact?.[key]).map(([key, label]) => (
                    <button key={key} className={`fga-facet${impact === key ? ' active' : ''}`} onClick={() => setImpact(impact === key ? '' : key)}>
                      <span>{label}</span><b>{summary.byImpact[key]}</b>
                    </button>
                  ))}
                </aside>

                <section className="fga-content">
                  <div className="fga-toolbar">
                    <input className="fga-search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Buscar por política, ID, interface ou texto…" />
                    <div className="seg fga-seg">
                      <button className={groupBy === 'finding' ? 'active' : ''} onClick={() => setGroupBy('finding')}>Achados</button>
                      <button className={groupBy === 'policy' ? 'active' : ''} onClick={() => setGroupBy('policy')}>Por política</button>
                    </div>
                    <button className="ghost" onClick={expandAll} disabled={!shown.length}>Expandir</button>
                    <button className="ghost" onClick={() => setExpanded(new Set())} disabled={!expanded.size}>Recolher</button>
                  </div>
                  <div className="fga-resultbar">
                    <span>{shown.length} de {findings.length} achados{groupBy === 'policy' ? ` em ${byPolicy.length} políticas` : ''}</span>
                    {filtersOn && <button className="fga-link" onClick={clearFilters}>Limpar filtros</button>}
                    {flash && <span className="fga-flash">{flash}</span>}
                  </div>

                  {!findings.length && <div className="fga-empty"><b>Nenhum achado</b><span>As políticas não acionaram nenhuma regra da análise com os dados disponíveis.</span></div>}
                  {!!findings.length && !shown.length && <div className="fga-empty"><b>Nada para este filtro</b><button className="ghost" onClick={clearFilters}>Limpar filtros</button></div>}

                  {groupBy === 'finding' && <div className="fga-list">{shown.map((f) => renderFinding(f))}</div>}

                  {groupBy === 'policy' && (
                    <div className="fga-list">
                      {byPolicy.map((g) => {
                        const open = expanded.has(g.key);
                        const p = g.head.policy || {};
                        const topSev = Object.values(SEV).find((s) => s.order === g.top) || SEV.baixa;
                        return (
                          <Fragment key={g.key}>
                            <article className={`fga-pgroup${open ? ' open' : ''}`}>
                              <button className="fga-pgroup-head" onClick={() => toggle(g.key)} aria-expanded={open}>
                                <i className={`fga-dot ${topSev.cls}`} />
                                <span className="fga-item-title">
                                  <b>{policyLabel(g.head)}{p.status === 'disable' && <span className="fgt-tag off">Desabilitada</span>}</b>
                                  <span className="fga-item-policy"><i>ID {g.head.policyid} · seq {g.head.position ?? '—'}</i><em className="fgt-upper">{intfLabel(p)}</em></span>
                                </span>
                                <span className="fga-pgroup-stats">
                                  {p.action && <span className={`fgt-action ${p.action}`}>{p.action === 'accept' ? 'ACEITAR' : p.action === 'deny' ? 'NEGAR' : p.action}</span>}
                                  <span>Hits <b>{num(p.hitCount)}</b></span>
                                  <span>Bytes <b>{p.bytes == null ? '—' : fmtBytes(p.bytes)}</b></span>
                                  <span className="fga-pgroup-count">{g.items.length} {g.items.length === 1 ? 'achado' : 'achados'}</span>
                                  <span className="fga-caret" aria-hidden="true">{open ? '▾' : '▸'}</span>
                                </span>
                              </button>
                              {open && (
                                <div className="fga-pgroup-body">
                                  {g.items.map((f) => renderFinding(f, { showPolicy: false }))}
                                  <div className="fga-pgroup-foot"><button className="ghost" onClick={() => onOpenPolicy(g.head.policyid)}>Ver política</button></div>
                                </div>
                              )}
                              {!open && <div className="fga-pgroup-cats">{g.items.map((f) => <span key={f.id} className={`fga-mini ${SEV[f.severity]?.cls}`}>{f.category}</span>)}</div>}
                            </article>
                          </Fragment>
                        );
                      })}
                    </div>
                  )}

                  {!!analysis?.limitations?.length && (
                    <details className="fga-limits">
                      <summary>Limitações da análise</summary>
                      <ul>{analysis.limitations.map((item, i) => <li key={i}>{item}</li>)}</ul>
                    </details>
                  )}
                </section>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
