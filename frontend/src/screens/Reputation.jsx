export default function ReputationScreen({
  closeRep, setRepHarvesting, setRepHarvestMsg, harvestRegions, loadRepDb,
  repDbLoading, repHarvesting, repHarvestMsg, PERIODOS, repDbDays,
  setPeriodo, repTab, setRepTab, fmtBytes, setPgRep, setPgBase,
  setRepDbCountry, setRepDbIp, publicIps, fmtWindow, useCustom, custom, minutes, checkRep, repLoading,
  pendingRep, repQuota, repMsg, sortedRepIps, pgRep, PAGE_REP, openIpModal,
  repMap, repBadge, repSource, pager, setRepDbOrder, repDbOrder, repDb,
  repDbIp, repDbCountry, repDbIpsOf, pgBase, VERDICTS, timeAgo, setLkIp,
  setLkOpen, runLookup, focusIp
}) {
  return (
    <main className="page-rep">
      <div className="page-head">
        <div className="page-title">
          <button className="ghost" onClick={closeRep} title="Voltar ao mapa (Esc)">← mapa</button>
          <div><h2>🚨 Reputação</h2><span className="hint">quem da rede fala com IP ruim, por faixa de score e contexto</span></div>
        </div>
        <div className="page-actions">
          <button className="ghost" onClick={async () => {
            setRepHarvesting(true); setRepHarvestMsg(null);
            try {
              const r = await harvestRegions(168);
              await loadRepDb();
              setRepHarvestMsg(`Coleta ok: ${r.ips ?? 0} IPs, ${r.upserted ?? 0} linhas em ip_daily.` +
                (r.truncadoES ? ' ⚠️ o ES tem mais IPs que o teto de 10.000 por lado: os bytes deste dia estão incompletos.' : '') +
                (r.semPais ? ` ${r.semPais} sem país (cota do AbuseIPDB ou IP sem dado).` : ''));
            } catch (e) {
              setRepHarvestMsg(`Falha na coleta: ${e?.message || 'erro desconhecido'}.`);
            } finally { setRepHarvesting(false); }
          }} disabled={repDbLoading || repHarvesting} title="Coletar agora os últimos 7 dias do ES (o job das 06:15 faz isso todo dia)">
            {repHarvesting ? 'Coletando…' : '⇅ coletar base'}
          </button>{' '}
          {repHarvestMsg && <span className={repHarvestMsg.startsWith('Falha') ? 'error' : 'hint'} style={{ display: 'inline-block', marginTop: 6 }}>{repHarvestMsg}</span>}
          <button className="ghost" onClick={() => loadRepDb()} disabled={repDbLoading} title="Reler base">↻</button>
        </div>
      </div>

      <div className="page-bar">
        <div className="seg" style={{ maxWidth: 430 }}>
          {PERIODOS.map((p) => <button key={p.v} className={repDbDays === p.v ? 'active' : ''} onClick={() => setPeriodo(p.v)} title={p.v === 0 ? 'Tudo que a base tem, sem filtro de janela' : `IPs com último avistamento nas últimas ${p.v === 1 ? 24 : p.v}h`}>{p.label}</button>)}
        </div>
        <div className="seg page-tabs">
          <button className={repTab === 'base' ? 'active' : ''} onClick={() => setRepTab('base')}>Base</button>
          <button className={repTab === 'cobertura' ? 'active' : ''} onClick={() => setRepTab('cobertura')}>Cobertura</button>
        </div>
      </div>

      <div className="page-body">
        {repTab === 'cobertura' && <>
          <h3>Cobertura do cache <span className="badge low">{publicIps.length} IPs públicos no mapa</span></h3>
          <p className="hint" style={{ marginBottom: 8 }}>O conjunto vem dos IPs públicos visíveis no mapa ({fmtWindow(useCustom, custom, minutes)}). Nada é consultado no AbuseIPDB até você apertar o botão.</p>
          {publicIps.length === 0 && <p className="hint">Nenhum IP público no mapa na janela atual.</p>}
          {publicIps.length > 0 && <>
            <button onClick={() => checkRep(publicIps)} disabled={repLoading || pendingRep(publicIps).length === 0 || !!repQuota?.limited} title={repQuota?.limited ? `Cota do AbuseIPDB esgotada: ${repQuota.note}` : pendingRep(publicIps).length === 0 ? 'Todos já vieram do cache local — nada a consultar' : 'Consulta só os IPs fora do cache (o resto já foi coletado às 06:15)'}>{repLoading ? 'Verificando…' : pendingRep(publicIps).length === 0 ? `Tudo em cache (${publicIps.length})` : `Verificar ${pendingRep(publicIps).length} IP${pendingRep(publicIps).length > 1 ? 's' : ''} sem cache`}</button>{' '}
            {repQuota?.limited && <p className="hint">⚠️ {repQuota.note} — o que aparece abaixo é o cache local, não uma consulta nova.</p>}
            {repMsg && <p className={repMsg.startsWith('Falha') ? 'error' : 'hint'}>{repMsg.startsWith('Falha') ? '⚠️ ' : 'ℹ️ '}{repMsg}</p>}
            {!repQuota?.limited && pendingRep(publicIps).length < publicIps.length && <p className="hint">{publicIps.length - pendingRep(publicIps).length} de {publicIps.length} IPs já vieram do cache (coleta diária 06:15, válido por {repQuota?.ttlDays || 7} dias). O botão só chama o AbuseIPDB nos {pendingRep(publicIps).length}.</p>}
            {sortedRepIps().slice(pgRep * PAGE_REP, pgRep * PAGE_REP + PAGE_REP).map((ip) => <div key={ip} className="talker" onClick={() => openIpModal(ip)} title="Clique para ver o dossiê completo"><div className="talker-top"><span className="talker-ip">{ip}</span><span>{repBadge(ip)}</span></div><span className="hint">{repSource(ip)}</span>{repMap[ip]?.abuse?.reports > 0 && <span className="hint">{repMap[ip].abuse.reports} reportes · último: {repMap[ip].abuse.lastReported || '-'}</span>}</div>)}
            {Object.values(repMap).some((r) => r?.note) && <p className="error">{Object.values(repMap).find((r) => r?.note)?.note}</p>}
            {pager(pgRep, setPgRep, sortedRepIps().length, PAGE_REP)}
          </>}
        </>}

        {repTab === 'base' && <>
          <div className="cmp-form"><div className="seg" style={{ maxWidth: 420, flex: 1 }}>
            <button className={repDbOrder === 'rep' ? 'active' : ''} onClick={() => { setRepDbOrder('rep'); setRepDbCountry(null); loadRepDb(repDbDays, 'rep'); }}>Score</button>
            <button className={repDbOrder === 'reports' ? 'active' : ''} onClick={() => { setRepDbOrder('reports'); setRepDbCountry(null); loadRepDb(repDbDays, 'reports'); }}>Denúncias</button>
            <button className={repDbOrder === 'bytes' ? 'active' : ''} onClick={() => { setRepDbOrder('bytes'); setRepDbCountry(null); loadRepDb(repDbDays, 'bytes'); }}>Bytes</button>
            <button className={repDbOrder === 'seen' ? 'active' : ''} onClick={() => { setRepDbOrder('seen'); setRepDbCountry(null); loadRepDb(repDbDays, 'seen'); }}>Visto por último</button>
          </div></div>
          <p className="hint">{repDb?.total ?? 0} IPs verificados · {repDb?.regions?.filter((r) => r.bad > 0).length ?? 0} regiões com IP problemático. Não ordene por score: isso consulta a API externa.</p>
          {repDb?.truncado && <p className="hint">A consulta traz no máximo {repDb.limit} IPs por vez: a lista e os totais por país abaixo cobrem {(repDb.ips || []).length} de {repDb.total}. Aumente o período ou filtre por faixa para caber tudo.</p>}
          {!repDb || repDbLoading ? <p>Calculando.</p> : repDb.error ? <p className="error">Falha ao carregar a base.</p> : !repDb.ips.length ? <p className="hint">Nenhum IP na base ainda. Use “⇅ coletar base” acima ou rode a coleta diária.</p> : !repDbIp ? <>
            {repDb.regions.map((r) => {
              const open = repDbCountry === r.country;
              const daRegiao = open ? repDbIpsOf(r.country) : [];
              return <div key={r.country}>
                <div className="talker" onClick={() => { setRepDbCountry(open ? null : r.country); setPgBase(0); }} title="Ver IPs desta região">
                  <div className="talker-top"><span className="talker-ip">{r.country} — {r.countryName}</span><span className="talker-bytes">{r.bad > 0 && <b style={{ color: 'var(--bad)' }}>{r.bad} com score </b>}{r.ips} IPs</span></div>
                  <div className="bar"><i style={{ width: `${Math.max(2, Math.round((r.ips / Math.max(1, ...repDb.regions.map((x) => x.ips))) * 100))}%` }} /></div>
                  <span className="hint">{fmtBytes(r.bytes)} trocados no histórico · clique para listar</span>
                </div>
                {open && daRegiao.slice(pgBase * PAGE_REP, pgBase * PAGE_REP + PAGE_REP).map((x) => <div key={x.ip} className="talker" style={{ marginLeft: 14 }} onClick={() => setRepDbIp(x)} title="Ver dossiê e histórico">
                  <div className="talker-top"><span className="talker-ip">{x.ip}</span><span><i className={`dot ${(VERDICTS[x.verdict] || VERDICTS.unknown).dot}`} /> {(VERDICTS[x.verdict] || VERDICTS.unknown).label}</span></div>
                  <span className="hint">score {x.score ?? '—'} · {x.reports ?? 0} denúncias · {fmtBytes(x.totalBytes)} · {x.totalFlows} fluxos{x.lastSeen ? ` · visto ${timeAgo(x.lastSeen)}` : ' · nunca visto no fluxo'}</span>
                </div>)}
                {open && pager(pgBase, setPgBase, daRegiao.length, PAGE_REP)}
                {open && daRegiao.length > PAGE_REP && <p className="hint" style={{ marginLeft: 14 }}>Exibindo {pgBase * PAGE_REP + 1}–{Math.min((pgBase + 1) * PAGE_REP, daRegiao.length)} de {daRegiao.length} IPs desta região ({PAGE_REP} por página).</p>}
              </div>;
            })}
          </> : (() => {
            const x = repDbIp;
            return <>
              <button className="ghost" onClick={() => setRepDbIp(null)} style={{ marginBottom: 10 }}>← voltar para a lista</button>
              <div className="cmp-form"><b style={{ fontSize: 16 }}>{x.ip}</b><span><i className={`dot ${(VERDICTS[x.verdict] || VERDICTS.unknown).dot}`} /> {(VERDICTS[x.verdict] || VERDICTS.unknown).label}</span><span className="hint">{x.country} — {x.countryName}</span></div>
              <div className="kpis" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginTop: 6 }}><div><b>{x.score ?? '—'}</b><span>score AbuseIPDB</span></div><div><b>{x.reports ?? 0}</b><span>denúncias</span></div><div><b>{fmtBytes(x.totalBytes)}</b><span>bytes no histórico</span></div><div><b>{x.totalFlows}</b><span>fluxos</span></div></div>
              <p className="hint" style={{ marginTop: 8 }}>{x.isp || 'ISP desconhecido'}{x.usageType ? ` · ${x.usageType}` : ''}{x.domain ? ` · ${x.domain}` : ''}{x.lastReported ? ` · última denúncia ${timeAgo(x.lastReported)}` : ''}{x.checkedAt ? ` · verificado ${timeAgo(x.checkedAt)}` : ''}</p>
              <div className="seg" style={{ marginTop: 10, flexWrap: 'wrap' }}><button onClick={() => openIpModal(x.ip)}>Dossiê completo</button><button className="ghost" onClick={() => { setLkIp(x.ip); setLkOpen(true); runLookup(x.ip, 7); }}>Histórico 7 dias</button><button className="ghost" onClick={() => { closeRep(); focusIp(x.ip); }}>Localizar no mapa</button></div>
              {!x.lastSeen && <p className="hint" style={{ marginTop: 8 }}>Esse IP está na base de reputação mas não apareceu no histórico de conexões — é de outra origem ou de outro período.</p>}
            </>;
          })()}
        </>}
      </div>
    </main>
  );
}
