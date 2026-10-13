export default function ExposureScreen({
  setExpOpen, fmtWindow, useCustom, custom, minutes, loadExposure, expLoading,
  expTab, setExpTab, expData, expIp, setExpIp, riskMap, RISK_COLORS,
  RISK_LABELS, fmtBytes, openIpModal, focusIp, timeAgo, loadBeacon, beacon
}) {
  return (
    <div className="modal-backdrop" onClick={() => setExpOpen(false)}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div><h2>🛡 Exposição externa</h2><span className="hint">janela: {fmtWindow(useCustom, custom, minutes)} · risco, entrada, novidades e atividade recente</span></div>
          <div><button className="ghost" onClick={() => loadExposure()} disabled={expLoading} title="Recalcular">↻</button>{' '}<button className="ghost" onClick={() => setExpOpen(false)}>✕</button></div>
        </div>
        <div className="seg" style={{ marginBottom: 10 }}>
          <button className={expTab === 'risk' ? 'active' : ''} onClick={() => setExpTab('risk')}>Risco por host</button>
          <button className={expTab === 'inbound' ? 'active' : ''} onClick={() => setExpTab('inbound')}>Entrada</button>
          <button className={expTab === 'new' ? 'active' : ''} onClick={() => setExpTab('new')}>Destinos novos</button>
          <button className={expTab === 'sessions' ? 'active' : ''} onClick={() => setExpTab('sessions')}>Sessões vivas</button>
        </div>

        {expLoading && <p className="hint">Consultando Elasticsearch e Postgres…</p>}
        {expTab === 'risk' && expData.risk?.reputacao === 'indisponivel' && <p className="error">Reputação indisponível: não é possível concluir que os destinos sem score são limpos.{expData.risk.reputationError ? ` ${expData.risk.reputationError}` : ''}</p>}
        {expTab === 'risk' && expData.risk?.reputacao === 'parcial' && <p className="error">Avaliação parcial: {expData.risk.reputationCoverage.assessedPeers} de {expData.risk.reputationCoverage.peers} relações host→destino ({expData.risk.reputationCoverage.peerPct}%) têm reputação recente; {expData.risk.reputationCoverage.unknownPeers} são desconhecidas. Os desconhecidos não estão sendo tratados como limpos.</p>}
        {expTab === 'risk' && expData.risk?.truncated && <p className="error">A lista está limitada: mostrando {expData.risk.shown} de {expData.risk.matches} hosts correspondentes.{expData.risk.processingTruncated ? ' O limite de processamento do Elasticsearch também foi atingido.' : ''}</p>}

        {expTab === 'risk' && (expData.risk?.error ? <p className="error">Falha ao calcular risco: {expData.risk.error}</p>
          : !expData.risk ? <p className="hint">Aguardando consulta.</p>
            : expData.risk.reputacao === 'indisponivel' && !expData.risk.hosts?.length ? <p className="hint">Sem reputação disponível; nenhum resultado pode ser classificado como limpo.</p>
              : !expData.risk.hosts?.length ? <p className="hint">Nenhum destino avaliado teve score &gt; 0 nesta janela.{expData.risk.reputationCoverage?.unknownPeers > 0 ? ` Ainda há ${expData.risk.reputationCoverage.unknownPeers} destinos sem avaliação recente.` : ` Cobertura: ${expData.risk.reputationCoverage?.peerPct ?? 100}% dos destinos.`}</p>
                : expIp ? (() => {
                  const h = riskMap[expIp];
                  if (!h) return <p className="hint">Host sem dados de risco na janela.</p>;
                  return <>
                    <button className="ghost" onClick={() => setExpIp(null)} style={{ marginBottom: 10 }}>← voltar para a lista</button>
                    <div className="cmp-form"><b style={{ fontSize: 16, color: RISK_COLORS[h.level] }}>{h.ip}</b><span>Risco {RISK_LABELS[h.level]}</span><span className="hint">{h.risk == null ? 'sem bytes com reputação recente' : `${Math.round(h.risk * 100)}% dos bytes avaliados · ${Math.round((h.badPeerShare || 0) * 100)}% dos destinos avaliados sinalizados`}</span></div>
                    <div className="kpis" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginTop: 6 }}><div><b>{h.badPeers}</b><span>IPs problemáticos</span></div><div><b>{fmtBytes(h.bytesBad)}</b><span>bytes para eles</span></div><div><b>{h.externalPeers}</b><span>destinos externos</span></div><div><b>{h.unknownPeers}</b><span>sem avaliação</span></div><div><b>{h.maxScore}</b><span>maior score</span></div></div>
                    {h.unknownPeers > 0 && <p className="error">Este host tem {h.unknownPeers} destinos sem reputação recente; a porcentagem de risco abaixo cobre apenas os destinos avaliados.</p>}
                    <h4>Destinos problemáticos</h4>
                    <div className="table-wrap"><table><thead><tr><th>IP</th><th>score</th><th>bytes</th><th>origem</th></tr></thead><tbody>{h.badDestinations.map((d) => <tr key={d.ip} className="ip-link" onClick={() => openIpModal(d.ip)}><td className="mono">{d.ip}</td><td><span className="dot" style={{ background: d.score >= 80 ? 'var(--bad)' : 'var(--warn)' }} /> {d.score}</td><td>{fmtBytes(d.bytes)}</td><td className="hint">{[d.country, d.isp].filter(Boolean).join(' · ') || '—'}</td></tr>)}</tbody></table></div>
                    {h.countries?.length > 0 && <><h4>Para onde o tráfego vai</h4><div className="table-wrap"><table><thead><tr><th>País</th><th>IPs</th><th>bytes</th><th>%</th></tr></thead><tbody>{h.countries.map((c) => <tr key={c.country}><td>{c.country}</td><td>{c.ips}</td><td>{fmtBytes(c.bytes)}</td><td>{Math.round(c.pct * 100)}%</td></tr>)}</tbody></table></div></>}
                    <div style={{ marginTop: 12, display: 'flex', gap: 8 }}><button className="ghost" onClick={() => { setExpOpen(false); openIpModal(h.ip); }}>Ver dossiê</button><button className="ghost" onClick={() => { setExpOpen(false); focusIp(h.ip); }}>Localizar no mapa</button>{h.topDestinations?.[0] && <button className="ghost" onClick={() => setExpTab('sessions')}>Ver sessões</button>}</div>
                  </>;
                })() : <>
                  <p className="hint">Escopo: saída IPv4 do host privado para destinos públicos via TCP/UDP. Risco = bytes para IPs com score &gt; 0, ponderados pelo score, sobre bytes com reputação recente. A quantidade de destinos sinalizados é exibida à parte. Não cobre entrada nem protocolos como PROTO-41. Não consome cota externa.</p>
                  {expData.risk.hosts.map((h) => <div key={h.ip} className="talker" onClick={() => setExpIp(h.ip)} title="Ver detalhe"><div className="talker-top"><span className="talker-ip" style={{ color: RISK_COLORS[h.level] }}>{h.ip}</span><span className="talker-bytes">{h.badPeers} de {h.assessedPeers} avaliados · {h.unknownPeers} desconhecidos · {fmtBytes(h.bytesBad)}</span></div><div className="bar"><i style={{ width: `${Math.max(2, Math.round((h.risk || 0) * 100))}%`, background: RISK_COLORS[h.level] }} /></div><span className="hint">{RISK_LABELS[h.level]} · {h.risk == null ? 'sem volume avaliado' : `${Math.round(h.risk * 100)}% dos bytes avaliados`}{h.badPeerShare != null ? ` · ${Math.round(h.badPeerShare * 100)}% dos destinos avaliados sinalizados` : ''} · cobertura de bytes {Math.round(h.coverageBytes * 100)}% · maior score {h.maxScore}</span></div>)}
                </>)}

        {expTab === 'inbound' && (expData.inbound?.error ? <p className="error">Falha ao listar tráfego de entrada: {expData.inbound.error}</p>
          : !expData.inbound ? <p className="hint">Aguardando consulta.</p> : <>
            <p className="hint">Fluxos IPv4 de IP público → rede privada na janela selecionada. Foram observados {expData.inbound.total} pares/protocolos, incluindo {expData.inbound.nonTransportCount} fora de TCP/UDP. PROTO-41, GRE e ICMP aparecem aqui também. “Fora de TCP/UDP” é um critério para revisar, não um veredito de ameaça.</p>
            {expData.inbound.truncated && <p className="error">Exibindo {expData.inbound.shown} de {expData.inbound.total} fluxos.{expData.inbound.processingTruncated ? ' O limite de processamento do Elasticsearch também foi atingido.' : ' Aumente o limite ou reduza a janela para ver os demais.'}</p>}
            {!expData.inbound.flows.length ? <p className="hint">Nenhum fluxo público → privado observado nesta janela.</p> : expData.inbound.flows.map((f) => {
              const unusual = f.nonTransport;
              return <div key={`${f.src}|${f.dst}|${f.protocol}`} className="talker"><div className="talker-top"><span className="talker-ip mono"><span className="ip-link" onClick={() => openIpModal(f.src)}>{f.src}</span> → {f.dst}</span><span className="talker-bytes">{fmtBytes(f.bytes)}</span></div><div className="bar"><i style={{ width: `${Math.max(2, Math.min(100, Math.round((f.bytes / Math.max(1, ...expData.inbound.flows.map((x) => x.bytes))) * 100)))}%`, background: unusual ? 'var(--warn)' : 'var(--acc)' }} /></div><span className="hint"><b>{f.protocolName || 'protocolo desconhecido'}</b> · {unusual ? 'fora de TCP/UDP — revisar contexto' : 'TCP/UDP'} · {f.flows} fluxos · {f.packets} pacotes{f.ports?.length ? ` · portas destino ${f.ports.join(', ')}` : ' · sem porta (protocolo IP)'}{f.lastSeen ? ` · último fluxo ${timeAgo(f.lastSeen)}` : ''}</span></div>;
            })}
          </>)}

        {expTab === 'new' && <>
          {expData.newExt?.historico === 'indisponivel' && <p className="error">O Postgres não respondeu; não é possível afirmar que um IP nunca foi visto. Resultado de novidade indisponível.</p>}
          {expData.newExt?.reputacao === 'parcial' && <p className="hint">A novidade usa o histórico de sightings; os scores AbuseIPDB são auxiliares e só estão disponíveis para {expData.newExt.reputationCoverage.assessed} de {expData.newExt.reputationCoverage.requested} destinos nesta consulta.</p>}
          {expData.newExt?.historico === 'ok' && expData.newExt.candidateCount > 0 && <p className="error">{expData.newExt.candidateCount} relações apontam para IPs que não constam no snapshot diário. Isso é candidato, não prova de IP inédito: o histórico atualiza em lote e pode estar atrasado.{expData.newExt.historyUpdatedAt ? ` Última atualização: ${new Date(expData.newExt.historyUpdatedAt).toLocaleString('pt-BR')}.` : ''}</p>}
          {expData.newExt?.truncated && <p className="error">Mostrando {expData.newExt.shown} de {expData.newExt.matches} relações novas correspondentes.{expData.newExt.processingTruncated ? ' O limite de processamento também foi atingido.' : ''}</p>}
          {expData.newExt?.error ? <p className="error">Falha ao listar destinos novos: {expData.newExt.error}</p> : expLoading || !expData.newExt ? <p className="hint">Consultando a base de sightings…</p> : !expData.newExt?.pairs?.length ? <p className="hint">{expData.newExt?.historico === 'indisponivel' ? 'Sem histórico disponível; ausência de resultados não significa que os destinos sejam conhecidos.' : 'Nenhum IP público de destino foi visto pela primeira vez nesta janela.'}</p> : <>
            <p className="hint">Novidade é global por IP de destino, não por relação entre hosts. {expData.newExt.confirmedNewCount} primeira(s) aparição(ões) confirmada(s) dentro da janela; {expData.newExt.candidateCount} relação(ões) apontam para IPs ausentes no snapshot diário ({expData.newExt.newIpCount} IPs candidatos/confirmados únicos). Histórico observado desde {expData.newExt.historySince ? new Date(expData.newExt.historySince).toLocaleDateString('pt-BR') : 'data desconhecida'}.</p>
            {expData.newExt.pairs.map((p) => <div key={`${p.src}|${p.dst}`} className="talker"><div className="talker-top"><span className="talker-ip mono ip-link" onClick={() => openIpModal(p.dst)}>{p.src} → {p.dst}</span><span className="talker-bytes">{fmtBytes(p.bytes)} · {p.ports.join(', ') || 'porta efêmera'}</span></div><span className="hint">{p.kind === 'nao-consta-no-historico' ? 'candidato: não consta no snapshot diário' : p.kind === 'primeira-vez' ? 'primeira aparição confirmada nesta janela' : p.kind === 'conhecido' ? 'IP já observado antes' : 'histórico indisponível'}{p.score != null ? ` · score AbuseIPDB ${p.score}` : ' · sem score AbuseIPDB recente'}{p.country ? ` · ${p.country}` : ''}{p.isp ? ` · ${p.isp}` : ''}</span></div>)}
          </>}
        </>}

        {expTab === 'sessions' && expData.sessions?.truncated && <p className="error">A lista está limitada: exibindo {expData.sessions.shown} de pelo menos {expData.sessions.count} pares retornados. Reduza a janela para conferir o conjunto completo.</p>}
        {expTab === 'sessions' && (expData.sessions?.error ? <p className="error">Falha ao listar sessões: {expData.sessions.error}</p>
          : expLoading || !expData.sessions ? <p className="hint">Consultando fluxos ativos…</p>
            : !expData.sessions?.sessions?.length ? <p className="hint">Nenhum fluxo NetFlow terminou nos últimos {expData.sessions?.activeSec || 120}s.</p> : <>
              <p className="hint">Pares cujo registro de fluxo terminou nos últimos {expData.sessions.activeSec}s. NetFlow não confirma conexão aberta. Duração é o intervalo entre o primeiro e o último fluxo agregado do par, não a duração de um socket.</p>
              {expData.sessions.sessions.map((s) => <div key={`${s.src}|${s.dst}`} className="talker" onClick={() => loadBeacon(s.src, s.dst)} title="Medir periodicidade deste par"><div className="talker-top"><span className="talker-ip mono">{s.direction === 'out' ? `${s.src} → ${s.dst}` : `${s.dst} ← ${s.src}`}</span><span className="talker-bytes">{fmtBytes(s.bytes)}{s.bps ? ` · ${fmtBytes(s.bps / 8)}/s` : ''}</span></div><span className="hint">{s.service || 'porta efêmera'} {s.ports.map((p) => p.port).join(', ')}{s.durationSec != null ? ` · ${s.durationSec}s` : ''} · clique para medir periodicidade</span></div>)}
              {beacon && (beacon.error ? <p className="error">{beacon.error}</p> : !beacon.data || beacon.data.insufficient ? <p className="hint">Menos de 4 inícios de fluxo distintos em {beacon.data?.windowMinutes || 240}min para este par — não há série para medir periodicidade.</p> : <>
                {beacon.data.truncated && <p className="error">Amostra limitada aos primeiros 2.000 registros; periodicidade e intervalos são inconclusivos.</p>}
                <div className="kpis" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginTop: 12 }}><div><b>{beacon.data.samples}{beacon.data.truncated ? ` / ${beacon.data.totalFlows}` : ''}</b><span>inícios distintos</span></div><div><b>{Math.round(beacon.data.intervalMs / 1000)}s</b><span>intervalo médio</span></div><div><b>{Math.round(beacon.data.sdMs / 1000)}s</b><span>desvio</span></div><div><b>{Math.round(beacon.data.minMs / 1000)}–{Math.round(beacon.data.maxMs / 1000)}s</b><span>faixa</span></div><div><b style={{ color: beacon.data.periodic ? 'var(--warn)' : undefined }}>{beacon.data.cv}</b><span>{beacon.data.truncated ? 'amostra limitada' : beacon.data.periodic ? 'cadência regular' : 'intervalo variável'}</span></div></div>
                <p className="hint">{beacon.src} → {beacon.dst} · {beacon.data.windowMinutes}min · {fmtBytes(beacon.data.meanBytes)} por início distinto. Cadência regular não é veredito de beacon: tarefas legítimas também são periódicas.{beacon.data.minMs <= 1000 && ' O menor intervalo é 1s: é o piso de reexportação do exporter, então o cv fica artificialmente alto — "irregular" aqui não descarta beacon.'}</p>
              </>)}
            </>)}
      </div>
    </div>
  );
}
