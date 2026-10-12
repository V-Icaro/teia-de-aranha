// Motor determinístico de análise de políticas de firewall (FortiGate).
//
// Cruza quatro fontes para cada regra:
//   - uso        -> /api/v2/monitor/firewall/policy (hit_count, bytes, packets,
//                   sessions, first/last_used e a série 1_week_ipv4)
//   - configuração -> /api/v2/cmdb/firewall/policy (serviços, endereços,
//                   interfaces, NAT, inspeção, logs, comentários)
//   - posição    -> ordem efetiva da lista da CMDB (não o policyid)
//   - tempo      -> last_used/first_used e a série semanal
//
// Saída = lista de sugestões justificadas. Nada é aplicado automaticamente:
// cada achado traz evidência objetiva, confiança da DETECÇÃO, impacto,
// risco da MUDANÇA e o que validar antes de mexer. Sem IA: regras claras.
//
// Não implementado nesta versão (documentado em limitations):
//   - sombreamento/precedência fina entre regras (exige match de VIP, identidade,
//     agenda efetiva e ferramentas de "policy lookup");
//   - objetos de endereço/serviço órfãos (exige a API de objetos + grafo de
//     referências);
//   - "hits por intervalo" confiável e mudança anormal (exige snapshots periódicos).

const SEVERITY_ORDER = { alta: 3, media: 2, baixa: 1 };
const CONFIDENCE_ORDER = { alta: 3, media: 2, baixa: 1 };

function isAny(list) {
  if (!Array.isArray(list) || !list.length) return false;
  return list.some((n) => {
    const s = String(n).trim().toLowerCase();
    return s === 'all' || s === 'any' || s === '0.0.0.0/0' || s === '::/0' || s === 'all_ipv4' || s === 'all_ipv6';
  });
}

function emptyOf(list) {
  return !Array.isArray(list) || list.length === 0 || (list.length === 1 && String(list[0]).trim() === '');
}

function normList(list) {
  return Array.isArray(list) ? [...list].map((x) => String(x).trim().toLowerCase()).sort().join(',') : '';
}

// Assinatura para detectar regras equivalentes. Inclui só o que decide o
// encaminhamento e a inspeção (ordem incluída; ordem não é comparada na
// assinatura porque a posição é tratada à parte).
function signature(p) {
  return [
    p.action,
    normList(p.flow.srcintf), normList(p.flow.dstintf),
    normList(p.flow.srcaddr), normList(p.flow.dstaddr),
    normList(p.flow.srcaddr6), normList(p.flow.dstaddr6),
    normList(p.services.service), p.schedule,
    p.services.nat, p.services.ippool, normList(p.services.poolname),
    p.security.utmStatus, p.security.sslSshProfile,
    p.security.avProfile, p.security.webfilterProfile, p.security.ipsSensor,
    p.security.applicationList, p.security.dnsfilterProfile, p.security.emailfilterProfile,
    p.security.logtraffic
  ].join('|');
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.round((p / 100) * (sorted.length - 1))));
  return sorted[idx];
}

const DAY_MS = 86400000;
const MONTH_MS = 30 * DAY_MS;

function daysSince(epoch, now) {
  if (!epoch) return null;
  return (now - epoch * 1000) / DAY_MS;
}

function fmtBytes(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n < 1024 ** 4) return `${(n / 1024 ** 3).toFixed(2)} GB`;
  if (n < 1024 ** 5) return `${(n / 1024 ** 4).toFixed(2)} TB`;
  return `${(n / 1024 ** 5).toFixed(2)} PB`;
}

// Construtor único de achado: garante o formato prometido.
function finding_(rule, ctx, extra) {
  const base = {
    id: `${rule}-${ctx.config.policyid}`,
    rule,
    policyid: ctx.config.policyid,
    policyName: ctx.config.name || null,
    position: ctx.config.position || null,
    category: '',
    severity: 'baixa',
    confidence: 'media',
    impact: 'organizacao',
    changeRisk: 'baixo',
    problem: '',
    recommendation: '',
    evidence: [],
    validation: ''
  };
  return { ...base, ...extra, id: `${rule}-${ctx.config.policyid}` };
}

function evaluate({ configs, stats, now, options }) {
  const staleDays = options.staleDays;
  const statsById = new Map((stats || []).map((s) => [s.policyid, s]));
  const rows = (configs || []).map((config) => ({ config, stats: statsById.get(config.policyid) || null }));
  const total = configs.length;

  const hitVals = rows.filter((r) => r.stats).map((r) => r.stats.hitCount || 0).sort((a, b) => a - b);
  const byteVals = rows.filter((r) => r.stats).map((r) => r.stats.bytes || 0).sort((a, b) => a - b);
  const hitsP90 = percentile(hitVals, 90);
  const bytesP90 = percentile(byteVals, 90);
  const bytesMedian = percentile(byteVals, 50);

  // Índice por assinatura para duplicidade.
  const bySig = new Map();
  for (const r of rows) {
    const sig = signature(r.config);
    if (!bySig.has(sig)) bySig.set(sig, []);
    bySig.get(sig).push(r);
  }

  const findings = [];
  const eager = (f) => { if (f) findings.push(f); };
  const push = (rule, ctx, extra) => eager(finding_(rule, ctx, extra));

  for (const ctx of rows) {
    const p = ctx.config;
    const s = ctx.stats;
    const accept = String(p.action || '').toLowerCase() === 'accept';
    const serviceAll = isAny(p.services.service);
    const srcAll = isAny(p.flow.srcaddr);
    const dstAll = isAny(p.flow.dstaddr);
    const internetObject = String(p.flow.internetService || '').toLowerCase() === 'enable';
    const notInspection = String(p.security.sslSshProfile || '').toLowerCase() === 'no-inspection';
    const utmOff = String(p.security.utmStatus || '').toLowerCase() !== 'enable';
    const hasProfiles = [p.security.avProfile, p.security.webfilterProfile, p.security.ipsSensor,
      p.security.applicationList, p.security.dnsfilterProfile, p.security.emailfilterProfile]
      .some((v) => v && String(v).trim() !== '' && String(v).toLowerCase() !== 'null');

    // 1. Regra aparentemente não utilizada.
    if (s && (s.hitCount || 0) === 0) {
      push('unused', ctx, {
        category: 'Regra aparentemente não utilizada',
        severity: 'alta',
        confidence: 'media',
        impact: 'organizacao',
        changeRisk: 'alto',
        problem: 'A política não registra correspondências no contador de hits.',
        recommendation: 'Verifique se ainda é necessária antes de considerar desativá-la.',
        evidence: [`hit_count = 0`, `last_used = ${s.lastUsed || 'nunca registrado'}`],
        validation: 'Zero hits não prova que a regra é inútil: pode ser sazonal, de contingência/DR ou de baixa frequência. Confira o período desde o último reset dos contadores e os logs antes de mexer.'
      });
    }

    // 5. Regra antiga sem uso recente.
    const idleDays = s ? daysSince(s.lastUsed, now) : null;
    if (s && (s.hitCount || 0) > 0 && idleDays != null && idleDays > staleDays) {
      push('stale', ctx, {
        category: 'Regra sem uso recente',
        severity: 'media',
        confidence: 'media',
        impact: 'organizacao',
        changeRisk: 'medio',
        problem: `A política teve uso no passado, mas o último hit foi há ~${Math.round(idleDays)} dias.`,
        recommendation: 'Confirme se o serviço ainda é necessário; se a janela for longa o bastante, planeje desativação com retorno.',
        evidence: [`hit_count = ${s.hitCount}`, `último uso há ${Math.round(idleDays)} dias`, `janela de ${staleDays} dias`],
        validation: 'Defina a janela (30/60/90 dias) conforme o serviço e considere reset de contadores e tráfego sazonal.'
      });
    }

    // 3. Regra permissiva demais.
    if (accept && serviceAll && (srcAll || dstAll)) {
      push('overly_permissive', ctx, {
        category: 'Regra permissiva demais',
        severity: 'alta',
        confidence: 'alta',
        impact: 'seguranca',
        changeRisk: 'alto',
        problem: 'A política aceita todos os serviços e usa origem e/ou destino abrangentes (ALL).',
        recommendation: 'Restrinja serviços, origens e destinos ao mínimo necessário para o fluxo.',
        evidence: [
          `action = ${p.action}`,
          `service = ${(p.services.service || []).join(' · ') || 'ALL'}`,
          srcAll ? 'srcaddr = ALL' : `srcaddr = ${(p.flow.srcaddr || []).join(' · ')}`,
          dstAll ? 'dstaddr = ALL' : `dstaddr = ${(p.flow.dstaddr || []).join(' · ')}`
        ],
        validation: 'Uma regra ampla pode ser intencional (ex.: saída de Internet genérica). Avalie o contexto e o conjunto dos campos antes de restringir.'
      });
    }

    // 9. Serviço ALL em regra com destino específico.
    if (accept && serviceAll && !dstAll && !emptyOf(p.flow.dstaddr)) {
      push('service_all_specific_target', ctx, {
        category: 'Serviço ALL em destino específico',
        severity: 'media',
        confidence: 'alta',
        impact: 'seguranca',
        changeRisk: 'medio',
        problem: 'O destino é específico, mas a política permite todos os serviços.',
        recommendation: 'Confirme quais protocolos/portas o fluxo realmente usa e limite o serviço a eles.',
        evidence: [`service = ${(p.services.service || []).join(' · ') || 'ALL'}`, `dstaddr = ${(p.flow.dstaddr || []).join(' · ')}`],
        validation: 'Muito útil em regras de aplicação, banco, backup, SMTP e administração remota. Valide com a documentação do serviço e os logs.'
      });
    }

    // 7. Permissão sem inspeção de segurança.
    if (accept && utmOff && notInspection && !hasProfiles) {
      push('no_inspection', ctx, {
        category: 'Permissão sem inspeção de segurança',
        severity: 'media',
        confidence: 'media',
        impact: 'seguranca',
        changeRisk: 'medio',
        problem: 'A regra aceita tráfego sem UTM habilitado, sem perfis de segurança e com SSL/SSH sem inspeção.',
        recommendation: 'Avalie se o fluxo precisa de IPS, antivírus, filtro web ou outros controles.',
        evidence: [`action = ${p.action}`, `utm-status = ${p.security.utmStatus || '—'}`, `ssl-ssh-profile = ${p.security.sslSshProfile || '—'}`, 'nenhum perfil associado'],
        validation: 'Não ligue todos os perfis automaticamente: backup e navegação têm requisitos diferentes. Verifique compatibilidade e finalidade.'
      });
    }

    // 8. Regra sem descrição.
    const nameShort = !p.name || String(p.name).trim().length < 6;
    if (!p.comments || String(p.comments).trim() === '') {
      push('no_description', ctx, {
        category: 'Regra sem descrição',
        severity: 'baixa',
        confidence: 'alta',
        impact: 'auditoria',
        changeRisk: 'baixo',
        problem: nameShort
          ? 'A política não tem comentário e o nome é pouco explicativo.'
          : 'A política não tem comentário.',
        recommendation: 'Adicione uma descrição com finalidade, responsável e serviço atendido.',
        evidence: [`comments = vazio`, `name = ${p.name || '—'}`],
        validation: 'Ajuda em auditorias e na transferência de conhecimento entre administradores.'
      });
    }

    // 2. Muito usada em posição baixa.
    const latePosition = total > 5 && p.position > Math.ceil(total * 0.75);
    if (s && latePosition && (s.hitCount || 0) >= Math.max(hitsP90, 1000)) {
      push('high_usage_low_position', ctx, {
        category: 'Regra muito usada em posição baixa',
        severity: 'media',
        confidence: 'media',
        impact: 'desempenho',
        changeRisk: 'alto',
        problem: `A regra tem uso elevado e está na posição ${p.position} de ${total}.`,
        recommendation: 'Avalie movê-la para uma posição anterior, se a semântica da política for preservada.',
        evidence: [`hit_count = ${s.hitCount}`, `posição = ${p.position}/${total}`, `p90 de hits = ${hitsP90}`],
        validation: 'Não mova só pelos hits: regras anteriores podem ser mais específicas ou bloquear intencionalmente. A mudança só vale se preservar a semântica.'
      });
    }

    // 6. Grande volume de tráfego.
    if (s && bytesP90 > 0 && (s.bytes || 0) >= bytesP90 && (s.bytes || 0) >= 10 * Math.max(1, bytesMedian) && (s.bytes || 0) > 1024 ** 3) {
      push('high_volume', ctx, {
        category: 'Grande volume de tráfego',
        severity: 'baixa',
        confidence: 'media',
        impact: 'desempenho',
        changeRisk: 'baixo',
        problem: `A política transporta ${fmtBytes(s.bytes)}, acima do padrão das regras comparáveis.`,
        recommendation: 'Verifique se o volume corresponde ao uso esperado (backup, replicação, transferências).',
        evidence: [`bytes = ${fmtBytes(s.bytes)}`, `p90 de bytes = ${fmtBytes(bytesP90)}`, `mediana = ${fmtBytes(bytesMedian)}`],
        validation: 'Muito tráfego não é, por si só, um problema. Compare a evolução no tempo e o perfil da regra.'
      });
    }

    // 4. Duplicada / redundante.
    const group = bySig.get(signature(p)) || [];
    if (group.length > 1) {
      const others = group.filter((g) => g.config.policyid !== p.policyid).map((g) => `${g.config.name || g.config.policyid} (ID ${g.config.policyid}, pos ${g.config.position})`);
      push('duplicate', ctx, {
        category: 'Regra possivelmente redundante',
        severity: 'media',
        confidence: 'media',
        impact: 'organizacao',
        changeRisk: 'alto',
        problem: 'A política tem a mesma assinatura de encaminhamento/inspeção de outra(s) regra(s).',
        recommendation: 'Avalie consolidar as regras equivalentes.',
        evidence: [`regra equivalente a: ${others.join('; ')}`],
        validation: 'Ordem, NAT, inspeção, logging e outras opções precisam ser comparados: regras parecidas não são necessariamente equivalentes.'
      });
    }

    // 12. Mudança anormal no padrão de tráfego (série semanal 1_week_ipv4).
    const series = s?.history?.bytes || null;
    if (Array.isArray(series) && series.filter((x) => Number.isFinite(x)).length >= 6) {
      const vals = series.map((x) => Number(x) || 0);
      const half = Math.floor(vals.length / 2);
      const first = vals.slice(0, half).reduce((a, b) => a + b, 0);
      const second = vals.slice(half).reduce((a, b) => a + b, 0);
      if (first > 0 && second > 0 && (second / first > 2 || second / first < 0.5)) {
        const trend = second > first ? 'aumento' : 'queda';
        push('traffic_shift', ctx, {
          category: 'Mudança anormal no padrão de tráfego',
          severity: 'baixa',
          confidence: 'baixa',
          impact: 'desempenho',
          changeRisk: 'baixo',
          problem: `O volume semanal mostra ${trend} de ~${(Math.abs(second / first - 1) * 100).toFixed(0)}% entre as metades da série.`,
          recommendation: 'Verifique se houve alteração operacional ou atividade inesperada.',
          evidence: [`1ª metade = ${fmtBytes(first)}`, `2ª metade = ${fmtBytes(second)}`, `fonte: série 1_week_ipv4.bytes`],
          validation: 'A série do monitoramento pode ter resolução/intervalo diferentes do contador acumulado. Confirme a semântica do campo no seu FortiOS.'
        });
      }
      // Inconsistência: hits da série todos zero, mas bytes positivos.
      const hitsSeries = s?.history?.hit_count;
      if (Array.isArray(hitsSeries) && hitsSeries.length && hitsSeries.every((x) => (Number(x) || 0) === 0) && second > 0) {
        push('counter_inconsistency', ctx, {
          category: 'Inconsistência nos contadores da série',
          severity: 'baixa',
          confidence: 'media',
          impact: 'auditoria',
          changeRisk: 'baixo',
          problem: 'A série semanal tem hits todos zerados, mas bytes positivos.',
          recommendation: 'Investigue antes de concluir que não houve tráfego.',
          evidence: ['1_week_ipv4.hit_count = [0,0,...]', `1_week_ipv4.bytes soma ${fmtBytes(vals.reduce((a, b) => a + b, 0))}`],
          validation: 'Confira a semântica dos campos na sua versão do FortiOS, o intervalo de coleta e se os contadores têm a mesma origem.'
        });
      }
    }
  }

  return findings;
}

function analyzePolicies({ configs = [], stats = [], now = Date.now(), options = {} } = {}) {
  const opts = { staleDays: Number(options.staleDays) > 0 ? Number(options.staleDays) : 90 };
  const findings = evaluate({ configs, stats, now, options: opts });

  const withStats = configs.filter((c) => stats.some((s) => s.policyid === c.policyid)).length;

  const bySeverity = { alta: 0, media: 0, baixa: 0 };
  const byCategory = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }

  findings.sort((a, b) =>
    (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) ||
    (CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence]) ||
    ((a.position || 0) - (b.position || 0))
  );

  return {
    generatedAt: new Date(now).toISOString(),
    staleDays: opts.staleDays,
    summary: {
      totalPolicies: configs.length,
      policiesWithStats: withStats,
      findings: findings.length,
      bySeverity,
      byCategory
    },
    findings,
    limitations: [
      'Detecção determinística: não aplica mudanças e não substitui a ferramenta de "policy lookup" do FortiGate.',
      'Sombreamento/precedência fina entre regras não é calculado nesta versão.',
      'Objetos de endereço/serviço órfãos exigem a API de objetos e o grafo de referências (não incluído).',
      'Mudança anormal usa a série semanal do próprio equipamento; sem snapshots históricos próprios não há janela mais longa.',
      'Zero hits não prova obsolescência: regras sazonais, de contingência/DR e de baixa frequência exigem validação humana.'
    ]
  };
}

module.exports = {
  analyzePolicies,
  signature,
  isAny,
  _internals: { evaluate, percentile, daysSince }
};
