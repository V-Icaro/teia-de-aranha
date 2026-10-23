// Auditoria de segurança do FortiGate (somente leitura):
//   - administradores        -> /api/v2/cmdb/system/admin
//   - usuários de API        -> /api/v2/cmdb/system/api-user
//   - usuários locais        -> /api/v2/cmdb/user/local
//   - grupos de usuários     -> /api/v2/cmdb/user/group
//   - autenticados agora     -> /api/v2/monitor/user/firewall
//   - interfaces e VLANs     -> /api/v2/cmdb/system/interface
//   - estatística interfaces -> /api/v2/monitor/system/interface
//   - VPN IPsec              -> /api/v2/cmdb/vpn.ipsec/phase1-interface, phase2-interface, /api/v2/monitor/vpn/ipsec
//   - SSL-VPN                -> /api/v2/cmdb/vpn.ssl/settings, /api/v2/monitor/vpn/ssl
// Foco: acesso administrativo exposto. Trusted hosts ausentes ("de qualquer
// lugar"), falta de 2FA, e serviços de gerência ativos nas interfaces
// (allowaccess) — principalmente em interface WAN ou com IP público.
// Cada consulta é independente: se o token não puder ler uma tabela, as
// outras seções continuam e a seção mostra o erro.
const { requestJson } = require('./fortigate.js');

const SEV_ORDER = { alta: 3, media: 2, baixa: 1 };

// ---- IPs e máscaras --------------------------------------------------
function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || '').trim());
  if (!m) return null;
  return ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
}
function maskToBits(mask) {
  const n = ipToInt(mask);
  if (n == null) return null;
  let bits = 0;
  for (let i = 31; i >= 0; i -= 1) { if ((n >>> i) & 1) bits += 1; else break; }
  return bits;
}
// "10.0.0.0 255.255.255.0" | "10.0.0.0/24" -> { ip, bits, cidr }
function parseV4(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  let ip; let bits;
  if (s.includes('/')) {
    const [a, b] = s.split('/');
    ip = a.trim(); bits = /^\d+$/.test(b.trim()) ? Number(b) : maskToBits(b);
  } else {
    const [a, b] = s.split(/\s+/);
    ip = a; bits = b ? maskToBits(b) : 32;
  }
  if (ipToInt(ip) == null || bits == null) return null;
  return { ip, bits, cidr: `${ip}/${bits}` };
}
function isPrivateV4(ip) {
  const n = ipToInt(ip);
  if (n == null) return false;
  const inRange = (base, bits) => ((n ^ ipToInt(base)) >>> (32 - bits)) === 0;
  return inRange('10.0.0.0', 8) || inRange('172.16.0.0', 12) || inRange('192.168.0.0', 16)
    || inRange('100.64.0.0', 10) || inRange('127.0.0.0', 8) || inRange('169.254.0.0', 16);
}
const isAnyV4 = (t) => !t || (t.bits === 0);
const isAnyV6 = (v) => { const s = String(v || '').trim(); return !s || s === '::/0' || s === '::/0 ::/0'; };

function finding(severity, title, detail, recommendation) {
  return { severity, title, detail, recommendation };
}
const worst = (findings) => findings.reduce((acc, f) => ((SEV_ORDER[f.severity] || 0) > (SEV_ORDER[acc] || 0) ? f.severity : acc), null);

// ---- Trusted hosts -----------------------------------------------------
// Em admin: trusthost1..10 / ip6-trusthost1..10 ("0.0.0.0 0.0.0.0" = não configurado).
// Em api-user: tabela trusthost [{ type, ipv4-trusthost, ipv6-trusthost }].
function trustedHostsOfAdmin(a) {
  const v4 = []; const v6 = [];
  for (let i = 1; i <= 10; i += 1) {
    const t = parseV4(a[`trusthost${i}`]);
    if (t && !isAnyV4(t)) v4.push(t.cidr);
    const t6 = a[`ip6-trusthost${i}`];
    if (!isAnyV6(t6)) v6.push(String(t6).trim());
  }
  return { v4, v6 };
}
function trustedHostsOfApiUser(u) {
  const v4 = []; const v6 = [];
  for (const t of Array.isArray(u.trusthost) ? u.trusthost : []) {
    const p = parseV4(t['ipv4-trusthost']);
    if (t.type !== 'ipv6-trusthost' && p && !isAnyV4(p)) v4.push(p.cidr);
    if (t.type === 'ipv6-trusthost' && !isAnyV6(t['ipv6-trusthost'])) v6.push(String(t['ipv6-trusthost']).trim());
  }
  return { v4, v6 };
}

function trustFindings(th, kind) {
  const out = [];
  if (!th.v4.length && !th.v6.length) {
    out.push(finding('alta', 'Acesso de qualquer lugar',
      `Nenhum trusted host configurado: o ${kind} pode autenticar a partir de qualquer IP que alcance uma interface com acesso administrativo.`,
      'Configure trusted hosts com as redes de gerência (jump host, VPN administrativa).'));
    return out;
  }
  if (th.v4.length && !th.v6.length) {
    out.push(finding('baixa', 'IPv6 sem trusted host',
      'Há trusted hosts IPv4, mas nenhum IPv6: se a gerência por IPv6 estiver ativa em alguma interface, ela não fica restrita.',
      'Configure ip6-trusthost (por exemplo ::1/128) se não usa gerência por IPv6.'));
  }
  const broad = th.v4.filter((c) => Number(c.split('/')[1]) < 16);
  if (broad.length) {
    out.push(finding('media', 'Trusted host muito amplo',
      `Faixas largas: ${broad.join(', ')}.`,
      'Restrinja às sub-redes ou hosts de gerência (idealmente /24 ou menor).'));
  }
  const publicNets = th.v4.filter((c) => !isPrivateV4(c.split('/')[0]));
  if (publicNets.length) {
    out.push(finding('media', 'Trusted host com IP público',
      `Endereços públicos liberados: ${publicNets.join(', ')}.`,
      'Confirme que cada IP público é de fato do time de gerência e ainda está em uso.'));
  }
  return out;
}

const names = (v) => (Array.isArray(v) ? v.map((x) => (x && typeof x === 'object' ? x.name : x)).filter(Boolean) : (v ? [v] : []));

// "Privilégio total" pelo CONTEÚDO do perfil, não pelo nome: o super_admin
// de fábrica ou qualquer perfil personalizado com Sistema em leitura/escrita
// e escopo global. Perfis que o token não consegue ler ficam como não-totais.
function hasFullPrivilege(profileName, profiles) {
  if (!profileName) return false;
  if (profileName === 'super_admin') return true;
  const p = profiles?.get(profileName);
  return !!p && p.sysgrp === 'read-write' && (p.scope || 'vdom') === 'global';
}

function auditAdmins(rows, profiles) {
  return rows.map((a) => {
    const th = trustedHostsOfAdmin(a);
    const profile = a.accprofile || null;
    const superAdmin = hasFullPrivilege(profile, profiles);
    const twoFactor = a['two-factor'] && a['two-factor'] !== 'disable' ? a['two-factor'] : null;
    const remote = a['remote-auth'] === 'enable';
    const findings = trustFindings(th, 'administrador');
    if (!twoFactor && !remote) {
      findings.push(finding(superAdmin ? 'alta' : 'media', 'Sem segundo fator (2FA)',
        `Conta local sem 2FA${superAdmin ? ` e com privilégio total (perfil ${profile})` : ''}: só a senha protege o acesso.`,
        'Habilite FortiToken, e-mail ou SMS (two-factor) ou use autenticação remota com MFA.'));
    }
    if (a.wildcard === 'enable') {
      findings.push(finding('media', 'Wildcard de autenticação remota',
        'Qualquer usuário do servidor remoto (RADIUS/LDAP) que autenticar recebe este perfil.',
        'Prefira contas individuais ou restrinja por grupo no servidor remoto.'));
    }
    if (String(a.name).toLowerCase() === 'admin') {
      findings.push(finding('baixa', 'Conta "admin" padrão',
        'O nome de usuário padrão é o primeiro alvo de força bruta.',
        'Crie contas nominais e desative ou renomeie a conta "admin".'));
    }
    return {
      kind: remote ? 'remoto' : 'local',
      name: a.name,
      profile,
      superAdmin,
      vdoms: names(a.vdom),
      trustedHosts: [...th.v4, ...th.v6],
      anywhere: !th.v4.length && !th.v6.length,
      twoFactor: twoFactor || (remote ? 'remoto' : null),
      remoteAuth: remote,
      comments: a.comments || null,
      findings,
      severity: worst(findings)
    };
  });
}

function auditApiUsers(rows, profiles) {
  return rows.map((u) => {
    const th = trustedHostsOfApiUser(u);
    const profile = u.accprofile || null;
    const full = hasFullPrivilege(profile, profiles);
    const findings = trustFindings(th, 'token de API');
    if (full) {
      findings.push(finding('media', 'Token de API com privilégio total',
        `O token (perfil ${profile}) tem permissão de escrita em todo o equipamento.`,
        'Crie um perfil só com as permissões necessárias (ex.: leitura).'));
    }
    if (u['cors-allow-origin'] === '*') {
      findings.push(finding('media', 'CORS liberado para qualquer origem',
        'cors-allow-origin = *: qualquer site aberto num navegador da rede pode usar o token.',
        'Restrinja à origem da aplicação que consome a API ou desative.'));
    }
    return {
      kind: 'api',
      name: u.name,
      profile,
      superAdmin: full,
      vdoms: names(u.vdom),
      trustedHosts: [...th.v4, ...th.v6],
      anywhere: !th.v4.length && !th.v6.length,
      twoFactor: null,
      remoteAuth: false,
      comments: u.comments || null,
      findings,
      severity: worst(findings)
    };
  });
}

// ---- Interfaces ----------------------------------------------------------
// Risco de cada serviço do allowaccess. `exposed` = papel WAN ou IP público.
const SERVICE_INFO = {
  telnet: { label: 'TELNET', exposed: 'alta', internal: 'alta', why: 'gerência em texto puro (senha trafega sem criptografia)' },
  http: { label: 'HTTP', exposed: 'alta', internal: 'media', why: 'GUI sem criptografia' },
  https: { label: 'HTTPS', exposed: 'alta', internal: null, why: 'GUI de administração exposta' },
  ssh: { label: 'SSH', exposed: 'alta', internal: null, why: 'CLI de administração exposta' },
  fgfm: { label: 'FGFM', exposed: 'alta', internal: null, why: 'protocolo do FortiManager (já teve falhas críticas exploradas)' },
  snmp: { label: 'SNMP', exposed: 'media', internal: null, why: 'SNMP v1/v2c usa community em texto puro' },
  'radius-acct': { label: 'RADIUS-ACCT', exposed: 'baixa', internal: null, why: 'recebe accounting RADIUS' },
  fabric: { label: 'FABRIC', exposed: 'media', internal: null, why: 'Security Fabric aceita conexões de outros equipamentos' },
  capwap: { label: 'CAPWAP', exposed: 'media', internal: null, why: 'controlador de APs/FortiExtender' },
  ftm: { label: 'FTM', exposed: 'baixa', internal: null, why: 'push do FortiToken Mobile' },
  'speed-test': { label: 'SPEED-TEST', exposed: 'baixa', internal: null, why: 'servidor de speed test' },
  'probe-response': { label: 'PROBE', exposed: 'baixa', internal: null, why: 'responde a probes de SD-WAN' },
  ping: { label: 'PING', exposed: 'baixa', internal: null, why: 'facilita descoberta do equipamento' },
  dnp: { label: 'DNP', exposed: 'baixa', internal: null, why: '' }
};

// monitor/system/interface devolve um OBJETO { nome: {...} } (ou lista em
// algumas versões). Normaliza para Map nome -> estatística.
function statsMap(results) {
  const map = new Map();
  const list = Array.isArray(results) ? results : (results && typeof results === 'object' ? Object.values(results) : []);
  for (const s of list) {
    if (!s || !s.name) continue;
    const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : null);
    map.set(s.name, {
      link: s.link === true || s.link === 'up' ? 'up' : s.link === false || s.link === 'down' ? 'down' : null,
      speed: num(s.speed),
      duplex: s.duplex ?? null,
      mac: s.mac || null,
      rxBytes: num(s.rx_bytes), txBytes: num(s.tx_bytes),
      rxPackets: num(s.rx_packets), txPackets: num(s.tx_packets),
      rxErrors: num(s.rx_errors), txErrors: num(s.tx_errors)
    });
  }
  return map;
}

function auditInterfaces(rows, stats = new Map()) {
  return rows.map((i) => {
    const addr = parseV4(i.ip);
    const hasIp = addr && addr.ip !== '0.0.0.0';
    const publicIp = hasIp && !isPrivateV4(addr.ip);
    const role = i.role || 'undefined';
    const exposed = role === 'wan' || publicIp;
    const services = String(i.allowaccess || '').split(/\s+/).filter(Boolean);
    const findings = [];
    const st = stats.get(i.name) || null;
    const up = st ? st.link === 'up' : (i.status !== 'down');
    const serviceRisk = services.map((svc) => {
      const info = SERVICE_INFO[svc] || { label: svc.toUpperCase(), exposed: null, internal: null, why: '' };
      let sev = exposed ? info.exposed : info.internal;
      if (sev && !up) sev = sev === 'alta' ? 'media' : 'baixa'; // interface desligada: risco latente
      if (sev) {
        findings.push(finding(sev, `${info.label} ${exposed ? 'exposto' : 'ativo'}`,
          `${info.label} em ${i.name}${exposed ? ` (${role === 'wan' ? 'papel WAN' : 'IP público'})` : ''}: ${info.why}.${up ? '' : ' Interface administrativamente desligada.'}`,
          svc === 'telnet' || svc === 'http'
            ? `Remova ${info.label} do allowaccess; use ${svc === 'telnet' ? 'SSH' : 'HTTPS'} apenas em interfaces internas.`
            : exposed
              ? `Remova ${info.label} desta interface ou restrinja com trusted hosts / local-in policy.`
              : `Confirme se ${info.label} é necessário nesta interface.`));
      }
      return { service: svc, label: info.label, severity: sev };
    });
    const errors = st ? (st.rxErrors || 0) + (st.txErrors || 0) : 0;
    const packets = st ? (st.rxPackets || 0) + (st.txPackets || 0) : 0;
    // Erros acima de 0,1% dos pacotes costumam indicar cabo, duplex ou óptico ruim.
    if (st && errors > 100 && packets > 0 && errors / packets > 0.001) {
      findings.push(finding('baixa', 'Erros de transmissão',
        `${errors.toLocaleString('pt-BR')} erros (${((errors / packets) * 100).toFixed(2)}% dos pacotes) desde o último reset dos contadores.`,
        'Verifique cabo/transceiver, negociação de velocidade e duplex dos dois lados.'));
    }
    return {
      name: i.name,
      alias: i.alias || null,
      description: i.description || null,
      role,
      type: i.type || null,
      vdom: i.vdom || null,
      // VLAN: mesma tabela, type=vlan com vlanid e interface pai.
      vlanId: i.type === 'vlan' && i.vlanid != null ? Number(i.vlanid) : null,
      parent: i.type === 'vlan' ? (i.interface || null) : null,
      status: up ? 'up' : 'down',
      ip: hasIp ? addr.cidr : null,
      publicIp: !!publicIp,
      exposed,
      services: serviceRisk,
      stats: st,
      findings,
      severity: worst(findings)
    };
  });
}

// ---- Usuários locais e grupos (autenticação de firewall/VPN) -------------
function auditLocalUsers(users, groups) {
  const groupsOf = new Map();
  const groupList = groups.map((g) => {
    const members = names(g.member);
    for (const m of members) {
      if (!groupsOf.has(m)) groupsOf.set(m, []);
      groupsOf.get(m).push(g.name);
    }
    const remote = Array.isArray(g.match) && g.match.length > 0;
    const findings = [];
    if (!members.length && !remote && (g['group-type'] || 'firewall') === 'firewall') {
      findings.push(finding('baixa', 'Grupo vazio', 'O grupo não tem membros locais nem regras de correspondência remota.', 'Remova o grupo se não é usado em políticas ou VPN.'));
    }
    return {
      name: g.name,
      type: g['group-type'] || 'firewall',
      members,
      remoteServers: names((g.match || []).map((m) => m['server-name'])).filter(Boolean),
      remoteMatches: (g.match || []).length,
      findings,
      severity: worst(findings)
    };
  });

  const userList = users.map((u) => {
    const enabled = u.status !== 'disable';
    const type = u.type || 'password';
    const twoFactor = u['two-factor'] && u['two-factor'] !== 'disable' ? u['two-factor'] : null;
    const memberOf = groupsOf.get(u.name) || [];
    const findings = [];
    if (enabled && type === 'password' && !twoFactor) {
      findings.push(finding('media', 'Senha local sem 2FA',
        'Usuário com senha guardada no próprio FortiGate e sem segundo fator (comum em VPN SSL/IPsec).',
        'Habilite FortiToken/e-mail no usuário ou migre para autenticação remota com MFA.'));
    }
    if (enabled && !memberOf.length) {
      findings.push(finding('baixa', 'Usuário sem grupo',
        'Não pertence a nenhum grupo: provavelmente não é usado em políticas, ou é usado diretamente (difícil de auditar).',
        'Remova se não é mais usado, ou coloque num grupo com finalidade clara.'));
    }
    return {
      name: u.name,
      enabled,
      type,
      server: u['ldap-server'] || u['radius-server'] || u['tacacs+-server'] || null,
      twoFactor,
      email: u['email-to'] || null,
      groups: memberOf,
      findings,
      severity: enabled ? worst(findings) : null
    };
  });

  return { users: userList, groups: groupList };
}

// ---- Usuários autenticados agora ----------------------------------------
function normalizeSessions(results) {
  const list = Array.isArray(results) ? results : [];
  const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : null);
  return list.map((s) => ({
    username: s.username || s.user_name || s.name || '—',
    ip: s.ipaddr || s.ip || s.src_ip || null,
    type: s.type || s.auth_type || null,
    method: s.method || s.authentication_method || null,
    groups: names(s.usergroup || s.user_group || s.groups || s.group),
    durationSec: num(s.duration ?? s.duration_secs),
    expirySec: num(s.expiry ?? s.expiry_secs),
    bytes: num(s.traffic_vol_bytes ?? s.traffic_volume ?? s.bytes),
    server: s.server || s.auth_server || null
  })).sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
}

// ---- VPN IPsec -------------------------------------------------------------
// Proposta FortiOS: "aes128-sha256 aes256gcm-prfsha384 chacha20poly1305-prfsha256"
// (cifra-integridade; nas AEAD o 2º termo é a PRF). Basta UMA opção fraca na
// lista para ela poder ser negociada com um peer que só ofereça a fraca.
const WEAK_ENC = { null: 'alta', des: 'alta', '3des': 'alta' };
const WEAK_HASH = { md5: 'alta', sha1: 'media', prfsha1: 'media' };

function parseProposals(value) {
  return String(value || '').split(/\s+/).filter(Boolean).map((token) => {
    const i = token.indexOf('-');
    const enc = i < 0 ? token : token.slice(0, i);
    const hash = i < 0 ? '' : token.slice(i + 1);
    const sev = WEAK_ENC[enc] || WEAK_HASH[hash] || null;
    return { token, enc, hash, aead: /gcm|poly1305/.test(enc), severity: sev };
  });
}

// Grupos DH: 1/2/5 = MODP < 2048 bits (quebráveis/descontinuados);
// 22/23/24 = MODP com subgrupo pequeno (RFC 8247: não usar); 25/26 = ECP fracas.
// 14/15/16 = MODP aceitável; 19/20/21 (ECP) e 31/32 (Curve25519/448) = recomendados.
const DH_WEAK = new Set([1, 2, 5]);
const DH_DISCOURAGED = new Set([22, 23, 24, 25, 26]);
const DH_STRONG = new Set([19, 20, 21, 27, 28, 29, 30, 31, 32]);
const parseDh = (v) => String(v || '').split(/\s+/).map(Number).filter((n) => Number.isFinite(n) && n > 0);

// `modpHint`: a dica "só MODP" (baixa) sai uma vez por túnel, na fase 1;
// repetir em cada seletor de fase 2 só inflava a contagem.
function cryptoFindings(proposals, dh, where, { modpHint = true } = {}) {
  const out = [];
  const weakAlta = proposals.filter((p) => p.severity === 'alta');
  const weakMedia = proposals.filter((p) => p.severity === 'media');
  if (weakAlta.length) {
    out.push(finding('alta', `Criptografia quebrada na ${where}`,
      `Propostas inseguras habilitadas: ${weakAlta.map((p) => p.token).join(', ')} (DES/3DES/MD5/NULL).`,
      'Remova essas propostas. Use AES-GCM (aes256gcm-prfsha384) ou AES-256 com SHA-256/384, iguais nos dois lados.'));
  }
  if (weakMedia.length) {
    out.push(finding('media', `SHA-1 na ${where}`,
      `Propostas com SHA-1: ${weakMedia.map((p) => p.token).join(', ')}. SHA-1 é descontinuado para IPsec (RFC 8221/8247).`,
      'Troque por SHA-256 ou superior (ex.: aes256-sha256) ou por AES-GCM. Ajuste o peer junto.'));
  }
  const weakDh = dh.filter((g) => DH_WEAK.has(g));
  const discouraged = dh.filter((g) => DH_DISCOURAGED.has(g));
  if (weakDh.length) {
    out.push(finding('alta', `Diffie-Hellman fraco na ${where}`,
      `Grupo(s) ${weakDh.join(', ')}: MODP abaixo de 2048 bits, viável de quebrar por atacante com recursos (Logjam).`,
      'Use grupo 19, 20 ou 21 (ECP) — ou no mínimo 14 — nos dois lados.'));
  }
  if (discouraged.length) {
    out.push(finding('media', `Grupo DH desaconselhado na ${where}`,
      `Grupo(s) ${discouraged.join(', ')}: a RFC 8247 recomenda não usar (subgrupo pequeno/curva fraca).`,
      'Prefira 19, 20 ou 21.'));
  }
  if (modpHint && dh.length && !weakDh.length && !dh.some((g) => DH_STRONG.has(g))) {
    out.push(finding('baixa', 'Somente DH MODP',
      `Grupo(s) ${dh.join(', ')}: aceitável (14 = 2048 bits), mas ECDH é mais forte e mais leve.`,
      'Quando o peer suportar, migre fase 1 e fase 2 (PFS) para o grupo 19, 20 ou 21.'));
  }
  return out;
}

const subnetOf = (v) => {
  const p = parseV4(v);
  return p ? p.cidr : null;
};
function selectorLabel(p2, side) {
  const type = p2[`${side}-addr-type`];
  if (type === 'name') return p2[`${side}-name`] || '—';
  if (type === 'range') return `${p2[`${side}-start-ip`] || '?'} – ${p2[`${side}-end-ip`] || '?'}`;
  if (type === 'ip') return p2[`${side}-start-ip`] || '—';
  return subnetOf(p2[`${side}-subnet`]) || '0.0.0.0/0';
}

function auditIpsec(p1Rows, p2Rows, monitorRows) {
  const mon = new Map((Array.isArray(monitorRows) ? monitorRows : []).map((m) => [m.name, m]));
  const p2ByP1 = new Map();
  for (const p2 of p2Rows) {
    if (!p2ByP1.has(p2.phase1name)) p2ByP1.set(p2.phase1name, []);
    p2ByP1.get(p2.phase1name).push(p2);
  }
  const known = new Set(p1Rows.map((p) => p.name));
  const orphans = p2Rows.filter((p2) => !known.has(p2.phase1name)).map((p2) => ({ name: p2.name, phase1name: p2.phase1name }));

  const tunnels = p1Rows.map((p1) => {
    const m = mon.get(p1.name) || null;
    const ikeVersion = String(p1['ike-version'] || '1');
    const dialup = p1.type === 'dynamic';
    const psk = (p1.authmethod || 'psk') === 'psk';
    const proposals = parseProposals(p1.proposal);
    const dh = parseDh(p1.dhgrp);
    const findings = cryptoFindings(proposals, dh, 'fase 1');

    if (ikeVersion === '1') {
      findings.push(finding(p1.mode === 'aggressive' ? 'alta' : 'media',
        p1.mode === 'aggressive' ? 'IKEv1 em modo agressivo' : 'IKEv1',
        p1.mode === 'aggressive'
          ? 'O modo agressivo envia o hash da PSK sem proteção: quem captura a negociação pode quebrar a chave offline.'
          : 'IKEv1 é legado: negociação mais lenta e menos robusta que IKEv2 (sem EAP, MOBIKE, proteção contra DoS).',
        'Migre para IKEv2 (set ike-version 2) combinando com o peer.'));
    }
    if (dialup && psk && (p1.peertype === 'any' || !p1.peertype) && p1.xauthtype === 'disable' && p1.eap !== 'enable') {
      findings.push(finding('alta', 'Dial-up só com PSK',
        'Túnel dinâmico (aceita qualquer IP de origem) autenticado só pela chave compartilhada: quem tiver a PSK conecta.',
        'Exija autenticação de usuário (XAuth/EAP com grupo) ou certificados, e restrinja peerid.'));
    }
    if (p1.dpd === 'disable') {
      findings.push(finding('baixa', 'DPD desativado',
        'Sem Dead Peer Detection, um túnel morto continua "up" e o tráfego não falha para a rota de backup.',
        'Use dpd on-idle (ou on-demand) com retry de 20 s.'));
    }
    const keylife = Number(p1.keylife);
    if (Number.isFinite(keylife) && keylife > 86400) {
      findings.push(finding('baixa', 'Vida da fase 1 longa',
        `keylife = ${keylife}s (${(keylife / 3600).toFixed(1)} h), acima do padrão de 24 h.`,
        'Use 86400 s ou menos (28800 s é comum).'));
    }

    const p2s = (p2ByP1.get(p1.name) || []).map((p2) => {
      const props2 = parseProposals(p2.proposal);
      const pfs = p2.pfs !== 'disable';
      const dh2 = pfs ? parseDh(p2.dhgrp) : [];
      const f2 = cryptoFindings(props2, dh2, 'fase 2', { modpHint: false });
      if (!pfs) {
        f2.push(finding('media', 'PFS desativado',
          'Sem Perfect Forward Secrecy, comprometer a chave da fase 1 permite decifrar o tráfego já capturado.',
          'Habilite pfs com DH 19/20/21 (ou 14) na fase 2, nos dois lados.'));
      }
      if (p2.replay === 'disable') {
        f2.push(finding('media', 'Proteção contra replay desativada',
          'Pacotes capturados podem ser reenviados dentro do túnel.',
          'Habilite replay (padrão do FortiOS).'));
      }
      const kl = Number(p2.keylifeseconds);
      if (Number.isFinite(kl) && kl > 43200 && p2['keylife-type'] !== 'kbs') {
        f2.push(finding('baixa', 'Vida da fase 2 longa',
          `keylifeseconds = ${kl}s (${(kl / 3600).toFixed(1)} h), acima do padrão de 12 h.`,
          'Use 43200 s ou menos (3600 s é comum).'));
      }
      const src = selectorLabel(p2, 'src');
      const dst = selectorLabel(p2, 'dst');
      if (src === '0.0.0.0/0' && dst === '0.0.0.0/0') {
        f2.push(finding('baixa', 'Seletores 0.0.0.0/0',
          'A fase 2 aceita qualquer origem e destino: o controle de acesso depende só das políticas de firewall do túnel.',
          'Normal em VPN baseada em rota; confira se as políticas do túnel restringem origem, destino e serviço.'));
      }
      const proxy = (m?.proxyid || []).filter((x) => x.p2name === p2.name);
      const up = proxy.some((x) => x.status === 'up');
      return {
        name: p2.name,
        proposals: props2,
        pfs,
        dh: dh2,
        replay: p2.replay !== 'disable',
        keylifeSec: Number.isFinite(kl) ? kl : null,
        autoNegotiate: p2['auto-negotiate'] === 'enable',
        src, dst,
        status: m ? (up ? 'up' : 'down') : null,
        inBytes: proxy.reduce((s, x) => s + (Number(x.incoming_bytes) || 0), 0),
        outBytes: proxy.reduce((s, x) => s + (Number(x.outgoing_bytes) || 0), 0),
        findings: f2,
        severity: worst(f2)
      };
    });

    const p2Up = p2s.filter((x) => x.status === 'up').length;
    if (m && p2s.length && p2Up === 0) {
      findings.push(finding('baixa', 'Túnel inativo',
        'Nenhuma fase 2 está ativa agora.',
        'Se o túnel não é mais usado, desative-o (e remova as políticas/rotas): túnel parado com PSK é superfície de ataque sem benefício.'));
    }
    if (!p2s.length) {
      findings.push(finding('baixa', 'Fase 1 sem fase 2', 'Não há seletores de fase 2 para este túnel.', 'Remova a fase 1 se não for usada.'));
    }

    const allFindings = [...findings, ...p2s.flatMap((x) => x.findings)];
    return {
      name: p1.name,
      comments: p1.comments || null,
      interface: p1.interface || null,
      remoteGw: dialup ? 'dial-up (qualquer IP)' : (p1['remote-gw'] && p1['remote-gw'] !== '0.0.0.0' ? p1['remote-gw'] : p1.remotegw_ddns || p1['remotegw-ddns'] || '—'),
      type: p1.type || 'static',
      dialup,
      ikeVersion,
      mode: ikeVersion === '1' ? (p1.mode || 'main') : null,
      authMethod: psk ? 'PSK' : (p1.authmethod === 'signature' ? 'Certificado' : p1.authmethod),
      proposals,
      dh,
      dpd: p1.dpd || null,
      nat: p1.nattraversal || null,
      keylifeSec: Number.isFinite(keylife) ? keylife : null,
      status: m ? (p2Up > 0 ? 'up' : 'down') : null,
      p2Up,
      p2Total: p2s.length,
      inBytes: m ? Number(m.incoming_bytes) || 0 : null,
      outBytes: m ? Number(m.outgoing_bytes) || 0 : null,
      uptimeSec: m && p2Up ? Number(m.creation_time) || null : null,
      phase2: p2s,
      findings,
      severity: worst(allFindings),
      findingCount: allFindings.length
    };
  });
  return { tunnels, orphans };
}

// ---- SSL-VPN -----------------------------------------------------------------
function auditSslVpn(settings, sessions) {
  const s = Array.isArray(settings) ? settings[0] : settings;
  if (!s || typeof s !== 'object') return null;
  const listen = names(s['source-interface']);
  const enabled = s.status !== 'disable';
  const active = enabled && listen.length > 0;
  const findings = [];
  const minTls = s['ssl-min-proto-ver'] || null;
  if (active) {
    findings.push(finding('media', 'SSL-VPN exposta',
      `Escutando em ${listen.join(', ')} na porta ${s.port}. O portal SSL-VPN do FortiOS teve várias falhas críticas exploradas em massa (ex.: CVE-2022-42475, CVE-2023-27997, CVE-2024-21762).`,
      'Mantenha o firmware atualizado. Se possível, migre os usuários para IPsec (IKEv2 + EAP/SAML) e desative a SSL-VPN; o FortiOS 7.6.3+ já remove o modo túnel.'));
    if (minTls && /tls1-0|tls1-1|ssl/.test(minTls)) {
      findings.push(finding('alta', 'TLS antigo permitido',
        `ssl-min-proto-ver = ${minTls}: TLS 1.0/1.1 são vulneráveis e descontinuados.`,
        'set ssl-min-proto-ver tls1-2 (ou tls1-3).'));
    }
    if (s.algorithm === 'low') {
      findings.push(finding('alta', 'Cifras fracas', 'algorithm = low permite cifras fracas (RC4, DES…).', 'set algorithm high.'));
    } else if (s.algorithm === 'medium' || s.algorithm === 'default') {
      findings.push(finding('baixa', 'Cifras médias permitidas', `algorithm = ${s.algorithm}.`, 'set algorithm high, se os clientes suportarem.'));
    }
    if (!names(s['source-address']).length || names(s['source-address']).includes('all')) {
      findings.push(finding('baixa', 'Sem restrição de origem',
        'Qualquer IP da Internet alcança o portal de login.',
        'Restrinja source-address por país/geolocalização ou faixas conhecidas, quando possível.'));
    }
    if (Number(s['idle-timeout']) === 0) {
      findings.push(finding('media', 'Sem timeout de inatividade', 'idle-timeout = 0: sessões esquecidas ficam abertas indefinidamente.', 'Defina idle-timeout (ex.: 300–900 s).'));
    }
    const attempts = Number(s['login-attempt-limit']);
    if (Number.isFinite(attempts) && (attempts === 0 || attempts > 5)) {
      findings.push(finding('media', 'Limite de tentativas fraco', `login-attempt-limit = ${attempts}.`, 'Use 3 a 5 tentativas com login-block-time ≥ 60 s.'));
    }
    const block = Number(s['login-block-time']);
    if (Number.isFinite(block) && block < 60) {
      findings.push(finding('baixa', 'Bloqueio curto após falhas', `login-block-time = ${block}s.`, 'Use pelo menos 60 s (300 s dificulta força bruta).'));
    }
    if (s.servercert === 'Fortinet_Factory' || s.servercert === 'Fortinet_SSL') {
      findings.push(finding('media', 'Certificado de fábrica', `servercert = ${s.servercert}: os usuários aprendem a ignorar o alerta de certificado (facilita MITM).`, 'Use um certificado emitido por CA confiável.'));
    }
  }
  const list = (Array.isArray(sessions) ? sessions : []).map((x) => ({
    username: x.user_name || x.username || '—',
    remoteHost: x.remote_host || x.src_ip || null,
    tunnelIp: (x.subsessions || []).map((y) => y.aip || y.tunnel_ip).find(Boolean) || x.tunnel_ip || null,
    loginTime: x.last_login_timestamp ? new Date(Number(x.last_login_timestamp) * 1000).toISOString() : (x.last_login_time || null),
    durationSec: Number.isFinite(Number(x.duration)) ? Number(x.duration) : null,
    bytes: (x.subsessions || []).reduce((sum, y) => sum + (Number(y.in_bytes) || 0) + (Number(y.out_bytes) || 0), 0) || null
  }));
  return {
    enabled,
    active,
    listenInterfaces: listen,
    port: s.port ?? null,
    minTls, maxTls: s['ssl-max-proto-ver'] || null,
    algorithm: s.algorithm || null,
    idleTimeout: s['idle-timeout'] ?? null,
    authTimeout: s['auth-timeout'] ?? null,
    loginAttemptLimit: s['login-attempt-limit'] ?? null,
    loginBlockTime: s['login-block-time'] ?? null,
    sourceAddress: names(s['source-address']),
    sessions: list,
    findings,
    severity: worst(findings)
  };
}

async function readTable(host, token, path, port) {
  try {
    const json = await requestJson(host, path, token, { port });
    return { rows: Array.isArray(json?.results) ? json.results : [], raw: json?.results ?? null, error: null, version: json?.version || null };
  } catch (e) {
    const msg = e.status === 403 ? 'o token não tem permissão de leitura nesta tabela (perfil precisa de leitura em Sistema)'
      : e.status === 404 ? 'tabela não existe nesta versão do FortiOS'
        : e.message;
    return { rows: [], raw: null, error: msg, version: null };
  }
}

const bySev = (a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0) || String(a.name).localeCompare(String(b.name));

// Eventos do log em memória (subtype system) que têm um usuário por trás:
// login/logout, alterações de configuração, download de backup etc. Eventos
// de VPN/sistema sem usuário real ("N/A") ficam de fora.
const ADMIN_EVENT_ROWS = Math.max(50, Math.min(2000, Number.parseInt(process.env.FORTIGATE_EVENT_ROWS || '500', 10) || 500));

function normalizeAdminEvent(r) {
  const ts = Number(r?._metadata?.timestamp);
  const when = Number.isFinite(ts) && ts > 0 ? new Date(ts).toISOString()
    : (r.date && r.time ? `${r.date}T${r.time}${r.tz ? r.tz.replace(/(\d{2})(\d{2})$/, '$1:$2') : ''}` : null);
  const cfg = [r.cfgpath, r.cfgobj].filter(Boolean).join(' ');
  return {
    when,
    user: String(r.user),
    action: r.action || null,
    description: r.logdesc || null,
    message: r.msg || null,
    level: r.level || null,
    status: r.status || null,
    ui: r.ui || null,
    srcip: r.srcip || null,
    method: r.method || null,
    profile: r.profile || null,
    config: cfg || null,
    configAttr: r.cfgattr || null,
    logid: r.logid || null
  };
}

async function readAdminEvents(host, token, port) {
  const path = `/api/v2/log/memory/event/system?rows=${ADMIN_EVENT_ROWS}&filter=${encodeURIComponent('subtype==system')}`;
  const t = await readTable(host, token, path, port);
  if (t.error) return { events: [], error: t.error };
  const events = t.rows
    .filter((r) => r && r.user && String(r.user).trim() && String(r.user).toUpperCase() !== 'N/A')
    .map(normalizeAdminEvent)
    .sort((a, b) => String(b.when || '').localeCompare(String(a.when || '')));
  return { events, error: null };
}

// ---- último login -----------------------------------------------------
// O FortiOS não guarda "último login" na configuração. A melhor fonte sem
// FortiAnalyzer é o log em memória (volátil) + quem está logado agora.
const isRealUser = (u) => u && String(u).trim() && String(u).toUpperCase() !== 'N/A';
const eventWhen = (r) => {
  const ts = Number(r?._metadata?.timestamp);
  return Number.isFinite(ts) && ts > 0 ? new Date(ts).toISOString() : null;
};

// Admins: eventos "Admin login successful" do log system + sessões ativas
// (monitor/system/current-admins), que cobrem o caso do log já ter girado.
function adminLastLogins(adminEvents, currentAdmins) {
  const map = new Map();
  const consider = (name, entry) => {
    if (!isRealUser(name) || !entry.when) return;
    const cur = map.get(name);
    if (!cur || entry.when > cur.when) map.set(name, entry);
  };
  for (const e of adminEvents) {
    if (e.action === 'login' && e.status === 'success') consider(e.user, { when: e.when, from: e.srcip || e.ui || null, method: e.method || null, source: 'log' });
  }
  for (const s of currentAdmins || []) {
    const t = Number(s.time);
    consider(s.admin, { when: Number.isFinite(t) && t > 0 ? new Date(t * 1000).toISOString() : null, from: s.srcaddr || null, method: s.method || null, source: 'sessao', active: true });
  }
  return map;
}

// Usuários locais: autenticações no log (SSL-VPN/IPsec/portal cativo) +
// quem está autenticado agora no firewall (monitor/user/firewall).
async function readUserLogins(host, token, port, firewallSessions) {
  const map = new Map();
  const consider = (name, entry) => {
    if (!isRealUser(name) || !entry.when) return;
    const cur = map.get(name);
    if (!cur || entry.when > cur.when) map.set(name, entry);
  };
  const errors = [];
  for (const sub of ['vpn', 'user']) {
    const path = `/api/v2/log/memory/event/system?rows=${ADMIN_EVENT_ROWS}&filter=${encodeURIComponent(`subtype==${sub}`)}`;
    const t = await readTable(host, token, path, port);
    if (t.error) { errors.push(`${sub}: ${t.error}`); continue; }
    for (const r of t.rows) {
      if (!isRealUser(r.user)) continue;
      // Só eventos de autenticação bem-sucedida de usuário (não negociação IKE por IP).
      const a = String(r.action || '').toLowerCase();
      const d = String(r.logdesc || '').toLowerCase();
      const ok = (a === 'tunnel-up' || a === 'ssl-login' || a === 'auth-logon' || a === 'authentication' || /logged in|login succeeded|auth(entication)? success/.test(d)) && r.status !== 'failure';
      if (!ok) continue;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(String(r.user))) continue; // IP de peer IPsec, não usuário
      consider(r.user, { when: eventWhen(r), from: r.remip || r.srcip || null, method: r.tunneltype || sub, source: 'log' });
    }
  }
  for (const s of firewallSessions || []) {
    const when = s.durationSec != null ? new Date(Date.now() - s.durationSec * 1000).toISOString() : null;
    consider(s.username, { when, from: s.ip || null, method: s.method || s.type || null, source: 'sessao', active: true });
  }
  return { map, error: errors.length ? errors.join(' · ') : null };
}

async function auditFortigate({ host, token, port }) {
  const [admins, apiUsers, interfaces, ifaceStats, localUsers, userGroups, authUsers, p1, p2, ipsecMon, sslSettings, sslMon, accprofiles, adminEvents, currentAdmins] = await Promise.all([
    readTable(host, token, '/api/v2/cmdb/system/admin', port),
    readTable(host, token, '/api/v2/cmdb/system/api-user', port),
    readTable(host, token, '/api/v2/cmdb/system/interface', port),
    readTable(host, token, '/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true', port),
    readTable(host, token, '/api/v2/cmdb/user/local', port),
    readTable(host, token, '/api/v2/cmdb/user/group', port),
    readTable(host, token, '/api/v2/monitor/user/firewall', port),
    readTable(host, token, '/api/v2/cmdb/vpn.ipsec/phase1-interface', port),
    readTable(host, token, '/api/v2/cmdb/vpn.ipsec/phase2-interface', port),
    readTable(host, token, '/api/v2/monitor/vpn/ipsec', port),
    readTable(host, token, '/api/v2/cmdb/vpn.ssl/settings', port),
    readTable(host, token, '/api/v2/monitor/vpn/ssl', port),
    // Perfis: para saber se um perfil personalizado tem privilégio total (o nome não importa).
    readTable(host, token, '/api/v2/cmdb/system/accprofile', port),
    readAdminEvents(host, token, port),
    readTable(host, token, '/api/v2/monitor/system/current-admins', port)
  ]);
  const profiles = new Map(accprofiles.rows.map((p) => [p.name, p]));
  // Sem nenhuma tabela legível não há o que mostrar: devolve o erro de verdade.
  if ([admins, apiUsers, interfaces, localUsers, userGroups].every((t) => t.error)) {
    throw Object.assign(new Error(`Não foi possível ler a configuração: ${admins.error}`), { status: 502 });
  }
  // Todo FortiGate tem ao menos um administrador, e o próprio token é um
  // usuário de API: lista vazia SEM erro significa que o FortiOS não liberou
  // os objetos para o perfil deste token (ele oculta contas com privilégio
  // maior; pedir uma pelo nome devolve 404). Seja qual for o nome do perfil,
  // a tela só informa que não há acesso.
  let adminsHidden = false;
  if (!admins.error && admins.rows.length === 0) {
    adminsHidden = true;
    admins.error = 'sem acesso: o perfil do token não permite listar os administradores.';
  }
  if (!apiUsers.error && apiUsers.rows.length === 0) {
    apiUsers.error = 'sem acesso: o perfil do token não permite listar os usuários de API.';
  }

  const adminList = [...auditAdmins(admins.rows, profiles), ...auditApiUsers(apiUsers.rows, profiles)].sort(bySev);
  const ifaces = auditInterfaces(interfaces.rows, statsMap(ifaceStats.raw)).sort(bySev);
  const local = auditLocalUsers(localUsers.rows, userGroups.rows);
  local.users.sort(bySev);
  local.groups.sort(bySev);
  const sessions = normalizeSessions(authUsers.raw);

  // Último login: admins pelo log system + sessões administrativas ativas;
  // usuários locais pelo log vpn/user + sessões autenticadas no firewall.
  const adminLogins = adminLastLogins(adminEvents.events, currentAdmins.rows);
  for (const u of adminList) u.lastLogin = adminLogins.get(u.name) || null;
  const userLogins = await readUserLogins(host, token, port, sessions);
  for (const u of local.users) u.lastLogin = userLogins.map.get(u.name) || null;

  const ipsec = auditIpsec(p1.rows, p2.rows, ipsecMon.rows);
  ipsec.tunnels.sort(bySev);
  const sslvpn = sslSettings.error ? null : auditSslVpn(sslSettings.raw, sslMon.rows);
  const vpnFindings = [
    ...ipsec.tunnels.flatMap((t) => [...t.findings, ...t.phase2.flatMap((x) => x.findings)]),
    ...(sslvpn?.findings || [])
  ];

  const allFindings = [
    ...adminList.flatMap((u) => u.findings),
    ...ifaces.flatMap((i) => i.findings),
    ...local.users.filter((u) => u.enabled).flatMap((u) => u.findings),
    ...local.groups.flatMap((g) => g.findings),
    ...vpnFindings
  ];
  const bySeverity = { alta: 0, media: 0, baixa: 0 };
  for (const f of allFindings) bySeverity[f.severity] += 1;

  return {
    generatedAt: new Date().toISOString(),
    version: admins.version || interfaces.version || apiUsers.version || localUsers.version,
    errors: {
      admins: admins.error,
      apiUsers: apiUsers.error,
      interfaces: interfaces.error,
      interfaceStats: ifaceStats.error,
      localUsers: localUsers.error,
      userGroups: userGroups.error,
      authUsers: authUsers.error,
      ipsecPhase1: p1.error,
      ipsecPhase2: p2.error,
      ipsecMonitor: ipsecMon.error,
      sslSettings: sslSettings.error,
      sslMonitor: sslMon.error,
      adminEvents: adminEvents.error,
      currentAdmins: currentAdmins.error,
      userLogins: userLogins.error
    },
    adminsHidden,
    summary: {
      admins: adminList.length,
      apiUsers: apiUsers.rows.length,
      adminsAnywhere: adminList.filter((u) => u.anywhere).length,
      adminsWithout2fa: adminList.filter((u) => u.kind !== 'api' && !u.twoFactor).length,
      superAdmins: adminList.filter((u) => u.superAdmin).length,
      localUsers: local.users.length,
      localUsersEnabled: local.users.filter((u) => u.enabled).length,
      localUsersWithout2fa: local.users.filter((u) => u.enabled && u.type === 'password' && !u.twoFactor).length,
      groups: local.groups.length,
      authenticated: sessions.length,
      interfaces: ifaces.length,
      vlans: ifaces.filter((i) => i.vlanId != null).length,
      interfacesDangerous: ifaces.filter((i) => i.severity === 'alta' || i.severity === 'media').length,
      exposedWithAdmin: ifaces.filter((i) => i.exposed && i.services.some((s) => ['https', 'ssh', 'http', 'telnet'].includes(s.service))).length,
      vpnTunnels: ipsec.tunnels.length,
      vpnTunnelsUp: ipsec.tunnels.filter((t) => t.status === 'up').length,
      vpnWeak: ipsec.tunnels.filter((t) => t.severity === 'alta' || t.severity === 'media').length,
      vpnFindings: vpnFindings.length,
      sslVpnActive: !!sslvpn?.active,
      sslVpnSessions: sslvpn?.sessions.length || 0,
      adminEvents: adminEvents.events.length,
      bySeverity
    },
    vpn: { ipsec: ipsec.tunnels, orphanPhase2: ipsec.orphans, sslvpn },
    admins: adminList,
    adminEvents: adminEvents.events,
    localUsers: local.users,
    groups: local.groups,
    sessions,
    interfaces: ifaces
  };
}

module.exports = { auditFortigate, _internals: { parseV4, isPrivateV4, trustedHostsOfAdmin, trustedHostsOfApiUser, auditAdmins, auditApiUsers, auditInterfaces, statsMap, auditLocalUsers, normalizeSessions, parseProposals, parseDh, auditIpsec, auditSslVpn } };
