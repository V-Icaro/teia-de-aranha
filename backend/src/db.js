// Postgres: pool + schema. Conexão via DATABASE_URL ou PG* avulsas.
// Tabelas criadas sozinhas na primeira conexão (init).
// Postgres guarda sub-redes, inventário manual e históricos usados pelo mapa/
// Reputação: watched_subnets, servers/server_ips/applications/listeners,
// ip_sightings, pair_daily e ip_reputation.
const { Pool } = require('pg');
const { encrypt, decrypt } = require('./crypto.js');

const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.PGHOST || '172.20.20.250',
        port: parseInt(process.env.PGPORT || '5432', 10),
        user: process.env.PGUSER || 'teia',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'teiadearanha'
      }
);

let ready = null;

async function init() {
  if (ready) return ready;
  ready = (async () => {
    const c = await pool.connect();
    try {
      await c.query(`
        -- A feature "Vigilância de hosts" foi removida. As tabelas
        -- watched_hosts, known_peers, pair_allowlist e findings continuam
        -- existindo no banco, órfãs: nada as cria, lê ou escreve.
        --
        -- NÃO as derrubamos aqui de propósito. Este bloco roda a cada boot e
        -- apagar dado sem autorização explícita não é decisão de código.
        -- Para limpar, uma vez, manualmente:
        --   drop table if exists findings, known_peers, pair_allowlist, watched_hosts;
        --
        -- O mesmo vale para ddos_incidents (recurso removido antes):
        --   drop table if exists ddos_incidents;
        -- histórico de IPs públicos. bytes/flows/periodo NÃO podem ser somados na
        -- hora da coleta: o job das 06:15 usa janela de 24h e o botão da tela
        -- 168h, então o mesmo byte entrava várias vezes (medido: 3–5× nos IPs de
        -- maior volume). Por isso a média mora por dia em ip_daily e o
        -- ip_sightings abaixo é o ROLLUP dela — substitui, nunca soma.
        CREATE TABLE IF NOT EXISTS ip_daily (
          day DATE NOT NULL,
          ip TEXT NOT NULL,
          bytes BIGINT NOT NULL DEFAULT 0,
          flows BIGINT NOT NULL DEFAULT 0,
          first_ts TIMESTAMPTZ NOT NULL,
          last_ts TIMESTAMPTZ NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          PRIMARY KEY (day, ip)
        );
        CREATE INDEX IF NOT EXISTS idx_ip_daily_ip ON ip_daily (ip, day DESC);
        CREATE INDEX IF NOT EXISTS idx_ip_daily_day ON ip_daily (day DESC);
        CREATE TABLE IF NOT EXISTS ip_sightings (
          ip TEXT PRIMARY KEY,
          first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
          last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
          bytes BIGINT NOT NULL DEFAULT 0,
          flows BIGINT NOT NULL DEFAULT 0,
          country TEXT,
          country_name TEXT,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS idx_sightings_last ON ip_sightings (last_seen DESC);
        -- Série diária por par e porta de destino. dport=0 representa fluxos
        -- sem porta e linhas antigas até que sejam reprocessadas do Elasticsearch.
        CREATE TABLE IF NOT EXISTS pair_daily (
          day DATE NOT NULL,
          src TEXT NOT NULL,
          dst TEXT NOT NULL,
          proto INT,
          dport INT NOT NULL DEFAULT 0,
          bytes BIGINT NOT NULL DEFAULT 0,
          packets BIGINT NOT NULL DEFAULT 0,
          flows BIGINT NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          PRIMARY KEY (day, src, dst, proto, dport)
        );
        ALTER TABLE pair_daily ADD COLUMN IF NOT EXISTS dport INT NOT NULL DEFAULT 0;
        DO $pair_daily_port_migration$
        DECLARE
          current_pk TEXT;
          current_pk_definition TEXT;
        BEGIN
          SELECT conname, pg_get_constraintdef(oid)
            INTO current_pk, current_pk_definition
            FROM pg_constraint
           WHERE conrelid = 'pair_daily'::regclass AND contype = 'p';
          IF current_pk IS NULL OR position('dport' in lower(current_pk_definition)) = 0 THEN
            IF current_pk IS NOT NULL THEN
              EXECUTE format('ALTER TABLE pair_daily DROP CONSTRAINT %I', current_pk);
            END IF;
            ALTER TABLE pair_daily ADD CONSTRAINT pair_daily_pkey PRIMARY KEY (day, src, dst, proto, dport);
          END IF;
        END;
        $pair_daily_port_migration$;
        CREATE INDEX IF NOT EXISTS idx_pair_daily_dst ON pair_daily (dst, day DESC);
        CREATE INDEX IF NOT EXISTS idx_pair_daily_src ON pair_daily (src, day DESC);
        CREATE INDEX IF NOT EXISTS idx_pair_daily_dport ON pair_daily (dport, day DESC);
        -- day é a 2ª coluna dos dois índices acima, então nenhum deles serve para
        -- "where day >= X" (série da Reputação e recuperação de dias faltando):
        -- sem este índice a consulta varre a tabela inteira, que não expira.
        CREATE INDEX IF NOT EXISTS idx_pair_daily_day ON pair_daily (day DESC);
        CREATE TABLE IF NOT EXISTS watched_subnets (
          cidr TEXT PRIMARY KEY,
          name TEXT,
          is_default BOOLEAN NOT NULL DEFAULT false,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS ip_reputation (
          ip TEXT PRIMARY KEY,
          verdict TEXT NOT NULL,
          score INT NOT NULL DEFAULT 0,
          reports INT NOT NULL DEFAULT 0,
          distinct_users INT,
          last_reported TIMESTAMPTZ,
          country TEXT,
          country_name TEXT,
          usage_type TEXT,
          isp TEXT,
          domain TEXT,
          hostnames TEXT[] NOT NULL DEFAULT '{}',
          whitelisted BOOLEAN,
          checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS servers (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          name TEXT NOT NULL CHECK (length(trim(name)) > 0),
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS server_ips (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          server_id BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          ip INET NOT NULL UNIQUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (id, server_id)
        );
        CREATE INDEX IF NOT EXISTS idx_server_ips_server ON server_ips (server_id, id);
        CREATE TABLE IF NOT EXISTS applications (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          server_id BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          name TEXT NOT NULL CHECK (length(trim(name)) > 0),
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (id, server_id),
          UNIQUE (server_id, name)
        );
        CREATE INDEX IF NOT EXISTS idx_applications_server ON applications (server_id, name);
        CREATE TABLE IF NOT EXISTS application_listeners (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          server_id BIGINT NOT NULL,
          application_id BIGINT NOT NULL,
          server_ip_id BIGINT NOT NULL,
          protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP')),
          port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          FOREIGN KEY (application_id, server_id) REFERENCES applications(id, server_id) ON DELETE CASCADE,
          FOREIGN KEY (server_ip_id, server_id) REFERENCES server_ips(id, server_id) ON DELETE CASCADE,
          UNIQUE (application_id, server_ip_id, protocol, port)
        );
        CREATE INDEX IF NOT EXISTS idx_application_listeners_app ON application_listeners (application_id);
        CREATE INDEX IF NOT EXISTS idx_application_listeners_ip ON application_listeners (server_ip_id);
        CREATE TABLE IF NOT EXISTS application_expected_clients (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          client_ip INET NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (application_id, client_ip)
        );
        CREATE INDEX IF NOT EXISTS idx_expected_clients_app ON application_expected_clients (application_id);
        CREATE TABLE IF NOT EXISTS fortigate (
          id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
          name TEXT NOT NULL CHECK (length(trim(name)) > 0),
          host TEXT NOT NULL CHECK (length(trim(host)) > 0),
          vdom TEXT NOT NULL DEFAULT 'root',
          token_cipher TEXT NOT NULL,
          token_iv TEXT NOT NULL,
          token_tag TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);
    } finally {
      c.release();
    }
    return true;
  })().catch((e) => {
    ready = null;
    console.warn(`[pg] sem Postgres (${e.message}) — histórico/sub-redes indisponíveis até conectar`);
    return false;
  });
  return ready;
}

// ---- sub-redes monitoradas (filtro do mapa) --------------------------
// Um único default: virar default limpa os outros na mesma transação, senão
// o front acabaria com dois "padrão" e o mapa abriria no último que chegou.
async function listSubnets() {
  const { rows } = await pool.query(
    'SELECT cidr, name, is_default, created_at FROM watched_subnets ORDER BY cidr'
  );
  return rows;
}

async function addSubnet(cidr, name) {
  const { rows } = await pool.query(
    `INSERT INTO watched_subnets (cidr, name) VALUES ($1, $2)
     ON CONFLICT (cidr) DO UPDATE SET name = EXCLUDED.name
     RETURNING cidr, name, is_default, created_at`,
    [cidr, name || null]
  );
  return rows[0];
}

async function patchSubnet(cidr, { name, is_default }) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    if (is_default) await c.query('UPDATE watched_subnets SET is_default = false WHERE cidr <> $1', [cidr]);
    const sets = [];
    const vals = [];
    if (name !== undefined) { vals.push(name || null); sets.push(`name = $${vals.length}`); }
    if (is_default !== undefined) { vals.push(!!is_default); sets.push(`is_default = $${vals.length}`); }
    if (!sets.length) throw Object.assign(new Error('Nada para atualizar'), { status: 400 });
    vals.push(cidr);
    const { rows } = await c.query(
      `UPDATE watched_subnets SET ${sets.join(', ')} WHERE cidr = $${vals.length}
       RETURNING cidr, name, is_default, created_at`,
      vals
    );
    await c.query('COMMIT');
    if (!rows.length) throw Object.assign(new Error('Sub-rede não encontrada'), { status: 404 });
    return rows[0];
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

async function delSubnet(cidr) {
  const r = await pool.query('DELETE FROM watched_subnets WHERE cidr = $1', [cidr]);
  if (!r.rowCount) throw Object.assign(new Error('Sub-rede não encontrada'), { status: 404 });
  return { ok: true, cidr };
}

// ---- inventário de servidores ----------------------------------------
// O nome pertence à máquina; os IPs são interfaces/endpoints sem rótulo manual.
async function listInventory() {
  const [serverRows, ipRows, appRows, listenerRows, expectedClientRows] = await Promise.all([
    pool.query('select id, name, created_at, updated_at from servers order by lower(name), id'),
    pool.query('select id, server_id, host(ip) as ip, created_at from server_ips order by server_id, host(ip)'),
    pool.query('select id, server_id, name, created_at, updated_at from applications order by server_id, lower(name), id'),
    pool.query(`select l.id, l.server_id, l.application_id, l.server_ip_id,
                       host(i.ip) as ip, l.protocol, l.port
                   from application_listeners l join server_ips i on i.id = l.server_ip_id
                  order by l.application_id, l.protocol, l.port, host(i.ip)`),
    pool.query(`select id, application_id, host(client_ip) as ip
                  from application_expected_clients order by application_id, host(client_ip)`)
  ]);

  const servers = new Map(serverRows.rows.map((r) => [String(r.id), {
    id: Number(r.id), name: r.name, createdAt: r.created_at, updatedAt: r.updated_at,
    ips: [], applications: []
  }]));
  const ips = new Map();
  for (const r of ipRows.rows) {
    const server = servers.get(String(r.server_id));
    if (!server) continue;
    const ip = { id: Number(r.id), ip: r.ip, createdAt: r.created_at };
    server.ips.push(ip);
    ips.set(String(r.id), ip);
  }
  const applications = new Map();
  for (const r of appRows.rows) {
    const server = servers.get(String(r.server_id));
    if (!server) continue;
    const app = { id: Number(r.id), serverId: Number(r.server_id), name: r.name, createdAt: r.created_at, listeners: [], expectedClients: [] };
    server.applications.push(app);
    applications.set(String(r.id), app);
  }
  for (const r of listenerRows.rows) {
    const app = applications.get(String(r.application_id));
    const ip = ips.get(String(r.server_ip_id));
    if (!app || !ip) continue;
    app.listeners.push({ id: Number(r.id), serverIpId: ip.id, ip: ip.ip, protocol: r.protocol, port: Number(r.port) });
  }
  for (const r of expectedClientRows.rows) {
    const app = applications.get(String(r.application_id));
    if (app) app.expectedClients.push({ id: Number(r.id), ip: r.ip });
  }
  return [...servers.values()];
}

async function inventoryNamesFor(ips) {
  const uniq = [...new Set((ips || []).filter(Boolean))];
  if (!uniq.length) return {};
  const { rows } = await pool.query(
    `select host(i.ip) as ip, s.name
       from server_ips i join servers s on s.id = i.server_id
      where i.ip = any($1::inet[])`, [uniq]);
  return Object.fromEntries(rows.map((r) => [r.ip, r.name]));
}

async function inventoryNameFor(ip) {
  const { rows } = await pool.query(
    `select s.name from server_ips i join servers s on s.id = i.server_id where i.ip = $1::inet`, [ip]);
  return rows[0]?.name || null;
}

async function inventoryApplicationsForIp(ip) {
  const machine = await pool.query(
    `select s.id, s.name, host(i.ip) as ip
       from server_ips i join servers s on s.id = i.server_id
      where i.ip = $1::inet`, [ip]);
  if (!machine.rowCount) return null;
  const m = machine.rows[0];
  const { rows } = await pool.query(
    `select a.id as application_id, a.name as application_name,
            l.id as listener_id, host(i.ip) as listener_ip, l.protocol, l.port
       from applications a
       left join application_listeners l on l.application_id = a.id
       left join server_ips i on i.id = l.server_ip_id
      where a.server_id = $1
      order by lower(a.name), l.protocol, l.port, host(i.ip)`, [m.id]);
  const apps = new Map();
  for (const r of rows) {
    let app = apps.get(String(r.application_id));
    if (!app) {
      app = { id: Number(r.application_id), name: r.application_name, listeners: [] };
      apps.set(String(r.application_id), app);
    }
    if (r.listener_id != null) app.listeners.push({
      id: Number(r.listener_id), ip: r.listener_ip, protocol: r.protocol, port: Number(r.port)
    });
  }
  return { serverId: Number(m.id), serverName: m.name, ip: m.ip, applications: [...apps.values()] };
}

async function createInventoryServer(name, addresses) {
  const c = await pool.connect();
  let id;
  try {
    await c.query('begin');
    const inserted = await c.query('insert into servers (name) values ($1) returning id', [name]);
    id = inserted.rows[0].id;
    for (const ip of addresses) await c.query('insert into server_ips (server_id, ip) values ($1, $2::inet)', [id, ip]);
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
  return (await listInventory()).find((s) => String(s.id) === String(id));
}

async function renameInventoryServer(id, name) {
  const { rows } = await pool.query(
    'update servers set name = $2, updated_at = now() where id = $1 returning id, name, updated_at', [id, name]);
  if (!rows.length) throw Object.assign(new Error('Máquina não encontrada'), { status: 404 });
  return { id: Number(rows[0].id), name: rows[0].name, updatedAt: rows[0].updated_at };
}

async function deleteInventoryServer(id) {
  const r = await pool.query('delete from servers where id = $1', [id]);
  if (!r.rowCount) throw Object.assign(new Error('Máquina não encontrada'), { status: 404 });
  return { ok: true, id: Number(id) };
}

async function addServerIp(serverId, ip) {
  const { rows } = await pool.query(
    `insert into server_ips (server_id, ip) values ($1, $2::inet)
     returning id, server_id, host(ip) as ip, created_at`, [serverId, ip]);
  return { id: Number(rows[0].id), serverId: Number(rows[0].server_id), ip: rows[0].ip, createdAt: rows[0].created_at };
}

async function deleteServerIp(id) {
  const c = await pool.connect();
  try {
    await c.query('begin');
    const info = await c.query('select server_id from server_ips where id = $1', [id]);
    if (!info.rowCount) throw Object.assign(new Error('IP da máquina não encontrado'), { status: 404 });
    await c.query('select id from servers where id = $1 for update', [info.rows[0].server_id]);
    const count = await c.query('select count(*)::int as count from server_ips where server_id = $1', [info.rows[0].server_id]);
    if (count.rows[0].count <= 1) throw Object.assign(new Error('A máquina precisa manter pelo menos um IP; adicione outro antes de remover este.'), { status: 409 });
    await c.query('delete from server_ips where id = $1', [id]);
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
  return { ok: true, id: Number(id) };
}

async function createApplication(serverId, name, listeners) {
  const c = await pool.connect();
  let id;
  try {
    await c.query('begin');
    const inserted = await c.query(
      'insert into applications (server_id, name) values ($1, $2) returning id', [serverId, name]);
    id = inserted.rows[0].id;
    for (const l of listeners) {
      await c.query(
        `insert into application_listeners (server_id, application_id, server_ip_id, protocol, port)
         values ($1, $2, $3, $4, $5)`, [serverId, id, l.serverIpId, l.protocol, l.port]);
    }
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
  return (await listInventory()).flatMap((s) => s.applications).find((a) => String(a.id) === String(id));
}

async function renameApplication(id, name) {
  const { rows } = await pool.query(
    'update applications set name = $2, updated_at = now() where id = $1 returning id, server_id, name, updated_at', [id, name]);
  if (!rows.length) throw Object.assign(new Error('Aplicação não encontrada'), { status: 404 });
  return { id: Number(rows[0].id), serverId: Number(rows[0].server_id), name: rows[0].name, updatedAt: rows[0].updated_at };
}

async function deleteApplication(id) {
  const r = await pool.query('delete from applications where id = $1', [id]);
  if (!r.rowCount) throw Object.assign(new Error('Aplicação não encontrada'), { status: 404 });
  return { ok: true, id: Number(id) };
}

async function addApplicationListener(applicationId, { serverIpId, protocol, port }) {
  const app = await pool.query('select server_id from applications where id = $1', [applicationId]);
  if (!app.rowCount) throw Object.assign(new Error('Aplicação não encontrada'), { status: 404 });
  const serverId = app.rows[0].server_id;
  const { rows } = await pool.query(
    `insert into application_listeners (server_id, application_id, server_ip_id, protocol, port)
     values ($1, $2, $3, $4, $5)
     returning id, server_id, application_id, server_ip_id, protocol, port`,
    [serverId, applicationId, serverIpId, protocol, port]);
  return rows[0];
}

async function deleteApplicationListener(id) {
  const r = await pool.query('delete from application_listeners where id = $1', [id]);
  if (!r.rowCount) throw Object.assign(new Error('Listener não encontrado'), { status: 404 });
  return { ok: true, id: Number(id) };
}

async function addExpectedApplicationClient(applicationId, clientIp) {
  const { rows } = await pool.query(
    `insert into application_expected_clients (application_id, client_ip)
     values ($1, $2::inet) returning id, application_id, host(client_ip) as ip`,
    [applicationId, clientIp]
  );
  return { id: Number(rows[0].id), applicationId: Number(rows[0].application_id), ip: rows[0].ip };
}

async function deleteExpectedApplicationClient(id) {
  const result = await pool.query('delete from application_expected_clients where id = $1', [id]);
  if (!result.rowCount) throw Object.assign(new Error('Cliente esperado não encontrado'), { status: 404 });
  return { ok: true, id: Number(id) };
}

function fortigatePublic(row) {
  return {
    id: Number(row.id), name: row.name, host: row.host, vdom: row.vdom || 'root',
    hasToken: Boolean(row.token_cipher),
    createdAt: row.created_at, updatedAt: row.updated_at
  };
}

async function listFortigates() {
  const { rows } = await pool.query(
    `select id, name, host, vdom, token_cipher, created_at, updated_at
       from fortigate order by lower(name), id`
  );
  return rows.map(fortigatePublic);
}

async function getFortigate(id) {
  const { rows } = await pool.query(
    `select id, name, host, vdom, token_cipher, token_iv, token_tag, created_at, updated_at
       from fortigate where id = $1`, [id]
  );
  const row = rows[0];
  if (!row) return null;
  return { ...fortigatePublic(row), token: decrypt({ ciphertext: row.token_cipher, iv: row.token_iv, tag: row.token_tag }) };
}

async function createFortigate({ name, host, vdom = 'root', token }) {
  const cleanName = String(name || '').trim();
  const cleanHost = String(host || '').trim();
  const cleanVdom = String(vdom || 'root').trim() || 'root';
  const cleanToken = String(token || '').trim();
  if (!cleanName || !cleanHost || !cleanToken) {
    throw Object.assign(new Error('Nome, host e token são obrigatórios.'), { status: 400 });
  }
  const secret = encrypt(cleanToken);
  const { rows } = await pool.query(
    `insert into fortigate (name, host, vdom, token_cipher, token_iv, token_tag)
     values ($1, $2, $3, $4, $5, $6)
     returning id, name, host, vdom, token_cipher, created_at, updated_at`,
    [cleanName, cleanHost, cleanVdom, secret.ciphertext, secret.iv, secret.tag]
  );
  return fortigatePublic(rows[0]);
}

async function updateFortigate(id, { name, host, vdom, token }) {
  const current = await pool.query('select id from fortigate where id = $1', [id]);
  if (!current.rowCount) throw Object.assign(new Error('FortiGate não encontrado.'), { status: 404 });
  const sets = [];
  const values = [];
  if (name !== undefined) {
    const clean = String(name || '').trim();
    if (!clean) throw Object.assign(new Error('Nome não pode ficar vazio.'), { status: 400 });
    values.push(clean); sets.push(`name = $${values.length}`);
  }
  if (host !== undefined) {
    const clean = String(host || '').trim();
    if (!clean) throw Object.assign(new Error('Host não pode ficar vazio.'), { status: 400 });
    values.push(clean); sets.push(`host = $${values.length}`);
  }
  if (vdom !== undefined) {
    const clean = String(vdom || 'root').trim() || 'root';
    values.push(clean); sets.push(`vdom = $${values.length}`);
  }
  if (token !== undefined && String(token).trim()) {
    const secret = encrypt(String(token).trim());
    values.push(secret.ciphertext); sets.push(`token_cipher = $${values.length}`);
    values.push(secret.iv); sets.push(`token_iv = $${values.length}`);
    values.push(secret.tag); sets.push(`token_tag = $${values.length}`);
  }
  if (!sets.length) throw Object.assign(new Error('Informe algo para atualizar.'), { status: 400 });
  values.push(id);
  const { rows } = await pool.query(
    `update fortigate set ${sets.join(', ')}, updated_at = now() where id = $${values.length}
     returning id, name, host, vdom, token_cipher, created_at, updated_at`, values
  );
  return fortigatePublic(rows[0]);
}

async function deleteFortigate(id) {
  const result = await pool.query('delete from fortigate where id = $1', [id]);
  if (!result.rowCount) throw Object.assign(new Error('FortiGate não encontrado.'), { status: 404 });
  return { ok: true, id: Number(id) };
}

module.exports = {
  pool, init, listSubnets, addSubnet, patchSubnet, delSubnet,
  listInventory, inventoryNamesFor, inventoryNameFor, inventoryApplicationsForIp,
  createInventoryServer, renameInventoryServer, deleteInventoryServer,
  addServerIp, deleteServerIp, createApplication, renameApplication,
  deleteApplication, addApplicationListener, deleteApplicationListener,
  addExpectedApplicationClient, deleteExpectedApplicationClient,
  listFortigates, getFortigate, createFortigate, updateFortigate, deleteFortigate
};
