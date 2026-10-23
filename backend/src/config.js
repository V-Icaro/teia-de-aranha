const db = require('./db');

async function ensureSchema() {
  await db.pool.query(`create table if not exists app_config (
    key text primary key,
    value text not null,
    updated_at timestamptz not null default now()
  )`);
}

async function get(key, fallback = null) {
  await ensureSchema();
  const { rows } = await db.pool.query('select value from app_config where key = $1', [key]);
  return rows[0]?.value ?? fallback;
}

async function set(key, value) {
  await ensureSchema();
  await db.pool.query(`insert into app_config (key, value, updated_at) values ($1,$2,now())
    on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at`, [key, String(value)]);
}

module.exports = { ensureSchema, get, set };
