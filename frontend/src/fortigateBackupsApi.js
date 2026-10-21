export async function listFortigateBackupPolicies() {
  const r = await fetch('/api/fortigate-backup/policies');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export async function createFortigateBackupPolicy(body) {
  const r = await fetch('/api/fortigate-backup/policies', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) { const j = await r.json().catch(()=>({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}
export async function updateFortigateBackupPolicy(id, body) {
  const r = await fetch(`/api/fortigate-backup/policies/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) { const j = await r.json().catch(()=>({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}
export async function deleteFortigateBackupPolicy(id) {
  const r = await fetch(`/api/fortigate-backup/policies/${id}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export async function runFortigateBackupPolicy(id) {
  const r = await fetch(`/api/fortigate-backup/policies/${id}/run`, { method: 'POST' });
  if (!r.ok) { const j = await r.json().catch(()=>({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}
export async function runFortigateBackupNow(id) {
  const r = await fetch(`/api/fortigate/${id}/backup`, { method: 'POST' });
  if (!r.ok) { const j = await r.json().catch(()=>({})); throw new Error(j.error || `HTTP ${r.status}`); }
  return r.json();
}
export async function listFortigateBackups(filters={}) {
  const p = new URLSearchParams();
  if(filters.fortigateId) p.set('fortigateId', String(filters.fortigateId));
  if(filters.policyId) p.set('policyId', String(filters.policyId));
  const r = await fetch(`/api/fortigate-backups?${p.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export async function getFortigateBackupContent(id) {
  const r = await fetch(`/api/fortigate-backups/${id}/content`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
export async function deleteFortigateBackup(id) {
  const r = await fetch(`/api/fortigate-backups/${id}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
