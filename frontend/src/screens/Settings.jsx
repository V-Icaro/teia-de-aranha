import { useEffect, useState } from 'react';

export default function SettingsScreen() {
  const [enabled, setEnabled] = useState(false);
  const [days, setDays] = useState(7);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    fetch('/api/config', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => { setEnabled(!!d.trafficCollectEnabled); setDays(d.trafficRetentionDays || 7); })
      .catch(() => {});
  }, []);

  async function save() {
    setMsg('');
    try {
      await fetch('/api/config', { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ trafficCollectEnabled: enabled, trafficRetentionDays: days }) });
      setMsg('Salvo.');
    } catch {
      setMsg('Falha ao salvar.');
    }
  }

  return (
    <main className="page-fortigate fau-page">
      <div className="fgt-head">
        <div className="page-title">
          <span className="fortigate-page-icon fau-icon" aria-hidden="true">CFG</span>
          <div><h2>Configurações</h2><span className="hint">Coleta e retenção do log de tráfego</span></div>
        </div>
      </div>
      <section className="fga-box">
        <label><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Ativar coleta de tráfego forward</label>
        <label>Manter últimos <input type="number" min="1" value={days} onChange={(e) => setDays(Number(e.target.value))} /> dias no banco</label>
        <button className="ghost" onClick={save}>Salvar</button>
        {msg && <span className="hint">{msg}</span>}
      </section>
    </main>
  );
}
