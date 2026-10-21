import { useEffect, useState } from 'react';
import { listFortigateBackupPolicies, createFortigateBackupPolicy, updateFortigateBackupPolicy, deleteFortigateBackupPolicy, runFortigateBackupPolicy, runFortigateBackupNow, listFortigateBackups, getFortigateBackupContent, deleteFortigateBackup } from '../fortigateBackupsApi';

const DAYS = ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'];

export default function FortigateBackupsScreen({ firewalls = [], onClose }) {
  const [tab, setTab] = useState('policies');
  const [policies, setPolicies] = useState([]);
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [view, setView] = useState(null);
  const [form, setForm] = useState({ name:'', enabled:true, hour:2, minute:0, runAllDays:true, daysOfWeek:[], retentionDays:7, targetFortigateIds:[] });

  async function loadPolicies(){ try { const r = await listFortigateBackupPolicies(); setPolicies(r.policies||[]); } catch(e){ setError(String(e.message||e)); } }
  async function loadBackups(){ try { const r = await listFortigateBackups(); setBackups(r.backups||[]); } catch(e){ setError(String(e.message||e)); } }

  useEffect(()=>{ loadPolicies(); loadBackups(); }, []);

  function openNew(){ setEditing(null); setForm({ name:'', enabled:true, hour:2, minute:0, runAllDays:true, daysOfWeek:[], retentionDays:7, targetFortigateIds:[] }); setShowForm(true); setError(''); setMsg(''); }
  function openEdit(p){ setEditing(p); setForm({ name:p.name, enabled:p.enabled, hour:p.hour, minute:p.minute, runAllDays:p.runAllDays, daysOfWeek:p.daysOfWeek||[], retentionDays:p.retentionDays, targetFortigateIds:(p.targets||[]).map(t=>t.id) }); setShowForm(true); setError(''); setMsg(''); }

  async function save(e){ e.preventDefault(); setLoading(true); setError(''); setMsg(''); try { if(editing) await updateFortigateBackupPolicy(editing.id, form); else await createFortigateBackupPolicy(form); setShowForm(false); await loadPolicies(); setMsg('Salvo'); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }

  async function togglePolicy(p){ setLoading(true); try { await updateFortigateBackupPolicy(p.id, { enabled: !p.enabled }); await loadPolicies(); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }
  async function removePolicy(p){ if(!confirm('Remover política?')) return; setLoading(true); try { await deleteFortigateBackupPolicy(p.id); await loadPolicies(); await loadBackups(); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }
  async function runPolicy(p){ setLoading(true); setMsg(''); try { const r = await runFortigateBackupPolicy(p.id); setMsg(`Backup iniciado em ${r.started} FortiGate(s)`); setTimeout(loadBackups, 2000); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }
  async function runNow(f){ if(!confirm('Executar backup manual agora?')) return; setLoading(true); try { await runFortigateBackupNow(f.id); setMsg('Backup iniciado'); setTimeout(loadBackups, 2000); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }
  async function viewBackup(b){ setLoading(true); setError(''); try { const r = await getFortigateBackupContent(b.id); setView({ ...r, id: b.id, fileName: r.fileName || b.fileName }); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }
  async function delBackup(b){ if(!confirm('Remover backup?')) return; setLoading(true); try { await deleteFortigateBackup(b.id); await loadBackups(); } catch(ex){ setError(String(ex.message||ex)); } finally { setLoading(false); } }

  function toggleDay(d){ setForm(f=>({ ...f, daysOfWeek: f.daysOfWeek.includes(d) ? f.daysOfWeek.filter(x=>x!==d) : [...f.daysOfWeek, d] })); }
  function toggleFg(id){ setForm(f=>({ ...f, targetFortigateIds: f.targetFortigateIds.includes(id) ? f.targetFortigateIds.filter(x=>x!==id) : [...f.targetFortigateIds, id] })); }

  return (
    <div style={{ padding: 16, width: '100%', boxSizing: 'border-box', minHeight: 'calc(100vh - 140px)' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:12 }}>
        <div>
          <h2 style={{ margin:0 }}>Backups FortiGate</h2>
          <span className="hint">Políticas · Histórico · Execução manual</span>
        </div>
        <div className="page-actions">
          <button className="ghost" onClick={()=>{ loadPolicies(); loadBackups(); }}>Atualizar</button>
        </div>
      </div>

      <div className="panel" style={{ padding: 16, width: '100%', minHeight: 400 }}>
        <div className="seg" style={{ marginBottom: 12 }}>
          <button className={tab==='policies'?'on':''} onClick={()=>setTab('policies')}>Políticas</button>
          <button className={tab==='backups'?'on':''} onClick={()=>{ setTab('backups'); loadBackups(); }}>Histórico</button>
          <button className={tab==='manual'?'on':''} onClick={()=>setTab('manual')}>Execução manual</button>
        </div>
        {error && <p className="error">{error}</p>}
        {msg && <p className="hint">{msg}</p>}

        {tab==='policies' && <>
          <div className="page-actions" style={{ marginBottom: 10 }}><button onClick={openNew}>Nova política</button></div>
            <div className="table-wrap" style={{overflowX:'auto'}}><table className="dashboard-data-table" style={{minWidth:980}}><thead><tr><th>Nome</th><th>Habilitada</th><th>Agendamento</th><th>Dias</th><th>Retenção</th><th>FortiGates</th><th style={{textAlign:'right'}}>Ações</th></tr></thead><tbody>
              {policies.map(p=>(
                <tr key={p.id}><td><b>{p.name}</b>{p.description && <div className="hint">{p.description}</div>}</td>
                <td><button className="ghost" onClick={()=>togglePolicy(p)}>{p.enabled?'Sim':'Não'}</button></td>
                <td>{String(p.hour).padStart(2,'0')}:{String(p.minute).padStart(2,'0')}</td>
                <td>{p.runAllDays?'Todos os dias':(p.daysOfWeek||[]).map(d=>DAYS[d]).join(', ')||'-'}</td>
                <td>{p.retentionDays} dias</td>
                <td>{(p.targets||[]).length}</td>
                <td style={{textAlign:'right'}}><div style={{display:'flex', gap:6, justifyContent:'flex-end', alignItems:'center', whiteSpace:'nowrap'}}><button className="ghost" onClick={()=>openEdit(p)}>Editar</button><button className="ghost" onClick={()=>runPolicy(p)}>Executar agora</button><button className="ghost" onClick={()=>removePolicy(p)}>Excluir</button></div></td></tr>
              ))}
              {!policies.length && <tr><td colSpan={7} className="empty">Nenhuma política</td></tr>}
            </tbody></table></div>
        </>}

        {tab==='backups' && <>
          <div className="page-actions" style={{ marginBottom: 10 }}><button className="ghost" onClick={()=>{loadBackups();}}>Atualizar</button></div>
            <div className="table-wrap" style={{overflowX:'auto'}}><table className="dashboard-data-table" style={{ tableLayout:'auto', minWidth:1020 }}><thead><tr><th>FortiGate</th><th>Política</th><th>Data/Hora</th><th>Status</th><th>Tamanho</th><th>Arquivo</th><th style={{textAlign:'right'}}>Ações</th></tr></thead><tbody>
              {backups.map(b=>(
                <tr key={b.id}><td>{b.fortigateName||'-'}</td><td>{b.policyName||'-'}</td><td>{b.createdAt?new Date(b.createdAt).toLocaleString():'-'}</td>
                <td>{b.status}</td><td>{b.sizeBytes?Math.round(b.sizeBytes/1024)+' KB':'-'}</td>                <td className="mono" style={{maxWidth:240,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{b.fileName||'-'}</td>
                <td style={{textAlign:'right'}}><div style={{display:'flex', gap:6, justifyContent:'flex-end', alignItems:'center', whiteSpace:'nowrap'}}>{b.status==='success' && <><button className="ghost" onClick={()=>viewBackup(b)}>Visualizar</button><button className="ghost" onClick={()=>{ window.location.href = `/api/fortigate-backups/${b.id}/download`; }}>Baixar</button></>}<button className="ghost" onClick={()=>delBackup(b)}>Excluir</button></div></td></tr>
              ))}
              {!backups.length && <tr><td colSpan={7} className="empty">Nenhum backup</td></tr>}
            </tbody></table></div>
        </>}

        {tab==='manual' && <>
          <p className="hint">Executa backup manual sem esperar o agendamento.</p>
            <div className="table-wrap" style={{overflowX:'auto'}}><table className="dashboard-data-table"><thead><tr><th>FortiGate</th><th>Host</th><th style={{textAlign:'right'}}>Ação</th></tr></thead><tbody>
              {firewalls.map(f=>(<tr key={f.id}><td>{f.name}</td><td className="mono">{f.host}</td><td style={{textAlign:'right',whiteSpace:'nowrap'}}><button onClick={()=>runNow(f)} disabled={loading}>Executar backup agora</button></td></tr>))}
              {!firewalls.length && <tr><td colSpan={3} className="empty">Nenhum FortiGate cadastrado</td></tr>}
            </tbody></table></div>
        </>}
      </div>

      {showForm && (
        <div className="modal-backdrop" onClick={()=>setShowForm(false)}>
          <div className="modal" onClick={(e)=>e.stopPropagation()}>
            <div className="modal-head"><div><h2>{editing?'Editar política':'Nova política'}</h2></div><button className="ghost" onClick={()=>setShowForm(false)}>✕</button></div>
            <div className="modal-body">
              <form onSubmit={save} style={{display:'flex',flexDirection:'column',gap:12}}>
                <label className="field"><span>Nome</span><input value={form.name} onChange={(e)=>setForm(f=>({...f,name:e.target.value}))} required style={{width:'100%'}}/></label>
                <label className="chk"><input type="checkbox" checked={form.enabled} onChange={(e)=>setForm(f=>({...f,enabled:e.target.checked}))}/> Habilitada</label>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                  <label className="field"><span>Hora</span><input type="number" min="0" max="23" value={form.hour} onChange={(e)=>setForm(f=>({...f,hour:Number(e.target.value)}))} style={{width:'100%'}}/></label>
                  <label className="field"><span>Minuto</span><input type="number" min="0" max="59" value={form.minute} onChange={(e)=>setForm(f=>({...f,minute:Number(e.target.value)}))} style={{width:'100%'}}/></label>
                </div>
                <label className="chk"><input type="checkbox" checked={form.runAllDays} onChange={(e)=>setForm(f=>({...f,runAllDays:e.target.checked}))}/> Todos os dias</label>
                {!form.runAllDays && <div style={{display:'flex',flexWrap:'wrap',gap:10}}>{DAYS.map((d,i)=><label className="chk" key={i}><input type="checkbox" checked={form.daysOfWeek.includes(i)} onChange={()=>toggleDay(i)}/> {d}</label>)}</div>}
                <label className="field"><span>Retenção (dias)</span><input type="number" min="1" value={form.retentionDays} onChange={(e)=>setForm(f=>({...f,retentionDays:Number(e.target.value)}))} style={{width:'100%'}}/></label>
                <div><span className="hint">FortiGates</span><div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8,marginTop:6}}>{firewalls.map(f=><label className="chk" key={f.id}><input type="checkbox" checked={form.targetFortigateIds.includes(f.id)} onChange={()=>toggleFg(f.id)}/> {f.name}</label>)}</div></div>
                <div className="page-actions" style={{justifyContent:'flex-end'}}><button type="button" className="ghost" onClick={()=>setShowForm(false)}>Cancelar</button><button type="submit" disabled={loading}>Salvar</button></div>
              </form>
            </div>
          </div>
        </div>
      )}

      {view && (
        <div className="modal-backdrop" onClick={()=>setView(null)}>
          <div className="modal modal-wide" style={{maxWidth:1100}} onClick={(e)=>e.stopPropagation()}>
            <div className="modal-head"><div><h2>Visualizar backup</h2><span className="hint">{view.fileName||''}</span></div><div className="page-actions"><button className="ghost" onClick={()=>{ window.location.href = `/api/fortigate-backups/${view.id}/download`; }}>Baixar</button><button className="ghost" onClick={()=>setView(null)}>Fechar</button></div></div>
            <div className="modal-body"><pre style={{maxHeight:'65vh',overflow:'auto',background:'#0f1115',color:'#d7e2ea',padding:12,borderRadius:8,fontSize:11}}>{view.content||''}</pre></div>
          </div>
        </div>
      )}
    </div>
  );
}