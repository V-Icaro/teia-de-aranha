import { createContext, useContext, useEffect, useState } from 'react';

const API = '/api';
const AuthContext = createContext(null);

async function api(path, opts = {}) {
  const res = await fetch(API + path, { credentials: 'include', headers: { 'Content-Type': 'application/json' }, ...opts });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (!res.ok) throw Object.assign(new Error(data?.error || `HTTP ${res.status}`), { status: res.status, data });
  return data;
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { refresh(); }, []);

  async function refresh() {
    try {
      const r = await api('/auth/me');
      setUser(r.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  async function login(username, password) {
    const r = await api('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    setUser(r.user);
    return r.user;
  }

  async function logout() {
    try { await api('/auth/logout', { method: 'POST' }); } catch {}
    setUser(null);
  }

  async function changePassword(currentPassword, newPassword) {
    const r = await api('/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) });
    await refresh();
    return r;
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, changePassword, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

function LoginScreen() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try { await login(username, password); }
    catch (err) { setError(err.message || 'Falha no login'); }
    finally { setBusy(false); }
  }

  return (
    <div className="auth-shell">
      <form className="auth-card" onSubmit={submit}>
        <h1>Teia de Aranha</h1>
        <p className="hint">Acesse com seu usuário e senha.</p>
        <label>Usuário<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" /></label>
        <label>Senha<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? 'Entrando…' : 'Entrar'}</button>
      </form>
    </div>
  );
}

function ChangePasswordScreen() {
  const { user, changePassword, logout } = useAuth();
  const [current, setCurrent] = useState(user?.mustChangePassword ? 'admin' : '');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    if (next !== confirm) { setError('A confirmação não confere.'); return; }
    setBusy(true);
    try { await changePassword(current, next); }
    catch (err) { setError(err.message || 'Falha ao trocar a senha'); }
    finally { setBusy(false); }
  }

  return (
    <div className="auth-shell">
      <form className="auth-card" onSubmit={submit}>
        <h1>Trocar senha</h1>
        <p className="hint">{user?.mustChangePassword ? 'No primeiro acesso é obrigatório definir uma senha nova.' : 'Defina uma nova senha.'}</p>
        <label>Senha atual<input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" /></label>
        <label>Nova senha (mín. 8 caracteres)<input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" /></label>
        <label>Confirmar nova senha<input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" /></label>
        {error && <p className="error">{error}</p>}
        <div className="auth-actions">
          <button type="submit" disabled={busy}>{busy ? 'Salvando…' : 'Salvar'}</button>
          <button type="button" className="ghost" onClick={logout}>Sair</button>
        </div>
      </form>
    </div>
  );
}

export function AuthGate({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="auth-shell"><p>Carregando…</p></div>;
  if (!user) return <LoginScreen />;
  if (user.mustChangePassword) return <ChangePasswordScreen />;
  return children;
}

export default AuthGate;
