import { useMemo } from 'react';

// Layout físico por modelo. Coordenadas em pixels dentro do painel.
const LAYOUTS = {
  'Fortigate-70G': {
    width: 760,
    ports: [
      { name: 'wan1', x: 90, y: 36, label: 'top' },
      { name: 'wan2', x: 90, y: 86, label: 'bottom' },
      { name: 'port1', x: 220, y: 48 },
      { name: 'port2', x: 275, y: 48 },
      { name: 'port3', x: 330, y: 48 },
      { name: 'port4', x: 385, y: 48 },
      { name: 'port5', x: 440, y: 48 },
      { name: 'port6', x: 495, y: 48 },
      { name: 'a', x: 560, y: 48 },
      { name: 'b', x: 615, y: 48 },
      { name: 'modem', x: 670, y: 48 }
    ]
  }
};

function normalize(name) {
  return String(name || '').trim().toLowerCase();
}

export default function FortigatePortMap({ model, interfaces = [], onPortClick }) {
  const physical = useMemo(() => (interfaces || []).filter((i) => i.type === 'physical'), [interfaces]);
  const layout = LAYOUTS[model] || null;

  const positions = useMemo(() => {
    if (layout) {
      return layout.ports.map((p) => {
        const iface = physical.find((i) => normalize(i.name) === normalize(p.name));
        return { ...p, iface };
      });
    }
    return physical.map((iface, idx) => ({ name: iface.name, x: 40 + (idx % 8) * 55, y: 48 + Math.floor(idx / 8) * 50, iface }));
  }, [layout, physical]);

  const width = layout?.width || Math.max(240, 40 + Math.min(8, positions.length) * 55);
  const extra = physical.filter((i) => !positions.some((p) => normalize(p.name) === normalize(i.name)));

  return (
    <div className="fgt-portmap-panel">
      <div className="fgt-portmap-title">
        <span className="fgt-portmap-brand">Fortinet</span>
        <b>{model || 'FortiGate'}</b>
      </div>
      <div className="fgt-portmap-canvas" style={{ width: `${width}px` }}>
        {positions.map((p) => {
          const iface = p.iface;
          const up = iface?.status === 'up';
          const title = iface
            ? `${iface.name}\n${iface.alias || iface.description || ''}\nIP: ${iface.ip || '—'}\nAdmin: ${iface.status || '—'}\nLink: ${up ? 'up' : 'down'}\nVelocidade: ${iface.stats?.speed || '—'}`
            : `${p.name} (não encontrada)`;
          return (
            <button
              key={p.name}
              type="button"
              className={`fgt-rj45 ${up ? 'up' : 'down'} ${iface ? '' : 'missing'}`}
              style={{ left: `${p.x}px`, top: `${p.y}px` }}
              title={title}
              onClick={() => iface && onPortClick?.(iface)}
            >
              <svg viewBox="0 0 28 18" width="28" height="18" aria-hidden="true">
                <rect x="1" y="1" width="26" height="16" rx="2" />
                <rect x="4" y="4" width="20" height="8" rx="1" className="fgt-rj45-inner" />
                <line x1="7" y1="6" x2="7" y2="10" />
                <line x1="11" y1="6" x2="11" y2="10" />
                <line x1="15" y1="6" x2="15" y2="10" />
                <line x1="19" y1="6" x2="19" y2="10" />
                <line x1="23" y1="6" x2="23" y2="10" />
              </svg>
              <span className="fgt-rj45-label">{(iface?.name || p.name).toUpperCase()}</span>
            </button>
          );
        })}
      </div>

    </div>
  );
}
