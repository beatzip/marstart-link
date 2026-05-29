import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { invoke } from '@tauri-apps/api/core';

type TunnelStatus = {
  is_active: boolean;
  adapter_name: string | null;
  interface_index: number | null;
  mtu: number | null;
  phase?: string;
  session_id?: number;
  health?: {
    adapter_ok?: boolean;
    interface_ok?: boolean;
    routes_ok?: boolean;
    dns_ok?: boolean;
    handshake_ok?: boolean;
    game_path_verified?: boolean;
    leak_detected?: boolean;
    packet_loss_percent?: number;
    avg_rtt_ms?: number;
    jitter_ms?: number;
  };
};

type TunnelStats = {
  is_active: boolean;
  total_tx: number;
  total_rx: number;
  last_handshake_unix?: number;
};

type TunnelDiagnostics = {
  session_id: number;
  phase: string;
  is_active: boolean;
  handshake_ok: boolean;
  handshake_age_secs: number | null;
  route_health_ok: boolean;
  dns_health_ok: boolean;
  game_path_verified: boolean;
  leak_detected: boolean;
  best_route_interface_index: number | null;
  expected_interface_index: number | null;
  packet_loss_percent: number;
  avg_rtt_ms: number;
  jitter_ms: number;
};

type SavedProfile = {
  id: string;
  name: string;
  privateKey: string;
  publicKey: string;
  endpoint: string;
  address: string;
  allowedIps: string;
  dnsServers: string;
};

type Phase = 'idle' | 'connecting' | 'connected' | 'disconnecting';

const PROFILE_KEY = 'ga_vps_profiles_v1';
const ACTIVE_PROFILE_KEY = 'ga_active_profile_v1';
const POLL_MS = 2500;
const MAX_ROUTES = 50;

const emptyProfile = (): SavedProfile => ({
  id: crypto.randomUUID?.() ?? `profile_${Date.now()}`,
  name: 'Новый VPS',
  privateKey: '',
  publicKey: '',
  endpoint: '',
  address: '10.0.0.2/32',
  allowedIps: '0.0.0.0/0',
  dnsServers: '1.1.1.1, 8.8.8.8',
});

function validateBase64Key(value: string, label: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return `${label}: пустое значение`;
  try {
    const decoded = atob(trimmed);
    return decoded.length === 32 ? null : `${label}: ожидается 32 байта`;
  } catch {
    return `${label}: неверный Base64`;
  }
}

function validateEndpoint(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return 'Endpoint пустой';

  if (trimmed.startsWith('[')) {
    const match = trimmed.match(/^\[(.+)\]:(\d+)$/);
    if (!match) return 'Endpoint: формат [IPv6]:port';
    const port = Number(match[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Endpoint: неверный порт';
    return null;
  }

  const idx = trimmed.lastIndexOf(':');
  if (idx <= 0) return 'Endpoint: формат host:port';
  const port = Number(trimmed.slice(idx + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Endpoint: неверный порт';
  return null;
}

function validateCidrList(value: string, label: string): string | null {
  const parts = value.split(',').map(s => s.trim()).filter(Boolean);
  if (parts.length === 0) return `${label}: пусто`;
  if (parts.length > MAX_ROUTES) return `${label}: максимум ${MAX_ROUTES}`;

  for (const part of parts) {
    const [ip, prefix] = part.split('/');
    if (!ip || prefix === undefined) return `${label}: ожидается IP/маска`;

    const prefixNum = Number(prefix);
    const isV6 = ip.includes(':');
    const maxPrefix = isV6 ? 128 : 32;
    if (!Number.isInteger(prefixNum) || prefixNum < 0 || prefixNum > maxPrefix) {
      return `${label}: маска должна быть 0–${maxPrefix}`;
    }

    if (!isV6) {
      const octets = ip.split('.');
      if (octets.length !== 4 || octets.some(v => Number.isNaN(Number(v)) || Number(v) < 0 || Number(v) > 255)) {
        return `${label}: неверный IPv4 ${ip}`;
      }
    } else if (!ip.includes(':')) {
      return `${label}: неверный IPv6 ${ip}`;
    }
  }
  return null;
}

function buildConfig(profile: SavedProfile): string {
  const lines = [
    '[Interface]',
    `PrivateKey = ${profile.privateKey.trim()}`,
    `Address = ${profile.address.trim()}`,
  ];

  if (profile.dnsServers.trim()) {
    lines.push(`DNS = ${profile.dnsServers.trim()}`);
  }

  lines.push(
    '',
    '[Peer]',
    `PublicKey = ${profile.publicKey.trim()}`,
    `Endpoint = ${profile.endpoint.trim()}`,
    `AllowedIPs = ${profile.allowedIps.trim()}`,
    'PersistentKeepalive = 25',
    '',
  );

  return lines.join('\n');
}

const styles: Record<string, CSSProperties> = {
  page: {
    minHeight: '100vh',
    background: 'linear-gradient(180deg, #06080f 0%, #0b1020 100%)',
    color: '#e5eefb',
    fontFamily: '"Segoe UI", system-ui, -apple-system, sans-serif',
    padding: '24px',
  },
  shell: {
    maxWidth: 1180,
    margin: '0 auto',
  },
  topbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: 16,
    marginBottom: 20,
  },
  title: {
    fontSize: 26,
    fontWeight: 700,
    margin: 0,
    letterSpacing: '-0.03em',
  },
  subtitle: {
    margin: '6px 0 0',
    color: '#86a2c6',
    fontSize: 13,
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: '360px 1fr',
    gap: 18,
  },
  card: {
    background: 'rgba(12, 18, 31, 0.94)',
    border: '1px solid #183052',
    borderRadius: 16,
    boxShadow: '0 18px 50px rgba(0,0,0,0.28)',
    padding: 18,
  },
  cardTitle: {
    margin: '0 0 14px',
    fontSize: 13,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: '#7fa3d6',
    fontWeight: 700,
  },
  label: {
    display: 'block',
    marginBottom: 6,
    fontSize: 13,
    color: '#bfd2ef',
  },
  input: {
    width: '100%',
    boxSizing: 'border-box',
    background: '#08111f',
    color: '#edf5ff',
    border: '1px solid #22436e',
    borderRadius: 10,
    padding: '11px 12px',
    fontSize: 14,
    outline: 'none',
  },
  textarea: {
    width: '100%',
    boxSizing: 'border-box',
    background: '#08111f',
    color: '#edf5ff',
    border: '1px solid #22436e',
    borderRadius: 10,
    padding: '11px 12px',
    fontSize: 14,
    outline: 'none',
    minHeight: 88,
    resize: 'vertical',
    fontFamily: '"Cascadia Code", "Consolas", monospace',
  },
  row: {
    marginBottom: 12,
  },
  small: {
    color: '#7b95b9',
    fontSize: 12,
    marginTop: 5,
  },
  buttonRow: {
    display: 'flex',
    gap: 10,
    flexWrap: 'wrap',
  },
  primary: {
    background: 'linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%)',
    color: '#fff',
    border: 'none',
    borderRadius: 10,
    padding: '11px 14px',
    fontWeight: 700,
    cursor: 'pointer',
  },
  ghost: {
    background: '#0d1728',
    color: '#bfd2ef',
    border: '1px solid #2a4976',
    borderRadius: 10,
    padding: '11px 14px',
    fontWeight: 700,
    cursor: 'pointer',
  },
  danger: {
    background: '#2a1012',
    color: '#ffbec6',
    border: '1px solid #61202b',
    borderRadius: 10,
    padding: '11px 14px',
    fontWeight: 700,
    cursor: 'pointer',
  },
  status: {
    borderRadius: 14,
    border: '1px solid #22436e',
    background: '#08111f',
    padding: 16,
    marginBottom: 18,
  },
  statusTitle: {
    margin: 0,
    color: '#7fa3d6',
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    fontWeight: 700,
  },
  statusBody: {
    margin: '10px 0 0',
    whiteSpace: 'pre-wrap',
    lineHeight: 1.55,
    fontFamily: '"Cascadia Code", "Consolas", monospace',
    color: '#dbeafe',
  },
  statGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: 12,
  },
  statBox: {
    border: '1px solid #22436e',
    borderRadius: 14,
    padding: 14,
    background: '#09111d',
  },
  statLabel: {
    margin: 0,
    color: '#7b95b9',
    fontSize: 12,
  },
  statValue: {
    margin: '8px 0 0',
    fontSize: 22,
    fontWeight: 700,
    color: '#f3f8ff',
    fontFamily: '"Cascadia Code", "Consolas", monospace',
  },
  profileList: {
    display: 'grid',
    gap: 10,
    marginTop: 12,
  },
  profileItem: {
    border: '1px solid #22436e',
    background: '#08111f',
    borderRadius: 12,
    padding: 12,
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
  },
  profileName: {
    margin: 0,
    fontWeight: 700,
  },
  profileMeta: {
    margin: '4px 0 0',
    color: '#7b95b9',
    fontSize: 12,
  },
};

export default function App() {
  const [phase, setPhase] = useState<Phase>('idle');
  const [status, setStatus] = useState<string>('Соединение не активно');
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<TunnelStats>({ is_active: false, total_tx: 0, total_rx: 0 });
  const [diag, setDiag] = useState<TunnelDiagnostics | null>(null);

  const [profiles, setProfiles] = useState<SavedProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string>('');
  const [form, setForm] = useState<SavedProfile>(emptyProfile());

  const phaseRef = useRef(phase);
  useEffect(() => { phaseRef.current = phase; }, [phase]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(PROFILE_KEY);
      if (raw) setProfiles(JSON.parse(raw));
      const active = localStorage.getItem(ACTIVE_PROFILE_KEY);
      if (active) setActiveProfileId(active);
    } catch {
      localStorage.removeItem(PROFILE_KEY);
      localStorage.removeItem(ACTIVE_PROFILE_KEY);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profiles));
  }, [profiles]);

  useEffect(() => {
    if (activeProfileId) {
      localStorage.setItem(ACTIVE_PROFILE_KEY, activeProfileId);
    }
  }, [activeProfileId]);

  const activeProfile = useMemo(
    () => profiles.find(p => p.id === activeProfileId) ?? null,
    [profiles, activeProfileId],
  );

  useEffect(() => {
    let mounted = true;

    const poll = async () => {
      try {
        const [statusRes, statsRes, diagRes] = await Promise.all([
          invoke<TunnelStatus>('tunnel_get_status'),
          invoke<TunnelStats>('tunnel_get_stats'),
          invoke<TunnelDiagnostics>('tunnel_get_diagnostics'),
        ]);

        if (!mounted) return;

        setStats(statsRes);
        setDiag(diagRes);
        if (statusRes.is_active) {
          setPhase(prev => (prev === 'disconnecting' ? prev : 'connected'));
          const phaseLabel = statusRes.phase ? String(statusRes.phase) : 'connected';
          setStatus(
            `Активно (${phaseLabel})
` +
            `Адаптер: ${statusRes.adapter_name ?? '—'}
` +
            `Индекс интерфейса: ${statusRes.interface_index ?? '—'}
` +
            `MTU: ${statusRes.mtu ?? '—'}
` +
            `Handshake: ${statusRes.health?.handshake_ok ? 'OK' : 'ожидание'}
` +
            `Маршрут игры: ${statusRes.health?.game_path_verified ? 'верифицирован' : 'не подтверждён'}
` +
            `DNS: ${statusRes.health?.dns_ok ? 'OK' : 'проверить'}`
          );
        } else if (phaseRef.current !== 'disconnecting') {
          setPhase('idle');
          setStatus('Соединение не активно');
        }
      } catch {
        // backend может еще подниматься
      }
    };

    poll();
    const timer = window.setInterval(poll, POLL_MS);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  const currentProfileForValidation = () => {
    return {
      privateKey: form.privateKey.trim(),
      publicKey: form.publicKey.trim(),
      endpoint: form.endpoint.trim(),
      address: form.address.trim(),
      allowedIps: form.allowedIps.trim(),
    };
  };

  const validationError = () => {
    const v = currentProfileForValidation();
    return (
      validateBase64Key(v.privateKey, 'PrivateKey') ??
      validateBase64Key(v.publicKey, 'PublicKey') ??
      validateEndpoint(v.endpoint) ??
      validateCidrList(v.address, 'Address') ??
      validateCidrList(v.allowedIps, 'AllowedIPs')
    );
  };

  const saveProfile = () => {
    const err = validationError();
    if (err) {
      setError(err);
      return;
    }

    const next: SavedProfile = {
      ...form,
      privateKey: form.privateKey.trim(),
      publicKey: form.publicKey.trim(),
      endpoint: form.endpoint.trim(),
      address: form.address.trim(),
      allowedIps: form.allowedIps.trim(),
      dnsServers: form.dnsServers.trim(),
    };

    setProfiles(prev => {
      const existing = prev.findIndex(p => p.id === next.id);
      if (existing >= 0) {
        const copy = [...prev];
        copy[existing] = next;
        return copy;
      }
      return [next, ...prev];
    });

    setActiveProfileId(next.id);
    setError(null);
  };

  const createNewProfile = () => {
    const profile = emptyProfile();
    setForm(profile);
    setActiveProfileId(profile.id);
    setError(null);
  };

  const loadProfile = (profile: SavedProfile) => {
    setForm(profile);
    setActiveProfileId(profile.id);
    setError(null);
  };

  const deleteProfile = (id: string) => {
    setProfiles(prev => prev.filter(p => p.id !== id));
    if (activeProfileId === id) {
      setActiveProfileId('');
      setForm(emptyProfile());
    }
  };

  const connect = async () => {
    if (phase === 'connecting' || phase === 'disconnecting') return;
    const err = validationError();
    if (err) {
      setError(err);
      return;
    }

    setPhase('connecting');
    setStatus('Инициализация адаптера...');
    setError(null);

    const payload = buildConfig(form);
    const routes = form.allowedIps.split(',').map(s => s.trim()).filter(Boolean);

    try {
      const result = await invoke<TunnelStatus>('tunnel_apply_config', {
        configContent: payload,
        adapterName: form.name || 'GameAccelerator',
        expectedRoutes: routes,
      });

      setPhase('connected');
      const phaseLabel = result.phase ? String(result.phase) : 'connected';
      setStatus(
        `Активно (${phaseLabel})
` +
        `Адаптер: ${result.adapter_name ?? form.name ?? 'GameAccelerator'}
` +
        `Индекс интерфейса: ${result.interface_index ?? '—'}
` +
        `MTU: ${result.mtu ?? '—'}
` +
        `Handshake: ${result.health?.handshake_ok ? 'OK' : 'ожидание'}
` +
        `Маршрут игры: ${result.health?.game_path_verified ? 'верифицирован' : 'не подтверждён'}
` +
        `DNS: ${result.health?.dns_ok ? 'OK' : 'проверить'}`
      );
    } catch (e) {
      setPhase('idle');
      setStatus('Соединение не активно');
      setError(`Ошибка подключения: ${String(e)}`);
    }
  };

  const disconnect = async () => {
    if (phase !== 'connected') return;
    setPhase('disconnecting');
    setStatus('Отключение...');
    try {
      await invoke('tunnel_disconnect');
      setPhase('idle');
      setStatus('Соединение не активно');
    } catch (e) {
      setPhase('idle');
      setError(`Ошибка отключения: ${String(e)}`);
    }
  };

  const bytesToMiB = (value: number) => (value / 1024 / 1024).toFixed(2);

  return (
    <div style={styles.page}>
      <div style={styles.shell}>
        <div style={styles.topbar}>
          <div>
            <h1 style={styles.title}>Game Accelerator</h1>
            <p style={styles.subtitle}>Черно-синий профильный клиент для WireGuard-NT</p>
          </div>
          <div style={styles.buttonRow}>
            <button style={styles.ghost} onClick={createNewProfile}>Новый VPS</button>
            <button style={styles.primary} onClick={saveProfile}>Сохранить профиль</button>
            <button style={styles.primary} onClick={connect} disabled={phase !== 'idle'}>Подключить</button>
            <button style={styles.ghost} onClick={disconnect} disabled={phase !== 'connected'}>Отключить</button>
          </div>
        </div>

        <div style={styles.status}>
          <p style={styles.statusTitle}>Статус</p>
          <p style={styles.statusBody}>{status}</p>
        </div>

        {error && (
          <div style={{ ...styles.status, borderColor: '#5a2230', background: '#190b12' }}>
            <p style={{ ...styles.statusTitle, color: '#ff8ea0' }}>Ошибка</p>
            <p style={{ ...styles.statusBody, color: '#ffd2da' }}>{error}</p>
          </div>
        )}

        <div style={styles.grid}>
          <div style={styles.card}>
            <p style={styles.cardTitle}>Профиль VPS</p>

            <div style={styles.row}>
              <label style={styles.label}>Название профиля</label>
              <input
                style={styles.input}
                value={form.name}
                onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Warsaw-01"
              />
            </div>

            <div style={styles.row}>
              <label style={styles.label}>Приватный ключ</label>
              <input
                style={styles.input}
                type="password"
                value={form.privateKey}
                onChange={e => setForm(prev => ({ ...prev, privateKey: e.target.value }))}
                placeholder="44 символа Base64"
              />
            </div>

            <div style={styles.row}>
              <label style={styles.label}>Публичный ключ сервера</label>
              <input
                style={styles.input}
                value={form.publicKey}
                onChange={e => setForm(prev => ({ ...prev, publicKey: e.target.value }))}
                placeholder="44 символа Base64"
              />
            </div>

            <div style={styles.row}>
              <label style={styles.label}>Endpoint</label>
              <input
                style={styles.input}
                value={form.endpoint}
                onChange={e => setForm(prev => ({ ...prev, endpoint: e.target.value }))}
                placeholder="1.2.3.4:51820"
              />
            </div>

            <div style={styles.row}>
              <label style={styles.label}>Адрес интерфейса</label>
              <input
                style={styles.input}
                value={form.address}
                onChange={e => setForm(prev => ({ ...prev, address: e.target.value }))}
                placeholder="10.0.0.2/32"
              />
            </div>

            <div style={styles.row}>
              <label style={styles.label}>AllowedIPs</label>
              <textarea
                style={styles.textarea}
                value={form.allowedIps}
                onChange={e => setForm(prev => ({ ...prev, allowedIps: e.target.value }))}
                placeholder="0.0.0.0/0, ::/0"
              />
              <div style={styles.small}>Через запятую. Максимум {MAX_ROUTES} маршрутов.</div>
            </div>

            <div style={styles.row}>
              <label style={styles.label}>DNS</label>
              <input
                style={styles.input}
                value={form.dnsServers}
                onChange={e => setForm(prev => ({ ...prev, dnsServers: e.target.value }))}
                placeholder="1.1.1.1, 8.8.8.8"
              />
            </div>
          </div>

          <div style={{ display: 'grid', gap: 18 }}>
            <div style={styles.card}>
              <p style={styles.cardTitle}>Трафик</p>
              <div style={styles.statGrid}>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>TX</p>
                  <p style={styles.statValue}>{bytesToMiB(stats.total_tx)} MB</p>
                </div>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>RX</p>
                  <p style={styles.statValue}>{bytesToMiB(stats.total_rx)} MB</p>
                </div>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>Состояние</p>
                  <p style={styles.statValue}>{stats.is_active ? 'UP' : 'DOWN'}</p>
                </div>
              </div>
            </div>

            <div style={styles.card}>
              <p style={styles.cardTitle}>Диагностика пути</p>
              <div style={styles.statGrid}>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>Handshake</p>
                  <p style={styles.statValue}>{diag?.handshake_ok ? 'OK' : 'WAIT'}</p>
                </div>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>Route</p>
                  <p style={styles.statValue}>{diag?.route_health_ok ? 'OK' : 'BAD'}</p>
                </div>
                <div style={styles.statBox}>
                  <p style={styles.statLabel}>Game Path</p>
                  <p style={styles.statValue}>{diag?.game_path_verified ? 'VERIFIED' : '—'}</p>
                </div>
              </div>
              <div style={{ ...styles.small, marginTop: 12 }}>
                RTT: {diag?.avg_rtt_ms ?? 0} ms · Jitter: {diag?.jitter_ms ?? 0} ms · Loss: {(diag?.packet_loss_percent ?? 0).toFixed(2)}%
              </div>
            </div>

            <div style={styles.card}>
              <p style={styles.cardTitle}>Сохранённые VPS</p>

              {profiles.length === 0 ? (
                <div style={styles.small}>Профилей пока нет. Создайте новый VPS и сохраните его.</div>
              ) : (
                <div style={styles.profileList}>
                  {profiles.map(profile => (
                    <div key={profile.id} style={styles.profileItem}>
                      <div>
                        <p style={styles.profileName}>{profile.name}</p>
                        <p style={styles.profileMeta}>{profile.endpoint} · {profile.address}</p>
                      </div>
                      <div style={styles.buttonRow}>
                        <button style={styles.ghost} onClick={() => loadProfile(profile)}>Открыть</button>
                        <button style={styles.danger} onClick={() => deleteProfile(profile.id)}>Удалить</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeProfile && (
                <div style={{ ...styles.small, marginTop: 12 }}>
                  Активный профиль: <strong>{activeProfile.name}</strong>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
