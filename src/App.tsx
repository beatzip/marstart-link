import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { invoke } from '@tauri-apps/api/core';

// ─── Types ────────────────────────────────────────────────────────────────────

type StartupDiagnostic = {
  wireguard_dll_found: boolean;
  wireguard_dll_path: string | null;
  wintun_dll_found: boolean;
  wintun_dll_path: string | null;
  wireguard_dll_loaded: boolean;
  load_error: string | null;
  log_dir: string;
  os_info: string;
};

type TunnelHealth = {
  adapter_ok: boolean;
  interface_ok: boolean;
  routes_ok: boolean;
  dns_ok: boolean;
  handshake_ok: boolean;
  game_path_verified: boolean;
  leak_detected: boolean;
  packet_loss_percent: number;
  avg_rtt_ms: number;
  jitter_ms: number;
};

type TunnelStatus = {
  is_active: boolean;
  adapter_name: string | null;
  interface_index: number | null;
  mtu: number | null;
  assigned_address: string | null;
  dns_servers: string[];
  phase: string;
  session_id: number;
  health: TunnelHealth;
  needs_reconnect: boolean;
};

type TunnelStats = {
  is_active: boolean;
  total_tx: number;
  total_rx: number;
  last_handshake_unix: number;
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

// ─── Constants ────────────────────────────────────────────────────────────────

const PROFILE_KEY        = 'ga_vps_profiles_v1';
const ACTIVE_PROFILE_KEY = 'ga_active_profile_v1';
const POLL_MS            = 2500;
const MAX_ROUTES         = 50;

const PHASE_COLOR: Record<Phase, string> = {
  idle:          '#7b95b9',
  connecting:    '#f59e0b',
  connected:     '#22c55e',
  disconnecting: '#f97316',
};

const PHASE_LABEL: Record<Phase, string> = {
  idle:          'Не подключено',
  connecting:    'Подключение…',
  connected:     'Подключено',
  disconnecting: 'Отключение…',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
  const t = value.trim();
  if (!t) return `${label}: пустое значение`;
  try {
    const d = atob(t);
    return d.length === 32 ? null : `${label}: ожидается 32 байта`;
  } catch {
    return `${label}: неверный Base64`;
  }
}

function validateEndpoint(value: string): string | null {
  const t = value.trim();
  if (!t) return 'Endpoint пустой';
  if (t.startsWith('[')) {
    const m = t.match(/^\[(.+)\]:(\d+)$/);
    if (!m) return 'Endpoint: формат [IPv6]:port';
    const p = Number(m[2]);
    return Number.isInteger(p) && p >= 1 && p <= 65535 ? null : 'Endpoint: неверный порт';
  }
  const idx = t.lastIndexOf(':');
  if (idx <= 0) return 'Endpoint: формат host:port';
  const p = Number(t.slice(idx + 1));
  return Number.isInteger(p) && p >= 1 && p <= 65535 ? null : 'Endpoint: неверный порт';
}

function validateCidrList(value: string, label: string): string | null {
  const parts = value.split(',').map(s => s.trim()).filter(Boolean);
  if (!parts.length) return `${label}: пусто`;
  if (parts.length > MAX_ROUTES) return `${label}: максимум ${MAX_ROUTES}`;
  for (const part of parts) {
    const [ip, prefix] = part.split('/');
    if (!ip || prefix === undefined) return `${label}: ожидается IP/маска`;
    const pn = Number(prefix);
    const v6 = ip.includes(':');
    const max = v6 ? 128 : 32;
    if (!Number.isInteger(pn) || pn < 0 || pn > max) return `${label}: маска 0–${max}`;
    if (!v6) {
      const o = ip.split('.');
      if (o.length !== 4 || o.some(v => Number.isNaN(Number(v)) || Number(v) < 0 || Number(v) > 255))
        return `${label}: неверный IPv4 ${ip}`;
    }
  }
  return null;
}

function buildConfig(p: SavedProfile): string {
  const lines = [
    '[Interface]',
    `PrivateKey = ${p.privateKey.trim()}`,
    `Address = ${p.address.trim()}`,
  ];
  if (p.dnsServers.trim()) lines.push(`DNS = ${p.dnsServers.trim()}`);
  lines.push('', '[Peer]',
    `PublicKey = ${p.publicKey.trim()}`,
    `Endpoint = ${p.endpoint.trim()}`,
    `AllowedIPs = ${p.allowedIps.trim()}`,
    'PersistentKeepalive = 25', '');
  return lines.join('\n');
}

function buildStatusText(r: TunnelStatus): string {
  return [
    `Адаптер: ${r.adapter_name ?? '—'}`,
    r.assigned_address ? `Адрес: ${r.assigned_address}` : null,
    `MTU: ${r.mtu ?? '—'} · Индекс: ${r.interface_index ?? '—'}`,
    `Handshake: ${r.health.handshake_ok ? 'OK' : 'ожидание'}`,
    `Маршрут игры: ${r.health.game_path_verified ? 'верифицирован ✓' : 'не подтверждён'}`,
    `DNS: ${r.health.dns_ok ? 'OK' : 'проверить'}`,
    r.health.leak_detected ? '⚠ Обнаружена утечка трафика!' : null,
    r.health.packet_loss_percent > 0
      ? `Потери: ${r.health.packet_loss_percent.toFixed(1)}%`
      : null,
  ].filter(Boolean).join('\n');
}

function toMiB(n: number): string { return (n / 1024 / 1024).toFixed(2); }

// ─── Styles ───────────────────────────────────────────────────────────────────

const S: Record<string, CSSProperties> = {
  page: {
    minHeight: '100vh',
    background: 'linear-gradient(180deg, #06080f 0%, #0b1020 100%)',
    color: '#e5eefb',
    fontFamily: '"Segoe UI", system-ui, -apple-system, sans-serif',
    padding: '24px',
  },
  shell: { maxWidth: 1180, margin: '0 auto' },
  topbar: {
    display: 'flex', justifyContent: 'space-between',
    alignItems: 'flex-start', gap: 16, marginBottom: 20,
  },
  title: { fontSize: 26, fontWeight: 700, margin: 0, letterSpacing: '-0.03em' },
  subtitle: { margin: '6px 0 0', color: '#86a2c6', fontSize: 13 },
  grid: { display: 'grid', gridTemplateColumns: '360px 1fr', gap: 18 },
  card: {
    background: 'rgba(12,18,31,0.94)', border: '1px solid #183052',
    borderRadius: 16, boxShadow: '0 18px 50px rgba(0,0,0,0.28)', padding: 18,
  },
  cardTitle: {
    margin: '0 0 14px', fontSize: 13, textTransform: 'uppercase',
    letterSpacing: '0.08em', color: '#7fa3d6', fontWeight: 700,
  },
  label:    { display: 'block', marginBottom: 6, fontSize: 13, color: '#bfd2ef' },
  input: {
    width: '100%', boxSizing: 'border-box', background: '#08111f', color: '#edf5ff',
    border: '1px solid #22436e', borderRadius: 10, padding: '11px 12px',
    fontSize: 14, outline: 'none',
  },
  textarea: {
    width: '100%', boxSizing: 'border-box', background: '#08111f', color: '#edf5ff',
    border: '1px solid #22436e', borderRadius: 10, padding: '11px 12px', fontSize: 14,
    outline: 'none', minHeight: 88, resize: 'vertical',
    fontFamily: '"Cascadia Code","Consolas",monospace',
  },
  row:       { marginBottom: 12 },
  small:     { color: '#7b95b9', fontSize: 12, marginTop: 5 },
  buttonRow: { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' },
  primary: {
    background: 'linear-gradient(135deg,#1d4ed8 0%,#2563eb 100%)', color: '#fff',
    border: 'none', borderRadius: 10, padding: '11px 14px',
    fontWeight: 700, cursor: 'pointer', fontSize: 14,
  },
  ghost: {
    background: '#0d1728', color: '#bfd2ef', border: '1px solid #2a4976',
    borderRadius: 10, padding: '11px 14px', fontWeight: 700, cursor: 'pointer', fontSize: 14,
  },
  danger: {
    background: '#2a1012', color: '#ffbec6', border: '1px solid #61202b',
    borderRadius: 10, padding: '11px 14px', fontWeight: 700, cursor: 'pointer', fontSize: 14,
  },
  amber: {
    background: '#2a1e00', color: '#fcd34d', border: '1px solid #78450a',
    borderRadius: 10, padding: '11px 14px', fontWeight: 700, cursor: 'pointer', fontSize: 14,
  },
  statusBar: {
    borderRadius: 14, border: '1px solid #22436e', background: '#08111f',
    padding: '12px 16px', marginBottom: 18,
    display: 'flex', alignItems: 'flex-start', gap: 12,
  },
  phaseDot: { width: 10, height: 10, borderRadius: '50%', flexShrink: 0, marginTop: 4 },
  statusBody: {
    flex: 1, margin: 0, whiteSpace: 'pre-wrap', lineHeight: 1.55,
    fontFamily: '"Cascadia Code","Consolas",monospace', color: '#dbeafe', fontSize: 13,
  },
  reconnectBanner: {
    borderRadius: 12, border: '1px solid #78450a', background: '#1a0f00',
    padding: '12px 16px', marginBottom: 14,
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
  },
  errorBanner: {
    borderRadius: 12, border: '1px solid #5a2230', background: '#190b12',
    padding: '12px 16px', marginBottom: 14,
    display: 'flex', alignItems: 'flex-start', gap: 10,
  },
  statGrid: { display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 12 },
  statBox:  { border: '1px solid #22436e', borderRadius: 14, padding: 14, background: '#09111d' },
  statLabel: { margin: 0, color: '#7b95b9', fontSize: 12 },
  statValue: {
    margin: '8px 0 0', fontSize: 22, fontWeight: 700, color: '#f3f8ff',
    fontFamily: '"Cascadia Code","Consolas",monospace',
  },
  profileList: { display: 'grid', gap: 10, marginTop: 12 },
  profileItem: {
    border: '1px solid #22436e', background: '#08111f', borderRadius: 12, padding: 12,
    display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12,
  },
  profileName: { margin: 0, fontWeight: 700 },
  profileMeta: { margin: '4px 0 0', color: '#7b95b9', fontSize: 12 },
  // Startup failure screen
  errScreen: {
    minHeight: '100vh',
    background: 'linear-gradient(180deg,#06080f 0%,#0b1020 100%)',
    color: '#e5eefb', fontFamily: '"Segoe UI",system-ui,sans-serif',
    display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32,
  },
  errCard: {
    maxWidth: 580, width: '100%', background: 'rgba(22,9,14,0.98)',
    border: '1px solid #5a2230', borderRadius: 20, padding: 36,
  },
  mono: { fontFamily: '"Cascadia Code","Consolas",monospace', fontSize: 12, color: '#ffa0b4' },
};

// ─── Startup failure screen ───────────────────────────────────────────────────

function StartupFailureScreen({ diag }: { diag: StartupDiagnostic }) {
  const openLog = () => invoke('open_log_dir').catch(() => {});
  return (
    <div style={S.errScreen}>
      <div style={S.errCard}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>⛔</div>
        <h2 style={{ margin: '0 0 8px', fontSize: 20, color: '#ff7f95' }}>
          Не удалось загрузить wireguard.dll
        </h2>
        {diag.load_error && (
          <p style={{ ...S.mono, marginBottom: 16, whiteSpace: 'pre-wrap' }}>
            {diag.load_error}
          </p>
        )}

        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 20, fontSize: 13 }}>
          <tbody>
            {(
              [
                ['wireguard.dll', diag.wireguard_dll_found, diag.wireguard_dll_path],
                ['wintun.dll',    diag.wintun_dll_found,    diag.wintun_dll_path],
              ] as [string, boolean, string | null][]
            ).map(([name, found, path]) => (
              <tr key={name} style={{ borderBottom: '1px solid #2a1a20' }}>
                <td style={{ padding: '7px 0', color: '#bfd2ef', width: 120 }}>{name}</td>
                <td style={{ padding: '7px 6px', color: found ? '#22c55e' : '#ff7f95' }}>
                  {found ? '✓ найден' : '✗ не найден'}
                </td>
                <td style={{ ...S.mono, padding: '7px 0', color: '#7b95b9' }}>
                  {path ?? '—'}
                </td>
              </tr>
            ))}
            <tr>
              <td style={{ padding: '7px 0', color: '#bfd2ef' }}>ОС</td>
              <td colSpan={2} style={{ ...S.mono, padding: '7px 0', color: '#7b95b9' }}>
                {diag.os_info}
              </td>
            </tr>
            <tr>
              <td style={{ padding: '7px 0', color: '#bfd2ef' }}>Журнал</td>
              <td colSpan={2} style={{ ...S.mono, padding: '7px 0', color: '#7b95b9' }}>
                {diag.log_dir}
              </td>
            </tr>
          </tbody>
        </table>

        <p style={{ color: '#86a2c6', fontSize: 13, marginBottom: 20, lineHeight: 1.6 }}>
          Убедитесь, что <code>wireguard.dll</code> и <code>wintun.dll</code> скопированы
          в папку <code>resources/</code> рядом с приложением, и что приложение запущено
          с правами администратора.
        </p>

        <div style={S.buttonRow}>
          <button style={S.danger} onClick={openLog}>
            📂 Открыть журнал
          </button>
          <button style={S.ghost} onClick={() => window.location.reload()}>
            ↺ Повторить запуск
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function App() {
  // ── Startup diagnostic state ──────────────────────────────────────────────
  const [startupDiag,  setStartupDiag]  = useState<StartupDiagnostic | null>(null);
  const [startupReady, setStartupReady] = useState(false);

  // ── Tunnel state ──────────────────────────────────────────────────────────
  const [phase,   setPhase]   = useState<Phase>('idle');
  const [status,  setStatus]  = useState<string>('Соединение не активно');
  const [error,   setError]   = useState<string | null>(null);
  const [stats,   setStats]   = useState<TunnelStats>({ is_active: false, total_tx: 0, total_rx: 0, last_handshake_unix: 0 });
  const [diag,    setDiag]    = useState<TunnelDiagnostics | null>(null);
  const [needsReconnect, setNeedsReconnect] = useState(false);

  // ── Profile state ─────────────────────────────────────────────────────────
  const [profiles,         setProfiles]         = useState<SavedProfile[]>([]);
  const [activeProfileId,  setActiveProfileId]  = useState<string>('');
  const [form,             setForm]             = useState<SavedProfile>(emptyProfile());

  const phaseRef = useRef(phase);
  useEffect(() => { phaseRef.current = phase; }, [phase]);

  // ── Load profiles from localStorage ──────────────────────────────────────
  useEffect(() => {
    try {
      const raw    = localStorage.getItem(PROFILE_KEY);
      if (raw) setProfiles(JSON.parse(raw) as SavedProfile[]);
      const active = localStorage.getItem(ACTIVE_PROFILE_KEY);
      if (active) setActiveProfileId(active);
    } catch {
      localStorage.removeItem(PROFILE_KEY);
      localStorage.removeItem(ACTIVE_PROFILE_KEY);
    }
  }, []);

  useEffect(() => { localStorage.setItem(PROFILE_KEY, JSON.stringify(profiles)); }, [profiles]);
  useEffect(() => { if (activeProfileId) localStorage.setItem(ACTIVE_PROFILE_KEY, activeProfileId); }, [activeProfileId]);

  // ── Startup diagnostic (once on mount) ───────────────────────────────────
  useEffect(() => {
    invoke<StartupDiagnostic>('get_startup_diagnostics')
      .then(d  => { setStartupDiag(d); setStartupReady(true); })
      .catch(() => setStartupReady(true));
  }, []);

  // ── Tunnel status polling ─────────────────────────────────────────────────
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

        // Surface needs_reconnect flag (set by power-resume monitor)
        if (statusRes.needs_reconnect) setNeedsReconnect(true);

        if (statusRes.is_active) {
          setPhase(prev => (prev === 'disconnecting' ? prev : 'connected'));
          setStatus(buildStatusText(statusRes));
        } else if (phaseRef.current !== 'disconnecting' && phaseRef.current !== 'connecting') {
          setPhase('idle');
          setStatus('Соединение не активно');
        }
      } catch {
        /* backend ещё подтягивается */
      }
    };

    poll();
    const timer = window.setInterval(poll, POLL_MS);
    return () => { mounted = false; window.clearInterval(timer); };
  }, []);

  const activeProfile = useMemo(
    () => profiles.find(p => p.id === activeProfileId) ?? null,
    [profiles, activeProfileId],
  );

  // ── Validation ────────────────────────────────────────────────────────────
  const validationError = (): string | null =>
    validateBase64Key(form.privateKey.trim(), 'PrivateKey') ??
    validateBase64Key(form.publicKey.trim(), 'PublicKey') ??
    validateEndpoint(form.endpoint.trim()) ??
    validateCidrList(form.address.trim(), 'Address') ??
    validateCidrList(form.allowedIps.trim(), 'AllowedIPs');

  // ── Shared connect logic ──────────────────────────────────────────────────
  const doConnect = async () => {
    const payload = buildConfig(form);
    const routes  = form.allowedIps.split(',').map(s => s.trim()).filter(Boolean);

    setPhase('connecting');
    setStatus('Инициализация адаптера…');
    setError(null);

    try {
      const result = await invoke<TunnelStatus>('tunnel_apply_config', {
        configContent: payload,
        adapterName:   form.name || 'GameAccelerator',
        expectedRoutes: routes,
      });
      setPhase('connected');
      setStatus(buildStatusText(result));
    } catch (e) {
      setPhase('idle');
      setStatus('Соединение не активно');
      setError(`Ошибка подключения: ${String(e)}`);
    }
  };

  // ── Handlers ──────────────────────────────────────────────────────────────
  const connect = async () => {
    if (phase === 'connecting' || phase === 'disconnecting') return;
    const err = validationError();
    if (err) { setError(err); return; }
    await doConnect();
  };

  const disconnect = async () => {
    if (phase !== 'connected') return;
    setPhase('disconnecting');
    setStatus('Отключение…');
    try {
      await invoke('tunnel_disconnect');
      setPhase('idle');
      setStatus('Соединение не активно');
    } catch (e) {
      setPhase('idle');
      setError(`Ошибка отключения: ${String(e)}`);
    }
  };

  const reconnect = async () => {
    if (phase === 'connecting' || phase === 'disconnecting') return;
    const err = validationError();
    if (err) { setError(err); return; }

    // Clear the backend flag before reconnecting
    await invoke('tunnel_clear_reconnect_flag').catch(() => {});
    setNeedsReconnect(false);

    if (phase === 'connected') {
      setPhase('disconnecting');
      setStatus('Переподключение…');
      await invoke('tunnel_disconnect').catch(() => {});
      setPhase('idle');
    }

    await doConnect();
  };

  const dismissReconnect = async () => {
    await invoke('tunnel_clear_reconnect_flag').catch(() => {});
    setNeedsReconnect(false);
  };

  const openLogDir = () => invoke('open_log_dir').catch(() => {});

  const saveProfile = () => {
    const err = validationError();
    if (err) { setError(err); return; }
    const next: SavedProfile = {
      ...form,
      privateKey:  form.privateKey.trim(),
      publicKey:   form.publicKey.trim(),
      endpoint:    form.endpoint.trim(),
      address:     form.address.trim(),
      allowedIps:  form.allowedIps.trim(),
      dnsServers:  form.dnsServers.trim(),
    };
    setProfiles(prev => {
      const idx = prev.findIndex(p => p.id === next.id);
      if (idx >= 0) { const c = [...prev]; c[idx] = next; return c; }
      return [next, ...prev];
    });
    setActiveProfileId(next.id);
    setError(null);
  };

  const createNewProfile = () => {
    const p = emptyProfile();
    setForm(p);
    setActiveProfileId(p.id);
    setError(null);
  };

  const loadProfile   = (p: SavedProfile) => { setForm(p); setActiveProfileId(p.id); setError(null); };
  const deleteProfile = (id: string) => {
    setProfiles(prev => prev.filter(p => p.id !== id));
    if (activeProfileId === id) { setActiveProfileId(''); setForm(emptyProfile()); }
  };

  // ── Startup failure screen (early return) ─────────────────────────────────
  if (startupReady && startupDiag && !startupDiag.wireguard_dll_loaded) {
    return <StartupFailureScreen diag={startupDiag} />;
  }

  // ── Main UI ───────────────────────────────────────────────────────────────
  return (
    <div style={S.page}>
      <div style={S.shell}>

        {/* Top bar */}
        <div style={S.topbar}>
          <div>
            <h1 style={S.title}>Game Accelerator</h1>
            <p style={S.subtitle}>WireGuard-NT · Windows x64</p>
          </div>
          <div style={S.buttonRow}>
            <button style={S.ghost}    onClick={openLogDir}>📂 Журнал</button>
            <button style={S.ghost}    onClick={createNewProfile}>Новый VPS</button>
            <button style={S.primary}  onClick={saveProfile}>Сохранить</button>
            <button
              style={{ ...S.primary, opacity: phase !== 'idle' ? 0.5 : 1 }}
              onClick={connect}
              disabled={phase !== 'idle'}
            >
              Подключить
            </button>
            <button
              style={{ ...S.amber, opacity: (phase !== 'idle' || !form.endpoint) ? 0.4 : 1 }}
              onClick={reconnect}
              disabled={phase === 'connecting' || phase === 'disconnecting'}
              title="Переподключиться (сбросить и поднять туннель заново)"
            >
              ↺ Reconnect
            </button>
            <button
              style={{ ...S.ghost, opacity: phase !== 'connected' ? 0.4 : 1 }}
              onClick={disconnect}
              disabled={phase !== 'connected'}
            >
              Отключить
            </button>
          </div>
        </div>

        {/* Reconnect-needed banner (system sleep/resume) */}
        {needsReconnect && (
          <div style={S.reconnectBanner}>
            <span style={{ color: '#fcd34d', fontSize: 14 }}>
              ⚡ Система вышла из режима сна — соединение могло разорваться.
            </span>
            <div style={S.buttonRow}>
              <button style={S.amber}  onClick={reconnect}>↺ Переподключить</button>
              <button style={S.ghost}  onClick={dismissReconnect}>Закрыть</button>
            </div>
          </div>
        )}

        {/* Status bar with phase dot */}
        <div style={S.statusBar}>
          <div style={{ ...S.phaseDot, background: PHASE_COLOR[phase] }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: PHASE_COLOR[phase], fontWeight: 700, marginBottom: 4 }}>
              {PHASE_LABEL[phase]}
            </div>
            <pre style={S.statusBody}>{status}</pre>
          </div>
        </div>

        {/* Error banner */}
        {error && (
          <div style={S.errorBanner}>
            <span style={{ fontSize: 16 }}>⚠</span>
            <div style={{ flex: 1 }}>
              <div style={{ color: '#ff8ea0', fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                Ошибка
              </div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#ffd2da', fontSize: 13,
                fontFamily: '"Cascadia Code","Consolas",monospace', lineHeight: 1.5 }}>
                {error}
              </pre>
            </div>
            <button
              onClick={() => setError(null)}
              style={{ background: 'none', border: 'none', color: '#7b95b9',
                fontSize: 18, cursor: 'pointer', padding: '0 4px', flexShrink: 0 }}
            >
              ×
            </button>
          </div>
        )}

        {/* Main grid */}
        <div style={S.grid}>

          {/* Left: profile form */}
          <div style={S.card}>
            <p style={S.cardTitle}>Профиль VPS</p>

            {[
              { label: 'Название профиля', key: 'name' as const, type: 'text',     ph: 'Warsaw-01' },
              { label: 'Приватный ключ',   key: 'privateKey' as const, type: 'password', ph: '44 символа Base64' },
              { label: 'Публичный ключ сервера', key: 'publicKey' as const, type: 'text', ph: '44 символа Base64' },
              { label: 'Endpoint',         key: 'endpoint' as const, type: 'text', ph: '1.2.3.4:51820' },
              { label: 'Адрес интерфейса', key: 'address' as const,  type: 'text', ph: '10.0.0.2/32' },
              { label: 'DNS',              key: 'dnsServers' as const, type: 'text', ph: '1.1.1.1, 8.8.8.8' },
            ].map(({ label, key, type, ph }) => (
              <div key={key} style={S.row}>
                <label style={S.label}>{label}</label>
                <input
                  style={S.input} type={type} value={form[key] as string}
                  onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))}
                  placeholder={ph}
                />
              </div>
            ))}

            <div style={S.row}>
              <label style={S.label}>AllowedIPs</label>
              <textarea
                style={S.textarea}
                value={form.allowedIps}
                onChange={e => setForm(prev => ({ ...prev, allowedIps: e.target.value }))}
                placeholder="0.0.0.0/0, ::/0"
              />
              <div style={S.small}>Через запятую. Максимум {MAX_ROUTES} маршрутов.</div>
            </div>
          </div>

          {/* Right column */}
          <div style={{ display: 'grid', gap: 18 }}>

            {/* Traffic stats */}
            <div style={S.card}>
              <p style={S.cardTitle}>Трафик</p>
              <div style={S.statGrid}>
                <div style={S.statBox}>
                  <p style={S.statLabel}>TX</p>
                  <p style={S.statValue}>{toMiB(stats.total_tx)} MB</p>
                </div>
                <div style={S.statBox}>
                  <p style={S.statLabel}>RX</p>
                  <p style={S.statValue}>{toMiB(stats.total_rx)} MB</p>
                </div>
                <div style={S.statBox}>
                  <p style={S.statLabel}>Канал</p>
                  <p style={{ ...S.statValue, color: stats.is_active ? '#22c55e' : '#7b95b9' }}>
                    {stats.is_active ? 'UP' : 'DOWN'}
                  </p>
                </div>
              </div>
            </div>

            {/* Path diagnostics */}
            <div style={S.card}>
              <p style={S.cardTitle}>Диагностика пути</p>
              <div style={S.statGrid}>
                {(
                  [
                    ['Handshake',  diag?.handshake_ok,        'OK',       'WAIT'],
                    ['Route',      diag?.route_health_ok,     'OK',       'BAD'],
                    ['Game Path',  diag?.game_path_verified,  'VERIFIED', '—'],
                  ] as [string, boolean | undefined, string, string][]
                ).map(([label, val, ok, bad]) => (
                  <div key={label} style={S.statBox}>
                    <p style={S.statLabel}>{label}</p>
                    <p style={{ ...S.statValue,
                      color: val ? '#22c55e' : '#7b95b9', fontSize: 16 }}>
                      {val ? ok : bad}
                    </p>
                  </div>
                ))}
              </div>
              <div style={{ ...S.small, marginTop: 12 }}>
                RTT: {diag?.avg_rtt_ms ?? 0} ms
                {' · '}
                Jitter: {diag?.jitter_ms ?? 0} ms
                {' · '}
                Loss: {(diag?.packet_loss_percent ?? 0).toFixed(2)}%
                {diag?.leak_detected ? ' · ⚠ Утечка!' : ''}
              </div>
            </div>

            {/* Saved profiles */}
            <div style={S.card}>
              <p style={S.cardTitle}>Сохранённые VPS</p>

              {profiles.length === 0 ? (
                <div style={S.small}>Профилей нет. Заполните форму и нажмите «Сохранить».</div>
              ) : (
                <div style={S.profileList}>
                  {profiles.map(profile => (
                    <div key={profile.id} style={{
                      ...S.profileItem,
                      ...(profile.id === activeProfileId
                        ? { borderColor: '#2563eb', background: '#0a1528' } : {}),
                    }}>
                      <div>
                        <p style={S.profileName}>{profile.name}</p>
                        <p style={S.profileMeta}>{profile.endpoint} · {profile.address}</p>
                      </div>
                      <div style={S.buttonRow}>
                        <button style={S.ghost}  onClick={() => loadProfile(profile)}>Открыть</button>
                        <button style={S.danger} onClick={() => deleteProfile(profile.id)}>Удалить</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeProfile && (
                <div style={{ ...S.small, marginTop: 12 }}>
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
