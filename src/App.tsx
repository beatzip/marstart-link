import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api'; // ✅ Исправлено: стандартный импорт для Tauri v1

// ============================================================
// Types
// ============================================================

interface TunnelStatus {
  is_active: boolean;
  adapter_name: string | null;
  interface_index: number | null;
  mtu: number | null;
}

interface SavedConfig {
  publicKey: string;
  endpoint: string;
  address: string;
  allowedIps: string;
}

type AppPhase = 'idle' | 'connecting' | 'connected' | 'disconnecting';

// ============================================================
// Constants
// ============================================================

const STORAGE_KEY = 'wg_config_v1';
const MAX_ROUTES = 50;
const POLL_INTERVAL_MS = 3000; // Опрос статуса каждые 3 секунды

// ============================================================
// Validation helpers
// ============================================================

function validateWgKey(key: string, fieldName: string): string | null {
  const trimmed = key.trim();
  if (!trimmed) return `${fieldName}: ключ не может быть пустым`;
  
  // ✅ Улучшено: Строгая проверка Base64 (32 байта = 43-44 символа)
  if (!/^[A-Za-z0-9+/]{42,43}={0,2}$/.test(trimmed)) {
    return `${fieldName}: неверный формат Base64 (ожидается 43-44 символа)`;
  }
  
  try {
    const decoded = atob(trimmed);
    if (decoded.length !== 32)
      return `${fieldName}: неверная длина после decode — ${decoded.length} байт (ожидается 32)`;
  } catch {
    return `${fieldName}: неверный формат Base64`;
  }
  return null;
}

function validateCidr(cidr: string, fieldName: string): string | null {
  const trimmed = cidr.trim();
  if (!trimmed) return `${fieldName}: не может быть пустым`;
  const parts = trimmed.split('/');
  if (parts.length !== 2) return `${fieldName}: ожидается формат IP/маска (например 10.0.0.2/32)`;
  const prefix = Number(parts[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32)
    return `${fieldName}: маска должна быть числом от 0 до 32`;
  const ipParts = parts[0].split('.');
  if (ipParts.length !== 4 || ipParts.some(p => isNaN(Number(p)) || Number(p) < 0 || Number(p) > 255))
    return `${fieldName}: неверный IP-адрес "${parts[0]}"`;
  return null;
}

function validateEndpoint(endpoint: string): string | null {
  const trimmed = endpoint.trim();
  if (!trimmed) return 'Endpoint не может быть пустым';
  try {
    if (trimmed.startsWith('[')) {
      const match = trimmed.match(/^\[(.+)\]:(\d+)$/);
      if (!match) return 'Неверный IPv6 endpoint (ожидается [IP]:port)';
      const port = Number(match[2]);
      if (port < 1 || port > 65535) return `Порт вне диапазона: ${port}`;
      return null;
    }
    const idx = trimmed.lastIndexOf(':');
    if (idx === -1) return 'Формат: host:port или [IPv6]:port';
    const host = trimmed.slice(0, idx);
    const port = Number(trimmed.slice(idx + 1));
    if (!host) return 'Пустой host';
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return `Неверный порт (ожидается 1–65535, получено "${trimmed.slice(idx + 1)}")`;
    return null;
  } catch {
    return 'Неверный endpoint';
  }
}

function validateAllFields(
  privateKey: string,
  publicKey: string,
  endpoint: string,
  address: string,
  allowedIps: string,
): string | null {
  return (
    validateWgKey(privateKey, 'PrivateKey') ??
    validateWgKey(publicKey, 'PublicKey') ??
    validateEndpoint(endpoint) ??
    validateCidr(address, 'Address') ??
    (() => {
      const routes = allowedIps.split(',').map(s => s.trim()).filter(Boolean);
      if (routes.length === 0) return 'AllowedIPs: не может быть пустым';
      if (routes.length > MAX_ROUTES) return `AllowedIPs: максимум ${MAX_ROUTES} маршрутов`;
      for (const cidr of routes) {
        const err = validateCidr(cidr, 'AllowedIPs');
        if (err) return err;
      }
      return null;
    })()
  );
}

// ============================================================
// Build config string
// ============================================================

function buildWireGuardConfig(
  privateKey: string,
  publicKey: string,
  endpoint: string,
  address: string,
  allowedIps: string,
): string {
  return [
    '[Interface]',
    `PrivateKey = ${privateKey.trim()}`,
    `Address = ${address.trim()}`,
    '',
    '[Peer]',
    `PublicKey = ${publicKey.trim()}`,
    `Endpoint = ${endpoint.trim()}`,
    `AllowedIPs = ${allowedIps.trim()}`,
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}

// ============================================================
// Styles
// ============================================================

const S = {
  root: {
    padding: '24px 20px',
    fontFamily: '"Segoe UI", system-ui, -apple-system, sans-serif',
    maxWidth: '600px',
    margin: '0 auto',
    minHeight: '100vh',
    backgroundColor: '#0f1117',
    color: '#e2e8f0',
  } as React.CSSProperties,
  header: { marginBottom: '24px' } as React.CSSProperties,
  h1: {
    fontSize: '20px', fontWeight: 600, color: '#f8fafc',
    margin: '0 0 4px 0', letterSpacing: '-0.3px',
  } as React.CSSProperties,
  subtitle: { fontSize: '12px', color: '#64748b', margin: 0 } as React.CSSProperties,
  card: {
    backgroundColor: '#1a1f2e', border: '1px solid #2d3748',
    borderRadius: '10px', padding: '20px', marginBottom: '16px',
  } as React.CSSProperties,
  cardTitle: {
    fontSize: '13px', fontWeight: 600, color: '#94a3b8',
    textTransform: 'uppercase' as const, letterSpacing: '0.06em', margin: '0 0 16px 0',
  } as React.CSSProperties,
  field: { marginBottom: '14px' } as React.CSSProperties,
  label: {
    display: 'flex', alignItems: 'center', gap: '6px',
    marginBottom: '6px', fontSize: '13px', fontWeight: 500, color: '#cbd5e1',
  } as React.CSSProperties,
  labelHint: { fontSize: '11px', color: '#475569', fontWeight: 400 } as React.CSSProperties,
  input: (disabled: boolean, hasError: boolean): React.CSSProperties => ({
    width: '100%', padding: '9px 12px', fontSize: '13px',
    fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
    background: disabled ? '#111827' : '#0d1117',
    border: `1px solid ${hasError ? '#ef4444' : '#2d3748'}`,
    borderRadius: '6px', color: disabled ? '#475569' : '#e2e8f0',
    boxSizing: 'border-box' as const, outline: 'none',
    transition: 'border-color 0.15s', cursor: disabled ? 'not-allowed' : 'text',
  }),
  statusBox: (phase: AppPhase): React.CSSProperties => ({
    padding: '12px 14px', borderRadius: '8px', fontSize: '13px',
    lineHeight: '1.6', fontFamily: '"Cascadia Code", monospace',
    whiteSpace: 'pre-wrap' as const, marginBottom: '16px', border: '1px solid',
    ...(phase === 'connected'
      ? { background: '#052e16', borderColor: '#166534', color: '#86efac' }
      : phase === 'connecting' || phase === 'disconnecting'
      ? { background: '#1c1f2e', borderColor: '#334155', color: '#94a3b8' }
      : { background: '#1a1f2e', borderColor: '#2d3748', color: '#64748b' }),
  }),
  errorBox: {
    padding: '10px 14px', borderRadius: '8px', fontSize: '13px',
    background: '#2d0a0a', border: '1px solid #7f1d1d', color: '#fca5a5',
    marginBottom: '16px', lineHeight: '1.5',
  } as React.CSSProperties,
  buttonRow: { display: 'flex', gap: '10px' } as React.CSSProperties,
  btnConnect: (disabled: boolean): React.CSSProperties => ({
    flex: 1, padding: '10px 20px', fontSize: '14px', fontWeight: 600,
    borderRadius: '7px', border: 'none', cursor: disabled ? 'not-allowed' : 'pointer',
    background: disabled ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
    color: disabled ? '#4b6fa5' : '#fff', transition: 'all 0.15s', letterSpacing: '0.01em',
  }),
  btnDisconnect: (disabled: boolean): React.CSSProperties => ({
    flex: 1, padding: '10px 20px', fontSize: '14px', fontWeight: 600,
    borderRadius: '7px', border: '1px solid #374151',
    cursor: disabled ? 'not-allowed' : 'pointer',
    background: disabled ? '#111827' : '#1f2937',
    color: disabled ? '#374151' : '#94a3b8', transition: 'all 0.15s', letterSpacing: '0.01em',
  }),
  indicator: (active: boolean): React.CSSProperties => ({
    width: '7px', height: '7px', borderRadius: '50%',
    background: active ? '#22c55e' : '#374151',
    boxShadow: active ? '0 0 6px #22c55e88' : 'none',
    display: 'inline-block', marginRight: '6px', flexShrink: 0,
  }),
} as const;

// ============================================================
// Component
// ============================================================

export default function App() {
  const [phase, setPhase] = useState<AppPhase>('idle');
  const [statusText, setStatusText] = useState<string>('Нет активного соединения');
  const [errorText, setErrorText] = useState<string | null>(null);

  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [address, setAddress] = useState('10.0.0.2/32');
  const [allowedIps, setAllowedIps] = useState('10.0.0.0/24');

  const [fieldErrors, setFieldErrors] = useState<Record<string, boolean>>({});

  const isConnected = phase === 'connected';
  const isBusy = phase === 'connecting' || phase === 'disconnecting';
  
  // ✅ Добавлено: Ref для безопасного чтения phase внутри setInterval
  const phaseRef = useRef(phase);
  useEffect(() => { phaseRef.current = phase; }, [phase]);

  // ✅ КРИТИЧЕСКОЕ УЛУЧШЕНИЕ: Фоновый опрос статуса туннеля (Sync с Windows Driver)
  useEffect(() => {
    let isMounted = true;

    const pollStatus = async () => {
      try {
        const status = await invoke<TunnelStatus>('tunnel_get_status');
        if (!isMounted) return;

        if (status.is_active) {
          // Если мы не в процессе отключения, считаем что подключены
          if (phaseRef.current !== 'disconnecting') {
            setPhase('connected');
            setStatusText(
              `Соединение активно\n` +
              `Адаптер: ${status.adapter_name ?? '—'}\n` +
              `Индекс интерфейса: ${status.interface_index ?? '—'}\n` +
              `MTU: ${status.mtu ?? '—'}`
            );
          }
        } else {
          // Если драйвер сообщает, что туннель мертв, синхронизируем UI
          if (phaseRef.current === 'connected' || phaseRef.current === 'connecting') {
            setPhase('idle');
            setStatusText('Нет активного соединения (Туннель потерян)');
          }
        }
      } catch {
        // Бэкенд еще грузится или команда не зарегистрирована — игнорируем
      }
    };

    pollStatus(); // Первый вызов сразу
    const interval = setInterval(pollStatus, POLL_INTERVAL_MS);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Загрузка конфига из LocalStorage
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved: SavedConfig = JSON.parse(raw);
      setPublicKey(saved.publicKey ?? '');
      setEndpoint(saved.endpoint ?? '');
      setAddress(saved.address ?? '10.0.0.2/32');
      setAllowedIps(saved.allowedIps ?? '10.0.0.0/24');
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  const markFieldErrors = useCallback(
    (priv: string, pub: string, endp: string, addr: string, allowed: string) => {
      setFieldErrors({
        privateKey: validateWgKey(priv, 'PrivateKey') !== null,
        publicKey: validateWgKey(pub, 'PublicKey') !== null,
        endpoint: validateEndpoint(endp) !== null,
        address: validateCidr(addr, 'Address') !== null,
        allowedIps: allowed.split(',').some(c => validateCidr(c.trim(), 'AllowedIPs') !== null),
      });
    },
    [],
  );

  const connect = async () => {
    if (isBusy || isConnected) return;

    const validationError = validateAllFields(privateKey, publicKey, endpoint, address, allowedIps);
    if (validationError) {
      markFieldErrors(privateKey, publicKey, endpoint, address, allowedIps);
      setErrorText(validationError);
      return;
    }

    setFieldErrors({});
    setErrorText(null);
    setPhase('connecting');
    setStatusText('Инициализация адаптера...');

    const config = buildWireGuardConfig(privateKey, publicKey, endpoint, address, allowedIps);
    const routesList = allowedIps.split(',').map(s => s.trim()).filter(Boolean);

    try {
      const result = await invoke<TunnelStatus>('tunnel_apply_config', {
        configContent: config,
        adapterName: 'GameAccelerator',
        expectedRoutes: routesList,
      });

      const toSave: SavedConfig = { publicKey, endpoint, address, allowedIps };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));

      setPhase('connected');
      setStatusText(
        `Соединение активно\n` +
        `Адаптер: ${result.adapter_name ?? 'GameAccelerator'}\n` +
        `Индекс интерфейса: ${result.interface_index ?? '—'}\n` +
        `MTU: ${result.mtu ?? '—'}`
      );
    } catch (err) {
      setPhase('idle');
      // ✅ Улучшено: Красивый вывод ошибки от Rust бэкенда
      const errMsg = typeof err === 'string' ? err : JSON.stringify(err);
      setErrorText(`Ошибка подключения: ${errMsg}`);
      setStatusText('Нет активного соединения');
    }
  };

  const disconnect = async () => {
    if (isBusy || !isConnected) return;
    setPhase('disconnecting');
    setStatusText('Отключение...');
    try {
      await invoke('tunnel_disconnect');
      setPhase('idle');
      setStatusText('Нет активного соединения');
      setErrorText(null);
    } catch (err) {
      setPhase('idle');
      setErrorText(`Ошибка при отключении: ${String(err)}`);
      setStatusText('Нет активного соединения');
    }
  };

  return (
    <div style={S.root}>
      <div style={S.header}>
        <h1 style={S.h1}>
          <span style={S.indicator(isConnected)} />
          Game Accelerator
        </h1>
        <p style={S.subtitle}>
          {isConnected ? 'WireGuard туннель активен' : 'WireGuard клиент · Windows'}
        </p>
      </div>

      <div style={S.statusBox(phase)}>{statusText}</div>

      {errorText && <div style={S.errorBox}>{errorText}</div>}

      <div style={S.card}>
        <p style={S.cardTitle}>Конфигурация</p>

        <div style={S.field}>
          <label style={S.label}>Приватный ключ (клиент)</label>
          <input
            type="password"
            value={privateKey}
            onChange={e => {
              setPrivateKey(e.target.value);
              setFieldErrors(prev => ({ ...prev, privateKey: false }));
              setErrorText(null);
            }}
            placeholder="44 символа Base64"
            style={S.input(isConnected || isBusy, fieldErrors.privateKey ?? false)}
            disabled={isConnected || isBusy}
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        <div style={S.field}>
          <label style={S.label}>
            Адрес интерфейса
            <span style={S.labelHint}>(IP туннеля, пример: 10.0.0.2/32)</span>
          </label>
          <input
            type="text"
            value={address}
            onChange={e => {
              setAddress(e.target.value);
              setFieldErrors(prev => ({ ...prev, address: false }));
              setErrorText(null);
            }}
            placeholder="10.0.0.2/32"
            style={S.input(isConnected || isBusy, fieldErrors.address ?? false)}
            disabled={isConnected || isBusy}
            spellCheck={false}
          />
        </div>

        <div style={S.field}>
          <label style={S.label}>Публичный ключ сервера</label>
          <input
            type="text"
            value={publicKey}
            onChange={e => {
              setPublicKey(e.target.value);
              setFieldErrors(prev => ({ ...prev, publicKey: false }));
              setErrorText(null);
            }}
            placeholder="44 символа Base64"
            style={S.input(isConnected || isBusy, fieldErrors.publicKey ?? false)}
            disabled={isConnected || isBusy}
            spellCheck={false}
          />
        </div>

        <div style={S.field}>
          <label style={S.label}>
            Endpoint сервера
            <span style={S.labelHint}>(IP:порт или [IPv6]:порт)</span>
          </label>
          <input
            type="text"
            value={endpoint}
            onChange={e => {
              setEndpoint(e.target.value);
              setFieldErrors(prev => ({ ...prev, endpoint: false }));
              setErrorText(null);
            }}
            placeholder="1.2.3.4:51820"
            style={S.input(isConnected || isBusy, fieldErrors.endpoint ?? false)}
            disabled={isConnected || isBusy}
            spellCheck={false}
          />
        </div>

        <div style={{ ...S.field, marginBottom: 0 }}>
          <label style={S.label}>
            Разрешённые IP (AllowedIPs)
            <span style={S.labelHint}>(через запятую, макс. {MAX_ROUTES})</span>
          </label>
          <input
            type="text"
            value={allowedIps}
            onChange={e => {
              setAllowedIps(e.target.value);
              setFieldErrors(prev => ({ ...prev, allowedIps: false }));
              setErrorText(null);
            }}
            placeholder="10.0.0.0/24, 192.168.1.0/24"
            style={S.input(isConnected || isBusy, fieldErrors.allowedIps ?? false)}
            disabled={isConnected || isBusy}
            spellCheck={false}
          />
        </div>
      </div>

      <div style={S.buttonRow}>
        <button
          style={S.btnConnect(isBusy || isConnected)}
          onClick={connect}
          disabled={isBusy || isConnected}
        >
          {phase === 'connecting' ? 'Подключение...' : 'Подключить'}
        </button>

        <button
          style={S.btnDisconnect(isBusy || !isConnected)}
          onClick={disconnect}
          disabled={isBusy || !isConnected}
        >
          {phase === 'disconnecting' ? 'Отключение...' : 'Отключить'}
        </button>
      </div>
    </div>
  );
}