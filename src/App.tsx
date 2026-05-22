import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

// Типизация ответа из Rust (explicit nullable для защиты от serde changes)
interface TunnelStatus {
  is_active: boolean;
  adapter_name: string | null;
  interface_index: number | null;
  mtu: number | null;
}

// В localStorage храним ВСЁ КРОМЕ приватного ключа
interface SavedConfig {
  publicKey: string;
  endpoint: string;
  address: string;
  allowedIps: string;
}

const STORAGE_KEY = 'wg_debug_config';

// Строгая валидация WG ключа с проверкой длины после decode
function validateWgKey(key: string): string | null {
  const trimmed = key.trim();
  if (!trimmed) return 'Ключ не может быть пустым';
  if (trimmed.length !== 44) return `Длина должна быть 44 символа (сейчас ${trimmed.length})`;
  
  try {
    const decoded = atob(trimmed);
    if (decoded.length !== 32) {
      return `Неверная длина после decode: ${decoded.length} байт (ожидается 32)`;
    }
  } catch {
    return 'Неверный формат Base64';
  }
  
  return null;
}

// Строгая валидация endpoint (IPv4:port, [IPv6]:port, domain:port)
function validateEndpoint(endpoint: string): string | null {
  const trimmed = endpoint.trim();
  if (!trimmed) return 'Endpoint не может быть пустым';

  try {
    // IPv6
    if (trimmed.startsWith('[')) {
      const match = trimmed.match(/^\[(.+)\]:(\d+)$/);
      if (!match) return 'Неверный IPv6 endpoint (ожидается [IP]:port)';
      const port = Number(match[2]);
      if (port < 1 || port > 65535) return 'Порт вне диапазона (1-65535)';
      return null;
    }

    // IPv4 / Domain
    const idx = trimmed.lastIndexOf(':');
    if (idx === -1) return 'Формат: host:port или [IPv6]:port';

    const host = trimmed.slice(0, idx);
    const port = Number(trimmed.slice(idx + 1));

    if (!host) return 'Пустой host';
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return 'Неверный порт (ожидается число 1-65535)';
    }

    return null;
  } catch {
    return 'Неверный endpoint';
  }
}

function App() {
  const [status, setStatus] = useState<string>('Отключено');
  const [loading, setLoading] = useState<boolean>(false);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  const [privateKey, setPrivateKey] = useState<string>('');
  const [publicKey, setPublicKey] = useState<string>('');
  const [endpoint, setEndpoint] = useState<string>('');
  const [address, setAddress] = useState<string>('10.0.0.2/32');
  const [allowedIps, setAllowedIps] = useState<string>('10.0.0.0/24');

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        const parsed: SavedConfig = JSON.parse(saved);
        setPublicKey(parsed.publicKey || '');
        setEndpoint(parsed.endpoint || '');
        setAddress(parsed.address || '10.0.0.2/32');
        setAllowedIps(parsed.allowedIps || '10.0.0.0/24');
      } catch (e) {
        console.error('Failed to parse saved config', e);
      }
    }
  }, []);

  const buildWireGuardConfig = (): string => {
    return `[Interface]
PrivateKey = ${privateKey.trim()}
Address = ${address.trim()}

[Peer]
PublicKey = ${publicKey.trim()}
Endpoint = ${endpoint.trim()}
AllowedIPs = ${allowedIps.trim()}
PersistentKeepalive = 25
`;
  };

  const connect = async () => {
    if (loading) return;

    const pkError = validateWgKey(privateKey);
    if (pkError) { setStatus(`❌ PrivateKey: ${pkError}`); return; }

    const pubError = validateWgKey(publicKey);
    if (pubError) { setStatus(`❌ PublicKey: ${pubError}`); return; }

    const epError = validateEndpoint(endpoint);
    if (epError) { setStatus(`❌ Endpoint: ${epError}`); return; }

    const config = buildWireGuardConfig();
    const routesList = allowedIps.split(',').map(s => s.trim()).filter(Boolean);

    // Сохраняем только публичные данные
    const configToSave: SavedConfig = { publicKey, endpoint, address, allowedIps };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(configToSave));

    setLoading(true);
    setStatus('🔄 Создание адаптера...');

    try {
      const result = await invoke<TunnelStatus>('tunnel_apply_config', {
        configContent: config,
        adapterName: 'GameAccelerator-Test',
        expectedRoutes: routesList,
      });

      console.log('Tauri invoke success:', result);
      
      setStatus(
        `⚠️ Адаптер создан (Index: ${result.interface_index}).\n` +
        `WG config пока не применён (TODO: SetConfiguration).\n` +
        `Address (${address.trim()}) пока не назначается на интерфейс.\n\n` +
        `Проверь в PowerShell:\n` +
        `  Get-NetAdapter | Where-Object Name -Like "*GameAccelerator*"`
      );
      setIsConnected(true);
    } catch (err) {
      console.error('Tauri invoke error:', err);
      setStatus(`❌ Ошибка: ${String(err)}`);
      setIsConnected(false);
    } finally {
      setLoading(false);
    }
  };

  const disconnect = async () => {
    if (loading) return;
    setLoading(true);
    setStatus('🔄 Отключение...');

    try {
      await invoke('tunnel_disconnect');
      setStatus('⭕ Отключено');
      setIsConnected(false);
    } catch (err) {
      console.error('Tauri invoke error:', err);
      setStatus(`❌ Ошибка: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    fontFamily: 'Consolas, Monaco, monospace',
    border: '1px solid #dcdde1',
    borderRadius: '4px',
    boxSizing: 'border-box',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    marginBottom: '4px',
    fontSize: '13px',
    fontWeight: '600',
    color: '#2c3e50',
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '12px',
  };

  return (
    <div style={{
      padding: '1.5rem',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      maxWidth: '640px',
      margin: '0 auto',
    }}>
      <h1 style={{ color: '#2c3e50', margin: '0 0 4px 0' }}>🚀 Game Accelerator</h1>
      <p style={{ color: '#7f8c8d', fontSize: '13px', margin: '0 0 1.5rem 0' }}>
        Debug UI · Данные сохраняются локально (localStorage)
      </p>

      <div style={{
        backgroundColor: '#f8f9fa',
        padding: '1rem',
        borderRadius: '6px',
        border: '1px solid #dcdde1',
      }}>
        <h3 style={{ margin: '0 0 12px 0', fontSize: '15px', color: '#2c3e50' }}>
          🔐 Конфигурация WireGuard
        </h3>

        <div style={fieldStyle}>
          <label style={labelStyle}>PrivateKey (клиент)</label>
          <input
            type="password"
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="44 символа Base64"
            style={inputStyle}
            disabled={isConnected}
          />
        </div>

        <div style={fieldStyle}>
          <label style={labelStyle}>
            Address <span style={{fontWeight: 'normal', color: '#95a5a6'}}>(пока не применяется backend)</span>
          </label>
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="10.0.0.2/32"
            style={inputStyle}
            disabled={isConnected}
          />
        </div>

        <div style={fieldStyle}>
          <label style={labelStyle}>PublicKey (сервер)</label>
          <input
            type="text"
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder="44 символа Base64 публичного ключа VPS"
            style={inputStyle}
            disabled={isConnected}
          />
        </div>

        <div style={fieldStyle}>
          <label style={labelStyle}>Endpoint (IP:port VPS)</label>
          <input
            type="text"
            value={endpoint}
            onChange={(e) =>