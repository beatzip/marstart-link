import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

// ─── Types ─────────────────────────────────────────────

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
  phase: 'idle' | 'connecting' | 'connected' | 'disconnecting';
  session_id: number;
  health: TunnelHealth;
  needs_reconnect: boolean;
};

// ─── Constants ─────────────────────────────────────────────

const POLL_MS = 2500;

// ─── Helpers ─────────────────────────────────────────────

function safeParse<T>(v: any, fallback: T): T {
  try {
    return v as T;
  } catch {
    return fallback;
  }
}

// ─── Component ─────────────────────────────────────────────

export default function App() {
  const [status, setStatus] = useState<TunnelStatus | null>(null);
  const [loading, setLoading] = useState(false);

  const activeSession = useRef<number>(0);
  const pollingRef = useRef<number | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    const startPolling = () => {
      if (pollingRef.current) window.clearInterval(pollingRef.current);

      pollingRef.current = window.setInterval(async () => {
        try {
          const res = await invoke<TunnelStatus>('tunnel_get_status');

          // защита от stale response после reconnect/disconnect
          if (!mountedRef.current) return;
          if (res.session_id < activeSession.current) return;

          activeSession.current = res.session_id;
          setStatus(res);
        } catch {
          // silent fail — production-safe polling
        }
      }, POLL_MS);
    };

    startPolling();

    return () => {
      mountedRef.current = false;
      if (pollingRef.current) window.clearInterval(pollingRef.current);
    };
  }, []);

  // ─── Actions ─────────────────────────────────────────────

  const connect = async (config: string, name: string, routes: string[]) => {
    setLoading(true);
    try {
      const res = await invoke<TunnelStatus>('tunnel_apply_config', {
        configContent: config,
        adapterName: name,
        expectedRoutes: routes,
      });

      activeSession.current = res.session_id;
      setStatus(res);
    } finally {
      setLoading(false);
    }
  };

  const disconnect = async () => {
    setLoading(true);
    try {
      await invoke('tunnel_disconnect');
      setStatus(null);
      activeSession.current = 0;
    } finally {
      setLoading(false);
    }
  };

  // ─── UI-safe guard ─────────────────────────────────────

  if (!status) {
    return (
      <div style={container}>
        <h2>VPN Tunnel</h2>
        <button onClick={disconnect} disabled={loading}>
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div style={container}>
      <h2>VPN Tunnel</h2>

      <div style={card}>
        <div>State: {status.phase}</div>
        <div>Adapter: {status.adapter_name ?? '-'}</div>
        <div>IP: {status.assigned_address ?? '-'}</div>
        <div>MTU: {status.mtu ?? '-'}</div>
        <div>Session: {status.session_id}</div>

        <div style={{ marginTop: 10 }}>
          <b>Health</b>
          <div>Handshake: {status.health.handshake_ok ? 'OK' : 'WAIT'}</div>
          <div>Routes: {status.health.routes_ok ? 'OK' : 'FAIL'}</div>
          <div>DNS: {status.health.dns_ok ? 'OK' : 'FAIL'}</div>
          <div>Leak: {status.health.leak_detected ? 'YES' : 'NO'}</div>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={disconnect} disabled={loading}>
          Disconnect
        </button>
      </div>
    </div>
  );
}

// ─── Styles ─────────────────────────────────────────────

const container: React.CSSProperties = {
  fontFamily: 'system-ui',
  padding: 20,
};

const card: React.CSSProperties = {
  padding: 12,
  border: '1px solid #333',
  borderRadius: 8,
  marginTop: 12,
};