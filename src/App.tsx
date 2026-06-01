import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface TunnelStatus {
  status: 'Disconnected' | 'Connecting' | 'Connected' | 'Error';
  message?: string;
}

function App() {
  const [status, setStatus] = useState<TunnelStatus>({ status: 'Disconnected' });
  const [profileId] = useState('default');

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const s: TunnelStatus = await invoke('get_status');
        setStatus(s);
      } catch {
        setStatus({ status: 'Error', message: 'Backend недоступен' });
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleConnect = async () => {
    try {
      await invoke('connect', { profileId });
    } catch (e) {
      setStatus({ status: 'Error', message: String(e) });
    }
  };

  const handleDisconnect = async () => {
    await invoke('disconnect');
  };

  return (
    <div style={{ padding: '20px' }}>
      <h1>Game Accelerator</h1>
      <button onClick={handleConnect} disabled={status.status !== 'Disconnected'}>
        Подключиться
      </button>
      <button onClick={handleDisconnect} disabled={status.status === 'Disconnected'}>
        Отключиться
      </button>
      <p>Статус: {status.status}</p>
      {status.message && <p>{status.message}</p>}
    </div>
  );
}

export default App;
