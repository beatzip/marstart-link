import { useEffect, useMemo, useState } from 'react';
import { api } from './api';
import type {
  AggregatedMetrics,
  AutopilotDecision,
  EndpointSpec,
  GameProfile,
  GameSignal,
  RouteEvaluation,
  RouteState,
  TunnelStatus,
} from './types';
import './App.css';

const defaultRoutes: EndpointSpec[] = [
  { id: 'eu-frankfurt', addr: '1.1.1.1:443', label: 'EU Frankfurt', weight: 1.15 },
  { id: 'eu-warsaw', addr: '8.8.8.8:443', label: 'EU Warsaw', weight: 1 },
  { id: 'tr-istanbul', addr: '9.9.9.9:443', label: 'TR Istanbul', weight: 0.95 },
];

const defaultTargets = [
  { id: 'eu-frankfurt', addr: '1.1.1.1', fallback_port: 443 },
  { id: 'eu-warsaw', addr: '8.8.8.8', fallback_port: 443 },
  { id: 'tr-istanbul', addr: '9.9.9.9', fallback_port: 443 },
];

type History = Record<string, Array<{ rtt: number | null; jitter: number; loss: number }>>;

function labelFor(status: TunnelStatus) {
  return status.status === 'Error' ? status.message : status.status;
}

function pct(value: number) {
  return `${Math.round(value * 100)}%`;
}

function ms(value: number | null | undefined) {
  return value == null || !Number.isFinite(value) ? '-' : `${value.toFixed(0)} ms`;
}

function Sparkline({ points, metric }: { points: History[string]; metric: 'rtt' | 'jitter' | 'loss' }) {
  const values = points
    .map((point) => point[metric])
    .filter((value): value is number => value != null && Number.isFinite(value));
  const max = Math.max(metric === 'loss' ? 0.1 : 50, ...values);
  const path = points
    .map((point, index) => {
      const raw = point[metric];
      const value = raw == null || !Number.isFinite(raw) ? max : raw;
      const x = points.length <= 1 ? 0 : (index / (points.length - 1)) * 100;
      const y = 36 - Math.min(36, (value / max) * 34);
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');

  return (
    <svg className="sparkline" viewBox="0 0 100 38" preserveAspectRatio="none" aria-hidden="true">
      <path d={path || 'M 0 36'} />
    </svg>
  );
}

function App() {
  const [profileId, setProfileId] = useState('default');
  const [status, setStatus] = useState<TunnelStatus>({ status: 'Disconnected' });
  const [metrics, setMetrics] = useState<AggregatedMetrics[]>([]);
  const [history, setHistory] = useState<History>({});
  const [routeEval, setRouteEval] = useState<RouteEvaluation | null>(null);
  const [routeState, setRouteState] = useState<RouteState | null>(null);
  const [profiles, setProfiles] = useState<GameProfile[]>([]);
  const [game, setGame] = useState<GameSignal | null>(null);
  const [autopilot, setAutopilot] = useState<AutopilotDecision | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draftProfile, setDraftProfile] = useState<GameProfile>({
    id: 'custom-game',
    name: 'Custom Game',
    process_names: ['game.exe'],
    udp_ports: [27015],
    burst_threshold_pps: 30,
    max_packet_size: 250,
  });

  const bestRoute = useMemo(
    () => routeEval?.scores.find((score) => score.id === routeEval.recommended),
    [routeEval],
  );

  async function refresh() {
    const [statusR, metricsR, routesR, routeStateR, profilesR, gameR] =
      await Promise.allSettled([
        api.status(),
        api.metrics(),
        api.routes(),
        api.routeState(),
        api.gameProfiles(),
        api.gameState(),
      ]);
    if (statusR.status === 'fulfilled') setStatus(statusR.value);
    const metrics = metricsR.status === 'fulfilled' ? metricsR.value : [];
    setMetrics(metrics);
    if (routesR.status === 'fulfilled') setRouteEval(routesR.value);
    if (routeStateR.status === 'fulfilled') setRouteState(routeStateR.value);
    if (profilesR.status === 'fulfilled') setProfiles(profilesR.value);
    if (gameR.status === 'fulfilled') setGame(gameR.value);
    setHistory((current) => {
      const updated = { ...current };
      for (const item of metrics) {
        const series = updated[item.target_id] ? [...updated[item.target_id]] : [];
        series.push({
          rtt: item.latest_rtt_ms,
          jitter: item.jitter_ms,
          loss: item.loss_ratio,
        });
        updated[item.target_id] = series.slice(-60);
      }
      return updated;
    });
  }

  useEffect(() => {
    // Boot sequence: set routes → start monitor with targets
    const boot = async () => {
      await api.setRoutes(defaultRoutes);
      await api.monitorStart({
        interval_ms: 1000,
        probe_timeout_ms: 800,
        targets: defaultTargets,
      });
      await refresh();
    };
    void boot().catch((e) => setError(String(e)));

    // Hot path: on every probe cycle update metrics + routes (3 IPC instead of 6)
    const unlistenTick = api.onMonitorTick((_tick) => {
      void (async () => {
        try {
          const [nextMetrics, nextRoutes, nextRouteState] = await Promise.all([
            api.metrics(),
            api.routes(),
            api.routeState(),
          ]);
          setMetrics(nextMetrics);
          setRouteEval(nextRoutes);
          setRouteState(nextRouteState);
          setHistory((current) => {
            const updated = { ...current };
            for (const item of nextMetrics) {
              const series = updated[item.target_id] ? [...updated[item.target_id]] : [];
              series.push({ rtt: item.latest_rtt_ms, jitter: item.jitter_ms, loss: item.loss_ratio });
              updated[item.target_id] = series.slice(-60);
            }
            return updated;
          });
        } catch (e) {
          setError(String(e));
        }
      })();
    });

    // Autopilot decisions arrive via event, not polling
    const unlistenAutopilot = api.onAutopilotAction((decision) => {
      setAutopilot(decision);
      if (decision.intent === 'Switch' && decision.to_route) {
        setRouteEval((prev) =>
          prev ? { ...prev, current: decision.to_route, recommended: decision.to_route } : null,
        );
      }
    });

    // Cold path: tunnel status only (no backend event yet), every 5 s
    const statusTimer = window.setInterval(() => {
      void api.status().then(setStatus).catch((e) => setError(String(e)));
    }, 5000);

    return () => {
      unlistenTick();
      unlistenAutopilot();
      window.clearInterval(statusTimer);
    };
  }, []);

  async function connect() {
    setError(null);
    try {
      await api.connect(profileId);
      await refresh();
    } catch (e) {
      setError(String(e));
      setStatus({ status: 'Error', message: String(e) });
    }
  }

  async function disconnect() {
    setError(null);
    try {
      await api.disconnect();
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  async function selectRoute(id: string | null) {
    setError(null);
    try {
      setRouteState(await api.selectRoute(id));
      setRouteEval(await api.routes());
    } catch (e) {
      setError(String(e));
    }
  }

  async function saveProfile() {
    setError(null);
    try {
      setProfiles(await api.saveGameProfile(draftProfile));
    } catch (e) {
      setError(String(e));
    }
  }

  async function removeProfile(id: string) {
    setError(null);
    try {
      setProfiles(await api.removeGameProfile(id));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <main className="shell">
      <section className="topbar">
        <div>
          <h1>MARSTART LINK</h1>
          <p>Gaming route control for WireGuard transport</p>
        </div>
        <div className={`status status-${status.status.toLowerCase()}`}>
          <span>{labelFor(status)}</span>
        </div>
      </section>

      {error && <div className="error">{error}</div>}

      <section className="control">
        <label>
          Profile
          <input value={profileId} onChange={(event) => setProfileId(event.target.value)} />
        </label>
        <button onClick={connect} disabled={status.status === 'Connected' || status.status === 'Connecting'}>
          Connect
        </button>
        <button onClick={disconnect} disabled={status.status === 'Disconnected'}>
          Disconnect
        </button>
        <button
          onClick={async () => {
            await api.autopilotEnable().catch((e) => setError(String(e)));
          }}
          disabled={autopilot != null}
        >
          Autopilot On
        </button>
        <button
          onClick={async () => {
            await api.autopilotDisable().catch((e) => setError(String(e)));
            setAutopilot(null);
          }}
          disabled={autopilot == null}
        >
          Autopilot Off
        </button>
        <div className="recommendation">
          <span>Recommended</span>
          <strong>{bestRoute?.id ?? '-'}</strong>
          <small>{routeEval?.reason ?? 'NoCandidates'}</small>
        </div>
        {autopilot && (
          <div className="autopilot-info" style={{ marginLeft: 'auto', fontSize: '0.8rem', color: '#94a3b8' }}>
            Autopilot: <strong>{autopilot.intent}</strong> → {autopilot.to_route ?? '-'}
            <small style={{ display: 'block' }}>FSM: {autopilot.fsm_state}</small>
          </div>
        )}
      </section>

      <section className="grid">
        <div className="panel">
          <div className="panel-title">
            <h2>Routes</h2>
            <button onClick={() => void selectRoute(null)}>Auto</button>
          </div>
          <div className="route-list">
            {(routeEval?.scores ?? []).map((route) => (
              <button
                className={`route-row ${route.id === routeEval?.recommended ? 'route-best' : ''}`}
                key={route.id}
                onClick={() => void selectRoute(route.id)}
              >
                <span>
                  <strong>{route.id}</strong>
                  <small>{route.health}</small>
                </span>
                <span>{route.weighted_score.toFixed(1)}</span>
              </button>
            ))}
          </div>
          <dl className="kv">
            <div>
              <dt>Current</dt>
              <dd>{routeState?.current ?? '-'}</dd>
            </div>
            <div>
              <dt>Manual</dt>
              <dd>{routeState?.manual_override ?? 'off'}</dd>
            </div>
            <div>
              <dt>Cooldown</dt>
              <dd>{routeState ? `${routeState.cooldown_ms} ms` : '-'}</dd>
            </div>
          </dl>
        </div>

        <div className="panel diagnostics">
          <div className="panel-title">
            <h2>Diagnostics</h2>
            <span>{metrics.length} targets</span>
          </div>
          {metrics.map((item) => (
            <div className="metric-row" key={item.target_id}>
              <div>
                <strong>{item.target_id}</strong>
                <small>
                  rtt {ms(item.latest_rtt_ms)} / jitter {ms(item.jitter_ms)} / loss {pct(item.loss_ratio)}
                </small>
              </div>
              <Sparkline points={history[item.target_id] ?? []} metric="rtt" />
            </div>
          ))}
        </div>

        <div className="panel">
          <div className="panel-title">
            <h2>Game Profiles</h2>
            <span>{game?.detected ? game.game_name : 'Idle'}</span>
          </div>
          <div className="profile-editor">
            <input
              value={draftProfile.id}
              onChange={(event) => setDraftProfile({ ...draftProfile, id: event.target.value })}
              placeholder="id"
            />
            <input
              value={draftProfile.name}
              onChange={(event) => setDraftProfile({ ...draftProfile, name: event.target.value })}
              placeholder="name"
            />
            <input
              value={draftProfile.process_names.join(',')}
              onChange={(event) =>
                setDraftProfile({
                  ...draftProfile,
                  process_names: event.target.value.split(',').map((value) => value.trim()).filter(Boolean),
                })
              }
              placeholder="process.exe"
            />
            <button onClick={saveProfile}>Save Profile</button>
          </div>
          <div className="profile-list">
            {profiles.map((profile) => (
              <div className="profile-row" key={profile.id}>
                <span>
                  <strong>{profile.name}</strong>
                  <small>{profile.process_names.join(', ')}</small>
                </span>
                <button onClick={() => void removeProfile(profile.id)}>Remove</button>
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}

export default App;