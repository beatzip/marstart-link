import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type {
  AggregatedMetrics,
  AutopilotDecision,
  ConnectionInfo,
  EndpointSpec,
  GameProfile,
  GameSignal,
  MonitorState,
  MonitorTick,
  MonitorTarget,
  RouteEvaluation,
  RouteState,
  TunnelStatus,
} from './types';

const isTauri = () =>
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

let mockStatus: TunnelStatus = { status: 'Disconnected' };
let mockRoutes: EndpointSpec[] = [];
let mockProfiles: GameProfile[] = [
  {
    id: 'cs2',
    name: 'Counter-Strike 2',
    process_names: ['cs2.exe'],
    udp_ports: [27015],
    burst_threshold_pps: 40,
    max_packet_size: 200,
  },
];

function mockMetrics(): AggregatedMetrics[] {
  const now = Date.now() / 1000;
  return mockRoutes.map((route, index) => {
    const rtt = 28 + index * 13 + Math.sin(now + index) * 5;
    const jitter = 3 + Math.abs(Math.cos(now * 1.3 + index) * 4);
    const loss = index === 2 ? 0.02 : 0.003;
    return {
      target_id: route.id,
      latest_rtt_ms: rtt,
      avg_rtt_ms: rtt + 2,
      min_rtt_ms: rtt - 6,
      max_rtt_ms: rtt + 12,
      jitter_ms: jitter,
      loss_ratio: loss,
      stability: Math.max(0, 1 - jitter / 50 - loss),
      samples: 60,
      window: 120,
    };
  });
}

function mockRouteState(): RouteState {
  return {
    candidates: mockRoutes.map((route) => ({
      id: route.id,
      addr: route.addr,
      label: route.label ?? route.id,
      weight: route.weight ?? 1,
    })),
    current: mockRoutes[0]?.id ?? null,
    manual_override: null,
    last_switch_ms: 0,
    cooldown_ms: 10000,
    switch_margin: 0.1,
  };
}

function mockRouteEvaluation(): RouteEvaluation {
  const metrics = mockMetrics();
  const scores = mockRoutes.map((route) => {
    const metric = metrics.find((item) => item.target_id === route.id);
    const score =
      (metric?.avg_rtt_ms ?? 999) +
      (metric?.jitter_ms ?? 0) * 2 +
      (metric?.loss_ratio ?? 0) * 1000;
    return {
      id: route.id,
      score,
      weighted_score: score / (route.weight ?? 1),
      health: metric && metric.loss_ratio > 0.1 ? 'Bad' : 'Good',
      weight: route.weight ?? 1,
    } satisfies RouteEvaluation['scores'][number];
  });
  const best = [...scores].sort((a, b) => a.weighted_score - b.weighted_score)[0];
  return {
    current: mockRoutes[0]?.id ?? null,
    recommended: best?.id ?? null,
    manual_override: null,
    scores,
    reason: best ? 'Improvement' : 'NoCandidates',
  };
}

export const api = {
  connect: async (profileId: string) => {
    if (isTauri()) return invoke<void>('connect', { profileId });
    mockStatus = { status: 'Connected' };
  },
  disconnect: async () => {
    if (isTauri()) return invoke<void>('disconnect');
    mockStatus = { status: 'Disconnected' };
  },
  status: () => (isTauri() ? invoke<TunnelStatus>('get_status') : Promise.resolve(mockStatus)),
  connectionInfo: () =>
    isTauri()
      ? invoke<ConnectionInfo | null>('get_connection_info')
      : Promise.resolve<ConnectionInfo | null>(null),
  metrics: () =>
    isTauri()
      ? invoke<AggregatedMetrics[]>('monitor_get_snapshot')
      : Promise.resolve(mockMetrics()),
  monitorTargets: (targets: MonitorTarget[]) =>
    isTauri()
      ? invoke<void>('monitor_set_targets', { targets })
      : Promise.resolve(void targets),
  monitorStart: (config?: { interval_ms: number; probe_timeout_ms: number; targets: MonitorTarget[] }) =>
    isTauri()
      ? invoke<MonitorState>('monitor_start', { config: config ?? null })
      : Promise.resolve<MonitorState>({ running: true, interval_ms: 1000, targets: [] }),
  routes: () =>
    isTauri()
      ? invoke<RouteEvaluation>('routes_list')
      : Promise.resolve(mockRouteEvaluation()),
  routeState: () =>
    isTauri() ? invoke<RouteState>('routes_get_state') : Promise.resolve(mockRouteState()),
  setRoutes: (candidates: EndpointSpec[]) => {
    if (isTauri()) return invoke<RouteState>('routes_set_candidates', { candidates });
    mockRoutes = candidates;
    return Promise.resolve(mockRouteState());
  },
  selectRoute: (id: string | null) =>
    isTauri()
      ? invoke<RouteState>('routes_select_manual', { id })
      : Promise.resolve({ ...mockRouteState(), manual_override: id, current: id }),
  gameProfiles: () =>
    isTauri() ? invoke<GameProfile[]>('game_list_profiles') : Promise.resolve(mockProfiles),
  saveGameProfile: (profile: GameProfile) => {
    if (isTauri()) return invoke<GameProfile[]>('game_add_profile', { profile });
    mockProfiles = [...mockProfiles.filter((item) => item.id !== profile.id), profile];
    return Promise.resolve(mockProfiles);
  },
  removeGameProfile: (id: string) => {
    if (isTauri()) return invoke<GameProfile[]>('game_remove_profile', { id });
    mockProfiles = mockProfiles.filter((item) => item.id !== id);
    return Promise.resolve(mockProfiles);
  },
  gameState: () =>
    isTauri()
      ? invoke<GameSignal>('game_get_state')
      : Promise.resolve({
          detected: false,
          game_id: null,
          game_name: null,
          confidence: 0,
          reason: 'Idle',
          timestamp_ms: Date.now(),
        }),
  autopilotEnable: () =>
    isTauri()
      ? invoke<{ enabled: boolean; message: string }>('autopilot_enable')
      : Promise.resolve({ enabled: true, message: 'mock autopilot enabled' }),
  autopilotDisable: () =>
    isTauri()
      ? invoke<{ enabled: boolean; message: string }>('autopilot_disable')
      : Promise.resolve({ enabled: false, message: 'mock autopilot disabled' }),
  autopilotState: () =>
    isTauri()
      ? invoke<AutopilotDecision | null>('autopilot_get_state')
      : Promise.resolve(null),
  onAutopilotAction: (callback: (decision: AutopilotDecision) => void) => {
    if (!isTauri()) return () => {};
    const unlisten = listen<AutopilotDecision>('autopilot:action', (event) => {
      callback(event.payload);
    });
    return () => { unlisten.then((f) => f()); };
  },
  onMonitorTick: (callback: (tick: MonitorTick) => void) => {
    if (!isTauri()) return () => {};
    const unlisten = listen<MonitorTick>('monitor:tick', (event) => {
      callback(event.payload);
    });
    return () => { unlisten.then((f) => f()); };
  },
  onRouteChanged: (callback: (routeId: string | null) => void) => {
    if (!isTauri()) return () => {};
    const unlisten = listen<string | null>('routes:changed', (event) => {
      callback(event.payload);
    });
    return () => { unlisten.then((f) => f()); };
  },
};