export type TunnelStatus =
  | { status: 'Disconnected' }
  | { status: 'Connecting' }
  | { status: 'Connected' }
  | { status: 'Error'; message: string };

export interface EndpointSpec {
  id: string;
  addr: string;
  label?: string;
  weight?: number;
}

export interface AggregatedMetrics {
  target_id: string;
  latest_rtt_ms: number | null;
  avg_rtt_ms: number | null;
  min_rtt_ms: number | null;
  max_rtt_ms: number | null;
  jitter_ms: number;
  loss_ratio: number;
  stability: number;
  samples: number;
  window: number;
}

export type RouteHealth = 'Unknown' | 'Good' | 'Degraded' | 'Bad';

export interface RouteScoreView {
  id: string;
  score: number;
  weighted_score: number;
  health: RouteHealth;
  weight: number;
}

export interface RouteEvaluation {
  current: string | null;
  recommended: string | null;
  manual_override: string | null;
  scores: RouteScoreView[];
  reason:
    | 'NoCandidates'
    | 'NoChange'
    | 'ManualOverride'
    | 'EmergencyBypass'
    | 'Improvement'
    | 'CooldownBlocked';
}

export interface RouteState {
  candidates: Array<Required<EndpointSpec>>;
  current: string | null;
  manual_override: string | null;
  last_switch_ms: number;
  cooldown_ms: number;
  switch_margin: number;
}

export interface MonitorTarget {
  id: string;
  addr: string;
  fallback_port: number;
}

export interface GameProfile {
  id: string;
  name: string;
  process_names: string[];
  udp_ports: number[];
  burst_threshold_pps: number;
  max_packet_size: number;
}

export interface GameSignal {
  detected: boolean;
  game_id: string | null;
  game_name: string | null;
  confidence: number;
  reason: 'Idle' | 'Process' | 'UdpBurst' | 'Both';
  timestamp_ms: number;
}

export interface ConnectionInfo {
  handshake_timestamp_unix: number;
  tx_bytes: number;
  rx_bytes: number;
  endpoint: string | null;
}

export type AutopilotIntent = 'Hold' | 'Switch';
export type DecisionReason = 'NoCandidates' | 'AlreadyOnBest' | 'StableNoImprovement' | 'CooldownActive' | 'HysteresisPending' | 'Improvement' | 'GameModeSwitch' | 'EmergencyBypass';
export type FsmState = 'Init' | 'Stable' | 'Degraded' | 'Recovery' | 'GameMode';

export interface PolicyVerdict {
  verdict: 'Allow' | 'Block';
  streak: number;
  streak_needed: number;
  elapsed_since_switch_ms: number;
  cooldown_ms: number;
}

export interface AutopilotDecision {
  intent: AutopilotIntent;
  reason: DecisionReason;
  from_route: string | null;
  to_route: string | null;
  fsm_state: FsmState;
  stability: Record<string, number>;
  verdict: PolicyVerdict | null;
  timestamp_ms: number;
}

export interface MonitorTick {
  timestamp_ms: number;
  samples: Array<{ target_id: string; sample: { rtt_ms: number | null; timestamp_ms: number } }>;
}

export interface MonitorState {
  running: boolean;
  interval_ms: number;
  targets: MonitorTarget[];
}
