export type Severity = 'critical' | 'warning' | 'info' | 'high' | 'medium' | 'low';
export type HealthLabel = 'HEALTHY' | 'DEGRADED' | 'AT RISK' | 'CRITICAL';
export type RemediationStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'FAILED';

export interface User {
  username: string;
  is_admin: boolean;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  username: string;
  expires_in_hours: number;
}

export interface Asset {
  asset_id: string;
  name: string;
  asset_type: string;
  ip_address?: string | null;
  protecting_controls: string[];
}

export interface SecurityControl {
  control_id: string;
  name: string;
  control_type: string;
  status: string;
  protects: string[];
}

export interface CommunicationPath {
  path_id: string;
  source_id: string;
  destination_id: string;
  protocol: string;
  passes_through: string[];
}

export interface SecurityProperty {
  property_id: string;
  description: string;
  control_id: string;
  severity: string;
  protection_level: number;
}

export interface BaselineStats {
  is_active: boolean;
  stats: {
    total_nodes: number;
    total_edges: number;
    node_types: Record<string, number>;
    edge_relationships: Record<string, number>;
  };
  assumptions: string[];
  properties: string[];
}

export interface ChangeEvent {
  change_type: string;
  description: string;
  affected_entities: string[];
  severity: Severity;
  potentially_breaks_assumptions: boolean;
  affected_assumption_id?: string | null;
  affected_assumption_desc?: string | null;
}

export interface DriftDetectionResponse {
  total_changes: number;
  changes: ChangeEvent[];
  critical_count: number;
  warning_count: number;
}

export interface DecayContributor {
  assumption_id: string;
  assumption_desc: string;
  change_desc: string;
  impact_percent: number;
}

export interface DecayReport {
  property_id: string;
  property_desc: string;
  baseline_protection: number;
  current_protection: number;
  decay_percent: number;
  health_label: HealthLabel;
  contributors: DecayContributor[];
}

export interface RepairCandidate {
  repair_id: string;
  description: string;
  action_type: string;
  total_cost: number;
  security_improvement: number;
  cost_effectiveness_ratio: number;
  restored_assumptions: string[];
  target_entity?: string | null;
  is_recommended: boolean;
  implementation_cost: number;
  business_impact: number;
  operational_risk: number;
  implementation_time: number;
}

export interface RepairResponse {
  total_candidates: number;
  recommended_repair: RepairCandidate | null;
  candidates: RepairCandidate[];
  restoration_target_percent: number;
}

export interface Remediation {
  id: number;
  remediation_id: string;
  repair_id: string;
  description: string;
  action_type: string;
  status: RemediationStatus;
  applied_by: string;
  created_at: string;
  resolved_at?: string | null;
  target_entity?: string | null;
  details?: Record<string, any>;
}

export interface RemediationVerifyResponse {
  remediation_id: string;
  status: RemediationStatus;
  current_protection: number;
  decay_percent: number;
  health_label: HealthLabel;
  total_changes: number;
  critical_count: number;
  warning_count: number;
  message: string;
  assets: Asset[];
  controls: SecurityControl[];
  paths: CommunicationPath[];
  changes: ChangeEvent[];
  decay: DecayReport;
  dashboard: {
    assets: number;
    controls: number;
    remediations: number;
    properties: number;
    open_remediations: number;
    current_protection: number;
    decay_percent: number;
    health_label: HealthLabel;
  };
}

export interface AuditLog {
  id: number;
  username: string;
  action: string;
  entity_type?: string | null;
  entity_id?: string | null;
  details?: Record<string, any> | null;
  timestamp: string;
}
