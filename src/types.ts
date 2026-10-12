/**
 * Core types for the agent governance framework.
 *
 * Controls:
 *   C1  Risk-proportional oversight
 *   C2  Deterministic guardrails
 *   C3  Agents as privileged identities
 *   C4  Isolated execution
 *   C5  Human-in-the-loop
 *   LC  Lifecycle (validate → test → productionise → monitor → support)
 */

export type DataClass = 'public' | 'internal' | 'confidential' | 'restricted';
export type ActionClass = 'read' | 'write' | 'transact';
export type Exposure = 'internal' | 'customer' | 'public';
export type Stage = 'validation' | 'testing' | 'production' | 'retired';
export type Sandbox = 'none' | 'process' | 'container' | 'vm';
export type ControlId = 'C1' | 'C2' | 'C3' | 'C4' | 'C5' | 'LC';

export const CONTROLS: Record<ControlId, string> = {
  C1: 'Risk-proportional oversight',
  C2: 'Deterministic guardrails',
  C3: 'Agents as privileged identities',
  C4: 'Isolated execution',
  C5: 'Human-in-the-loop',
  LC: 'Lifecycle',
};

export interface ArgSpec {
  type: 'string' | 'number' | 'integer' | 'boolean';
  pattern?: string;
  enum?: Array<string | number>;
  min?: number;
  max?: number;
  maxLength?: number;
  required?: boolean;
  /** A known-good value, used by adversarial probes to build valid calls. */
  example?: string | number | boolean;
}

export interface ToolSpec {
  name: string;
  effect: ActionClass;
  /** The identity scope a credential must carry to call this tool. */
  scope: string;
  irreversible?: boolean;
  requiresApproval?: boolean;
  rateLimitPerMinute?: number;
  /** Per-call ceiling for transacting tools (call.amount). */
  maxAmount?: number;
  args?: Record<string, ArgSpec>;
}

export interface AgentManifest {
  apiVersion: string;
  kind: 'Agent';
  metadata: {
    id: string;
    name: string;
    owner: string;
    team?: string;
    description?: string;
  };
  spec: {
    lifecycle: {
      stage: Stage;
      validated?: { date: string; by: string; useCase: string };
      lastReview?: string;
      reviewIntervalDays?: number;
      runbook?: string;
      support?: { onCall?: string; escalation?: string };
    };
    risk: {
      dataClassification: DataClass;
      actions: ActionClass;
      exposure: Exposure;
      reversibility: 'reversible' | 'irreversible';
      regulated?: boolean;
    };
    identity: {
      principal: string;
      credentialTtlMinutes: number;
      scopes: string[];
    };
    tools: ToolSpec[];
    guardrails: {
      denyOnUnknownTool?: boolean;
      /** Circuit breaker: quarantine the agent after N consecutive denials. */
      maxConsecutiveDenials?: number;
      spendLimitPerDay?: number;
    };
    execution: {
      sandbox: Sandbox;
      network: { egress: string[] };
      productionDataAccess?: boolean;
      dataBroker?: string;
    };
    oversight: {
      approvers?: string[];
      monitoring?: { telemetry?: boolean; alertOnDenials?: boolean; killSwitch?: boolean };
    };
  };
}

/** Manifests arrive from YAML and are untrusted: every field may be missing. */
export type DeepPartial<T> = T extends Array<infer U>
  ? Array<DeepPartial<U>>
  : T extends object
    ? { [K in keyof T]?: DeepPartial<T[K]> }
    : T;

export type LooseManifest = DeepPartial<AgentManifest>;

export interface TierDefinition {
  tier: 1 | 2 | 3;
  label: string;
  maxScore: number;
  maxReviewDays: number;
  maxCredentialTtlMinutes: number;
  allowedSandboxes: Sandbox[];
  requireKillSwitch: boolean;
  requireRateLimits: boolean;
  requiredProbes: string[];
}

export interface TierPolicy {
  apiVersion: string;
  kind: 'TierPolicy';
  scoring: {
    dataClassification: Record<string, number>;
    actions: Record<string, number>;
    exposure: Record<string, number>;
    irreversible: number;
    regulated: number;
  };
  tiers: TierDefinition[];
}

export type Severity = 'error' | 'warning';

export interface Finding {
  rule: string;
  control: ControlId;
  severity: Severity;
  passed: boolean;
  message: string;
}

export type ControlStatus = 'pass' | 'warn' | 'fail';

export interface Evaluation {
  agentId: string;
  name: string;
  owner: string;
  team?: string;
  stage: string;
  tier: 1 | 2 | 3;
  tierLabel: string;
  riskScore: number;
  findings: Finding[];
  controls: Record<ControlId, ControlStatus>;
  compliant: boolean;
}

export type Decision = 'allow' | 'deny' | 'pending_approval' | 'quarantined';

export interface ToolCall {
  tool: string;
  args?: Record<string, unknown>;
  /** Network target, checked against the egress allowlist. */
  url?: string;
  amount?: number;
  approvalId?: string;
}

export interface GuardResult {
  decision: Decision;
  control: ControlId;
  reason: string;
}

export interface ProbeStep {
  label: string;
  call: { tool: string; url?: string; amount?: number; note?: string };
  expected: string;
  decision: Decision;
  reason: string;
  ok: boolean;
}

export interface ProbeResult {
  id: string;
  title: string;
  control: ControlId;
  applicable: boolean;
  passed: boolean;
  summary: string;
  steps: ProbeStep[];
}
