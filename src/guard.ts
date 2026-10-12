/**
 * Runtime enforcement. The model proposes a tool call; the guard — plain,
 * deterministic code outside the model — decides. Nothing the model says can
 * talk its way past these checks.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { scopeGranted } from './scopes.js';
import type { AgentManifest, ArgSpec, ControlId, Decision, GuardResult, ToolCall, ToolSpec } from './types.js';

export { scopeGranted };

export interface Clock {
  now(): number;
}
export const systemClock: Clock = { now: () => Date.now() };

/** A clock you can move — used by probes and tests. */
export class ManualClock implements Clock {
  constructor(private t = Date.parse('2026-10-13T00:00:00Z')) {}
  now() {
    return this.t;
  }
  advance(ms: number) {
    this.t += ms;
  }
}

// ── C3 · Identity: short-lived, scoped, signed credentials ────────────────────

export interface Claims {
  sub: string;
  agent: string;
  scp: string[];
  iat: number;
  exp: number;
  jti: string;
}

const b64u = (s: string) => Buffer.from(s).toString('base64url');

export class IdentityIssuer {
  constructor(
    private readonly secret: string,
    private readonly clock: Clock = systemClock,
  ) {
    if (!secret || secret.length < 16) throw new Error('IdentityIssuer: signing secret must be at least 16 characters');
  }

  private sign(body: string) {
    return createHmac('sha256', this.secret).update(body).digest('base64url');
  }

  issue(m: AgentManifest, opts: { scopes?: string[]; ttlMinutes?: number } = {}): string {
    const iat = this.clock.now();
    const claims: Claims = {
      sub: m.spec.identity.principal,
      agent: m.metadata.id,
      scp: opts.scopes ?? m.spec.identity.scopes,
      iat,
      exp: iat + (opts.ttlMinutes ?? m.spec.identity.credentialTtlMinutes) * 60_000,
      jti: randomUUID(),
    };
    const body = b64u(JSON.stringify(claims));
    return `${body}.${this.sign(body)}`;
  }

  verify(token: string): { ok: true; claims: Claims } | { ok: false; reason: string } {
    if (typeof token !== 'string' || !token.includes('.')) return { ok: false, reason: 'malformed credential' };
    const [body, sig] = token.split('.', 2);
    const expected = Buffer.from(this.sign(body));
    const given = Buffer.from(sig ?? '');
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
      return { ok: false, reason: 'credential signature invalid (tampered or forged)' };
    }
    let claims: Claims;
    try {
      claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
      return { ok: false, reason: 'malformed credential' };
    }
    if (this.clock.now() >= claims.exp) return { ok: false, reason: 'credential expired' };
    return { ok: true, claims };
  }
}

// ── Audit: append-only, hash-chained ─────────────────────────────────────────

export interface AuditEntry {
  seq: number;
  ts: string;
  agent: string;
  principal: string;
  tool: string;
  target?: string;
  amount?: number;
  decision: Decision | 'released';
  control: ControlId;
  reason: string;
  prevHash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

export class AuditLog {
  readonly entries: AuditEntry[] = [];

  private digest(e: Omit<AuditEntry, 'hash'>) {
    const { prevHash, ...rest } = e;
    return createHash('sha256').update(prevHash + JSON.stringify(rest)).digest('hex');
  }

  append(e: Omit<AuditEntry, 'seq' | 'prevHash' | 'hash'>): AuditEntry {
    const prevHash = this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS;
    const base = { ...e, seq: this.entries.length + 1, prevHash };
    const entry = { ...base, hash: this.digest(base) };
    this.entries.push(entry);
    return entry;
  }

  /** Recompute the chain; any edit, insertion or deletion breaks it. */
  verify(): { ok: true } | { ok: false; brokenAt: number } {
    let prev = GENESIS;
    for (const [i, e] of this.entries.entries()) {
      const { hash, ...base } = e;
      if (e.prevHash !== prev || e.seq !== i + 1 || this.digest(base) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash;
    }
    return { ok: true };
  }
}

// ── C5 · Approvals: single-use, bound to agent + tool + amount ───────────────

interface Ticket {
  agent: string;
  tool: string;
  amount?: number;
  approver: string;
  expires: number;
  used: boolean;
}

export class ApprovalStore {
  private readonly tickets = new Map<string, Ticket>();
  constructor(private readonly clock: Clock = systemClock) {}

  grant(req: { agent: string; tool: string; amount?: number; approver: string; ttlMinutes?: number }): string {
    const id = `APR-${randomUUID()}`;
    this.tickets.set(id, {
      agent: req.agent,
      tool: req.tool,
      amount: req.amount,
      approver: req.approver,
      expires: this.clock.now() + (req.ttlMinutes ?? 30) * 60_000,
      used: false,
    });
    return id;
  }

  /** Redeem a ticket. Returns the reason it is unusable, or null on success. */
  consume(id: string | undefined, agent: string, tool: string, amount?: number): string | null {
    const t = id ? this.tickets.get(id) : undefined;
    if (!t) return 'no such approval';
    if (t.used) return 'approval already used (replay)';
    if (this.clock.now() > t.expires) return 'approval expired';
    if (t.agent !== agent || t.tool !== tool) return 'approval was issued for a different action';
    if (t.amount !== undefined && amount !== t.amount) return `approval covers amount ${t.amount}, not ${amount}`;
    t.used = true;
    return null;
  }

  approverOf(id: string) {
    return this.tickets.get(id)?.approver;
  }
}

// ── Argument schema validation ───────────────────────────────────────────────

export function validateArgs(spec: Record<string, ArgSpec> | undefined, args: Record<string, unknown> = {}): string | null {
  if (!spec) return null; // no schema declared — the static gate flags this; runtime honours the manifest
  for (const key of Object.keys(args)) {
    if (!Object.prototype.hasOwnProperty.call(spec, key)) return `unexpected argument "${key}"`;
  }
  for (const [key, a] of Object.entries(spec)) {
    const v = args[key];
    if (v === undefined) {
      if (a.required === false) continue;
      return `missing argument "${key}"`;
    }
    switch (a.type) {
      case 'string':
        if (typeof v !== 'string') return `"${key}" must be a string`;
        if (a.maxLength !== undefined && v.length > a.maxLength) return `"${key}" exceeds ${a.maxLength} characters`;
        if (a.pattern && !new RegExp(`^(?:${a.pattern})$`).test(v)) return `"${key}" does not match ${a.pattern}`;
        break;
      case 'integer':
        if (!Number.isInteger(v)) return `"${key}" must be an integer`;
        break;
      case 'number':
        if (typeof v !== 'number' || !Number.isFinite(v)) return `"${key}" must be a number`;
        break;
      case 'boolean':
        if (typeof v !== 'boolean') return `"${key}" must be a boolean`;
        break;
      default:
        return `"${key}" has an unsupported type`;
    }
    if (a.enum && !a.enum.includes(v as string | number)) return `"${key}" is not one of ${a.enum.join(', ')}`;
    if (typeof v === 'number') {
      if (a.min !== undefined && v < a.min) return `"${key}" is below ${a.min}`;
      if (a.max !== undefined && v > a.max) return `"${key}" is above ${a.max}`;
    }
  }
  return null;
}

// ── C4 · Egress ──────────────────────────────────────────────────────────────

export function egressAllowed(allow: string[], url: string): { ok: boolean; host: string } {
  let host = '';
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') return { ok: false, host: u.host };
    if (u.username || u.password) return { ok: false, host: u.host };
    host = u.hostname.toLowerCase();
    if (u.port && u.port !== '443') return { ok: false, host: u.host };
  } catch {
    return { ok: false, host: url };
  }
  const ok = allow.some((rule) => {
    const r = String(rule).toLowerCase();
    if (r === '*') return true; // an open allow-list — the static gate rejects this
    if (r.startsWith('*.')) return host.endsWith(r.slice(1)) && host.length > r.length - 1;
    return host === r;
  });
  return { ok, host };
}

// ── The guard ────────────────────────────────────────────────────────────────

export interface GuardDeps {
  identity: IdentityIssuer;
  audit: AuditLog;
  approvals: ApprovalStore;
  clock?: Clock;
  /** Called on every denial and quarantine — wire to paging/SIEM. */
  onAlert?: (r: GuardResult & { agent: string; tool: string }) => void;
}

export class Guard {
  private consecutiveDenials = 0;
  private quarantined = false;
  private readonly calls = new Map<string, number[]>();
  private spendDay = '';
  private spentToday = 0;
  private readonly clock: Clock;

  constructor(
    readonly manifest: AgentManifest,
    private readonly deps: GuardDeps,
  ) {
    this.clock = deps.clock ?? systemClock;
  }

  get isQuarantined() {
    return this.quarantined;
  }

  authorize(token: string, call: ToolCall): GuardResult {
    let result = this.decide(token, call);
    const limit = this.manifest.spec.guardrails?.maxConsecutiveDenials;

    if (result.decision === 'deny') {
      this.consecutiveDenials += 1;
      if (Number.isInteger(limit) && (limit as number) > 0 && this.consecutiveDenials >= (limit as number)) {
        this.quarantined = true;
        result = {
          ...result,
          reason: `${result.reason} — circuit breaker tripped after ${this.consecutiveDenials} consecutive denials; agent quarantined pending human review`,
        };
      }
    } else if (result.decision === 'allow') {
      this.consecutiveDenials = 0;
    }

    const claims = this.deps.identity.verify(token);
    this.deps.audit.append({
      ts: new Date(this.clock.now()).toISOString(),
      agent: this.manifest.metadata.id,
      principal: claims.ok ? claims.claims.sub : 'unverified',
      tool: call.tool,
      target: call.url,
      amount: call.amount,
      decision: result.decision,
      control: result.control,
      reason: result.reason,
    });

    if (result.decision === 'deny' || result.decision === 'quarantined') {
      if (this.manifest.spec.oversight?.monitoring?.alertOnDenials) {
        this.deps.onAlert?.({ ...result, agent: this.manifest.metadata.id, tool: call.tool });
      }
    }
    return result;
  }

  /** Kill switch release: only a named human can return an agent to service. */
  release(by: string) {
    if (!by) throw new Error('release requires a named human');
    this.quarantined = false;
    this.consecutiveDenials = 0;
    this.deps.audit.append({
      ts: new Date(this.clock.now()).toISOString(),
      agent: this.manifest.metadata.id,
      principal: by,
      tool: '-',
      decision: 'released',
      control: 'C1',
      reason: `quarantine released by ${by}`,
    });
  }

  /** Kill switch engage. */
  quarantine(reason = 'kill switch engaged') {
    this.quarantined = true;
    return reason;
  }

  private deny(control: ControlId, reason: string): GuardResult {
    return { decision: 'deny', control, reason };
  }

  private decide(token: string, call: ToolCall): GuardResult {
    const m = this.manifest;
    if (this.quarantined) return { decision: 'quarantined', control: 'C1', reason: 'agent is quarantined; all actions blocked until a human releases it' };

    // C3 — who is calling, and are they allowed to?
    const id = this.deps.identity.verify(token);
    if (!id.ok) return this.deny('C3', id.reason);
    if (id.claims.agent !== m.metadata.id || id.claims.sub !== m.spec.identity.principal) {
      return this.deny('C3', 'credential belongs to a different identity');
    }

    // C2 — only allow-listed tools
    const tool: ToolSpec | undefined = m.spec.tools?.find((t) => t.name === call.tool);
    if (!tool) {
      if (m.spec.guardrails?.denyOnUnknownTool === false) {
        return { decision: 'allow', control: 'C2', reason: 'unknown tool allowed by manifest (denyOnUnknownTool: false)' };
      }
      return this.deny('C2', `tool "${call.tool}" is not on the allow-list`);
    }

    // C3 — least privilege
    if (!scopeGranted(id.claims.scp, tool.scope)) return this.deny('C3', `credential lacks scope "${tool.scope}"`);

    // C4 — network isolation
    if (call.url !== undefined) {
      const egress = egressAllowed(m.spec.execution?.network?.egress ?? [], call.url);
      if (!egress.ok) return this.deny('C4', `egress to ${egress.host || 'invalid target'} is not on the allow-list`);
    }

    // C2 — argument schema
    const argError = validateArgs(tool.args, call.args ?? {});
    if (argError) return this.deny('C2', `argument rejected: ${argError}`);

    // C2 — rate limit (sliding 60s window)
    const now = this.clock.now();
    const recent = (this.calls.get(tool.name) ?? []).filter((t) => now - t < 60_000);
    if (tool.rateLimitPerMinute && recent.length >= tool.rateLimitPerMinute) {
      return this.deny('C2', `rate limit ${tool.rateLimitPerMinute}/min reached`);
    }

    // C2 — spend controls
    const day = new Date(now).toISOString().slice(0, 10);
    if (day !== this.spendDay) {
      this.spendDay = day;
      this.spentToday = 0;
    }
    if (tool.effect === 'transact') {
      const amount = call.amount;
      if (typeof amount !== 'number' || !(amount > 0)) return this.deny('C2', 'transaction amount missing or invalid');
      if (tool.maxAmount !== undefined && amount > tool.maxAmount) return this.deny('C2', `amount ${amount} exceeds per-call cap ${tool.maxAmount}`);
      const cap = m.spec.guardrails?.spendLimitPerDay;
      if (cap !== undefined && this.spentToday + amount > cap) {
        return this.deny('C2', `daily spend limit ${cap} would be exceeded (spent ${this.spentToday})`);
      }
    }

    // C5 — human approval for consequential actions
    if (tool.requiresApproval) {
      if (!call.approvalId) return { decision: 'pending_approval', control: 'C5', reason: `"${tool.name}" requires human approval` };
      const problem = this.deps.approvals.consume(call.approvalId, m.metadata.id, tool.name, call.amount);
      if (problem) return this.deny('C5', `approval rejected: ${problem}`);
    }

    // Commit side effects of an allowed call.
    recent.push(now);
    this.calls.set(tool.name, recent);
    if (tool.effect === 'transact') this.spentToday += call.amount as number;
    const approver = call.approvalId ? this.deps.approvals.approverOf(call.approvalId) : undefined;
    return { decision: 'allow', control: tool.requiresApproval ? 'C5' : 'C2', reason: approver ? `allowed — approved by ${approver}` : 'allowed by policy' };
  }
}
