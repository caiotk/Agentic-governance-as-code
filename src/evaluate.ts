/**
 * Static policy evaluation: checks an agent manifest against the five
 * operational controls and the lifecycle, at the strictness its risk tier
 * demands. Pure and dependency-free so it runs in CI, in the API and in
 * the browser playground alike.
 */
import { scoreRisk } from './risk.js';
import { scopeGranted } from './scopes.js';
import type {
  ControlId,
  ControlStatus,
  Evaluation,
  Finding,
  LooseManifest,
  Severity,
  TierPolicy,
  ToolSpec,
  DeepPartial,
} from './types.js';

const DAY_MS = 86_400_000;
const PRINCIPAL_RE = /^svc-agent-[a-z0-9][a-z0-9-]{1,62}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VALID = {
  dataClassification: ['public', 'internal', 'confidential', 'restricted'],
  actions: ['read', 'write', 'transact'],
  exposure: ['internal', 'customer', 'public'],
  reversibility: ['reversible', 'irreversible'],
  stage: ['validation', 'testing', 'production', 'retired'],
  sandbox: ['none', 'process', 'container', 'vm'],
};

export interface EvaluateOptions {
  now?: Date;
}

/** True when an egress entry is an explicit host or a scoped subdomain wildcard. */
export function isExplicitEgress(entry: unknown): boolean {
  if (typeof entry !== 'string' || entry.length === 0) return false;
  if (entry.includes('*')) {
    // Only "*.a.b" style wildcards are allowed — never "*", "*.com" or "a*".
    return /^\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(entry);
  }
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(entry);
}

function parseDate(v: unknown): Date | null {
  if (typeof v !== 'string' && !(v instanceof Date)) return null;
  const d = new Date(v as string);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function evaluate(manifest: LooseManifest, policy: TierPolicy, opts: EvaluateOptions = {}): Evaluation {
  const now = opts.now ?? new Date();
  const m = manifest ?? {};
  const s = m.spec ?? {};
  const { score, tier } = scoreRisk(m, policy);
  const findings: Finding[] = [];
  const check = (rule: string, control: ControlId, severity: Severity, passed: boolean, message: string) =>
    findings.push({ rule, control, severity, passed, message });

  const tools: DeepPartial<ToolSpec>[] = Array.isArray(s.tools) ? s.tools : [];
  const lifecycle = s.lifecycle ?? {};
  const risk = s.risk ?? {};
  const identity = s.identity ?? {};
  const guardrails = s.guardrails ?? {};
  const execution = s.execution ?? {};
  const oversight = s.oversight ?? {};
  const monitoring = oversight.monitoring ?? {};
  const stage = String(lifecycle.stage ?? 'undeclared');
  const isLive = stage === 'testing' || stage === 'production';

  // ── C1 · Risk-proportional oversight ─────────────────────────────────────
  const riskDeclared =
    VALID.dataClassification.includes(String(risk.dataClassification)) &&
    VALID.actions.includes(String(risk.actions)) &&
    VALID.exposure.includes(String(risk.exposure)) &&
    VALID.reversibility.includes(String(risk.reversibility)) &&
    typeof risk.regulated === 'boolean';
  check('C1.1', 'C1', 'error', riskDeclared,
    riskDeclared
      ? `Risk profile declared → scored ${score}, ${tier.label} tier`
      : 'Risk profile incomplete: undeclared attributes are scored at maximum weight (fail closed)');

  const interval = Number(guardsafe(lifecycle.reviewIntervalDays));
  check('C1.2', 'C1', 'error', interval > 0 && interval <= tier.maxReviewDays,
    `Review interval ${interval > 0 ? interval + ' days' : 'undeclared'}; ${tier.label} tier allows at most ${tier.maxReviewDays} days`);

  const lastReview = parseDate(lifecycle.lastReview);
  if (!lastReview) {
    check('C1.3', 'C1', 'error', false, 'No lastReview date recorded');
  } else {
    const due = new Date(lastReview.getTime() + (interval > 0 ? interval : tier.maxReviewDays) * DAY_MS);
    const current = due.getTime() >= now.getTime();
    check('C1.3', 'C1', 'warning', current,
      current
        ? `Governance review current (next due ${due.toISOString().slice(0, 10)})`
        : `Governance review overdue since ${due.toISOString().slice(0, 10)} — drift`);
  }

  if (tier.requireKillSwitch) {
    check('C1.4', 'C1', 'error', monitoring.killSwitch === true,
      monitoring.killSwitch === true ? 'Kill switch wired' : `${tier.label} tier requires a kill switch (oversight.monitoring.killSwitch)`);
  }

  // ── C2 · Deterministic guardrails ────────────────────────────────────────
  check('C2.1', 'C2', 'error', guardrails.denyOnUnknownTool === true,
    guardrails.denyOnUnknownTool === true ? 'Unknown tools are denied by default' : 'denyOnUnknownTool must be true: tools are allow-listed, never open-ended');

  const maxDen = guardrails.maxConsecutiveDenials;
  const breakerOk = Number.isInteger(maxDen) && (maxDen as number) >= 1 && (maxDen as number) <= 3;
  check('C2.2', 'C2', 'error', breakerOk,
    breakerOk
      ? `Circuit breaker quarantines the agent after ${maxDen} consecutive denials`
      : 'No circuit breaker (maxConsecutiveDenials 1–3): an agent told "no" can keep probing for a way round');

  check('C2.3', 'C2', 'error', tools.length > 0, tools.length > 0 ? `${tools.length} tool(s) allow-listed` : 'No tools declared');

  const unschematised = tools.filter((t) => !t.args || typeof t.args !== 'object').map((t) => t.name);
  check('C2.4', 'C2', 'error', unschematised.length === 0,
    unschematised.length === 0 ? 'Every tool validates its arguments against a schema' : `Tools without an argument schema: ${unschematised.join(', ')}`);

  const unconstrained: string[] = [];
  for (const t of tools) {
    for (const [name, a] of Object.entries(t.args ?? {})) {
      if (a?.type === 'string' && !a.pattern && !a.enum && !a.maxLength) unconstrained.push(`${t.name}.${name}`);
    }
  }
  check('C2.5', 'C2', 'error', unconstrained.length === 0,
    unconstrained.length === 0 ? 'All string arguments are constrained (pattern, enum or maxLength)' : `Unconstrained string arguments: ${unconstrained.join(', ')}`);

  const noRate = tools.filter((t) => !(Number(t.rateLimitPerMinute) > 0)).map((t) => t.name);
  check('C2.6', 'C2', tier.requireRateLimits ? 'error' : 'warning', noRate.length === 0,
    noRate.length === 0 ? 'Every tool is rate limited' : `Tools without a rate limit: ${noRate.join(', ')}`);

  const transacting = tools.filter((t) => t.effect === 'transact');
  if (transacting.length > 0) {
    const uncapped = transacting.filter((t) => !(Number(t.maxAmount) > 0)).map((t) => t.name);
    const daily = Number(guardrails.spendLimitPerDay) > 0;
    check('C2.7', 'C2', 'error', uncapped.length === 0 && daily,
      uncapped.length === 0 && daily
        ? `Transactions capped per call and at ${guardrails.spendLimitPerDay}/day`
        : `Transacting tools need maxAmount and a daily spendLimitPerDay${uncapped.length ? ` (uncapped: ${uncapped.join(', ')})` : ''}`);
  }

  // ── C3 · Agents as privileged identities ─────────────────────────────────
  const principal = String(identity.principal ?? '');
  check('C3.1', 'C3', 'error', PRINCIPAL_RE.test(principal),
    PRINCIPAL_RE.test(principal) ? `Dedicated non-human principal ${principal}` : 'Agent must run as its own service principal (svc-agent-*), never a shared or human account');

  const owner = String(m.metadata?.owner ?? '');
  check('C3.2', 'C3', 'error', EMAIL_RE.test(owner),
    EMAIL_RE.test(owner) ? `Named owner of record: ${owner}` : 'A named, accountable human owner (email) is required');

  const ttl = Number(identity.credentialTtlMinutes);
  check('C3.3', 'C3', 'error', ttl > 0 && ttl <= tier.maxCredentialTtlMinutes,
    `Credential lifetime ${ttl > 0 ? ttl + ' min' : 'undeclared'}; ${tier.label} tier allows at most ${tier.maxCredentialTtlMinutes} min`);

  const scopes: string[] = Array.isArray(identity.scopes) ? identity.scopes.map(String) : [];
  const wildcard = scopes.filter((x) => x === '*' || x.endsWith(':*') || x.endsWith('*'));
  check('C3.4', 'C3', 'error', scopes.length > 0 && wildcard.length === 0,
    wildcard.length ? `Wildcard scopes are standing privilege: ${wildcard.join(', ')}` : scopes.length ? 'Scopes are explicit (least privilege)' : 'No scopes declared');

  const ungranted = tools.filter((t) => !t.scope || !scopeGranted(scopes, String(t.scope))).map((t) => `${t.name} (${t.scope ?? 'no scope'})`);
  check('C3.5', 'C3', 'error', ungranted.length === 0,
    ungranted.length === 0 ? 'Every tool maps to a granted scope' : `Tools whose scope is not granted: ${ungranted.join(', ')}`);

  const used = new Set(tools.map((t) => String(t.scope)));
  const excess = scopes.filter((x) => !wildcard.includes(x) && !used.has(x));
  check('C3.6', 'C3', 'warning', excess.length === 0,
    excess.length === 0 ? 'No unused privileges' : `Granted but unused scopes (excess privilege): ${excess.join(', ')}`);

  // ── C4 · Isolated execution ──────────────────────────────────────────────
  const sandbox = String(execution.sandbox ?? 'none');
  check('C4.1', 'C4', 'error', (tier.allowedSandboxes as string[]).includes(sandbox),
    `Runs in "${sandbox}"; ${tier.label} tier allows ${tier.allowedSandboxes.join(' | ')}`);

  const egress: unknown[] = Array.isArray(execution.network?.egress) ? execution.network!.egress! : [];
  const loose = egress.filter((e) => !isExplicitEgress(e)).map(String);
  check('C4.2', 'C4', 'error', loose.length === 0,
    loose.length === 0
      ? egress.length ? `Egress allow-list: ${egress.join(', ')}` : 'No network egress'
      : `Egress must be an explicit allow-list; rejected entries: ${loose.join(', ')}`);

  if (execution.productionDataAccess === true) {
    check('C4.3', 'C4', 'error', typeof execution.dataBroker === 'string' && execution.dataBroker.length > 0,
      execution.dataBroker ? `Production data reached only through broker ${execution.dataBroker}` : 'Production data access must go through a mediating data broker');
  }

  // ── C5 · Human-in-the-loop ───────────────────────────────────────────────
  const consequential = tools.filter((t) => t.effect === 'transact' || t.irreversible === true);
  const ungated = consequential.filter((t) => t.requiresApproval !== true).map((t) => t.name);
  check('C5.1', 'C5', 'error', ungated.length === 0,
    consequential.length === 0
      ? 'No irreversible or transacting tools'
      : ungated.length === 0
        ? `Human approval gates: ${consequential.map((t) => t.name).join(', ')}`
        : `Irreversible/transacting tools without an approval gate: ${ungated.join(', ')}`);

  const gated = tools.some((t) => t.requiresApproval === true);
  if (gated) {
    const approvers: string[] = Array.isArray(oversight.approvers) ? oversight.approvers.map(String) : [];
    check('C5.2', 'C5', 'error', approvers.length > 0, approvers.length ? `Approvers: ${approvers.join(', ')}` : 'Approval-gated tools need named approvers');
    const independent = approvers.some((a) => a !== owner);
    check('C5.3', 'C5', 'warning', independent,
      independent ? 'At least one approver is independent of the owner' : 'Separation of duties: the owner should not be the only approver');
  }

  // ── LC · Lifecycle ───────────────────────────────────────────────────────
  check('LC.1', 'LC', 'error', VALID.stage.includes(stage), `Lifecycle stage: ${stage}`);

  const v = lifecycle.validated;
  const validated = !!(v && parseDate(v.date) && v.by && v.useCase);
  check('LC.2', 'LC', isLive ? 'error' : 'warning', validated,
    validated ? `Use case validated ${String(v!.date).slice(0, 10)} by ${v!.by}` : 'Use case not validated (validated.date, by, useCase)');

  if (stage === 'production') {
    const observed = monitoring.telemetry === true && monitoring.alertOnDenials === true;
    check('LC.4', 'LC', 'error', observed,
      observed ? 'Behavioural telemetry on; denials raise alerts' : 'Production agents need telemetry and alerting on denied actions');
    const supported = !!lifecycle.runbook && !!lifecycle.support?.onCall;
    check('LC.5', 'LC', 'error', supported,
      supported ? `Runbook ${lifecycle.runbook}; on-call ${lifecycle.support!.onCall}` : 'Production agents need a runbook and an on-call owner');
  }

  return finalize({
    agentId: String(m.metadata?.id ?? 'unknown'),
    name: String(m.metadata?.name ?? m.metadata?.id ?? 'Unnamed agent'),
    owner,
    team: m.metadata?.team,
    stage,
    tier: tier.tier,
    tierLabel: tier.label,
    riskScore: score,
    findings,
  });
}

function guardsafe(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Roll findings up into per-control status and an overall verdict. */
export function finalize(e: Omit<Evaluation, 'controls' | 'compliant'>): Evaluation {
  const controls = { C1: 'pass', C2: 'pass', C3: 'pass', C4: 'pass', C5: 'pass', LC: 'pass' } as Record<ControlId, ControlStatus>;
  for (const f of e.findings) {
    if (f.passed) continue;
    if (f.severity === 'error') controls[f.control] = 'fail';
    else if (controls[f.control] !== 'fail') controls[f.control] = 'warn';
  }
  const compliant = !e.findings.some((f) => !f.passed && f.severity === 'error');
  return { ...e, controls, compliant };
}
