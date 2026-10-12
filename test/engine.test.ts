import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { assess, loadManifest, loadPolicy } from '../src/assess.js';
import { evaluate, isExplicitEgress } from '../src/evaluate.js';
import { ApprovalStore, AuditLog, egressAllowed, Guard, IdentityIssuer, ManualClock, validateArgs } from '../src/guard.js';
import { runProbe } from '../src/probes.js';
import { scoreRisk } from '../src/risk.js';
import { scopeGranted } from '../src/scopes.js';
import type { AgentManifest } from '../src/types.js';

const policy = loadPolicy();
const NOW = new Date('2026-10-13T00:00:00Z');
const claims = loadManifest('agents/claims-payment-agent.yaml') as AgentManifest;
const unsafe = loadManifest('examples/unsafe/market-research-agent.yaml') as AgentManifest;
const clone = <T>(x: T): T => structuredClone(x);
const failed = (m: unknown) =>
  evaluate(m as AgentManifest, policy, { now: NOW }).findings.filter((f) => !f.passed).map((f) => f.rule);

function rig(m: AgentManifest) {
  const clock = new ManualClock(NOW.getTime());
  const identity = new IdentityIssuer('test-secret-at-least-sixteen', clock);
  const audit = new AuditLog();
  const approvals = new ApprovalStore(clock);
  const guard = new Guard(m, { identity, audit, approvals, clock });
  return { clock, identity, audit, approvals, guard, token: identity.issue(m) };
}

describe('C1 · risk-proportional oversight', () => {
  it('scores the sample agents into three different tiers', () => {
    const tiers = ['meeting-summariser', 'customer-support-agent', 'claims-payment-agent'].map(
      (id) => scoreRisk(loadManifest(`agents/${id}.yaml`), policy).tier.tier,
    );
    assert.deepEqual(tiers, [1, 2, 3]);
  });

  it('fails closed: an undeclared risk profile lands in the highest tier', () => {
    assert.equal(scoreRisk({}, policy).tier.tier, 3);
  });

  it('flags an overdue review as drift (warning), not a hard failure', () => {
    const e = evaluate(claims, policy, { now: NOW });
    const review = e.findings.find((f) => f.rule === 'C1.3')!;
    assert.equal(review.passed, false);
    assert.equal(review.severity, 'warning');
    assert.equal(e.compliant, true);
    assert.equal(e.controls.C1, 'warn');
  });

  it('holds higher tiers to tighter credential lifetimes', () => {
    const m = clone(claims);
    m.spec.identity.credentialTtlMinutes = 30;
    assert.ok(failed(m).includes('C3.3'));
  });
});

describe('static gate', () => {
  // Unit tests pin the reference manifests; judging whatever is in agents/ is the gate's job.
  it('passes the three reference agents', () => {
    for (const id of ['meeting-summariser', 'customer-support-agent', 'claims-payment-agent']) {
      assert.equal(assess(`agents/${id}.yaml`, policy, { now: NOW }).evaluation.compliant, true, id);
    }
  });

  it('blocks the unsafe example on every control it violates', () => {
    const a = assess('examples/unsafe/market-research-agent.yaml', policy, { now: NOW });
    assert.equal(a.evaluation.compliant, false);
    for (const rule of ['C2.1', 'C2.2', 'C2.5', 'C3.1', 'C3.4', 'C4.1', 'C4.2', 'LC.4']) {
      assert.ok(a.evaluation.findings.some((f) => f.rule === rule && !f.passed), rule);
    }
  });

  it('requires approval gates on transacting tools', () => {
    const m = clone(claims);
    m.spec.tools.find((t) => t.name === 'payments.issue')!.requiresApproval = false;
    assert.ok(failed(m).includes('C5.1'));
  });

  it('rejects open or vague egress', () => {
    assert.equal(isExplicitEgress('*'), false);
    assert.equal(isExplicitEgress('*.com'), false);
    assert.equal(isExplicitEgress('api.example.com'), true);
    assert.equal(isExplicitEgress('*.internal.example.com'), true);
  });
});

describe('C2 · deterministic guardrails (runtime)', () => {
  it('validates arguments strictly', () => {
    const spec = { id: { type: 'string' as const, pattern: 'CLM-[0-9]{6}' } };
    assert.equal(validateArgs(spec, { id: 'CLM-123456' }), null);
    assert.match(validateArgs(spec, { id: 'CLM-123456; DROP' })!, /does not match/);
    assert.match(validateArgs(spec, { id: 'CLM-123456', extra: 1 })!, /unexpected/);
  });

  it('trips the circuit breaker after consecutive denials and stays tripped', () => {
    const r = rig(claims);
    for (let i = 0; i < 3; i++) r.guard.authorize(r.token, { tool: 'shell.exec' });
    assert.equal(r.guard.isQuarantined, true);
    const legit = r.guard.authorize(r.token, { tool: 'claims.lookup', args: { claimId: 'CLM-104233' } });
    assert.equal(legit.decision, 'quarantined');
    r.guard.release('on-call-lead@example.com');
    assert.equal(r.guard.authorize(r.token, { tool: 'claims.lookup', args: { claimId: 'CLM-104233' } }).decision, 'allow');
  });

  it('enforces rate limits', () => {
    const r = rig(claims);
    const call = { tool: 'claims.lookup', args: { claimId: 'CLM-104233' } };
    for (let i = 0; i < 30; i++) assert.equal(r.guard.authorize(r.token, call).decision, 'allow');
    assert.equal(r.guard.authorize(r.token, call).decision, 'deny');
  });
});

describe('C3 · identity', () => {
  it('rejects forged and expired credentials', () => {
    const r = rig(claims);
    const [body] = r.token.split('.');
    assert.equal(r.identity.verify(`${body}.AAAA`).ok, false);
    r.clock.advance(16 * 60_000);
    assert.equal(r.identity.verify(r.token).ok, false);
  });

  it('matches scopes exactly unless a wildcard was granted', () => {
    assert.equal(scopeGranted(['claims:read'], 'claims:write'), false);
    assert.equal(scopeGranted(['claims:*'], 'claims:write'), true);
    assert.equal(scopeGranted(['*'], 'anything'), true);
  });

  it('detects audit log tampering', () => {
    const r = rig(claims);
    r.guard.authorize(r.token, { tool: 'claims.lookup', args: { claimId: 'CLM-104233' } });
    r.guard.authorize(r.token, { tool: 'shell.exec' });
    assert.equal(r.audit.verify().ok, true);
    r.audit.entries[0].reason = 'edited';
    assert.deepEqual(r.audit.verify(), { ok: false, brokenAt: 1 });
  });
});

describe('C4 · isolated execution', () => {
  it('only reaches allow-listed hosts over https on 443', () => {
    const allow = ['api.example.com', '*.internal.example.com'];
    assert.equal(egressAllowed(allow, 'https://api.example.com/x').ok, true);
    assert.equal(egressAllowed(allow, 'https://a.internal.example.com/x').ok, true);
    assert.equal(egressAllowed(allow, 'https://internal.example.com.evil.io/x').ok, false);
    assert.equal(egressAllowed(allow, 'http://api.example.com/x').ok, false);
    assert.equal(egressAllowed(allow, 'https://api.example.com:8443/x').ok, false);
    assert.equal(egressAllowed(allow, 'https://u:p@api.example.com/x').ok, false);
  });
});

describe('C5 · human-in-the-loop', () => {
  it('holds, then allows exactly once with a bound approval', () => {
    const r = rig(claims);
    const call = { tool: 'payments.issue', args: { claimId: 'CLM-104233', currency: 'NZD' }, amount: 1200 };
    assert.equal(r.guard.authorize(r.token, call).decision, 'pending_approval');
    const id = r.approvals.grant({ agent: 'claims-payment-agent', tool: 'payments.issue', amount: 1200, approver: 'claims-lead@example.com' });
    assert.equal(r.guard.authorize(r.token, { ...call, approvalId: id }).decision, 'allow');
    assert.equal(r.guard.authorize(r.token, { ...call, approvalId: id }).decision, 'deny');
  });
});

describe('adversarial probes', () => {
  it('the boundary probe passes for a governed agent and fails for the unsafe one', () => {
    assert.equal(runProbe('boundary-probe', claims).passed, true);
    const p = runProbe('boundary-probe', unsafe);
    assert.equal(p.passed, false);
    assert.ok(p.steps.some((s) => s.decision === 'allow' && s.call.url?.includes('stats-portal')));
  });

  it('every probe the critical tier requires passes for the claims agent', () => {
    for (const id of policy.tiers[2].requiredProbes) assert.equal(runProbe(id, claims).passed, true, id);
  });

  it('an unknown probe is a failure, never a silent pass', () => {
    assert.equal(runProbe('does-not-exist', claims).passed, false);
  });
});
