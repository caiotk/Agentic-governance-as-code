/**
 * Node-side assessment: load policy and manifests from disk, run the static
 * evaluation, then execute the adversarial probes the agent's tier requires.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { parse } from 'yaml';
import { evaluate, finalize } from './evaluate.js';
import { runProbe } from './probes.js';
import { assertPolicy, scoreRisk } from './risk.js';
import type { AgentManifest, Evaluation, LooseManifest, ProbeResult, TierPolicy } from './types.js';

export interface Assessment {
  file: string;
  manifest: LooseManifest;
  evaluation: Evaluation;
  probes: ProbeResult[];
}

export function loadPolicy(path = 'policy/tiers.yaml'): TierPolicy {
  return assertPolicy(parse(readFileSync(path, 'utf8')));
}

export function listManifests(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => /\.ya?ml$/i.test(f))
    .sort()
    .map((f) => join(dir, f));
}

export function loadManifest(file: string): LooseManifest {
  const doc = parse(readFileSync(file, 'utf8'));
  if (!doc || typeof doc !== 'object') throw new Error(`${file}: not a YAML mapping`);
  return doc as LooseManifest;
}

export function assess(file: string, policy: TierPolicy, opts: { now?: Date; root?: string } = {}): Assessment {
  const root = opts.root ?? process.cwd();
  let manifest: LooseManifest;
  try {
    manifest = loadManifest(file);
  } catch (err) {
    const evaluation = finalize({
      agentId: relative(root, file),
      name: relative(root, file),
      owner: '',
      stage: 'unknown',
      tier: 3,
      tierLabel: policy.tiers[policy.tiers.length - 1].label,
      riskScore: 0,
      findings: [{ rule: 'LC.0', control: 'LC', severity: 'error', passed: false, message: `Manifest could not be parsed: ${(err as Error).message}` }],
    });
    return { file, manifest: {}, evaluation, probes: [] };
  }

  const base = evaluate(manifest, policy, { now: opts.now });
  const findings = [...base.findings];

  if (manifest.kind !== 'Agent' || manifest.apiVersion !== 'governance/v1') {
    findings.push({ rule: 'LC.0', control: 'LC', severity: 'error', passed: false, message: 'Manifest must be apiVersion governance/v1, kind Agent' });
  }

  // Lifecycle · Support: the runbook a manifest points at must actually exist.
  const runbook = manifest.spec?.lifecycle?.runbook;
  if (runbook) {
    const exists = existsSync(resolve(root, String(runbook)));
    findings.push({ rule: 'LC.6', control: 'LC', severity: 'error', passed: exists, message: exists ? `Runbook present at ${runbook}` : `Runbook ${runbook} does not exist` });
  }

  // Lifecycle · Test: run the adversarial probes this tier requires.
  const { tier } = scoreRisk(manifest, policy);
  const probes = tier.requiredProbes.map((id) => runProbe(id, manifest as AgentManifest));
  for (const p of probes) {
    findings.push({
      rule: `LC.3:${p.id}`,
      control: p.control,
      severity: 'error',
      passed: p.passed,
      message: `${p.passed ? 'Probe passed' : 'Probe FAILED'} — ${p.title}: ${p.summary}`,
    });
  }

  return { file, manifest, evaluation: finalize({ ...base, findings }), probes };
}

export function assessDir(dir: string, policy: TierPolicy, opts: { now?: Date; root?: string } = {}): Assessment[] {
  return listManifests(dir).map((f) => assess(f, policy, opts));
}
