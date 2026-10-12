import type { LooseManifest, TierDefinition, TierPolicy } from './types.js';

/** Validate a parsed tier policy document. Throws on anything malformed. */
export function assertPolicy(doc: unknown): TierPolicy {
  const p = doc as TierPolicy;
  if (!p || p.kind !== 'TierPolicy') throw new Error('policy: kind must be TierPolicy');
  if (!p.scoring || typeof p.scoring !== 'object') throw new Error('policy: scoring missing');
  for (const k of ['dataClassification', 'actions', 'exposure'] as const) {
    if (!p.scoring[k] || typeof p.scoring[k] !== 'object') throw new Error(`policy: scoring.${k} missing`);
  }
  if (!Array.isArray(p.tiers) || p.tiers.length === 0) throw new Error('policy: tiers missing');
  const sorted = [...p.tiers].sort((a, b) => a.maxScore - b.maxScore);
  sorted.forEach((t, i) => {
    if (t.tier !== i + 1) throw new Error('policy: tiers must be numbered 1..n in ascending maxScore order');
    if (!Array.isArray(t.requiredProbes) || !Array.isArray(t.allowedSandboxes)) {
      throw new Error(`policy: tier ${t.tier} is incomplete`);
    }
  });
  return { ...p, tiers: sorted };
}

/** Highest weight in a scoring table — used for unknown values so we fail closed. */
const worst = (table: Record<string, number>) => Math.max(...Object.values(table));

const weight = (table: Record<string, number>, value: unknown) =>
  typeof value === 'string' && Object.prototype.hasOwnProperty.call(table, value) ? table[value] : worst(table);

export interface RiskAssessment {
  score: number;
  tier: TierDefinition;
  breakdown: Array<{ factor: string; value: string; points: number }>;
}

export function scoreRisk(manifest: LooseManifest, policy: TierPolicy): RiskAssessment {
  const r = manifest.spec?.risk ?? {};
  const s = policy.scoring;
  const breakdown = [
    { factor: 'dataClassification', value: String(r.dataClassification ?? 'undeclared'), points: weight(s.dataClassification, r.dataClassification) },
    { factor: 'actions', value: String(r.actions ?? 'undeclared'), points: weight(s.actions, r.actions) },
    { factor: 'exposure', value: String(r.exposure ?? 'undeclared'), points: weight(s.exposure, r.exposure) },
    {
      factor: 'reversibility',
      value: String(r.reversibility ?? 'undeclared'),
      // Anything not explicitly reversible is treated as irreversible.
      points: r.reversibility === 'reversible' ? 0 : s.irreversible,
    },
    {
      factor: 'regulated',
      value: String(r.regulated ?? 'undeclared'),
      points: r.regulated === false ? 0 : r.regulated === true ? s.regulated : s.regulated,
    },
  ];
  const score = breakdown.reduce((n, b) => n + b.points, 0);
  const tier = policy.tiers.find((t) => score <= t.maxScore) ?? policy.tiers[policy.tiers.length - 1];
  return { score, tier, breakdown };
}
