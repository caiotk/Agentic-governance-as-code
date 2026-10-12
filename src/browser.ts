/**
 * Browser entry for the dashboard playground: the same static rules CI runs,
 * bundled with esbuild. Adversarial probes need the runtime and run in CI.
 */
import { parse } from 'yaml';
import { evaluate } from './evaluate.js';
import { assertPolicy, scoreRisk } from './risk.js';
import type { LooseManifest } from './types.js';

export function evaluateYaml(text: string, policyDoc: unknown) {
  const policy = assertPolicy(policyDoc);
  let manifest: LooseManifest;
  try {
    manifest = parse(text) as LooseManifest;
  } catch (err) {
    return { error: `YAML error: ${(err as Error).message}` };
  }
  if (!manifest || typeof manifest !== 'object') return { error: 'The manifest must be a YAML mapping.' };
  const evaluation = evaluate(manifest, policy);
  const { breakdown, tier } = scoreRisk(manifest, policy);
  return { evaluation, breakdown, requiredProbes: tier.requiredProbes };
}
