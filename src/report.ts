import { readFileSync } from 'node:fs';
import type { Assessment } from './assess.js';
import { CONTROLS, type ControlId, type ControlStatus, type TierPolicy } from './types.js';

const ICON: Record<ControlStatus, string> = { pass: '✅', warn: '⚠️', fail: '❌' };
const COLS: ControlId[] = ['C1', 'C2', 'C3', 'C4', 'C5', 'LC'];

export function gateMarkdown(results: Assessment[], opts: { title?: string; commit?: string } = {}): string {
  const blocked = results.filter((r) => !r.evaluation.compliant);
  const lines: string[] = [];
  lines.push(`## ${opts.title ?? 'Agent governance gate'}`);
  lines.push('');
  lines.push(
    blocked.length === 0
      ? `**PASSED** — ${results.length} agent(s) meet the controls their risk tier requires.`
      : `**BLOCKED** — ${blocked.length} of ${results.length} agent(s) do not meet the controls their risk tier requires. This change cannot be deployed.`,
  );
  if (opts.commit) lines.push(`\n<sub>Evaluated at ${opts.commit}</sub>`);
  lines.push('');
  lines.push(`| Agent | Tier | Stage | ${COLS.map((c) => `${c}`).join(' | ')} | Result |`);
  lines.push(`|---|---|---|${COLS.map(() => ':-:').join('|')}|---|`);
  for (const r of results) {
    const e = r.evaluation;
    lines.push(
      `| \`${e.agentId}\` | ${e.tier} · ${e.tierLabel} | ${e.stage} | ${COLS.map((c) => ICON[e.controls[c]]).join(' | ')} | ${e.compliant ? 'Deployable' : '**Blocked**'} |`,
    );
  }
  lines.push('');
  lines.push(`<sub>${COLS.map((c) => `${c} ${CONTROLS[c]}`).join(' · ')}</sub>`);

  for (const r of results) {
    const failed = r.evaluation.findings.filter((f) => !f.passed);
    if (failed.length === 0) continue;
    lines.push('');
    lines.push(`### ${r.evaluation.compliant ? '⚠️' : '❌'} \`${r.evaluation.agentId}\` — ${r.file}`);
    for (const f of failed) {
      lines.push(`- ${f.severity === 'error' ? '❌' : '⚠️'} **${f.rule}** (${CONTROLS[f.control]}): ${f.message}`);
    }
    const failedProbes = r.probes.filter((p) => !p.passed);
    for (const p of failedProbes) {
      lines.push('');
      lines.push(`<details><summary>Probe transcript: ${p.title}</summary>\n`);
      lines.push('| Step | Expected | Decision | Reason |');
      lines.push('|---|---|---|---|');
      for (const s of p.steps) lines.push(`| ${s.ok ? '✅' : '❌'} ${s.label} | ${s.expected} | \`${s.decision}\` | ${s.reason.replace(/\|/g, '\\|')} |`);
      lines.push('\n</details>');
    }
  }
  return lines.join('\n') + '\n';
}

export interface DriftItem {
  agent: string;
  file: string;
  owner: string;
  issues: string[];
}

export function findDrift(results: Assessment[]): DriftItem[] {
  return results
    .map((r) => ({
      agent: r.evaluation.agentId,
      file: r.file,
      owner: r.evaluation.owner,
      issues: r.evaluation.findings.filter((f) => !f.passed).map((f) => `${f.rule}: ${f.message}`),
    }))
    .filter((d) => d.issues.length > 0);
}

export function driftMarkdown(items: DriftItem[], when: Date): string {
  const lines = [`## Governance drift report — ${when.toISOString().slice(0, 10)}`, ''];
  if (items.length === 0) {
    lines.push('No drift: every registered agent is within its review cycle and controls.');
    return lines.join('\n') + '\n';
  }
  lines.push(`${items.length} agent(s) have drifted from policy. Owners: please review, re-attest and update the manifest via pull request.`, '');
  for (const d of items) {
    lines.push(`### \`${d.agent}\` — owner ${d.owner || 'unassigned'}`);
    lines.push(`Manifest: \`${d.file}\``);
    for (const i of d.issues) lines.push(`- [ ] ${i}`);
    lines.push('');
  }
  lines.push('<sub>Opened automatically by the drift monitor. It updates this issue daily and closes it when drift clears.</sub>');
  return lines.join('\n') + '\n';
}

export function buildReport(agents: Assessment[], examples: Assessment[], policy: TierPolicy, meta: { repo?: string; commit?: string }) {
  const all = agents.map((a) => toEntry(a, false)).concat(examples.map((a) => toEntry(a, true)));
  const controlRate = Object.fromEntries(
    (Object.keys(CONTROLS) as ControlId[]).map((c) => [c, agents.filter((a) => a.evaluation.controls[c] === 'pass').length]),
  );
  const probes = agents.flatMap((a) => a.probes.filter((p) => p.applicable));
  return {
    generatedAt: new Date().toISOString(),
    repo: meta.repo,
    commit: meta.commit,
    controls: CONTROLS,
    policy,
    summary: {
      agents: agents.length,
      compliant: agents.filter((a) => a.evaluation.compliant).length,
      drift: agents.filter((a) => a.evaluation.findings.some((f) => !f.passed && f.severity === 'warning')).length,
      probesRun: probes.length,
      probesPassed: probes.filter((p) => p.passed).length,
      byTier: [1, 2, 3].map((t) => agents.filter((a) => a.evaluation.tier === t).length),
      controlPass: controlRate,
    },
    agents: all,
  };
}

function toEntry(a: Assessment, example: boolean) {
  const s = a.manifest.spec ?? {};
  return {
    example,
    file: a.file,
    // Manifests ship their YAML so the dashboard playground can load them.
    source: readFileSync(a.file, 'utf8'),
    evaluation: a.evaluation,
    probes: a.probes,
    profile: {
      description: a.manifest.metadata?.description,
      principal: s.identity?.principal,
      ttl: s.identity?.credentialTtlMinutes,
      scopes: s.identity?.scopes,
      sandbox: s.execution?.sandbox,
      egress: s.execution?.network?.egress,
      tools: (s.tools ?? []).map((t) => ({ name: t?.name, effect: t?.effect, approval: !!t?.requiresApproval })),
      approvers: s.oversight?.approvers,
      risk: s.risk,
      lastReview: s.lifecycle?.lastReview,
      reviewIntervalDays: s.lifecycle?.reviewIntervalDays,
    },
  };
}
