/**
 * agc — agent governance CLI
 *
 *   validate <dir> [--markdown out.md]      gate: exit 1 if any agent is non-compliant
 *   drift <dir> [--markdown out.md]         monitor: report drift, set GitHub output drift=true|false
 *   report <dir> [--examples dir] --out f   dashboard data (JSON)
 */
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { assessDir, loadPolicy, type Assessment } from './assess.js';
import { buildReport, driftMarkdown, findDrift, gateMarkdown } from './report.js';

const [, , command, dir = 'agents', ...rest] = process.argv;
const flag = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};
const env = process.env;
const commit = env.GITHUB_SHA ? env.GITHUB_SHA.slice(0, 7) : undefined;
const repo = env.GITHUB_REPOSITORY;

function write(path: string | undefined, content: string) {
  if (!path) return;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function summary(md: string) {
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md + '\n');
}

function output(key: string, value: string) {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

/** GitHub annotations put each failed rule on the manifest in the PR diff. */
function annotate(results: Assessment[]) {
  if (!env.GITHUB_ACTIONS) return;
  for (const r of results) {
    for (const f of r.evaluation.findings.filter((x) => !x.passed)) {
      const level = f.severity === 'error' ? 'error' : 'warning';
      const msg = `${f.rule}: ${f.message}`.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
      console.log(`::${level} file=${r.file},title=${r.evaluation.agentId} ${f.rule}::${msg}`);
    }
  }
}

function table(results: Assessment[]) {
  const pad = (s: string, n: number) => s.padEnd(n);
  console.log(`\n${pad('AGENT', 30)}${pad('TIER', 14)}${pad('STAGE', 12)}C1   C2   C3   C4   C5   LC   RESULT`);
  for (const r of results) {
    const e = r.evaluation;
    const cells = (['C1', 'C2', 'C3', 'C4', 'C5', 'LC'] as const).map((c) => pad(e.controls[c].toUpperCase(), 5)).join('');
    console.log(`${pad(e.agentId, 30)}${pad(`${e.tier} ${e.tierLabel}`, 14)}${pad(e.stage, 12)}${cells}${e.compliant ? 'DEPLOYABLE' : 'BLOCKED'}`);
  }
  for (const r of results) {
    const failed = r.evaluation.findings.filter((f) => !f.passed);
    if (!failed.length) continue;
    console.log(`\n${r.evaluation.agentId} (${r.file})`);
    for (const f of failed) console.log(`  ${f.severity === 'error' ? '✗' : '!'} ${f.rule.padEnd(24)} ${f.message}`);
  }
  console.log('');
}

const policy = loadPolicy();

switch (command) {
  case 'validate': {
    const results = assessDir(dir, policy);
    if (results.length === 0) {
      console.error(`No agent manifests found in ${dir}`);
      process.exit(1);
    }
    table(results);
    annotate(results);
    const md = gateMarkdown(results, { commit });
    write(flag('markdown'), md);
    summary(md);
    const blocked = results.filter((r) => !r.evaluation.compliant).length;
    output('blocked', String(blocked));
    console.log(blocked ? `Gate BLOCKED: ${blocked} non-compliant agent(s).` : `Gate PASSED: ${results.length} agent(s) compliant.`);
    process.exit(blocked ? 1 : 0);
  }
  case 'drift': {
    const now = new Date();
    const items = findDrift(assessDir(dir, policy, { now }));
    const md = driftMarkdown(items, now);
    write(flag('markdown'), md);
    summary(md);
    output('drift', items.length ? 'true' : 'false');
    console.log(md);
    process.exit(0);
  }
  case 'report': {
    const out = flag('out') ?? 'site/data/report.json';
    const examples = flag('examples');
    const report = buildReport(assessDir(dir, policy), examples ? assessDir(examples, policy) : [], policy, { repo, commit });
    write(out, JSON.stringify(report, null, 2));
    console.log(`Wrote ${out}: ${report.summary.agents} agents, ${report.summary.compliant} compliant, ${report.summary.probesPassed}/${report.summary.probesRun} probes passed.`);
    process.exit(0);
  }
  default:
    console.error('usage: agc <validate|drift|report> <dir> [--markdown file] [--out file] [--examples dir]');
    process.exit(2);
}
