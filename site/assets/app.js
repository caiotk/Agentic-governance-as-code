// Agent Governance Control Plane — dashboard
// Reads data/report.json (built by CI from the agents/ manifests) and renders
// the control matrix, probe replays and an in-browser manifest playground.

const COLS = ['C1', 'C2', 'C3', 'C4', 'C5', 'LC'];
const LABEL = { pass: 'PASS', warn: 'WARN', fail: 'FAIL' };
const GLYPH = { pass: '✓', warn: '!', fail: '✕' };

const $ = (sel) => document.querySelector(sel);
const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

let report;
let selected;

const pill = (status) => `<span class="pill ${status}"><span aria-hidden="true">${GLYPH[status]}</span>${LABEL[status]}</span>`;

function renderStats() {
  const s = report.summary;
  const tiles = [
    { n: s.agents, l: 'agents registered' },
    { n: `${s.compliant}<small>/${s.agents}</small>`, l: 'pass the governance gate' },
    { n: `${s.probesPassed}<small>/${s.probesRun}</small>`, l: 'adversarial probes held' },
    { n: s.drift, l: s.drift === 1 ? 'agent with review drift' : 'agents with review drift' },
  ];
  $('#stats').innerHTML = tiles.map((t) => `<div class="stat"><div class="n">${t.n}</div><div class="l">${esc(t.l)}</div></div>`).join('');
  const when = new Date(report.generatedAt);
  const commit = report.commit ? ` · commit ${esc(report.commit)}` : '';
  $('#meta').innerHTML = `Report generated ${esc(when.toISOString().replace('T', ' ').slice(0, 16))} UTC${commit}`;
  $('#footer-meta').textContent = `Policy ${report.policy.apiVersion} · ${report.policy.tiers.length} risk tiers`;
  if (report.repo) $('#repo-link').href = `https://github.com/${report.repo}`;
}

function row(a) {
  const e = a.evaluation;
  return `<tr class="${selected === a ? 'selected' : ''}">
    <td><button type="button" class="agent-btn" data-id="${esc(a.file)}" aria-pressed="${selected === a}">
      <span class="nm">${esc(e.name)}${a.example ? '<span class="badge">example</span>' : ''}</span>
      <span class="ow">${esc(e.owner || 'no named owner')}</span></button></td>
    <td class="tier">${e.tier} · ${esc(e.tierLabel)}</td>
    <td class="tier">${esc(e.stage)}</td>
    ${COLS.map((c) => `<td>${pill(e.controls[c])}</td>`).join('')}
    <td><span class="gate ${e.compliant ? 'ok' : 'no'}">${e.compliant ? 'DEPLOYABLE' : 'BLOCKED'}</span></td>
  </tr>`;
}

function renderMatrix() {
  const live = report.agents.filter((a) => !a.example);
  const examples = report.agents.filter((a) => a.example);
  let html = live.map(row).join('');
  if (examples.length) {
    html += `<tr class="divider"><td colspan="10">Examples · evaluated for illustration, never deployed</td></tr>`;
    html += examples.map(row).join('');
  }
  $('#matrix-body').innerHTML = html;
  document.querySelectorAll('.agent-btn').forEach((b) =>
    b.addEventListener('click', () => {
      selected = report.agents.find((a) => a.file === b.dataset.id);
      renderMatrix();
      renderDetail();
      $('#detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }),
  );
}

function transcript(steps) {
  return `<ol class="transcript">${steps
    .map((s) => {
      const target = s.call.url ? ` → ${esc(s.call.url)}` : '';
      const amount = s.call.amount !== undefined ? ` · amount ${esc(s.call.amount)}` : '';
      const note = s.call.note ? ` · ${esc(s.call.note)}` : '';
      return `<li><span class="dot ${s.ok ? 'ok' : 'bad'}" aria-label="${s.ok ? 'as expected' : 'control failed'}">${s.ok ? '✓' : '✕'}</span>
        <div><div class="t-label">${esc(s.label)}</div>
        <div class="t-call">${esc(s.call.tool)}${target}${amount}${note}</div>
        <div class="t-out">expected ${esc(s.expected)} · got <code class="${esc(s.decision)}">${esc(s.decision)}</code> — ${esc(s.reason)}</div></div></li>`;
    })
    .join('')}</ol>`;
}

function findingsByControl(findings) {
  return COLS.map((c) => {
    const fs = findings.filter((f) => f.control === c);
    if (!fs.length) return '';
    const worst = fs.some((f) => !f.passed && f.severity === 'error') ? 'fail' : fs.some((f) => !f.passed) ? 'warn' : 'pass';
    return `<div class="finding-group"><h5>${pill(worst)} ${esc(c)} · ${esc(report.controls[c])}</h5>
      <ul class="findings-list">${fs
        .map((f) => {
          const st = f.passed ? 'pass' : f.severity === 'error' ? 'fail' : 'warn';
          return `<li><span class="mark ${st}">${LABEL[st]}</span><span class="rule">${esc(f.rule.split(':')[0])}</span><span>${esc(f.message)}</span></li>`;
        })
        .join('')}</ul></div>`;
  }).join('');
}

function renderDetail() {
  if (!selected) return;
  const a = selected;
  const e = a.evaluation;
  const p = a.profile;
  const tools = (p.tools || [])
    .map((t) => `<li><code>${esc(t.name)}</code> <span class="muted">${esc(t.effect)}</span>${t.approval ? '<span class="tag">human approval</span>' : ''}</li>`)
    .join('');
  const probes = a.probes
    .filter((x) => x.applicable)
    .map((x) => `<details class="probe"><summary>${pill(x.passed ? 'pass' : 'fail')}<span>${esc(x.title)}</span></summary>
      <div class="body"><p class="muted">${esc(x.summary)}</p>${transcript(x.steps)}</div></details>`)
    .join('');
  $('#detail').innerHTML = `<article class="detail-card">
    <div class="detail-head"><div><h3>${esc(e.name)}</h3><p>${esc(p.description || '')}</p></div>
      <span class="gate ${e.compliant ? 'ok' : 'no'}">${e.compliant ? 'DEPLOYABLE' : 'BLOCKED'}</span></div>
    <div class="detail-grid">
      <div class="profile"><h4>Profile</h4><dl class="profile-list">
        <dt>Manifest</dt><dd><code>${esc(a.file)}</code></dd>
        <dt>Risk</dt><dd>${esc(e.tier)} · ${esc(e.tierLabel)} (score ${esc(e.riskScore)})</dd>
        <dt>Owner</dt><dd>${esc(e.owner || '—')}</dd>
        <dt>Principal</dt><dd><code>${esc(p.principal || '—')}</code></dd>
        <dt>Credential</dt><dd>${esc(p.ttl ?? '—')} min · ${esc((p.scopes || []).join(', '))}</dd>
        <dt>Sandbox</dt><dd>${esc(p.sandbox || '—')}</dd>
        <dt>Egress</dt><dd>${esc((p.egress || []).join(', ') || 'none')}</dd>
        <dt>Approvers</dt><dd>${esc((p.approvers || []).join(', ') || '—')}</dd>
        <dt>Review</dt><dd>${esc(p.lastReview || '—')} · every ${esc(p.reviewIntervalDays ?? '—')} days</dd>
        <dt>Tools</dt><dd><ul class="tool-list">${tools}</ul></dd>
      </dl></div>
      <div class="findings"><h4>Findings</h4>${findingsByControl(e.findings)}
        <h4 style="margin-top:20px">Adversarial probes</h4>${probes || '<p class="muted">No probes run.</p>'}</div>
    </div></article>`;
}

function renderReplay() {
  const boundary = (a) => a.probes.find((p) => p.id === 'boundary-probe' && p.applicable);
  const governed = report.agents.find((a) => !a.example && boundary(a) && a.evaluation.tier === 3) || report.agents.find((a) => !a.example && boundary(a));
  const unsafe = report.agents.find((a) => a.example && boundary(a));
  const card = (a, good) => {
    const p = boundary(a);
    return `<article><h3>${esc(a.evaluation.name)}</h3>
      <p class="verdict ${p.passed ? 'good' : 'bad'}">${esc(p.summary)}</p>${transcript(p.steps)}</article>`;
  };
  $('#replay-body').innerHTML = [governed && card(governed, true), unsafe && card(unsafe, false)].filter(Boolean).join('');
}

function setupPlayground() {
  const unsafe = report.agents.find((a) => a.example && a.source);
  const box = $('#yaml');
  if (unsafe) box.value = unsafe.source;
  $('#load-unsafe').addEventListener('click', () => unsafe && (box.value = unsafe.source));
  const governed = report.agents.filter((a) => !a.example && a.source).sort((x, y) => y.evaluation.tier - x.evaluation.tier)[0];
  $('#load-safe').addEventListener('click', () => governed && (box.value = governed.source));
  $('#run').addEventListener('click', async () => {
    const out = $('#play-out');
    try {
      const { evaluateYaml } = await import('./engine.js');
      const r = evaluateYaml(box.value, report.policy);
      if (r.error) {
        out.innerHTML = `<p class="error">${esc(r.error)}</p>`;
        return;
      }
      const e = r.evaluation;
      out.innerHTML = `<div class="play-verdict"><strong>${esc(e.name)}</strong>
          <span class="gate ${e.compliant ? 'ok' : 'no'}">${e.compliant ? 'PASSES STATIC GATE' : 'BLOCKED'}</span></div>
        <p class="breakdown">${e.tier} · ${esc(e.tierLabel)} — risk score ${e.riskScore} = ${r.breakdown.map((b) => `${esc(b.factor)} ${esc(b.value)} (+${b.points})`).join(' · ')}</p>
        <div class="controls-row">${COLS.map((c) => `<span>${esc(c)} ${pill(e.controls[c])}</span>`).join('')}</div>
        ${findingsByControl(e.findings)}
        <p class="muted">CI would also run these probes against the live guard: ${r.requiredProbes.map((x) => `<code>${esc(x)}</code>`).join(', ')}.</p>`;
    } catch (err) {
      out.innerHTML = `<p class="error">The policy engine could not load: ${esc(err.message)}</p>`;
    }
  });
}

async function main() {
  try {
    const res = await fetch('data/report.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    report = await res.json();
  } catch (err) {
    $('#meta').innerHTML = `<span class="error">Could not load data/report.json (${esc(err.message)}). Run <code>npm run build:site</code>.</span>`;
    return;
  }
  selected = report.agents.find((a) => !a.example && !a.evaluation.compliant) || report.agents.find((a) => !a.example && a.evaluation.findings.some((f) => !f.passed)) || report.agents[0];
  renderStats();
  renderMatrix();
  renderDetail();
  renderReplay();
  setupPlayground();
}

main();
