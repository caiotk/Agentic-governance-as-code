/**
 * Governance control plane — a reference HTTP API.
 *
 * Agents call /authorize before every tool call; the platform gets
 * credentials, approvals, kill switch and the audit trail in one place.
 * Only manifests that pass the governance gate are admitted to runtime.
 *
 *   GOV_SIGNING_SECRET  HMAC secret for agent credentials (random per boot if unset)
 *   ADMIN_KEY           required on admin routes; mandatory when HOST is not loopback
 *   HOST / PORT         default 127.0.0.1:8787
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { parse as parseYaml } from 'yaml';
import { assessDir, loadPolicy, type Assessment } from './assess.js';
import { evaluate } from './evaluate.js';
import { ApprovalStore, AuditLog, Guard, IdentityIssuer } from './guard.js';
import { runProbe } from './probes.js';
import { scoreRisk } from './risk.js';
import type { AgentManifest, LooseManifest, ToolCall } from './types.js';

const HOST = process.env.HOST ?? '127.0.0.1';
const PORT = Number(process.env.PORT ?? 8787);
const ADMIN_KEY = process.env.ADMIN_KEY ?? '';
const LOOPBACK = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
const MAX_BODY = 256 * 1024;

if (!LOOPBACK && ADMIN_KEY.length < 24) {
  console.error('Refusing to start: set ADMIN_KEY (24+ chars) before binding to a non-loopback address.');
  process.exit(1);
}

const policy = loadPolicy();
const identity = new IdentityIssuer(process.env.GOV_SIGNING_SECRET ?? randomBytes(32).toString('hex'));
const audit = new AuditLog();
const approvals = new ApprovalStore();
const alerts: Array<{ at: string; agent: string; tool: string; decision: string; reason: string }> = [];

const registry = new Map<string, { assessment: Assessment; guard?: Guard }>();
for (const a of assessDir(process.env.AGENTS_DIR ?? 'agents', policy)) {
  const m = a.manifest as AgentManifest;
  // Admission control: non-compliant agents are registered but never given a runtime guard.
  const guard = a.evaluation.compliant
    ? new Guard(m, { identity, audit, approvals, onAlert: (r) => alerts.push({ at: new Date().toISOString(), agent: r.agent, tool: r.tool, decision: r.decision, reason: r.reason }) })
    : undefined;
  registry.set(a.evaluation.agentId, { assessment: a, guard });
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(body, null, 2));
}

async function readBody(req: IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, 'request body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function json<T>(req: IncomingMessage): Promise<T> {
  const raw = await readBody(req);
  try {
    return (raw ? JSON.parse(raw) : {}) as T;
  } catch {
    throw new HttpError(400, 'body must be JSON');
  }
}

function requireAdmin(req: IncomingMessage) {
  if (!ADMIN_KEY) return; // loopback-only development mode
  const given = Buffer.from(String(req.headers['x-admin-key'] ?? ''));
  const expected = Buffer.from(ADMIN_KEY);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new HttpError(401, 'admin key required');
}

function agent(id: string) {
  const entry = registry.get(id);
  if (!entry) throw new HttpError(404, `no agent "${id}"`);
  return entry;
}

function runtime(id: string) {
  const entry = agent(id);
  if (!entry.guard) throw new HttpError(409, `agent "${id}" failed the governance gate and is not admitted to runtime`);
  return { entry, guard: entry.guard, manifest: entry.assessment.manifest as AgentManifest };
}

async function route(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const parts = url.pathname.split('/').filter(Boolean);
  const method = req.method ?? 'GET';

  if (method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok: true, agents: registry.size });

  if (method === 'GET' && url.pathname === '/api/agents') {
    return send(res, 200, [...registry.values()].map(({ assessment: a, guard }) => ({
      id: a.evaluation.agentId,
      name: a.evaluation.name,
      tier: a.evaluation.tier,
      stage: a.evaluation.stage,
      controls: a.evaluation.controls,
      compliant: a.evaluation.compliant,
      admitted: !!guard,
      quarantined: guard?.isQuarantined ?? false,
    })));
  }

  if (method === 'POST' && url.pathname === '/api/evaluate') {
    const raw = await readBody(req);
    let manifest: LooseManifest;
    try {
      manifest = (String(req.headers['content-type'] ?? '').includes('json') ? JSON.parse(raw) : parseYaml(raw)) as LooseManifest;
    } catch (err) {
      throw new HttpError(400, `could not parse manifest: ${(err as Error).message}`);
    }
    if (!manifest || typeof manifest !== 'object') throw new HttpError(400, 'manifest must be a mapping');
    const evaluation = evaluate(manifest, policy);
    const probes = scoreRisk(manifest, policy).tier.requiredProbes.map((p) => runProbe(p, manifest as AgentManifest));
    return send(res, 200, { evaluation, probes, deployable: evaluation.compliant && probes.every((p) => p.passed) });
  }

  if (method === 'GET' && url.pathname === '/api/audit') {
    requireAdmin(req);
    return send(res, 200, { integrity: audit.verify(), entries: audit.entries.slice(-500), alerts: alerts.slice(-100) });
  }

  if (parts[0] === 'api' && parts[1] === 'agents' && parts[2]) {
    const id = decodeURIComponent(parts[2]);
    const action = parts[3];

    if (method === 'GET' && !action) {
      const { assessment } = agent(id);
      return send(res, 200, { file: assessment.file, evaluation: assessment.evaluation, probes: assessment.probes });
    }

    if (method === 'POST' && action === 'credentials') {
      requireAdmin(req);
      const { guard, manifest } = runtime(id);
      if (guard.isQuarantined) throw new HttpError(423, 'agent is quarantined');
      return send(res, 201, { token: identity.issue(manifest), expiresInMinutes: manifest.spec.identity.credentialTtlMinutes });
    }

    if (method === 'POST' && action === 'authorize') {
      const { guard } = runtime(id);
      const body = await json<{ token?: string; call?: ToolCall }>(req);
      if (!body.call || typeof body.call.tool !== 'string') throw new HttpError(400, 'call.tool is required');
      const result = guard.authorize(String(body.token ?? ''), body.call);
      return send(res, result.decision === 'allow' ? 200 : result.decision === 'pending_approval' ? 202 : 403, result);
    }

    if (method === 'POST' && action === 'approvals') {
      requireAdmin(req);
      const { manifest } = runtime(id);
      const body = await json<{ tool?: string; amount?: number; approver?: string }>(req);
      const approvers = manifest.spec.oversight?.approvers ?? [];
      if (!body.approver || !approvers.includes(body.approver)) throw new HttpError(403, 'approver is not authorised for this agent');
      if (!manifest.spec.tools.some((t) => t.name === body.tool && t.requiresApproval)) throw new HttpError(400, 'tool does not take approvals');
      const approvalId = approvals.grant({ agent: id, tool: body.tool!, amount: body.amount, approver: body.approver });
      return send(res, 201, { approvalId });
    }

    if (method === 'POST' && action === 'quarantine') {
      requireAdmin(req);
      const { guard } = runtime(id);
      const body = await json<{ reason?: string }>(req);
      return send(res, 200, { quarantined: true, reason: guard.quarantine(body.reason) });
    }

    if (method === 'POST' && action === 'release') {
      requireAdmin(req);
      const { guard } = runtime(id);
      const body = await json<{ by?: string }>(req);
      if (!body.by) throw new HttpError(400, 'release requires "by": the named human taking responsibility');
      guard.release(body.by);
      return send(res, 200, { quarantined: false, releasedBy: body.by });
    }
  }

  throw new HttpError(404, 'not found');
}

const server = createServer((req, res) => {
  route(req, res).catch((err) => {
    const status = err instanceof HttpError ? err.status : 500;
    if (status === 500) console.error(err);
    send(res, status, { error: status === 500 ? 'internal error' : err.message });
  });
});

server.listen(PORT, HOST, () => {
  const admitted = [...registry.values()].filter((r) => r.guard).length;
  console.log(`Governance control plane on http://${HOST}:${PORT} — ${admitted}/${registry.size} agents admitted to runtime`);
});

