## What this changes

<!-- New agent, manifest change, policy change or engine change? -->

## Governance checklist

- [ ] The agent's use case is validated (`spec.lifecycle.validated`) and the owner is a named person
- [ ] Risk profile is declared honestly — undeclared attributes score at maximum
- [ ] Tools are allow-listed with constrained argument schemas and rate limits
- [ ] The agent runs as its own `svc-agent-*` principal with explicit, least-privilege scopes
- [ ] Egress is an explicit host allow-list; the agent runs sandboxed
- [ ] Irreversible or transacting tools require human approval from named approvers
- [ ] A runbook exists and an on-call owner is set

The **Governance gate** check evaluates every agent and runs adversarial probes. It must pass before merge.
