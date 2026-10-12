# Runbook — Claims Payment Agent

| | |
|---|---|
| **Owner** | tom.fifita@example.com |
| **Approvers** | claims-lead@example.com, finance-controller@example.com |
| **On-call** | claims-platform-oncall |
| **Risk tier** | 3 · Critical (regulated, irreversible payments) |
| **Manifest** | [`agents/claims-payment-agent.yaml`](../../agents/claims-payment-agent.yaml) |

## Controls in force

- Every `payments.issue` call needs a single-use human approval bound to the claim amount.
- Per-payment cap 5,000; daily cap 20,000.
- 15-minute credentials; runs in an isolated VM; production data only through `claims-data-broker`.

## Alerts and what they mean

| Alert | Meaning | First response |
|---|---|---|
| `C5 approval rejected` | Fabricated, replayed or mismatched approval | **Incident.** Quarantine, preserve the audit log, notify the chief risk officer. |
| `C2 spend limit` | Per-call or daily ceiling reached | Confirm volume is legitimate before raising any limit (limit changes need a PR). |
| `C4 egress denial` | Attempted call outside claims / payments | Quarantine and investigate. |
| `Quarantined` | Circuit breaker tripped | Payments queue for manual processing. |

## Kill switch

`POST /api/agents/claims-payment-agent/quarantine`. Release requires the on-call lead **and** a named approver; both are written to the audit log.

## Regulatory

- Payment errors are irreversible: recovery follows the overpayment procedure.
- Notifiable incidents follow the regulator reporting timeline.
- 90-day governance review — the drift monitor opens an issue the day a review falls due.
