# Runbook — Customer Support Agent

| | |
|---|---|
| **Owner** | mere.walker@example.com |
| **On-call** | cx-platform-oncall |
| **Risk tier** | 2 · Elevated |
| **Manifest** | [`agents/customer-support-agent.yaml`](../../agents/customer-support-agent.yaml) |

## Alerts and what they mean

| Alert | Meaning | First response |
|---|---|---|
| `C3 scope denial` | The agent tried an action its credential does not cover | Possible prompt injection from ticket content. Pull the ticket and transcript. |
| `C2 argument rejected` | Reply text or IDs failed validation | Check for injected markup in customer messages. |
| `C4 egress denial` | Attempted call outside CRM / KB / ticketing | Treat as an incident: quarantine, then review. |
| `Quarantined` | Circuit breaker tripped | Tickets fall back to the human queue automatically. |

## Kill switch

`POST /api/agents/customer-support-agent/quarantine` routes all tickets to people.
Release with a named approver: `POST /api/agents/customer-support-agent/release`.

## Customer impact

- Replies are reversible (follow-up message), but anything already read by a customer is not. If a wrong reply went out, contact the customer within one business day.
- Personal information is reached only through `crm-data-broker`; a suspected privacy breach goes to the privacy officer within 24 hours.

## Support

- 180-day governance review. Update `lastReview` by pull request after the review.
