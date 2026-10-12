# Runbook — Meeting Summariser

| | |
|---|---|
| **Owner** | aroha.ngata@example.com |
| **On-call** | workplace-it-oncall |
| **Risk tier** | 1 · Low |
| **Manifest** | [`agents/meeting-summariser.yaml`](../../agents/meeting-summariser.yaml) |

## Alerts and what they mean

| Alert | Meaning | First response |
|---|---|---|
| `C2 denial` | A tool call was refused (bad argument, unknown tool) | Check the audit log entry; usually a malformed meeting ID. No action unless repeated. |
| `C4 egress denial` | The agent tried to reach a host outside its allow-list | Treat as a behavioural anomaly. Review the prompt/transcript that preceded it. |
| `Quarantined` | Circuit breaker tripped after 3 consecutive denials | Agent is stopped. Investigate before releasing. |

## Kill switch

Quarantine immediately: `POST /api/agents/meeting-summariser/quarantine`.
Release only after the cause is understood: `POST /api/agents/meeting-summariser/release` with your name — the release is written to the audit log.

## Support

- Summaries are reversible: delete the note and re-run.
- Users report quality issues to workplace-it-oncall; log them against the agent ID.
- Annual governance review (365-day cycle). Update `lastReview` in the manifest by pull request.
