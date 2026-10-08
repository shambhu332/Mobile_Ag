# Contributor starter tasks

Choose one small task, open or comment on the corresponding issue, and agree on scope before a large change. These are proposed work items, not implemented capabilities or promises of acceptance. Repository access is required while the project is private.

| Area | Bounded task | Acceptance criteria |
| --- | --- | --- |
| Documentation | Add troubleshooting for unavailable local static-scan prerequisites | Explain missing JADX/APKTool, bubblewrap and ordinary-user systemd; show how to read readiness output; preserve fail-closed isolation and never recommend root or an unsafe fallback. |
| UI testing | Cover Overview invalid-file and multi-file drop states | Use synthetic files and a local fixture; show an accessible error; assert zero upload/execution requests for rejected input; prove later valid selection recovers. |
| Accessibility | Add upload focus-recovery regression coverage | Verify keyboard selection/cancellation and return from the advanced IPA modal at desktop and 320px; no automatic scans, device selection, or consent. |
| Static analysis | Add narrowly scoped manifest parser fixtures | Use hand-written synthetic fixtures; document expected and negative cases; distinguish declarations from runtime reachability and exploitability. |
| Reporting | Improve candidate/evidence status documentation | Explain a synthetic example from candidate to recorded analyst evidence; do not equate shell/root observations, model opinions or severity with independent exploit proof. |

## What makes a useful contribution?

- One clear problem and a small, reviewable diff.
- A reproducible fixture with no real APK, customer data, tokens, or credentials.
- Tests showing the intended behavior **and** a negative control.
- Exact commands/results and limitations, not just a screenshot of a passing counter.
- No unrequested device/model/network activity, weakened approval gates, or disabled tests.

Start with [CONTRIBUTING.md](../CONTRIBUTING.md). This roadmap does not guarantee that every task is unassigned; check repository issues first.
