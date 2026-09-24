# Changelog

## 1.0.1 - 2026-09-23

- Bind job completion to the assigned node and reject repeated results.
- Restrict probe imports to verified vendor directories and privileged callers.
- Validate admission claims, profiles, capabilities and telemetry; reject active identity collisions.
- Enforce WebSocket masking, opcode, continuation, UTF-8, control-frame and aggregate size rules.
- Require valid upgrades and same-origin browser connections; restrict HTTP metadata.
- Remove disconnected sessions, fail abandoned jobs, and bound admission/job retention.
- Refuse client-authored replica clocks and fix missed-key convergence.
- Fail integrity checks for empty, malformed, changed, extra or escaping vendor trees.
- Reject empty test discovery as promotion evidence and propagate CLI gate failures.
- Invalidate tickets on restart and enforce loopback policy for library callers.
- Fix wheel packaging of the browser console and isolate runtime data from installed code.
- Quote Python launcher paths on Windows.
- Add regression coverage, CI, release documentation, Apache 2.0 LICENSE and NOTICE.
