# Continuous Fabric Platform 1.0.1 audit

Date: 2026-09-23. Source: CFP_Continuous_Fabric_Platform_v1.0.0.
Copyright 2026 RUSSELL PHILIP SMITHSON.

## Scope and result

Reviewed all Python modules, the browser client, package metadata, Windows launchers,
and the existing test suite. The original source had five passing tests. This patch
addresses the concrete defects below and adds 28 regression tests. It does not certify
the separately vendored estate or establish production readiness.

| Finding | Remediation | Regression coverage |
|---|---|---|
| Any admitted node could forge or replay a job result | Assigned-node and pending-state checks | Ownership and replay tests |
| Probe accepted filesystem traversal and constructed import source | Contained paths, verified manifests, importlib arguments, device capability | Traversal and unprivileged probe tests |
| Empty grants became default grants; malformed profiles reached the scheduler | Explicit grant semantics and type/range validation | Admission and profile tests |
| Client clocks could overwrite shared replica state | Remote writes go through gateway-authored set commands | Raw sync injection test |
| Vector clocks could hide a missing older key | Reconcile current per-key values | Missing-key convergence test |
| Fragmented messages bypassed frame size limits; malformed RFC 6455 frames were accepted | Aggregate limits, strict masking/opcodes/UTF-8/control/continuation rules | Frame rejection and round-trip tests |
| HTTP metadata leaked inventory and filesystem paths | Metadata requires authenticated terminal access | HTTP restriction tests |
| Unvalidated upgrades allowed cross-origin browser sessions | Validate upgrade headers, key, version and Origin | Upgrade tests |
| Reconnects retained sessions and pending jobs | Reject active duplicates; clean sessions and fail abandoned jobs | Disconnect tests |
| Empty/forged manifests and zero-test suites could pass checks | Fail-closed tree verification and zero-test detection | Manifest and gate tests |
| Wheel installation omitted browser assets | Explicit package discovery and packaged web resources | Installed-wheel smoke check |

## Validation

- Windows, Python 3.12: `python -m unittest discover -s tests -v`: **33 passed**.
- Built `cfp-1.0.1-py3-none-any.whl` without runtime dependencies.
- Packaging smoke check covers version, browser resources, LICENSE and NOTICE.
- Python syntax compilation, browser JavaScript syntax, version consistency,
  whitespace review, and targeted credential-pattern scan are release checks.
- GitHub CI runs the suite and package checks on Windows and Linux with Python
  3.10, 3.12, and 3.14. Hosted results are recorded separately from local results.

## Limitations

- No hardware attestation, tenant isolation, durable consensus, physical QPU test,
  WAN deployment test, or full third-party stockpile audit was performed here.
- Gates and probes execute trusted vendor code with the invoking OS user's rights.
- Hash manifests are local integrity baselines, not authenticated publisher signatures.
- State and tickets are volatile; restart invalidates tickets. Shared admitted nodes
  can read the fabric topology and, with state.read, the shared state namespace.
- The custom WebSocket transport supports bounded text messages without extensions;
  it has not undergone a full Autobahn conformance run or external penetration test.
- Global connection-rate limiting, operating-system sandboxing, TLS termination and
  durable state storage remain deployment responsibilities.
- The retained U6/U7 report describes historical work on other source folders. Its
  claims are not fresh validation of those repositories in this release.

Protocol reference: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455).
License source: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).
