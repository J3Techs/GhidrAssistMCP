# Context, diagnostics, analysis and process-policy repairs

This track implements review findings 9, 13, 17 and 19, the confirmed omitted-arguments issue, and explicit dispositions for capability-policy findings 1 and 18. The prototype hypothesis was also narrowed to an unnecessary EDT dependency and inaccurate failure reporting, both repaired.

| Area | Applied behavior | Regression evidence |
| --- | --- | --- |
| Null arguments | Common backend handling normalizes omitted arguments to an empty map; schema-required arguments still fail. | `AppliedProtocolConformanceTest` sends no-argument and required-argument calls over HTTP; `DiagnosticPurityTest` exercises the direct backend. |
| Diagnostics | Runtime resource/tool consult the supplied backend's attached services without creating the global GUI manager. | `DiagnosticPurityTest` checks absent and existing manager identity. |
| Bound BSim project | A supplied backend determines the project; global GUI/AppInfo state does not substitute a different one. Open program selectors use `ProgramIdentity`. | `BsimContextTest.boundProjectWinsOverDifferentGlobalProject` uses two disposable projects. |
| Temporary analysis settings | Invalid mode/range is rejected before option changes. Original typed/default values are restored after actual analysis termination, including failure and cancellation. Error results carry `isError`. | `TemporaryAnalysisOptionsTest` checks success, exception, cancellation, defaults, nondefault integers and invalid requests. |
| Prototype commands | Database signature application runs on the owning caller rather than waiting for the EDT. Its reference comment is part of the same successful transaction; parse/apply errors are flagged. | `PrototypeExecutionTest` applies a signature from the EDT and verifies invalid input leaves signature/comment unchanged. |
| Authentication | Explicit process configuration owns installation; calls cannot replace it with differing settings. No configuration preserves existing authentication. Installation is idempotent; partial initialization failure poisons retries. | `BsimAuthenticationTest` uses injected fake authentication, without credentials or network. |
| Deployment policy | Loopback is mandatory by default; remote binding requires explicit operator opt-in. Intended script/native operations retain their public enabled state. Host-file native tools have open-world annotations. | `DiagnosticPurityTest` checks loopback, wildcard rejection and opt-in. See `DEPLOYMENT_TRUST.md`. |

The earlier cancellation, resource selection and task error fixes remain in place. Read-during-analysis snapshot guarantees and arbitrary regex execution-time bounds were review hypotheses, not reproduced defects; no universal concurrency or regex-time guarantee is claimed. VT's early `commit=true` error branch exits before applying markup and avoids rolling back another writer's enclosing transaction, so changing it mechanically to rollback would be incorrect. Shared backend ownership is documented as an explicit local-client model.

Focused and integrated execution results are recorded in the final repair/install report after the coordinated suite finishes. Tests named here are acceptance evidence, not a claim that live GUI projects or external BSim services were exercised.
