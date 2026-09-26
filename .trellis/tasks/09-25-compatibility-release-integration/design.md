# Design: compatibility claim and release integration

## Objective

Produce one consistent release-facing compatibility claim from independently
verified child outputs, without making the final integration child a second
implementation owner.

## Reconciliation flow

```text
child feature/status/evidence
  -> fixtures/manifest.json and real-sample registry
  -> validators and rendered reports
  -> README / COMPATIBILITY.md / native and backend specs
  -> package-release and release-smoke
  -> retained release artifacts
```

The manifest and evidence producers remain authoritative for status. Human
documentation explains the claim and proof boundary; it does not invent rows.

## Integration checks

- Every feature ID has one status/owner and matching positive/negative evidence.
- Every runtime row names its environment and artifact producer.
- Outer, HostContext, parser/model, and runtime-specific rows are distinct.
- Frame/profile/version terminology is current and stale migration language is
  explicitly historical.
- Contract inventory contains no duplicate current offsets or owners.
- Release bundle reports only claims whose evidence gate passed.

## Rollback

If a child artifact is incomplete, retain the prior release matrix and mark the
new row `unknown`/`rejected`; do not partially publish documentation or release
claims.
