# Strict evaluator chain binding design

## Data flow

```text
.artifacts/protected-image/<tier>/<runtime>/<unit>
  -> read-only evidence validator
  -> copied raw evidence under evaluator/compatibility/<unit>/raw/product-chain
  -> recomputed six stage records
  -> compatibility/<unit>/unit.json
  -> existing calculate_compatibility / gate / analysis-input
```

The evaluator never executes the target, mutates product inputs, or trusts a passed aggregate field. It reads the product evidence produced by the build job and recomputes continuity across role/stage files, hashes, ABI, consumer, loader, oracle, and closed manifests.

## Stage projection

- `protector`: producer stage passed; `outputSha256` is the canonical Protected Image artifact digest.
- `protected-image`: producer role/stage passed; `artifactSha256`, `abiId`, and `abiVersion` are copied and checked.
- `rehydration`: `rehydration.json` passed; `protectedImageSha256`, `nativeImageSha256`, and `consumerId` are checked.
- `native-image`: `native-image.json`/`native-image.bin` passed; `sha256` is the Native Image digest.
- `target-loader`: `target-loader.json` passed; `nativeImageSha256`, `evidenceSha256`, and `loaderId` are checked.
- `behavioral-oracle`: `behavioral-oracle.json` passed; `comparisonSha256` and oracle identity are checked.

Each stage also carries `sourceImageSha256`, `unitId`, and `profile` in the recomputed projection. The corpus row's `sourceSha256` remains the registered source-provenance identity; it is not overwritten by the compiled Source Image digest.

## Evidence isolation

The runner accepts an optional `--product-evidence-root` or `EVALUATOR_PRODUCT_EVIDENCE_ROOT`, defaulting to the local protected-image unit path. It rejects symlink roots, traversal, stale temporary files, open/invalid `SHA256SUMS`, and unit/profile mismatch. It copies only verified regular files into the evaluator raw subtree and emits a new closed raw manifest; the original product evidence remains untouched.

When the product evidence root is absent, the existing baseline-zero projection remains byte/semantic compatible with the frozen evaluator behavior. When present and valid, the candidate unit can be complete, but `calculate_compatibility` still sees the immutable zero baseline and therefore keeps a null factor and non-claimable gate.

## CI boundary

The evaluator job downloads the build job's `test-evidence-${{ github.run_id }}` artifact with `if: always()` and `continue-on-error: true`, then the read-only evaluator consumes `.artifacts/protected-image/`. Existing evaluator dependencies, required-job checks, uploads, and positive-baseline claim enforcement remain unchanged.
