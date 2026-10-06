# Protected Image Emission Implementation Plan

## 1. Model and codec

- Add typed Protected Image v1 records/operations and bounded canonical codec.
- Add source/request/profile/producer/rehydrator identity binding and SHA-256 role evidence.
- Add stable diagnostics and malformed/overflow/duplicate/overlap tests.

## 2. Protection plan boundary

- Extract or expose a layout-neutral protection plan from existing function analysis/emission.
- Keep explicit selector/pass ordering and legacy final-ELF `Protect` behavior intact.
- Ensure Protected Image emission does not call final `PT_NULL`/`PT_LOAD` placement.
- Add a no-spare-program-header fixture test for emission only.

## 3. Evidence and CLI/API

- Add an explicit producer API or CLI mode that emits Protected Image v1 and role metadata.
- Publish atomically, verify bytes/hash/size, and publish nothing on failure.
- Keep Protected Image artifact distinct from complete source/final ELF/current PayloadFrame.

## 4. Tests and CI

- Add valid round-trip and nearest-negative tests.
- Preserve all existing protection/parser/frame/pack tests and E2E evidence.
- Add `.artifacts/protected-image/<tier>/<runtime>/<unit>/` evidence and upload on failure/success.
- Add only additive benchmark fields for analysis/emission cost, size, and failure stage; no strength factor.

## Validation

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore
dotnet test UrProtect.sln --configuration Release --no-restore
python3 scripts/validate-evaluator-manifests.py
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
python3 scripts/check-protection-evidence.py .artifacts/protection/pr/glibc --tier pr --runtime glibc
```

Native execution and CI evidence require the declared AArch64 runner. Local absence of the SDK/runtime is retained as environment evidence, not passed as support.

## Rollback

Disable only the opt-in Protected Image producer path and remove no existing artifacts/tests. Never fall back silently to direct ELF for a strict-chain role.
