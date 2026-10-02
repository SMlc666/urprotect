# Open-world AArch64 compatibility and opt-in function protection

## Goal

Improve real-world AArch64 ELF compatibility while adding explicitly selected, function-level register permutation and control-flow flattening.

## Confirmed Requirements

- Compatibility and function-level protection are one coordinated initiative, with separate acceptance measures for file acceptance, runtime behavior, and transformation coverage.
- A valid but not-yet-modeled ELF feature should not automatically make the whole binary invalid when untouched data can be preserved and native runtime behavior can be delegated. Semantically relevant behavior that the selected execution profile cannot preserve must remain an explicit boundary.
- Function transformation is never enabled by default and never implicitly applies to all functions. The user explicitly selects the target functions.
- The initial transformation scope may rely on trustworthy function boundaries, such as symbol-derived ranges. Functions without reliable boundaries are outside the initial transformation scope.
- The initial function inventory uses both `.symtab` and `.dynsym` entries of type `STT_FUNC` when they provide trustworthy non-empty ranges.
- Function selectors use exact symbol identity/name matching; ambiguous same-name symbols require explicit address/identity disambiguation and must never silently select one candidate.
- Register permutation is in scope. Register pressure/resource sufficiency is a first-class transformation constraint; a simple def-use, liveness, and temporary-register allocation pass is not sufficient.
- Both register permutation and control-flow flattening are required function-level transformation capabilities in this initiative; neither is a substitute for the other.
- Users can select register permutation and control-flow flattening independently or request both in one operation; both remain disabled unless explicitly requested.
- When both transformations are requested, the pipeline applies control-flow flattening first and register permutation to the resulting instruction stream.
- AsmStone should become part of the actual function analysis/obfuscation pipeline, not remain only an optional instruction-decoding report.
- Non-selected functions must not receive obfuscation transformations. Selected functions that fail analysis or resource requirements must have an explicit, inspectable outcome.
- Static validation, native baseline execution, protected execution, behavioral equivalence, and per-function protection coverage must be reported as distinct outcomes.
- The first compatibility phase must include glibc, musl, and bionic runtime families; musl and bionic are not deferred to a later phase.
- First-phase bionic E2E is specifically the locked native ARM64 Termux/bionic userspace exercised through `/system/bin/linker64`; Android framework/JNI/native-bridge coverage is a separate scope and is not required to claim this bionic runtime cell.
- If any explicitly selected function cannot be transformed, the whole protection operation fails atomically; no partial protected output is published.
- A small deterministic glibc, musl, and Termux/bionic protection E2E smoke is a required gate on every PR; broader real-binary E2E coverage runs nightly.
- Nightly real-binary compatibility E2E runs the full 100-project approved registry across glibc, musl, and bionic; it must not silently replace the registry with a sampled subset.
- Every nightly real-sample identity receives baseline and outer-wrapper execution in its declared runtime profile; function transformations run only for per-project symbol selectors explicitly declared by the test policy, never by automatic all-function selection.
- Every nightly identity must pass both original-baseline and packed outer-wrapper execution in its declared runtime, with no `not-applicable` downgrade for missing dependency closure or unfinished profile support; failures are explicit and fail the required full-corpus gate.
- Every PR protection smoke includes both a symbolized transformation fixture and at least one representative real executable in each of the three runtime profiles; nightly extends the real-binary set.
- The PR real-runtime witnesses are musl BusyBox, glibc GNU coreutils `ls`, and Termux/bionic Node.js, each executed in its matching pinned runtime/dependency environment. These real-program witnesses measure compatibility; the symbolized fixture separately measures function transformations.

## Repository Findings

- `fixtures/real-samples/manifest.json` currently has 100 statically applicable projects, one baseline-execution-applicable project (`busybox`), and zero projects applicable to outer-wrapper or HostContext execution.
- The approved corpus has 78 glibc, 21 musl, and one bionic identity; it contains 96 `ET_DYN` and four dynamic `ET_EXEC` inputs.
- The public corpus has 78 glibc, 21 musl, and one bionic executable; its declared ELF types are 96 `ET_DYN` and four dynamic `ET_EXEC` images with the expected runtime interpreters.
- Existing per-runtime real-binary candidates include musl BusyBox from the pinned Alpine minirootfs, glibc Debian packages such as `gnu-coreutils`/`gnu-bash`, and the Termux/bionic `nodejs` package; only BusyBox currently has a complete declared runtime rootfs/baseline oracle.
- `src/UrProtect.Core/Pack/ElfPackService.cs` currently accepts the Linux glibc and musl interpreter names but rejects bionic `/system/bin/linker64`; the approved full nightly outer-wrapper matrix requires adding and validating that runtime profile.
- `scripts/run-real-sample-matrix.sh` currently hard-codes outer-wrapper results as `not-applicable`; it must gain a real pack/run/behavior-comparison oracle for every registry identity.
- `scripts/run-real-sample-matrix.sh` maps successful `validate` exit status to the static-layer label `accepted-and-runs`; this does not execute the sample and must be corrected as part of compatibility measurement.
- `src/UrProtect.Core/Elf/ElfParser.cs` parses dynamic symbols but does not currently expose ordinary `.symtab` function symbols.
- `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs` performs bounded linear scanning and does not construct a complete function CFG.
- `src/UrProtect.Core/Aarch64/Aarch64Decoder.cs` invokes AsmStone with `A64FeatureSet.All` by default and projects only part of the instruction model into the project adapter.
- The current managed pipeline validates/copies or packages source bytes; it does not provide a general ELF rewriting/emission pipeline.
- `ElfPackService.IsPackableInput` currently accepts Linux glibc/musl `PT_INTERP` names only and rejects the corpus's `/system/bin/linker64` bionic image; full nightly outer-wrapper evidence requires a tested bionic profile.
- `scripts/run-real-sample-matrix.sh` currently sets outer-wrapper results to `not-applicable`; it must pack and execute every approved identity and compare behavior against its baseline.
- Current CI runs the core build/fixture/packed-fixture path on native ARM64 glibc; the PR runtime-matrix tier covers current glibc and bionic but omits musl. Musl runtime-container coverage is currently scheduled/manual/release rather than a required PR E2E path.
- The native ARM64 bionic CI lane uses a locked Termux/bionic container and is present on PR runs, but tests baseline PIE and a native HostContext adapter fixture rather than function-protected output. A separate Android native-bridge JNI lane is scheduled/release/manual and does not currently test protected output; it is outside the first-phase bionic acceptance target.

## Acceptance Criteria

- Compatibility results distinguish structural validation, target-runtime execution, protection eligibility, transformation completion, and protected behavior equivalence.
- A valid, unselected or untransformable function does not cause unrelated functions to be transformed; user selection is the sole transformation scope.
- The tool reports exact selection resolution, function boundaries, analysis/transform status, and register-resource failure reasons for every selected function.
- Function discovery and selection account for both `.symtab` and `.dynsym`; ambiguous selectors fail before transformation unless the user disambiguates them.
- Every explicitly selected function must complete the requested transformation for the operation to succeed; a missing, ambiguous, unsupported, or resource-infeasible selected function fails the entire operation without publishing partial output.
- Register permutation and control-flow flattening each have explicit transformation-pass coverage and standalone end-to-end behavior-equivalence evidence on selected functions.
- The combined register-permutation plus control-flow-flattening pipeline has end-to-end behavior-equivalence evidence on explicitly selected functions.
- Combined-pass evidence verifies the selected order: control-flow flattening precedes register permutation.
- A transformed output is structurally revalidated, its transformed functions are re-decoded, and target-runtime tests compare original and transformed behavior.
- Compatibility evidence includes real end-to-end execution; static parser acceptance is never reported as execution success.
- First-phase end-to-end evidence covers glibc, musl, and bionic, with runtime-specific baseline and protected execution evidence for each declared profile.
- Every PR runs the required three-runtime protection smoke; nightly runs add broader real-binary coverage.
- Nightly E2E processes all 100 approved real-sample identities and retains an explicit result/evidence record per identity and applicable layer; missing runtime closure or execution is surfaced as a failure/environment result, never silently omitted.
- Nightly baseline and outer-wrapper results are retained for all 100 real-sample identities; function transformation evidence is separately keyed to explicit per-project function selectors.
- Every nightly sample must have a pinned, reproducible runtime dependency closure and an explicit bounded invocation policy; missing closure, command policy, or runtime support is a failing result, never silently omitted or classified `not-applicable`.
- The bionic outer-wrapper lane handles `/system/bin/linker64` in the locked native ARM64 Termux environment.
- Each runtime's PR E2E includes a real executable in addition to the deterministic symbolized function-transformation fixture.
- PR compatibility E2E runs BusyBox in its Alpine/musl rootfs, GNU coreutils `ls` with a pinned glibc dependency environment, and Termux Node.js with a pinned bionic dependency environment.

## Resolved Planning Decisions

- Nightly performs baseline plus packed outer-wrapper E2E for all 100 real-sample identities in each identity's declared glibc, musl, or bionic environment. It does not replace full coverage with a sampled subset.
- Function transforms remain opt-in: nightly runs them only for exact per-project selectors explicitly listed by test policy; all other functions and projects remain untransformed.
- Bionic outer-wrapper E2E uses the locked native ARM64 Termux runtime and `/system/bin/linker64`; Android framework/native-bridge coverage is separate.
- PR runs the three runtime transformation fixtures and BusyBox/musl, coreutils `ls`/glibc, and Termux Node.js/bionic compatibility witnesses.
