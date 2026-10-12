# Progress Log

## 2026-08-29

- Initialized the repository and moved the default branch to `main`.
- Added a .NET 8 library and dependency-free executable test project.
- Added the initial IR, register/operand model, diagnostics, and bit-field
  utilities.
- Added the first complete vertical slice for `nop`, `b`, `bl`, `br`, `blr`,
  `ret`, `adr`, `adrp`, and add/subtract immediate forms.
- Added round-trip and boundary-oriented smoke tests.

## 2026-08-29 - TableGen pipeline

- Built a matching LLVM `llvm-tblgen` from the pinned LLVM revision in a local
  cache.
- Exported the expanded AArch64 TableGen JSON and added an LLVM inventory pass.
- Confirmed `8840` AArch64 records: `7484` encodable, `1356` pseudo, `7468`
  complete encodings, and `16` partial encodings requiring custom handling.
- Added repeatable build/export scripts for the local source cache.
- Added the generated runtime catalog with all `7484` non-pseudo AArch64
  records, including mask/value matching, operand DAG text, feature predicates,
  decoder methods, and encoded-field mappings.
- Added generated operand bindings and `449` referenced LLVM operand codec
  records, preserving register classes, immediate/PC-relative codec methods,
  print methods, and parser match classes.
- Added feature-profile filtering for generated lookups, including LLVM
  `_or_` predicates; a NEON encoding is rejected by Base and accepted by the
  NEON profile.
- Added a compact candidate index and name lookup so generated catalog
  queries avoid scanning unrelated instruction records.
- Removed the unused text parser/formatter surface; the active scope is binary
  IR, encoding, decoding, feature profiles, and generated metadata.
- Connected feature-aware decode directly to the generated catalog, returning
  generated IR with raw encoded fields when no specialized semantic codec is
  available.
- Corrected ADD/SUB flag-setting register roles and added overflow-safe
  unsigned address displacement checks.
- Hardened TableGen field validation and added source-revision/hash provenance
  to generated code; export scripts now reject an unlocked LLVM checkout.
- Generated decoding now materializes common GPR/FPR/AdvSIMD/SVE/predicate
  registers, scaled immediates, and PC-relative targets while preserving a raw
  field fallback for instruction-specific codecs.
- Added an explicit exact-overlap allowlist for the current LLVM PSTATE alias
  pair; unexpected exact encoding overlaps stop C# emission.
- Added reverse field mapping for generated binary encoding. Generated IR from
  `CBZ`, scaled `LDR`, and AdvSIMD `ADD` now round-trips to its original word.
- Added public catalog enumeration/count checks and corrected ADR versus ADRP
  PC-relative scaling in generated operand materialization.
- Added typed generated memory operands for offset, register-offset, pre-index,
  post-index, pair, exclusive, and LSE CAS forms; complete-record zero-vector
  round-trip coverage now exercises all `7468` complete generated encodings.
- Added randomized variable-bit round-trip coverage and fixed modular 64-bit
  PC-relative deltas, signed immediate bounds, and preservation of opaque
  TableGen variable bits.
- Added nested LLVM DAG support for shifted and extended register operands,
  increasing the generated operand codec catalog to `456` types; `ADDXrs`,
  `ADDXrx`, and their W-register forms now produce typed modified-register IR.
- Added typed vector register-list and system-register operands with binary
  round-trip coverage.
- Added logical-immediate mask conversion, AdvSIMD vector shift conversion,
  and raw-field preservation for non-canonical encodings.
- Generated binary coverage now includes every `7468` complete record at its
  source value plus `1000` deterministic randomized variable-bit samples.
- Added SVE/SME register-group materialization for `ZPR2/ZPR4`, `ZZ/ZZZ/ZZZZ`,
  and predicate-pair codecs, plus SVE `sve_incdec_imm` semantic conversion.
- Added binary tests for SVE grouped loads, system-register MRS/MSR, AdvSIMD
  vector shifts, logical masks, and the full generated record set.
- Added SVE predicate/enum immediate materialization, feature-aware byte-span
  encoding, and corrected the public `A64Feature` overload to use generated
  predicate gating.
- Added AdvSIMD Type10 modified-immediate conversion for `simdimmtype10`, with
  semantic 64-bit mask values, raw-field preservation, and modified-value
  re-encoding tests.
- Added scalar FP immediate conversion for `fpimm16/32/64`, with IEEE single
  semantic values and raw 8-bit encoding retention for exact round trips.
- Added move-wide immediate conversion for `MOVZ/MOVN/MOVK`, including
  halfword shift semantics and raw `hw` field retention.
- Added `A64InstructionCatalog.TryEncodeFields` and its public API wrapper for
  complete raw-field assembly of generated records, including complex SVE
  forms before their high-level operand codec exists.
- Added public byte-span decode/encode and raw-field byte assembly APIs with
  little-endian verification; the pinned one-click LLVM generation script now
  reproduces the checked-in catalog.
- Added typed MOPS coverage for `CPYFP` and `SETP` multi-writeback forms, plus
  the public `A64Feature.Mops` profile.
- Expanded public feature profiles for CRC, full FP16, BF16, I8MM, FP8, LSE2,
  SME2.x, SVE2.x, and MTE2 predicate families.
- Added FP16 profile dependency checks against the generated `FCMPHri` record;
  vector-capable FP16 profiles now include NEON automatically.
- Completed the final `16` previously partial LLVM records with explicit
  DUP-from-GPR, FCMP-zero, and INS-lane encodings; the generated A64 table now
  reports `7484/7484` complete encodings.
- Added a one-command generated-catalog reproducibility check covering the
  locked LLVM revision, inventory, and byte-for-byte C# output.
- Added default `All` overloads for raw-field encoding while retaining
  feature-aware overloads for strict target profiles.
- Strict generated decode now reports `UnsupportedFeature` when the encoding
  matches a known record outside the selected profile, separating it from
  `UnknownEncoding`.
- Generated instruction effects now expose load/store, compare, barrier,
  terminator, and side-effect flags from LLVM metadata.
- Generated effects now also expose `WritesBack`, including multi-address MOPS
  operations and fixed/pre/post-index memory records.
- Generated effects now expose `IsAtomic` for LLVM exclusive/CAS instruction
  classes; LDXR/STXR/CAS tests verify the combined effect flags.
- Generated effects now expose `IsSystem` for BaseSystemI, exception, and
  special-return classes; MRS/MSR tests verify system classification.
- Generated catalog provenance is now available at runtime through commit,
  input SHA-256, and source record-count properties.
- NuGet packaging now includes both the project README and third-party input
  notice for generated LLVM/AARCHMRS provenance.
- NuGet packaging also includes `spec/source-lock.json` so the shipped binary
  catalog's exact source revisions and hashes remain inspectable.
- Raw-field round-trip now traverses all `7484` complete records, independent
  of the typed operand materializer.
- Added semantic AdvSIMD modified-shift conversion for logical/move vector
  shift operands and propagated terminator metadata through the generated
  catalog.
- Changed unqualified binary decode to use `A64FeatureSet.All`; callers can
  still pass an explicit profile for strict target-feature validation.
- Added `A64ExecutionMode` handling for streaming/non-streaming compound LLVM
  predicates, including SME-safe and streaming-SVE combinations.
- Expanded deterministic randomized variable-bit coverage to `10000` samples;
  all generated complete-record round trips remain lossless.
- SVE/SME register groups now retain element widths (`b/h/s/d/q`) in their IR;
  grouped memory forms validate the width on re-encode.
- Generated memory bindings now retain literal fixed offsets for fixed-writeback
  encodings, and RCPC profiles include the current `HasRCPC3` predicate.
- Register-offset memory forms now fold their `extend/shift` modifier into
  `MemoryOperand.IndexModifier`, covering X/W extended-index loads without a
  detached modifier operand.
- Added decoded modifier semantics for arithmetic/logical shifted registers
  and extended registers while retaining their raw encoding for lossless
  binary round trips.
- Connected execution-mode filtering to the generated `ZERO_M` SME record;
  unspecified mode rejects it while non-streaming mode accepts it.
- Added typed `MatrixTileMaskOperand` handling for `ZERO_M` tile masks with
  feature-context and binary round-trip coverage.
- Added semantic construction helpers for shifted/extended register operands,
  so callers can request `LSR/ASR/ROR` or `UXT*/SXT*` without hand-encoding
  modifier bits.
- Generated encoding now validates register class and width for GPR/FPR/V/SVE/
  predicate operands; invalid W/X and cross-class combinations are rejected.
- Added authenticated load/writeback coverage for `LDRAA` under the strict
  Pointer Authentication profile, including signed scaled offsets.
- Added TBZ/TBNZ bit-index conversion, including the implicit +32 X-register
  range encoded by `tbz_imm32_63`.
- Added a pinned LLVM MC oracle and a single `saas-linux-2xlarge-amd64` GitLab
  job with 32 local workers that partitions and checks the complete 32-bit
  AArch64 encoding space with compact semantic fingerprints.
- Added NuGet package readme metadata; `dotnet pack` now produces a package
  containing the root README without warnings.
- Tightened AdvSIMD half-word modified-shift validation to its architectural
  `#0/#8` range and added an invalid-value regression.
- Restored signed two's-complement field insertion for negative scaled offsets
  and PC-relative targets while retaining overflow rejection; the deterministic
  random suite now runs `10000` variable-bit samples without failures.
- Removed the separate opcode-specific decoder and encoder paths; control-flow,
  PC-relative, and add/subtract instructions now use the same generated path as
  the rest of the catalog.
- Added compiled field, binding, predicate, and memory metadata plans so the
  generated hot path does not parse TableGen strings per call.
- Added generator-emitted exact-word dispatch for fixed encodings, including
  `NOP`, so fixed instructions avoid the candidate index scan.
- Added generated decoder constraints for reserved add/sub immediate shift
  selectors and preserved SME bit-immediate mappings from TableGen.
- Added zero-allocation raw and semantic decode views backed by caller-owned
  operand storage; allocation regression tests cover the generated hot path.
- Emitted LLVM instruction constraints into the generated catalog and compiled
  them into symmetric operand tie metadata for the object and span APIs.
- Added typed SVE optional-`lsl #8` immediate handling, exact SVE floating
  immediates, HINTE operand-domain validation, and standalone `UXTX/SXTX`
  arithmetic modifier operands.
- Added generated semantic descriptor metadata for operand kinds, directions,
  ties, register constraints, field widths, scales, and immediate domains.
- Extended SME spill/fill memory recognition to nested tile/address brackets and
  preserved the LLVM-defined shared tile-slice/offset encoding.
- Added catalog-wide regression audits proving every decodable complete record
  has a non-opaque object and semantic operand representation.
- Classified barrier options, nXS barrier immediates, condition codes, and
  range-prefetch hints as typed enum operands; nXS values preserve their sparse
  encoded field while exposing architectural #16/#20/#24/#28 values.
- Removed the last runtime legacy operand-dispatch fallback; object encoding
  now uses the same compiled generated operand switch for every binding.
- Added canonical validation for raw shifted/extended register modifiers and
  semantic/raw matrix-register pairs, preventing invalid IR from re-encoding.
- Extended `A64OperandView` with the compiled binding contract: register and
  field widths, scale/signedness, register roles and constraints, page-relative
  classification, semantic domains, and fixed modifiers remain available on
  the zero-allocation span API.
- Consolidated view semantic and binding metadata propagation into one value
  construction step to keep the expanded span view allocation-free.
- Corrected SVE enum validation to distinguish named printer aliases from the
  full numeric operand domains: `sve_pred_enum` accepts `0..31` and
  `sve_prfop` accepts `0..15`, matching LLVM TableGen predicates.
- Added an exhaustive diagnostic mode (`--diagnose`) that reports the first
  per-word LLVM/AsmStone semantic mismatch instead of only a chunk digest.
- Updated exhaustive CI to cache the pinned LLVM CMake build trees and compile
  LLVM/oracle with 32 parallel workers, avoiding a cold rebuild on every run.
- Changed the generated catalog to lazy compiled-plan materialization with a
  bounded 8-bit bucket index and 16-bit candidate indices; ordinary process
  startup no longer constructs all 7484 binding plans at once.
