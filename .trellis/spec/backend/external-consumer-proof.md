# Selected External-Table Consumer Proof and Managed Publication

## 1. Scope / Trigger

Use this contract when changing the demand-driven external-provider query in
`Aarch64JumpTableResolver`, pinned provider input, SPS6 consumer serialization,
selected-consumer emission, or rehydration publication. Managed Slice B is
independently accepted for one selected consumer of one four-entry
signed-relative-32 provider table. A scoped native AArch64/glibc source-versus-
rehydrated-Native-Image observation and separate provider-loaded rollback
observation are now retained and independently checked; the feature row remains
unknown/non-promoted pending hosted CI and runtime-specific gates.

The public proof query remains a proof-only seam: success or a constructed DTO
does not authorize publication. Ordinary `Analyze` / `protect` without the
pinned-provider integration remains fail-closed. `protect-image` and
`rehydrate-image` have an explicit host-pinned managed path through the existing
workflow, resolver, semantic factory, codec, emitter and layout owners. Do not
add a second resolver/parser or a raw-byte publication bypass.

See [safe provider input](./quality-guidelines.md#scenario-bounded-private-provider-file-input),
[provider errors](./error-handling.md#scenario-managed-external-provider-failures),
and the [scoped runtime evidence boundary](./runtime-compatibility.md#scenario-external-provider-managed-admission-and-scoped-native-evidence).

## 2. Signatures

The existing resolver owns the unchanged public query:

```csharp
public static bool TryProveExternalProviderTableConsumer(
    IReadOnlyList<Aarch64FunctionInstruction> selectedInstructions,
    int branchIndex,
    ElfFunctionSymbol selectedFunction,
    ElfFile consumer,
    Aarch64ExternalJumpTableProviderFacts providerFacts,
    out Aarch64ExternalJumpTableConsumerProof? proof,
    out string failure);

public sealed record ExternalJumpTableProviderInput(
    string Path,
    string ExpectedSoname,
    string ExpectedBuildIdHex,
    string ExpectedSha256);
```

`ProtectedImageProducerOptions.ExternalJumpTableProviderInput` and
`RehydrationOptions.ExternalJumpTableProviderInput` are nullable host-only
inputs. The command grammar adds the following optional **whole group** to
`protect-image` and `rehydrate-image` only:

```text
[--provider-file PATH --provider-soname SONAME
 --provider-build-id HEX --provider-sha256 SHA256]
```

All absent means no provider mode. A partial/empty/duplicate group is a usage
error. Build ID is 8–128 even hexadecimal characters; SHA-256 is exactly 64
hexadecimal characters; the CLI normalizes both to lowercase. Semantic reading
also validates canonical SONAME and identity fields. No environment variable,
payload path or snapshot field selects a provider. `protect` gains no provider
flags.

The internal publication owner is
`Application/Rehydration/SemanticExternalJumpTablePublicationValidator.cs`:

```csharp
public static bool ValidateSourceAndProvider(
    ElfFile source, ProtectedImageDocument document,
    SemanticPlanSnapshot snapshot, ExternalJumpTableProviderInput? providerInput,
    DiagnosticBag diagnostics, out Aarch64FunctionAnalysis? validatedAnalysis);

public static bool ValidateRehydratedImage(
    ElfFile source, ElfFile output, ElfLayoutPlan layoutPlan,
    SemanticPlanSnapshot? snapshot, Aarch64FunctionAnalysis? validatedAnalysis,
    DiagnosticBag diagnostics);
```

It reuses the existing emitter's internal seam rather than a second writer:

```csharp
internal bool FunctionProtectionService.TryReemitExternalConsumer(
    ElfFile source, Aarch64FunctionAnalysis analysis, ulong outputAddress,
    out byte[] bytes,
    out IReadOnlyDictionary<ulong, ulong> instructionOffsets);
```

## 3. Contracts

### Pinned input and wire ownership

- `ExternalJumpTableProviderFileReader.Read(ExternalJumpTableProviderInput)`
  coordinates only; Infrastructure owns file I/O. It returns private bytes and
  sanitized diagnostics, not a provider path in the semantic plan.
- Reject raw input over `MaximumProviderElfBytes` (8 MiB) before allocation or
  caller-memory access. Public `SemanticExternalJumpTableProviderReader.Read`
  copies caller memory once; internal `ReadPrivateSnapshot` uses the already
  private Infrastructure byte array without another full copy. SHA-256 is
  compared in fixed time **before** `ElfParser.Parse`. Parsing and every
  identity/table/target fact use that same snapshot, never a reopened path or
  another caller-memory observation.
- Keep **URP-SPS6/version 6 only**; reject v1–v5, no dual decoder. The
  `SemanticExternalJumpTableExtension` provider-facts discriminator is **8**
  and its existing wire fields/bytes are unchanged. Provider-only records
  still decode and canonicalize byte-for-byte without a consumer companion.
  That codec capability does not admit a provider-only executable publication.
  Protected Image ABI remains **v1**.
- The appended `SemanticExternalJumpTableConsumerExtension` discriminator is
  **9**. Its fields are `ProviderTableIdentity`, `ProviderSha256`, and
  `ConsumerProof`. Link it to exactly one provider-facts extension by table
  identity **and** full content hash. Cross-validate the proof's SONAME/build
  ID/hash/table name/size/table-byte hash and ordered `(entry index, target
  symbol)` bindings against provider facts; swapping target names independently
  of table-entry order is invalid.
- Bind one unique `SemanticIndirectTargetExtension` at `BranchAddress`, exact
  `SemanticEntityId.Instruction(new VirtualAddress(BranchAddress))`,
  `RuntimeResolved` resolution and runtime binding
  `external-provider-table:{ProviderSha256}:{TableIdentity}`. A binding string
  or refreshed digest alone is not ownership evidence. Missing/duplicate owners
  or removing both provider and consumer extensions cannot bypass ordinary
  indirect-target completeness validation.
- Provider facts retain only derived content identity, symbols, ranges, entry
  displacements and table bytes. `ExternalJumpTableProviderInput` (path/operator
  pin configuration) is not serialized; derived SONAME/build ID/content hash
  are serialized facts, not persisted host configuration.

### Source proof and selected-function boundary

- A successful provider read supplies `CreateConsumerProofInput()`; failure
  supplies none. The proof query re-decodes the complete bounded selected
  function from consumer ELF bytes. Supplied addresses, offsets and words must
  match that exact range. A public DTO constructor is not trusted provenance.
- Bind the exact sole provider SONAME dependency, undefined global/default
  dynamic `STT_OBJECT`, unique non-PLT `R_AARCH64_GLOB_DAT` by exact dynsym and
  RELA tuple/source-row identity, and aligned writable file-backed eight-byte
  GOT slot. The GOT is a pointer carrier, not external table storage. Undefined
  consumer `st_size == 0` is allowed; the pinned defined provider object proves
  the 16-byte table extent.
- Require adjacent bounds compare / `B.HI`, a safely terminating taken default
  path, and the ordered five producers ADRP / GOT-LDR / indexed signed LDRSW /
  table-base ADD / BR. Entry width is 4, signed, scale shift 2, bounds 0–3;
  the target is table start plus the signed displacement. Reject default edges
  entering/re-entering the dispatch chain and any W/X write to the checked
  architectural GPR after the compare.
- Compare writes NZCV with one zero-register destination matching index width,
  the matching index input and exact bound. `SUBS WZR,W0,#3` is a valid CMP
  alias; `SUBS W0,W0,#3` is not.
- Preserve modifier kind/amount at `AsmStoneAdapter`, including attached,
  standalone and encoded-field forms. Unknown recognized modifiers cannot
  become plain registers. ADD accepts no modifier or identity `Lsl` / `Uxtx` /
  `Sxtx` amount zero only with the exact 64-bit register chain; narrow
  extensions and nonzero shifts are not this expression.
- Provider facts must have exactly four non-null target identities. Copy a
  target enumerable with at most five successful observations before rejecting
  excess input; never first materialize an unbounded enumerable.

### Source, logical output and physical output revalidation

1. At rehydration, snapshot/hash/parse the supplied provider again and compare
   **all** retained provider facts with independently derived facts. Bind the
   selected source function by exact table/index/full symbol record and one
   matching `ProtectedImageEmitRegion`; independently analyze that source with
   pinned facts and require one exact external-consumer proof. Compare bounds,
   default path, registers, ordered producers, GOT/file offsets, import owner
   and provider identities, not `Proof` prose.
2. Reproject the rederived analysis with `Aarch64SemanticPlanFactory` and the
   canonical codec. Compare source semantic instructions and unique exact
   fixups: source VA/file/range, original encoding, kind, target/identity,
   expression place/scale/page/addend/target and relaxation. Omitting an
   instruction **and** its fixup or coordinating target/expression edits still
   fails the source-derived projection comparison.
3. Keep the consumer GOT/page mappings identity-preserved, including every map
   containing either address; validate file offsets through `LoadMap` when
   file-backed. Each producer needs its exact source instruction identity and
   a four-byte output row inside the one emitted function, matching VA/file
   deltas and a contiguous five-instruction chain. Bound emitted size to
   **65,536 instructions**. Provider VAs/offsets stay in provider-specific types:
   no local `AddressMap` rows, table clones, veneers or implicit translation.
4. **Do not confuse encoding origins.** Pre-placement region bytes are encoded
   at layout-neutral origin **0**; snapshot output ranges retain a source-domain
   anchor for offset calculations, not the instruction PC. Validate neutral
   ADRP at `0 + producerOffset`. Final bytes are encoded/decoded at
   `physicalOutputVA + producerOffset`. Nonzero rebased source VAs must work;
   never check neutral bytes using the source-anchored PC.
5. Retain the rederived **`Aarch64FunctionAnalysis`**, not just its proof, across
   materialization. Resolve the unique physical placement from the planner and
   executable output `LoadMap`. Re-emit the **entire** selected consumer using
   `TryReemitExternalConsumer` at that physical VA; compare every emitted byte
   and each producer's actual offset with the carried mapping. This binds the
   dispatcher, bounds, default and live chain. Counting BRs or finding a
   plausible path is insufficient: replacing the live BR with RET while mapping
   to an appended valid dead copy must fail.
6. Require exactly one BR at the mapped chain end, the unchanged full selected
   entry symbol, and a decoded source-entry B stub to the physical function.
   Require output `NeededLibraries` exactly equal the proven source list,
   rederive the final GLOB_DAT/dynsym owner with physical producer sites,
   require one relocation owner for the import, and compare GOT VA/file mapping
   and pointer bytes with source. The ADRP word comes only from
   `Aarch64InstructionEncoder` with decoder round-trip; the remaining chain
   words match source. Fail before Native Image publication on any mismatch.

Only the selected consumer is rewritten. Provider table/targets remain
external/runtime-owned and unmodified; no provider-domain VA is added to the
consumer `AddressMap`. The retained native row separately executes source and
rehydrated Native Image `urp_entry` plus `urp_observer`, and its checker binds
the observer's original provider import/RELA/GOT facts, bytes, runtime mapping,
target identities, statuses, streams and release. This is one glibc scoped
observation only, not general runtime acceptance.

## 4. Validation & Error Matrix

| Input / boundary | Required behavior |
|---|---|
| Valid reader-derived facts and exact source-byte query | `true`, non-null proof; not publication authorization |
| Source range/word mismatch, unsafe default, checked-index clobber or non-identity modifier | query `false`, null proof, explanatory failure |
| Duplicate GOT slot owner or another relocation owner for imported symbol | reject at exact slot/symbol owner boundary; keep both negatives distinct |
| Wrong-pin/non-success provider read | no proof input; wrong SHA gives `OutputIdentityMismatch` before parsing |
| Partial provider flags | CLI usage error (2), no publication |
| Missing trusted provider at executable rehydration, missing/duplicate companion or wrong carrier identity | `SemanticPlanSnapshotMalformed`, no Native Image |
| Source/fixup disagreement, including coordinated omission | `SemanticPlanSnapshotMalformed`; `source-derived projection` message |
| Non-identity GOT/page map, incorrect producer source/file/output mapping or neutral chain | `SemanticPlanSnapshotMalformed`; `GOT output mapping` message |
| Final entry symbol/dependency/dispatcher/default/chain/GOT mismatch or self-consistent dead-copy mapping | `SemanticPlanSnapshotMalformed`; final `instruction/reference chain` message; no Native Image |
| No official hosted CI result despite retained local source/transformed evidence | row remains `unknown` / scoped observation not promoted |
| Native evidence absent despite managed pass | managed evidence only; no runtime promotion |

Null query arguments use existing argument exceptions. Query failure is not a
new public diagnostic API. See the error spec for safe-file and codec errors.

## 5. Good / Base / Bad Cases

- **Good:** all four host flags, one SHA-pinned provider snapshot, exact source
  owner proof, SPS6 kinds 8+9, identity-preserved GOT, source-derived fixups,
  neutral validation and complete physical re-emission comparison succeed;
  publication is managed evidence, while the retained source/transformed native
  run remains a separate scoped observation until hosted CI confirms it.
- **Base:** a legacy provider-only SPS6 record still decodes to identical
  canonical bytes. Ordinary same-image/shared table and dynamic-import paths
  retain their own owners/regressions. The unconfigured external consumer
  remains rejected.
- **Bad:** changing CMP's destination/ADD's modifier, swapping target names,
  trusting snapshot target expressions, using source VA as neutral PC, or
  accepting an appended valid chain after bypassing the live dispatcher.

## 6. Tests Required

- `Aarch64ExternalJumpTableConsumerProofTests` asserts reader-to-query linkage,
  exact sites/provider identity, ordinary-analyzer rejection, valid CMP alias
  and identity modifiers, decoded clobber/modifier negatives, separate slot and
  symbol owner ambiguity. RELA negatives must have valid DT_RELASZ/row counts
  and distinct physical source-row addresses, so rejection reaches its owner.
- `AsmStoneAdapterTests` asserts actual-word modifier projection. Provider reader
  tests assert wrong-hash-before-parse, maximum-plus-one-before-memory-access,
  private-snapshot mutation isolation, table/target facts and strict provider
  profile without changing ordinary zero-PT_DYNAMIC parser behavior.
- `SemanticPlanSnapshotTests` asserts kinds 8/9, exact carrier linkage, ordered
  entry/target cross-validation, duplicate/null guards and
  `PreviouslyEmittedProviderOnlySps6SnapshotStillDecodesWithIdenticalCanonicalBytes`
  against retained `Fixtures/ExternalJumpTable/provider-only-urp-sps6-legacy.b64`.
- `ExternalJumpTableProviderPublicationTests` asserts pinned producer→snapshot→
  rehydration, wrong/missing pins, source owner/chain tamper, missing owners,
  encoder failure, exact fixup and map binding, instruction+fixup co-omission,
  appended-dead-chain mapping **with and without live BR removal**, each final
  chain/entry/dependency/GOT/dispatcher/bounds/default mutation, and positives
  rebased by `0x4000` and `0x100000`. Refresh nested and outer digests where
  applicable; prove semantic rejection, not merely stale-checksum detection.
- `CliApplicationTests` asserts complete/partial provider groups on both commands,
  provider-path redaction and no artifacts on failure. `LinuxSafeFileInputTests`
  owns FIFO, final symlink, descriptor replacement and deterministic growth /
  truncation negatives; see the safe-input spec for assertion points.
- The indirect-control independent checker preflights the complete closed root
  before reading, hashing, or parsing any evidence bytes. It rejects symlink and
  special-file entries, applies explicit per-file and aggregate byte/count
  bounds, opens root-relative files with no-follow descriptors, and verifies
  truncation/growth and snapshot identity while reading. Its PT_LOAD owner
  contract comes from the sibling `evidence_load_range.py` loaded by explicit
  file path, not ambient `PYTHONPATH`. The private module key is scoped to the
  checker instance, and any pre-existing `sys.modules` entry must be the exact
  module object owned by that checker; foreign-origin and same-origin entries
  with forged source-digest markers are rejected before reuse. Positive-provider
  and rollback roots
  retain and hash the exact producer/checker/parser inventory, including this
  shared range helper; refreshed manifests do not replace those source-hash
  checks. These hashes pin retained source within the evidence contract, not a
  cryptographic build attestation, and do not promote the runtime row.
- Accepted managed gate logs are under `.artifacts/managed-provider-review/`:
  64 publication, 9 original-regression/legacy/safe-file, 340 focused,
  **754 full with no skips**, Release 0 warnings/errors, architecture/encoder
  checks/self-tests and 7 boundary unit tests. Exact commands are recorded in
  the task implementation log. They remain managed evidence, not a substitute
  for the separate native row.
- Native Slice C evidence is retained under
  `.artifacts/indirect-control/provider-rollback-native-image-implementation-20261020-4/`
  (transformed provider positive/rollback) and
  `.artifacts/indirect-control/provider-loaded-rollback-ci-validation-20261020T153308Z-18193`
  (source-loader rollback). Current root-bound Python suites pass 26/26 and
  5/5 respectively; focused fixture/digest-chain/regression tests pass 3/3.
  The retained full local gate records managed 754/754, native runtime suite
  success and Python 458/458. The independent integration review passed the
  exact current roots, but no official hosted Actions run has occurred; the
  fixture/runtime row stays `unknown` and non-promoted. See
  [runtime evidence and its inventory](./runtime-compatibility.md#scenario-external-provider-managed-admission-and-scoped-native-evidence).

## 7. Wrong vs Correct

```text
Wrong: trust snapshot instructions/fixups because their digests agree; keep
       only a proof; find one valid BR/GOT chain in the output and publish.
Correct: rederive source analysis and provider facts, compare the canonical
         source projection and exact mappings, retain that analysis, re-emit
         the whole consumer at its physical PC, compare all bytes and offsets,
         then bind the entry, dependency, owner and unchanged GOT before publish.
```

```text
Wrong: use a blocking FileStream then reject a FIFO, or stat a path and reopen
       it for reading; hash one observation and parse another.
Correct: nonblocking/no-final-symlink open, descriptor regular-file/size check,
         same-handle bounded snapshot, SHA verification before parse, sanitized
         diagnostics. Never infer runtime acceptance from this managed boundary.
```
