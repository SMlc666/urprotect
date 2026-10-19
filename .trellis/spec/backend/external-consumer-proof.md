# Selected External-Table Consumer Proof

## 1. Scope / Trigger

Use this contract when changing the demand-driven external-provider query in
`Aarch64JumpTableResolver`, its project-owned operand model, or its focused
tests. This is a proof-only seam for one four-entry signed-relative-32 table,
not production external-table admission. Normal function analysis and
`protect` / `protect-image` / `rehydrate-image` must remain fail-closed for
this external consumer until separate integration and publication work lands.
See [Quality Guidelines](./quality-guidelines.md) for bounded ELF reads and
the current SPS6 provider-facts foundation.

## 2. Signatures

The existing resolver owns the query; do not introduce another parser/resolver:

```csharp
public static bool TryProveExternalProviderTableConsumer(
    IReadOnlyList<Aarch64FunctionInstruction> selectedInstructions,
    int branchIndex,
    ElfFunctionSymbol selectedFunction,
    ElfFile consumer,
    Aarch64ExternalJumpTableProviderFacts providerFacts,
    out Aarch64ExternalJumpTableConsumerProof? proof,
    out string failure);
```

A successful `SemanticExternalJumpTableProviderReadResult` supplies
`CreateConsumerProofInput()`; a non-success result returns no proof input.
The query trusts verified provider facts, not arbitrary caller assertions of
SHA identity. It does not reopen provider bytes or perform publication-time
revalidation. Public DTO construction is not proof of trusted provenance.

## 3. Contracts

- Re-decode the complete bounded selected function from consumer ELF bytes;
  supplied instruction addresses, offsets and words must match that range.
- Bind the exact provider SONAME dependency, undefined global/default dynamic
  `STT_OBJECT`, unique non-PLT `R_AARCH64_GLOB_DAT`, and aligned writable,
  file-backed eight-byte GOT slot. An undefined consumer symbol may have size
  zero; the verified provider definition establishes the table extent.
- Require adjacent bounds compare / `B.HI` and the ordered
  ADRP / GOT-LDR / indexed signed LDRSW / table-base ADD / BR chain. The taken
  default edge must terminate safely without entering the dispatch chain.
- Bounds compare must write NZCV with one zero-register destination matching
  the index width, a matching index input and the exact bound. Reject any
  W/X definition of the checked architectural GPR. Canonical
  `SUBS WZR,W0,#3` is a valid CMP alias; `SUBS W0,W0,#3` is not.
- Preserve register modifier kind and amount at `AsmStoneAdapter`, including
  register-attached and standalone/encoded-field forms. Unknown recognized
  modifiers must not become plain registers. ADD accepts no modifier or
  identity `Lsl` / `Uxtx` / `Sxtx` amount zero only with the surrounding
  exact 64-bit producer-register constraints. Narrow extensions and nonzero
  shifts are not this target expression.
- Provider facts carry SONAME/build ID/content hash, table identity/name/size,
  table-byte hash and four provider-local target names/indices. Copy the target
  enumerable with at most five successful observations before rejecting an
  overlong input; do not first materialize an unbounded enumerable.
- Output retains bounds/default sites, ordered producer sites, register views,
  signedness/width/scale, typed GOT address/file offset and import/provider
  identities. Never turn provider addresses into consumer AddressMap rows,
  source-image table bytes, clones or runtime translations.
- No new CLI/environment inputs or wire format are introduced by this query.

## 4. Validation & Error Matrix

| Input / boundary | Required behavior |
|---|---|
| Valid source-byte chain and verified provider facts | `true`, non-null proof |
| Source range/word mismatch, unsafe default or register clobber | `false`, null proof and explanatory failure |
| SUBS writes checked W/X register | Reject at bounds proof |
| ADD LSL #1, UXTW #0, SXTX #1 or unknown modifier | Reject exact target expression |
| Two owners of selected GOT slot | Reject exact non-PLT GLOB_DAT owner uniqueness |
| Unique selected slot, second owner of imported symbol | Reject symbol relocation-owner ambiguity |
| Wrong-pin/non-success provider reader result | No consumer proof input |
| Wrong target count or null target in DTO | Constructor rejects; enumeration remains bounded |
| Opt-in proof succeeds | Ordinary production analysis still rejects external dispatch |

Null query arguments use the existing argument exceptions. Proof failure is
not a publication diagnostic API; do not infer a new public diagnostic code.

## 5. Good / Base / Bad Cases

- **Good:** reader-derived pinned facts plus a four-entry source-byte consumer,
  valid zero-destination compare, safe default and identity ADD.
- **Base:** ordinary same-image relative/shared jump-table resolution keeps its
  existing owner and behavior; shared helpers must retain these regressions.
- **Bad:** changing only the CMP destination or ADD modifier yields an apparent
  register chain but not the proven bounded target expression.

## 6. Tests Required

- `Aarch64ExternalJumpTableConsumerProofTests`: positive exact sites/identity,
  real reader-to-consumer linkage, normal-analyzer rejection, and decoded
  source-byte mutations for SUBS index writes and ADD modifiers. Assert the
  intended failure boundary, not only a generic false result.
- `AsmStoneAdapterTests`: actual instruction-word modifier projections,
  including standalone extension evidence and valid identity forms.
- Duplicate-relocation fixtures must declare matching DT_RELASZ/row counts and
  valid preceding metadata. Assert distinct slot-owner and symbol-owner
  failures. Give separate physical RELA rows distinct source-row addresses.
- Retain provider-reader wrong-pin/no-proof-input and bounded target-copy tests,
  plus relative/shared-table and dynamic-import-owner regressions whenever
  shared resolver or decoder helpers change.
- Source-byte negatives should demonstrate red-before / green-after behavior;
  successful compilation or a mnemonic/register-only match is insufficient.

## 7. Wrong vs Correct

**Wrong:** accept any `subs*` as CMP, flatten modified operands into registers,
or count a duplicate-RELA test as coverage when inconsistent DT_RELASZ causes
an earlier failure.

**Correct:** prove zero destination/NZCV/index non-clobber, retain and constrain
modifier semantics, and keep all earlier metadata valid so each negative
exercises its intended boundary.

A scoped proof-query PASS does not establish snapshot serialization,
publication-time consumer/provider byte revalidation, selected GOT-page
re-encoding, unselected-observer preservation, native loading/execution, or
glibc/musl/Bionic support. Those remain separate validation stages.
