# TLS semantic baseline research

## Repository facts

- `src/UrProtect.Core/SemanticPlanning/SemanticPlanExtensions.cs` already has
  `SemanticTlsBindingExtension`, but its model is a non-empty `string` plus a
  generic `RelocationBinding`. Snapshot encoding/decoding preserves the string
  and generic relocation; validation checks presence/string validity rather than
  model-to-relocation or instruction-sequence consistency.
- `RelocationBinding` preserves decoded relocation kind, raw type, symbol index,
  addend, target, relocation address, and raw `r_info`. It is a useful shared
  primitive, not a complete TLS semantic model.
- `src/UrProtect.Core/StructuralElf` owns program headers, load maps, dynamic
  metadata, symbols, relocations, and bounded ranges after G1. TLS facts must be
  added there rather than reconstructed by semantic or runtime code.
- `src/UrProtect.Core/SemanticPlanning` owns the immutable semantic plan and
  current snapshot codec. TLS extensions must use this owner and must not add a
  second protocol grammar or change the current Payload Frame v3 header.
- `src/UrProtect.Core/ElfLayout` and the G2 `ProtectionWorkflow` own physical
  placement, materialization, profile policy, and atomic publication. TLS
  materialization must preserve PT_TLS/template/zero-fill and use the shared
  layout writer.
- `native/urprotect-runtime/host_image_validation.c` currently validates a
  bounded PT_TLS slice and accepts the narrow AArch64 initial-exec
  `R_AARCH64_TLS_TPREL64` family through the system loader. The existing native
  rows are runtime-adapter evidence, not proof of managed TLS rewriting.
- `fixtures/manifest.json` already contains
  `runtime.host-context.pt-tls` and
  `runtime.host-context.threaded-initial-exec-tls`. The first is current-thread
  initial-exec evidence; the second is opt-in registered-worker initial-exec
  evidence limited to native AArch64 glibc. Dynamic TLS is currently a negative
  boundary.
- G2 is complete and archived. TLS must consume its shared ProtectionWorkflow,
  layout/materializer, HostContext profile policy, publication, and evidence
  owners.

## Existing prior research

Archived TLS work established the current native lifecycle contract:

- `09-24-p4a-aarch64-tls/design.md` selected bounded initial-exec TLS with
  `R_AARCH64_TLS_TPREL64` as the first native slice and kept dynamic TLS,
  reentrancy, and live-thread unload outside that slice.
- `09-25-tls-lifecycle-expansion/design.md` added an explicit opt-in
  `URP_HOST_CAP_THREAD_LIFETIME` contract for registered workers, preserving
  the 56-byte HostContext minimum and adding current table/launch-args views.
- Those decisions remain valid as runtime evidence boundaries, but this task now
  requires the managed semantic layer to model and rewrite all five TLS models
  before promoting any runtime matrix row.

## Required five-model inventory

The semantic gate must cover the ABI-defined families, using the exact
relocation constants already owned by `StructuralElf`/`ElfConstants`:

1. Local-exec: thread-pointer-relative access with executable-local TLS
   assumptions and TPREL relocation forms.
2. Initial-exec: statically allocated module TLS, including GOTTPREL/TPREL
   instruction and relocation forms.
3. Local-dynamic: local module identity plus DTPREL access forms.
4. General-dynamic: module/symbol resolution through the dynamic TLS access
   sequence and `__tls_get_addr` contract.
5. TLSDESC: descriptor address formation, descriptor relocation/GOT state, and
   resolver call sequence.

The exact relocation-family inventory, instruction-sequence recognizers, and
nearest-negative pairs belong in the design and implementation artifacts and
must be checked against the ABI/toolchain fixtures rather than inferred from
model names.

The managed positive forms are documented in `.trellis/spec/backend/quality-guidelines.md`. The GNU TLSIE standalone `LD_GOTTPREL_PREL19` form is also bounded by the research oracle at `aarch64-tlsie-ld-gottprel-prel19-oracle.md`; it remains semantic/layout evidence only, not runtime or lifecycle evidence.
The exact TLSLD ADRP/ADD + `BL __tls_get_addr` + DTPREL ADD/ADD candidate is documented in `.trellis/tasks/10-06-tls-relocation-runtime-matrix/research/aarch64-tlsld-oracle.md`. It is semantic/layout evidence only; its loader-owned DTPMOD64 GOT relocation, resolver call ownership, PT_TLS template, and zero-fill must be preserved before runtime evaluation.
The task also records an encoding-boundary correction in `research/aarch64-encoder-ownership.md`: AsmStone already covers the required final AArch64 instruction families, while UrProtect retains ELF/TLS relocation and sequence semantics. The current implementation gap is incomplete AsmStone encoder integration and duplicated manual instruction-word construction. Production migration and fixture/golden test correction are semantic-gate requirements, not optional cleanup.

## Boundary conclusion

The correct order is:

```text
structural PT_TLS/dynamic facts
  -> typed five-model TLS semantic IR
  -> sequence/relocation/GOT/TLSDESC recognition
  -> semantic TLS fixups and address expressions
  -> shared layout/materialization with PT_TLS preservation
  -> current snapshot/artifact extension validation
  -> per-model/profile/runtime evidence matrix
```

A runtime adapter accepting an unmodified initial-exec image cannot promote a
managed rewrite claim. Each evidence row must retain baseline, transformed,
materialized, loader, lifecycle, and hash witnesses independently.
