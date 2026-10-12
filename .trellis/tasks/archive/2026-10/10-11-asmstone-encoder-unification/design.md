# Technical design: AsmStone encoder integration and single final-word boundary

## Design goal

Create one stable final-word path:

```text
StructuralElf / SemanticPlanning / ElfLayout
  -> project-owned encoding request
  -> Aarch64InstructionEncoder
  -> AsmStone generated encoder
  -> AsmStone decode round-trip
  -> UrProtect decoder projection
  -> final word
```

UrProtect remains the semantic authority for ELF and relocation facts. AsmStone
becomes the sole low-level instruction encoding authority for generated and
re-encoded AArch64 instructions.

## Ownership boundary

### UrProtect owns

- ELF headers, program headers, load maps, file/virtual/runtime address domains;
- relocation type and pair selection;
- symbol identity, addends, GOT and TLSDESC ownership;
- PT_TLS template, zero-fill, alignment, and runtime/profile requirements;
- source/output address mapping and target calculation;
- branch relaxation, veneer choice, and layout placement;
- preservation policy for non-relocation instruction fields;
- publication, reparse, and artifact validation;
- stable diagnostic mapping and no-partial-publication behavior.

### AsmStone owns

- generated instruction identity and catalog lookup;
- opcode/form selection from a project request;
- operand legality;
- register classes, widths, modifiers, and constraints;
- immediate field encoding and scale legality;
- PC-relative field encoding and generic range/alignment checks;
- final instruction word generation;
- decode/encode operand round-trip at the instruction level.

AsmStone does not receive raw ELF relocation types, TLS models, GOT owners, or
loader policy.

## Adapter contract

The existing project-owned adapter remains the only public boundary:

```text
Aarch64InstructionEncoder.TryEncode(Aarch64InstructionEncodeRequest)
Aarch64InstructionEncoder.TryCreate(Aarch64InstructionBuildRequest)
```

The request records remain project-owned. The adapter may internally use
AsmStone's `A64InstructionCode`, typed descriptors, `A64Operand`, and
generated field metadata.

The adapter should add only the minimum project-owned families needed by current
writers:

- `MoveWideImmediate`: MOVZ/MOVN/MOVK form selected by source/template;
- `MoveRegister`: register-to-register MOV alias backed by the canonical
  ORR/register form;
- `CompareImmediate`: CMP/SUBS immediate form with width and shift;
- `Return`: RET with optional source template validation;
- existing branch, conditional branch, ADR/ADRP, literal, ADD, and unsigned
  load/store families remain canonical;
- a generic template re-encode operation may be used for instructions whose
  operands are unchanged but whose address or register permutation changed.

The adapter must not leak generated instruction codes in its request or result
records. If it uses descriptors, it projects only bounded project-owned facts
for validation.

Every successful adapter operation must:

1. validate source/output alignment;
2. decode source and optional output template;
3. verify family and expected width/form;
4. replace only the requested structured operand(s);
5. encode through AsmStone;
6. decode through AsmStone;
7. validate family, requested target/immediate/width, and template-preserved
   operands;
8. decode through `AsmStoneAdapter` and return only its project-owned
   instruction projection.

Any failure returns no word and a stable adapter diagnostic.

## Writer migration design

### Protection dispatcher

`FunctionProtectionCodeEmitter.CodeEmitter` should collect structured branch
patch requests and structured generated-instruction requests. It may reserve
instruction slots while labels are unresolved, but finalization must call the
adapter with source/template family and resolved target/address.

Generated dispatcher instructions use:

- MOV wide immediate for state IDs;
- CMP immediate for block comparisons;
- Branch26 for dispatcher and block jumps;
- ConditionalBranch19 for state selection;
- MoveRegister for register shuffles;
- RET for invalid-state guard.

Branch range checks remain in the emitter/layout policy. The adapter performs
the final encoding and its generic range validation.

### Layout branches

`ElfLayoutPlanner` is the owner of branch placement decisions, not final
opcode construction. It computes source/target placement and asks the adapter
to encode a Branch26 or Call26 request using the source instruction as template.
The planned byte edit contains only the adapter result.

`ElfLayoutMaterializer` compares emitted bytes with the plan and reparses them.
It does not reconstruct an expected branch word through a private encoder. A
shared project-owned validation helper may decode and compare the planned word,
but it cannot assemble a new word independently.

### Semantic fixups

`Aarch64SemanticFixupEncoder` computes relocation values and selects the
project-owned family. For ADD and load/store low-12 forms it supplies the
resolved immediate, expected width/scale, source encoding, output address, and
output template to the adapter. It no longer masks and inserts immediate bits.

Absolute data relocations and non-instruction ELF metadata remain binary field
serialization, not instruction encoding, and stay in their current owners.

### TLS materialization

TLS semantic code validates model, sequence, register/resource ownership,
relocation pair, addend, target, GOT/TLSDESC owner, and PT_TLS facts first.
It then calls the adapter for:

- TLSIE LD_GOTTPREL_PREL19;
- TLSIE ADRP/LD64;
- TLSLD/TLSGD ADD, ADRP, and CALL26;
- TLSDESC ADRP, LD64, ADD, and marker validation;
- local-exec forms as each current output writer is migrated.

The adapter receives instruction templates and structured resolved values. It
does not infer TLS meaning from an encodable instruction.

For linked retained-reloc objects, UrProtect first validates that any
pre-resolved source field equals the carried GOT owner plus addend. Only then
does the adapter re-encode the output instruction.

### Remaining raw masks

Allowed:

- bounded instruction recognition and nearest-negative checks;
- checking that a decoded instruction belongs to an expected form;
- extracting source fields before project-owned validation;
- ELF relocation/header/r_info serialization;
- byte-preserving copy of an unchanged instruction.

Forbidden:

- creating a new final word by OR-ing an opcode constant with operand bits;
- inserting a relocation immediate into a word with a local mask;
- patching branch fields in a second writer;
- retaining the source/output template when AsmStone rejects the request.

## Upstream compatibility and vendor update

The vendor update should be a separately reviewable commit:

1. fetch exact upstream commit `ff961cff17c833f404cc6d9cb49065bd99278ecb`;
2. replace the vendored source while preserving project-local integration
   boundaries;
3. verify `COMMIT`, source lock, license, generated catalog and project
   reference;
4. run AsmStone restore/build/tests;
5. run UrProtect adapter tests before touching writer migrations.

The update is expected to preserve existing object-level APIs. New
`A64InstructionCode` and descriptor APIs are internal adapter implementation
tools, not an UrProtect public contract.

## Diagnostics and failure behavior

Adapter backend, operand, range, alignment, family, source/template, and
round-trip failures map to existing semantic/layout diagnostic codes. No caller
may convert an adapter failure into source-word retention, partial output, or a
successful plan.

Every writer migration must preserve atomic publication. A failure after
planning but before publication leaves no Native Image, role, stage, report, or
evidence set marked successful.

## Testing architecture

- Adapter unit tests cover each new family, all operand widths, ranges,
  alignment, template mismatch, backend failure, and both decode round-trips.
- Production-path tests assert dispatcher and layout output decodes to the
  expected generated family and operands.
- TLS tests assert relocation/GOT/PT_TLS mismatches fail even when the
  corresponding instruction is individually encodable.
- GNU differential fixtures remain independent ABI/toolchain oracles.
- The architecture scanner checks final-word construction sites and retains an
  allowlist only for bounded recognition, ELF serialization, and byte copying.
- Full managed, Python, fixture, regression, and native suites run at the
  final gate.

## Compatibility and rollback

The task does not alter Protected Image ABI v1, Payload Frame v3, HostContext
ABI v1, CLI schemas, or runtime feature status. Each migration batch is a
separate commit and can be reverted independently. The vendor update is
reverted together with any adapter code that depends on new AsmStone APIs; no
fallback branch or alternate writer is introduced.
