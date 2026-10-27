# Cross-Layer Contract Guide

> Trace data and ownership across every boundary before changing a format or
> workflow.

## Map the end-to-end path

For a managed ELF protection change, write down the actual owner chain. A
representative path is:

```text
CLI/input boundary
  → selected-function analysis
  → semantic plan and canonical snapshot
  → layout planning/materialization
  → Protected Image / Native Image publication
  → evidence producer and independent checker
  → fixture registry and CI gate
  → runtime observation (when claimed)
```

The path varies by feature; do not assume every feature uses every stage. For
each edge, record the representation, identity, bounds, failure result, and the
component responsible for validation.

## Define boundaries explicitly

| Boundary | Questions to answer |
| --- | --- |
| CLI / application | Are all required inputs explicit and validated before side effects? Are host-only pins excluded from serialized artifacts? |
| ELF / semantic analysis | Is code analysis rooted only at selected functions? Are table, relocation, symbol, and target queries bounded and demand-driven? |
| Semantic snapshot / layout | Are source facts and output bindings typed and re-derived? Is one canonical plan consumed by one planner/materializer? |
| Publication / rehydration | Does failure occur before successful artifact publication? Does the consumer independently validate the complete source-derived result? |
| Evidence producer / checker | Does the checker parse retained source/output bytes and recompute claims rather than trust booleans, counts, or hashes alone? |
| Registry / CI / runtime | Are evidence paths, registry digests, execution tiers, runtime identity, and support state synchronized and accurately scoped? |

## Cross-layer failure modes

- **Duplicated validation:** the same format rule is implemented differently in
  a producer and consumer. Assign one owner and make other layers call or
  independently verify the defined contract as appropriate.
- **Lost identity:** an address, symbol, table entry, relocation, or process
  result moves across a boundary without its source identity and mapping. Carry
  typed identities and validate the relation at the receiving boundary.
- **Trusting declarations:** a manifest path, `success: true`, checksum, or
  producer-reported count is mistaken for proof. Re-open bounded retained
  artifacts and derive the facts independently.
- **Layer confusion:** parser acceptance is treated as protection support;
  managed publication as runtime acceptance; hosted CI as general support; or
  evidence availability as a pass. State each claim at the layer actually
  demonstrated.
- **Whole-image discovery:** a generic parser, packer, or layout path scans
  unrelated instructions. Keep instruction analysis explicit, rooted at the
  selected function, and demand-driven for referenced data.
- **Partial publication:** a late failure leaves a success marker or artifact.
  Bind publication to final validation and test the no-output failure path.
- **Registry drift:** an auxiliary registry changes without updating its
  declared digest owner. Add a regression that validates the complete registry
  chain rather than checking only the changed file.

## Validation checklist

- [ ] End-to-end data flow and every owner boundary are mapped.
- [ ] Each boundary has an explicit input/output contract and stable failure.
- [ ] Address, symbol, table, relocation, and evidence identities survive the
      path and are independently rechecked where required.
- [ ] Producer and consumer agree on schema and contract version; obsolete
      versions fail clearly rather than entering a compatibility fallback.
- [ ] Tests cover valid behavior, nearest malformed input, and refreshed-checksum
      semantic tampering where artifacts carry claims.
- [ ] No failed operation publishes a success artifact or runtime claim.
- [ ] Registry, tests, documentation, and CI agree on evidence paths and scope.
- [ ] Runtime evidence records actual status, streams, identity, and mappings;
      unsupported or unavailable rows remain explicitly unknown/unpromoted.
