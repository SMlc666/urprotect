# Support indirect control flow and jump tables

## Goal

Promote indirect branches/calls and ambiguous compiler-generated jump tables from permanent rejection boundaries to modeled, relocatable, and behaviorally verified features.

## Requirements

- Resolve exact and bounded target sets using CFG, value ranges, relocation metadata, function tables, and compiler patterns.
- Model jump-table base, entry width, signedness, relative/absolute representation, bounds, default target, and target ownership.
- Rewrite table entries or references when protected blocks/functions move.
- Define a stable-address veneer or runtime target-translation strategy for opaque targets that can enter relocated code.
- Record unresolved target classification before publication; never guess a target set.

## Acceptance criteria

- [ ] Direct and indirect switch fixtures with bounded targets transform and preserve all cases.
- [ ] Function-pointer and indirect-call fixtures exercise the declared static/runtime mapping strategy.
- [ ] Ambiguous, malformed, out-of-range, and externally owned tables have nearest-negative evidence.
- [ ] All three native runtime lanes retain status, streams, and target-selection evidence for promoted rows.
- [ ] The final report names target-resolution mode and address-map bindings.
