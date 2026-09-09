# Third-Party Inputs

AsmStone records source revisions and file hashes in `spec/source-lock.json`.
Source data is fetched locally for generation and is not embedded in the
runtime package by this initial milestone.

## AARCHMRS

Repository:
`https://kernel.googlesource.com/pub/scm/linux/kernel/git/maz/AARCHMRS`

The pinned AARCHMRS tooling branch provides Arm-originated JSON under the BSD
3-Clause terms stated by its notice. Keep the upstream notice with any copied
input or generated distribution material.

## LLVM

Repository: `https://github.com/llvm/llvm-project`

LLVM TableGen is the operational source for generated instruction records. Keep
the LLVM license, LLVM exception, and revision metadata with generated
artifacts when they are distributed.

## Arm XML/ASL

Arm XML/ASL is an optional private completeness oracle. It is not fetched by
the project script and no XML, ASL, or derived archive is committed here.
Review the terms shipped with the exact archive before using it outside a
local validation environment.
