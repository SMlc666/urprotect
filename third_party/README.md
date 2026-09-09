# Third-party dependencies

## AsmStone

The vendored `AsmStone` source under `third_party/AsmStone/src/AsmStone` is
used as the pinned AArch64 instruction decoder/encoder backend.

- Upstream: https://gitlab.com/ursafe/AsmStone
- Pinned commit: see `third_party/AsmStone/COMMIT`
- Runtime license: MIT, see `third_party/AsmStone/LICENSE`
- Generated-input notices: see `third_party/AsmStone/docs/THIRD_PARTY.md`

The project consumes AsmStone only through `UrProtect.Core.Aarch64.AsmStoneAdapter`.
