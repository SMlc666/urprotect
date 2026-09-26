# Contract literal inventory

This inventory distinguishes format/ABI values from intentional fixture bytes.
The owner column is the location that defines the value; consumers should use
that definition or a named test fixture constant instead of repeating a raw
offset or limit.

| Contract | Owner | Consumers / checks | Classification |
| --- | --- | --- | --- |
| ELF64 class, machine, type, program-header sizes and dynamic tags | `src/UrProtect.Core/Elf/ElfTypes.cs` | `ElfParser`, `ElfValidator`, `ElfFixture`, parser tests | production ELF contract |
| ELF symbol-version definition/requirement models and parser-summary counts | `src/UrProtect.Core/Elf/ElfTypes.cs`, `src/UrProtect.Core/Elf/ElfSymbolVersionParser.cs`, and `src/UrProtect.Cli/ProductReport.cs` | parser/report tests and CLI JSON consumers | parser observation only; runtime import requirements are limited to the separate single-libc HostContext feature row |
| Frame v1/v2 migration layouts plus current v3 profile header, trailer, digest and field offsets | `native/urprotect-runtime/include/urp/payload_frame.h` and `PayloadFrameCodec` | native runtime, profile launchers, frame tests, contract probe | cross-language wire contract |
| HostContext ABI, capabilities, minimum structure sizes | `native/urprotect-runtime/include/urp/host_context.h` and `HostContextContract` | runtime, adapter, frame tests, contract probe | cross-language ABI contract |
| HostContext image preflight and bounded ELF feature rejection, including exact weak-undefined JUMP_SLOT PLT, libc.so.6 GNU-hash version-need validation, and closed libc.so.6 + glibc-loader dependency pair | `native/urprotect-runtime/host_image_validation.c` | `host_adapter.c`, native self-tests, PLT/dependency fixtures, fixture matrix | sole native owner of dependency names/count, relocation, dynsym, GNU-hash, and accepted Verneed-chain validation before image-handle creation |
| Sealed image resource lifetime, loader handoff, symbol lookup, release, and pair-only loader-environment gate | `native/urprotect-runtime/host_adapter.c` | runtime, native self-tests, fixture matrix | native adapter lifecycle/environment owner; applies the pair gate after preflight and before memfd creation |
| HostContext two-dependency positive/negative fixtures and fake-loader marker probe | `native/urprotect-runtime/host_context_graph_fixture.c`, `host_context_graph_self_test.c`, `host_context_fake_loader.c`, `host_context_fake_loader_probe.c` | managed AArch64 glibc handoff and PR evidence gate | controlled fixture contracts only; fake loader is a test witness, not a supported system dependency |
| Native frame limits | `payload_frame.h` / `PayloadFrameLimits` | launcher, runtime, codec tests | shared safety limit |
| Profile-specific launcher ABI markers and managed launcher validation | `src/UrProtect.Core/Pack/LauncherContract.cs` | `ElfPackService`, profile launcher tests | launcher contract |
| Synthetic ELF offsets and segment layout | `tests/UrProtect.Core.Tests/ElfFixture.cs` | parser, pack, and property tests | named fixture data |
| Native rejection sentinels and mutation offsets | `native/urprotect-runtime/host_context_self_test.c` | native HostContext self-test | intentional wire mutation |
| SHA-256 round constants and known-answer digests | `native/urprotect-launcher/sha256.c` / `self_test.c` | native self-test | algorithm/test vector, not protocol layout |
| CLI exit codes and command limits | `src/UrProtect.Cli/CliApplication.cs` | CLI tests and E2E scripts | public CLI contract |

Raw ELF and frame byte arrays remain in tests only where changing an individual
byte is the behavior under test. New tests should reference the owning layout
constants for offsets and sizes.
