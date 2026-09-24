# Contract literal inventory

This inventory distinguishes format/ABI values from intentional fixture bytes.
The owner column is the location that defines the value; consumers should use
that definition or a named test fixture constant instead of repeating a raw
offset or limit.

| Contract | Owner | Consumers / checks | Classification |
| --- | --- | --- | --- |
| ELF64 class, machine, type, program-header sizes and dynamic tags | `src/UrProtect.Core/Elf/ElfTypes.cs` | `ElfParser`, `ElfValidator`, `ElfFixture`, parser tests | production ELF contract |
| Frame v1/v2 header, trailer, digest and field offsets | `native/urprotect-runtime/include/urp/payload_frame.h` and `PayloadFrameCodec` | native runtime, launcher, frame tests, contract probe | cross-language wire contract |
| HostContext ABI, capabilities, minimum structure sizes | `native/urprotect-runtime/include/urp/host_context.h` and `HostContextContract` | runtime, adapter, frame tests, contract probe | cross-language ABI contract |
| Native frame limits | `payload_frame.h` / `PayloadFrameLimits` | launcher, runtime, codec tests | shared safety limit |
| Launcher ABI marker and managed launcher validation | `src/UrProtect.Core/Pack/LauncherContract.cs` | `ElfPackService`, launcher tests | launcher contract |
| Synthetic ELF offsets and segment layout | `tests/UrProtect.Core.Tests/ElfFixture.cs` | parser, pack, and property tests | named fixture data |
| Native rejection sentinels and mutation offsets | `native/urprotect-runtime/host_context_self_test.c` | native HostContext self-test | intentional wire mutation |
| SHA-256 round constants and known-answer digests | `native/urprotect-launcher/sha256.c` / `self_test.c` | native self-test | algorithm/test vector, not protocol layout |
| CLI exit codes and command limits | `src/UrProtect.Cli/CliApplication.cs` | CLI tests and E2E scripts | public CLI contract |

Raw ELF and frame byte arrays remain in tests only where changing an individual
byte is the behavior under test. New tests should reference the owning layout
constants for offsets and sizes.
