# Concurrency and large-input implementation plan

1. Add `Concurrency` and `LargeInput` test fixtures and profile configuration.
2. Cover parser, frame codec, and no-op pipeline concurrent use with serial
   oracles and independent output checks.
3. Add exact-limit, plus-one, multi-megabyte, and publication-safety cases.
4. Add bounded PR/nightly runners, timeout enforcement, `/usr/bin/time` resource
   output when available, and failure-parameter artifacts.
5. Repeat PR runs for flakiness, then execute the amplified native CI profile.

Validation:

```sh
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --filter "Category=Concurrency|Category=LargeInput"
```
<!-- End of task artifact. -->
