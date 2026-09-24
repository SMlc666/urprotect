# Constants and assertion design

## Boundaries

Keep production parser/codec/ABI owners in their existing namespaces. Remove
consumer-side copies of those values; keep raw byte literals only where the
test explicitly verifies wire bytes. Native headers remain the native source
for native layout, with a probe/check comparing the managed and native views.

## Shape

- Add a checked-in inventory of contract values and their owner/use sites.
- Reuse `ElfConstants`, `PayloadFrameCodec`, `HostContextContract`,
  `LauncherContract`, and `native/urprotect-runtime/include/urp/runtime.h`
  rather than introducing a parallel constant catalog.
- Add a small managed test helper for diagnostic/result/byte-identity checks.
- Add a native contract probe or stable probe output consumed by a script/test;
  failure names the field, expected value, and observed value.

## Compatibility

This stream changes names and test structure only. It must preserve all frame
bytes, ABI offsets, limits, diagnostic codes, and compatibility statuses.
<!-- End of task artifact. -->
<!-- End of task artifact. -->
