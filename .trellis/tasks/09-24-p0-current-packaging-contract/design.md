# P0 Design: Current AArch64 Packaging Contract

## Goal

Make one current frame contract carry two explicit, independently validated
execution profiles: `outer-execveat` and `host-context-entry`.

## Current implementation choice

Introduce frame format v3. Do not overload v1/v2 semantics. The v3 common
header retains the existing identity, size, offset, and digest fields, adds a
profile field, and carries HostContext metadata only for the HostContext
profile. The managed and native layout owners must be updated together and
covered by `ContractLayoutTests` and `contract_probe`.

The exact offsets are owned by `PayloadFrameCodec` and
`native/urprotect-runtime/include/urp/payload_frame.h`; consumers import those
owners instead of repeating literals. Unknown versions, profiles, flags,
capabilities, reserved fields, profile metadata, and launcher markers fail
closed.

## Profiles

### outer-execveat

- Source is the current standalone AArch64 PIE class.
- The profile launcher is the static AArch64 launcher.
- Dispatch keeps anonymous memfd + `execveat(AT_EMPTY_PATH)` semantics.
- The frame must not carry HostContext-only fields.

### host-context-entry

- Source is a declared AArch64 ET_DYN entry image exposing the bounded entry
  symbol, initially `urp_entry`.
- The profile launcher/runtime uses the existing native HostContext adapter.
- Dispatch verifies both digests, creates/seals the image memfd, resolves the
  exact symbol, calls it once, releases the image, and returns its status.
- The first profile slice accepts only the already validated adapter subset.

## Managed API

Add a typed pack profile/options value rather than a free-form string. The CLI
exposes an explicit `--profile` option and `--entry-symbol` only for the
HostContext profile. A profile-specific launcher remains required. Invalid
profile/source/launcher combinations return `UnsupportedPackInput` or
`LauncherUnavailable` before frame encoding.

## Native integration

The outer launcher accepts only the current v3 outer profile. The HostContext
runtime self-test and production launcher path accept only the current v3
HostContext profile. During P0, legacy v1/v2 parsers may remain in isolated
migration tests, but the current launcher marker and managed pack path never
select them implicitly.

## Evidence

The P0 oracle must retain separate artifacts for:

- managed pack result and frame metadata;
- outer profile baseline/wrapped execution;
- HostContext profile entry status and release order;
- profile/launcher mismatch and stale frame rejection;
- frame round-trip and digest verification.

The compatibility matrix should upgrade the production-pack row only after the
managed HostContext pack path has executed the real profile-matched runtime.
