# Technical Design

## Schema Shape

The fixture manifest becomes a matrix manifest with separate feature and case
records:

    {
      "schemaVersion": 3,
      "hostContract": { "id": "urp-host-v1", "version": 1 },
      "features": [
        {
          "id": "elf.et-dyn.aarch64",
          "status": "proven",
          "obligation": "bounded identity and load-map invariants",
          "oracle": "parser-tests",
          "evidence": ["..."]
        }
      ],
      "cases": [
        {
          "id": "c-gcc-glibc-pie",
          "features": ["elf.et-dyn.aarch64"],
          "language": "c",
          "toolchain": "gcc",
          "runtime": "glibc",
          "target": "aarch64-linux-gnu",
          "artifact": "pie",
          "source": "fixtures/samples/c/main.c",
          "tier": "pr",
          "required": true,
          "execution": "native-linux",
          "host": {
            "environment": "native-arm64-linux",
            "libc": "glibc"
          }
        },
        {
          "id": "c-termux-bionic-pie",
          "features": ["elf.et-dyn.aarch64", "runtime.bionic.linker"],
          "language": "c",
          "toolchain": "termux-clang",
          "runtime": "bionic",
          "target": "aarch64-linux-android",
          "artifact": "pie",
          "source": "fixtures/samples/bionic/main.c",
          "tier": "nightly",
          "required": true,
          "execution": "native-arm64-bionic-container",
          "host": {
            "environment": "termux-userspace",
            "image": "termux/termux-docker@sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4",
            "sourceCommit": "7033c7639eb86107a4fdf8b72bd6388c07b1284a",
            "linker": "/system/bin/linker64",
            "androidRuntime": false,
            "pageSize": "recorded"
          }
        }
      ]
    }

The exact field names are frozen before code migration. Feature records own
proof status; case records own reproducible inputs and the feature set they
exercise. Host/image facts are nested facts, not compatibility profiles.
The runtime vocabulary treats glibc, musl, and bionic as peer userspace facts.
The host object records how a case was executed; it must not become a
platform-specific runtime branch.

## Status Semantics

- proven: contract invariant, implementation obligation, and required model
  checks are complete;
- validated: deterministic execution passed, but a stated host assumption is
  not formally closed;
- rejected: input or feature is intentionally refused with a stable reason;
- unknown: insufficient evidence; it cannot gate a support claim.

The schema requires an obligation and evidence reference for proven or
validated features. Rejected features require a reason and a negative oracle.
Unknown features require a next-evidence note or an explicit deferral.

## Naming Migration

Project-owned profiles array becomes cases. Script selection uses tier for PR,
nightly, release, and manual. Container profile becomes image or environment
identity. Package-release shell variables use libc_variant or artifact_variant.
Cargo's external profile.release is not changed.

The native bionic case pins both the Termux Docker source commit and the ARM64
image digest. Its host facts also record the bionic linker path, architecture,
kernel, and page size. The Android JNI/native-bridge case remains a separate
execution witness even though both cases use bionic; a bionic userspace pass
does not imply Android framework support.

The migration is applied to:

- fixtures/manifest.json;
- scripts/validate-fixtures.py;
- scripts/run-fixture-matrix.sh;
- scripts/run-packed-fixture-matrix.sh;
- scripts/package-release.sh;
- README and CI workflow references.

Archived task documents are historical records and are not rewritten as part
of the product migration.

## Validation and Generation

The schema validator is the single owner of required fields, uniqueness,
feature references, status/evidence consistency, source existence, and valid
case selection. Fixture runners consume validator output rather than parsing
the manifest independently.

The matrix report is generated from the same manifest and includes:

- feature status and obligation;
- cases that exercise each feature;
- proof/model evidence;
- runtime execution evidence;
- rejected and unknown cases;
- host/toolchain/environment facts.

For a bionic case, validation additionally requires direct checks that the
runner is AArch64, the fixture requests the bionic linker, the recorded page
size is present, and no QEMU, native bridge, AVD, or Waydroid path was used.
The validator must fail closed when the image digest, source commit, or linker
evidence is missing. The upstream image documentation is also recorded as
evidence that this lane is not a complete Android runtime.

CI fails a required proven claim with missing model evidence. Optional runtime
evidence may be unavailable only when the row is not itself claimed as proven.

## Coverage Strategy

The matrix avoids full Cartesian products. A case may cover several independent
features, and interaction constraints state when a combination is required.
The review gate requires:

- every proven feature has at least one positive case or model witness;
- every accepted boundary has a nearest negative case;
- every pair of high-risk features has a covering case or an explicit
  rationale for why pairwise coverage is not meaningful;
- no toolchain label is treated as proof of a feature it does not exercise.
