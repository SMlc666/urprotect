# Technical Design

## Runtime Shape

The new runtime is an AArch64 position-independent ET_DYN image loaded by the
ordinary host native loader. It contains the runtime core and a versioned
payload frame. It never writes the recovered payload to an executable
temporary pathname and never emulates process startup.

The runtime flow is:

1. discover the embedded frame from the mapped outer image;
2. validate all frame ranges, flags, limits, and ABI metadata;
3. verify encoded and decoded payload digests;
4. ask HostContext to create an immutable image handle from the decoded bytes;
5. resolve the required HostContext entry symbol;
6. invoke the entry with explicit launch arguments;
7. release the image handle according to the lifetime contract.

The current native launcher remains a legacy v1 baseline while the new runtime
is developed. It is not silently reused for HostContext payloads.

## HostContext ABI

The ABI uses fixed-width C data and a size/version prefix on every public
structure:

    struct urp_host_context_v1 {
        uint32_t abi_version;
        uint32_t struct_size;
        uint64_t capabilities;
        void *userdata;
        int (*load_image)(void *userdata, const void *bytes,
                          size_t size, uint32_t flags,
                          urp_image_handle *out);
        int (*lookup_symbol)(void *userdata, urp_image_handle image,
                             const char *name, const char *version,
                             uintptr_t *address);
        int (*release_image)(void *userdata, urp_image_handle image);
        int (*emit_diagnostic)(void *userdata, uint32_t code,
                               const char *message);
    };

    struct urp_launch_args_v1 {
        uint32_t abi_version;
        uint32_t struct_size;
        uint32_t argc;
        const char *const *argv;
        const char *const *envp;
    };

    int32_t urp_entry(const struct urp_host_context_v1 *host,
                      const struct urp_launch_args_v1 *args);

The exact typedef spelling, callback flags, handle representation, and stable
diagnostic codes are frozen in a native public header before implementation.
The design intentionally keeps the first surface small. Memory allocation,
thread creation, TLS, and synchronization are not passed as callbacks unless
an accepted payload feature requires them; an image that requires an absent
capability is rejected before entry.

The host owns userdata and image handles. The runtime owns the decoded byte
buffer until load_image returns. The host must not retain the byte pointer
after the callback. A successful image handle remains valid until release or
entry return, whichever contract rule is stricter. Callbacks must not throw
across the ABI and must return a documented negative error code on failure.

## Frame and ABI Versioning

Legacy frame v1 remains readable for regression tests and the old launcher.
HostContext payloads use a new frame version that records:

- frame format version;
- HostContext ABI version;
- required capability bits;
- source/encoded sizes and offsets;
- source and encoded digests;
- a safe diagnostic/entry name where needed.

The new version is a format migration, not an operating-system profile. The
managed codec and native runtime reject a version they do not understand.

## Host Loader Boundary

HostContext load_image is the only boundary that may depend on host loader
mechanics. A conforming implementation must provide an immutable image handle
without an executable temporary pathname. The first implementation should
connect this callback to a platform-native FD or memory-backed loader where
available. It must not fall back silently to the legacy temporary extraction
path.

The runtime does not initially reimplement all dynamic linking. The accepted
payload feature set therefore includes only image forms whose dependency,
relocation, TLS, constructor, and property behavior the host callback can
account for. Custom mapping and relocation become a separate explicitly
planned capability if the host loader boundary is insufficient.

## Failure Model

Failure order is deterministic:

1. ABI prefix and frame bounds;
2. required capability check;
3. encoded digest;
4. bounded decode and exact output size;
5. decoded digest;
6. HostContext load;
7. entry lookup and invocation.

No entry callback occurs after a failure. Existing structured diagnostics are
reused where their meaning is unchanged; new ABI mismatch, missing capability,
image load, and entry failure codes are added only if callers need to
distinguish them.

## Test Strategy

- Native ABI self-tests cover structure sizes, version negotiation, null and
  truncated callbacks, handle lifetime, and error propagation.
- Managed frame tests cover the new metadata, deterministic bytes, limits,
  legacy v1 rejection/compatibility behavior, and digest failures.
- A minimal HostContext image proves in-process entry and verifies that the
  host process remains alive after return.
- Malformed and capability-negative cases prove fail-closed behavior.
- External ELF tools inspect the outer runtime image; no test treats an
  arbitrary main entry as a HostContext entry.
