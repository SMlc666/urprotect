# HostContext runtime core

This directory defines the versioned, host-neutral `HostContext` entry
contract and a bounded frame-dispatch runtime. `urp_runtime_execute_frame`
verifies the legacy v1 or HostContext v2 frame and both payload digests, asks
the host for an immutable image, resolves the declared entry symbol, invokes
it, and releases the image before returning.

The native evidence adapter implements the contract with an anonymous memfd
and the host's `dlopen`/`dlsym` loader through the generated virtual
`/proc/self/fd/<N>` reference. It creates no executable filesystem pathname
and keeps the descriptor open until `release_image`. Before loading, the
adapter requires AArch64 ELF64 `ET_DYN` program headers and rejects an
interpreter, TLS, GNU property, dependency, constructor, text-relocation, or
path-search requirement that this first entry slice does not define. The
system loader remains the authority for applying relocation and memory
protection. This adapter accepts only AArch64 `RELATIVE`/`RELR` relocation
forms with checked writable targets, and permits only immediate-binding
dynamic flags; other relocation or lifecycle forms remain outside the
declared slice. Section headers are not consulted by this adapter; bounded
program headers and mapped dynamic metadata are authoritative for the
sectionless image slice.

The self-test includes both the deterministic fake host contract oracle and a
real AArch64 `urp_entry` shared-object fixture loaded in-process. It therefore
validates this narrow adapter slice while leaving broader relocation, TLS,
constructor, dependency, and instruction-property combinations explicit in
the compatibility matrix.

The runtime accepts the legacy frame v1 and HostContext frame v2. Both use the
same 112-byte common header. A v2 header is 136 bytes and appends, in order,
the HostContext ABI version, a reserved zero field, required capability bits,
the UTF-8 entry-symbol byte length, and a second reserved zero field. Its
variable data is `source_name`, `entry_name`, then compressed payload. The
runtime validates those fields before decoding and copies the bounded entry
name into a terminated local buffer before symbol lookup.

Legacy v1 keeps its wrapper-absolute encoded offset for the existing launcher.
HostContext v2 uses a frame-relative encoded offset because the standalone
runtime receives the frame slice directly; the managed wrapper reader applies
the corresponding versioned interpretation.

Run the native contract self-test on a native AArch64 host:

```sh
make -C native/urprotect-runtime test
```
