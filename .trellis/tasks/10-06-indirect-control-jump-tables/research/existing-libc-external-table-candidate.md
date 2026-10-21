# Existing libc external-table candidate reconnaissance

## Disposition

**No viable non-vtable external jump-table candidate was found in the exact native AArch64/glibc libc available here. This leaves external-table support blocked on an explicit provider-contract decision.** The allowed libc contains two bounded, exported objects whose runtime words point into libc executable text, but they are stdio operation vectors (`_IO_file_jumps` and `_IO_wfile_jumps`): vtable-shaped callback dispatch, explicitly not a generic jump-table candidate. The other exported object found with a code pointer is only a single scalar callback slot. None matches the current selected signed-relative jump-table family.

This follows the conservative no-policy-expansion path. It does **not** approve or imply a dedicated provider DSO, alter HostContext's dependency contract, establish cross-runtime availability, or promote transformed/runtime evidence. The previously existing note, `.trellis/tasks/10-06-indirect-control-jump-tables/research/external-jump-table-support-feasibility.md`, already distinguishes a provider-owned payload from a consumer GOT carrier and leaves provider admission/ownership open. The inspection below confirms the missing libc candidate rather than changing that conclusion.

## Proof-backed observations

### Exact libc and loader/runtime identity

- Canonical libc path: `/usr/lib/aarch64-linux-gnu/libc.so.6` (the `/lib/aarch64-linux-gnu/libc.so.6` alias is the same file; device 65102, inode 630629, size 1,788,240 bytes).
- SHA-256: `4306bea54c5862911d6ed2ee19adc0cdcb092cd1948ceb14a9c1e3592e8487d7`.
- GNU build-id: `b50ceafbd17dc6bceee344a66671c7eaa152bef4`.
- ELF identity: ELF64, little-endian, GNU OSABI, `ET_DYN`, `EM_AARCH64`; `DT_SONAME=libc.so.6`; `DT_NEEDED=ld-linux-aarch64.so.1`.
- Runtime queried in this environment: native `aarch64`, Ubuntu 26.04 LTS, `glibc 2.43` (`getconf GNU_LIBC_VERSION`; Python `gnu_get_libc_version()` also returned `2.43`; `ldd` identified package version `2.43-2ubuntu2`). Kernel identity from `uname -a`: `Linux localhost 5.15.167-android13-8-o-gd338dcf7ece7 ... aarch64`.
- Canonical loader: `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`, the `DT_NEEDED` provider; device 65102, inode 633104, size 201,872 bytes; SHA-256 `058b11f959fd1006abfc289a7fa9e2df86892e8a05f2d8b79a137e6a29c11a78`; GNU build-id `cdacfd9aa4cc22db5064c2659a66990c940d3823`.

A read-only Python/ctypes observation in PID 1195 loaded this libc and reported `glibc 2.43`. Its exact `/proc/self/maps` rows were:

```text
7c4d0b0000-7c4d259000 r-xp 00000000 fe:4e 630629 /usr/lib/aarch64-linux-gnu/libc.so.6
7c4d259000-7c4d26d000 ---p 001a9000 fe:4e 630629 /usr/lib/aarch64-linux-gnu/libc.so.6
7c4d26d000-7c4d270000 r--p 001ad000 fe:4e 630629 /usr/lib/aarch64-linux-gnu/libc.so.6
7c4d270000-7c4d272000 rw-p 001b0000 fe:4e 630629 /usr/lib/aarch64-linux-gnu/libc.so.6
7c4d440000-7c4d46a000 r-xp 00000000 fe:4e 633104 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
7c4d47e000-7c4d480000 r--p 0002e000 fe:4e 633104 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
7c4d480000-7c4d481000 rw-p 00030000 fe:4e 633104 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
```

The addresses below are observations for this one ASLR-mapped process, not stable addresses or cross-runtime claims.

### Dynamic-object scan and near matches

The libc `.dynsym` has 3,103 rows. Excluding undefined/absolute/zero-size rows, the scan resolved and checked all **139 defined nonzero-size `STT_OBJECT` rows** in the loaded libc. It checked aligned 64-bit words for pointers into the exact `.text` section (`[0x22600, 0x152214)`), rather than treating every pointer into the combined executable `PT_LOAD` as code: this distinction matters because this libc's read-only data is also within an `R E` load segment. A separate bounded discovery pass checked signed-32 entries relative to each exported object's `st_value`; there were no objects with two or more contiguous entries decoding into exported `STT_FUNC`/`STT_GNU_IFUNC` ranges.

The only object rows with aligned words in `.text` were:

| `.dynsym` row | Name | `st_value` | `st_size` | Type/binding/visibility/section | Observed content and classification |
|---:|---|---:|---:|---|---|
| 77 | `obstack_alloc_failed_handler@@GLIBC_2.17` | `0x1c11a0` | 8 | `OBJECT GLOBAL DEFAULT`, section 27 | One runtime pointer into libc `.text` (ELF VA `0x9fee0` in the scan); a scalar callback object, not a bounded table. |
| 1158 | `_IO_file_jumps@@GLIBC_2.17` | `0x1bf1b8` | 168 | `OBJECT GLOBAL DEFAULT`, section 24 | 21 eight-byte slots: two zero words followed by 19 runtime pointers into libc `.text`; stdio operation-vector/vtable near-match, not a generic selector jump table. |
| 1868 | `_IO_wfile_jumps@@GLIBC_2.17` | `0x1bf3b0` | 168 | `OBJECT GLOBAL DEFAULT`, section 24 | Same bounded 21-slot shape, with stdio wide-file callback pointers; also a vtable near-match. |

The two 168-byte objects are defined provider payloads, not GOT carriers. Their section/range facts are:

- `.data.rel.ro` is section 24, `SHT_PROGBITS`, VMA `0x1bd0d0`, file offset `0x1ad0d0`, size `0x29b8`, ELF flags `WA`.
- The second `PT_LOAD` is file offset `0x1ad080`, VMA `0x1bd080`, `RW`, `p_filesz=0x4458`; `PT_GNU_RELRO` starts at file offset `0x1ad080` / VMA `0x1bd080`, size `0x2f80`, ending at VMA `0x1c0000`.
- `_IO_file_jumps`: symbol range `[0x1bf1b8,0x1bf260)`, file offset `[0x1af1b8,0x1af260)`, runtime range `[0x7c4d26f1b8,0x7c4d26f260)`. Its observed range is wholly inside the libc `r--p` map `0x7c4d26d000-0x7c4d270000` after relocation/RELRO.
- `_IO_wfile_jumps`: symbol range `[0x1bf3b0,0x1bf458)`, file offset `[0x1af3b0,0x1af458)`, runtime range `[0x7c4d26f3b0,0x7c4d26f458)`, in that same `r--p` map.

Exact on-disk bytes (168 bytes each, from the named file offsets) are recorded below; qwords are little-endian. Runtime qwords are absolute pointers relocated by the loader, so their leading bytes depend on the observed load bias.

```text
_IO_file_jumps file bytes @ 0x1af1b8:
000000000000000000000000000000006c230800000000006830080000000000e02b08000000000080520800000000002868080000000000a03c080000000000c03e08000000000040340800000000006056080000000000e02a0800000000008032080000000000c03b070000000000203b080000000000e03b080000000000503b080000000000c03b0800000000006c3b080000000000406a080000000000606a080000000000

_IO_wfile_jumps file bytes @ 0x1af3b0:
000000000000000000000000000000006c23080000000000c0c6070000000000e0bd07000000000080a40700000000004ca207000000000060d2070000000000c03e08000000000000cb0700000000006056080000000000e02a08000000000060c90700000000002056070000000000203b080000000000e03b080000000000503b080000000000c03b0800000000006c3b080000000000406a080000000000606a080000000000
```

At the exact observed runtime mapping, `dlsym()` returned `_IO_file_jumps=0x7c4d26f1b8` and `_IO_wfile_jumps=0x7c4d26f3b0`. The complete mapped 168-byte images were:

```text
_IO_file_jumps runtime bytes:
000000000000000000000000000000006c23134d7c0000006830134d7c000000e02b134d7c0000008052134d7c0000002868134d7c000000a03c134d7c000000c03e134d7c0000004034134d7c0000006056134d7c000000e02a134d7c0000008032134d7c000000c03b124d7c000000203b134d7c000000e03b134d7c000000503b134d7c000000c03b134d7c0000006c3b134d7c000000406a134d7c000000606a134d7c000000

_IO_wfile_jumps runtime bytes:
000000000000000000000000000000006c23134d7c000000c0c6124d7c000000e0bd124d7c00000080a4124d7c0000004ca2124d7c00000060d2124d7c000000c03e134d7c00000000cb124d7c0000006056134d7c000000e02a134d7c00000060c9124d7c0000002056124d7c000000203b134d7c000000e03b134d7c000000503b134d7c000000c03b134d7c0000006c3b134d7c000000406a134d7c000000606a134d7c000000
```

For `_IO_file_jumps`, the nonzero qwords at offsets `+0x10` through `+0xa0` resolve to libc ELF VAs `0x8236c`, `0x83068`, `0x82be0`, `0x85280`, `0x86828`, `0x83ca0`, `0x83ec0`, `0x83440`, `0x85660`, `0x82ae0`, `0x83280`, `0x73bc0`, `0x83b20`, `0x83be0`, `0x83b50`, `0x83bc0`, `0x83b6c`, `0x86a40`, `0x86a60`. The exported function identities for the matching entries include `_IO_file_finish`, `_IO_file_overflow`, `_IO_file_underflow`, `_IO_default_uflow`, `_IO_default_pbackfail`, `_IO_file_xsputn`, `_IO_file_seekoff`, `_IO_file_setbuf`, `_IO_file_sync`, `_IO_file_doallocate`, `_IO_file_read`, `_IO_file_write`, `_IO_file_seek`, `_IO_file_close`, and `_IO_file_stat`. Four addresses do not match an exported dynsym function extent, but are still inside the `.text` range; `objdump -d` confirms instruction bytes at sampled such addresses (e.g. `0x83ec0`, `0x85660`, `0x86a40`). `_IO_wfile_jumps` similarly has wide-file callback targets plus shared file callbacks; its exact mapped qwords are retained above. This demonstrates executable-provider targets for the near-match without recasting it as the requested table family.

The table classification is **not** inferred merely from an arbitrary `OBJECT` name: the paired `_IO_*_jumps` names, fixed pointer-sized callback slots, and observed `_IO_file_*` / `_IO_wfile_*` targets establish the stdio-operation-vector shape. The installed libc is stripped (`nm -an` reports no symbols), so no DWARF/source type definition was available in this inspection. The deliberate scope classification remains: this is a vtable-like callback vector, not a candidate for generic external jump-table support.

Other tempting data are not candidates: for example `h_errlist`, `_sys_errlist`, and signal-name arrays contain pointers into read-only string data; those addresses must not be counted as function targets merely because `.rodata` shares the libc's executable `PT_LOAD`. The exact `.text`-range filter avoids that false positive.

### Compatibility with the current selected-function model

The checked-in `Aarch64JumpTableResolver` confirms the existing family is a different contract (`src/UrProtect.Core/Aarch64Semantics/Aarch64JumpTableResolver.cs:180-281`): it recognizes a bounded in-function chain ending in `BR`, requires an adjacent unsigned `CMP`/`B.HI` guard, an indexed `LDRSW`, reads four-byte signed entries from one wholly file-backed range in the parsed source ELF, and resolves the signed values to executable targets inside the selected function closure. Current semantic/layout publication likewise binds a local `SemanticSourceRange`/entry set and copied-and-retargeted signed-32 table (`src/UrProtect.Core/SemanticPlanning/SemanticPlanExtensions.cs:60-84`; `src/UrProtect.Core/Application/Rehydration/GenericRehydrationEngine.cs:1590-1656`; `src/UrProtect.Core/ElfLayout/ElfLayoutPlanner.cs:3186-3215`).

The libc near-match is an external provider object's 8-byte absolute callback slots in a RELRO range, not the current consumer-owned 4-byte signed-relative table; its targets are libc callbacks, not targets in the selected consumer function. A consumer using a bounded indexed `LDR` of a callback slot followed by `BLR`/`BR` would therefore require a separately declared external function-pointer/vtable family and a provider runtime-identity contract. **It does not fit the current resolver.** Because the found object is a vtable, this note does not recommend building that consumer fixture or treating it as the requested positive.

## Inference and residual blocker

- **Evidence-based conclusion:** in this exact, runtime-loaded libc, the only bounded exported `STT_OBJECT` payloads found with multiple words resolving into executable `.text` are the two stdio vtable-like vectors above. The only additional code-pointer object is an 8-byte scalar. The scan found no other exported bounded object table matching the requested non-vtable external jump-table definition.
- **Scope limitation:** this is one exact Ubuntu/glibc 2.43 AArch64 image and loader. It says nothing about other glibc builds, musl, Bionic, or transformed images. The signed-32 discovery check covered the common table-base convention and exported function symbols; it is not a proof against every arbitrary private encoding or consumer-chosen base.
- **Required decision:** the no-policy-expansion path has no suitable libc payload candidate. External-table support remains blocked until the owner explicitly chooses a provider/ownership contract. Do not infer permission to add a DSO, loader allowlist, or arbitrary process-global provider from the earlier “可以”.
- No source, tests, fixture, manifest, CI, task status, provider policy, or accepted evidence was changed. No tests or fixture builds were run. This was read-only ELF and loaded-libc introspection; it is not promoted runtime evidence and does not claim transformed execution.

## Commands and results

Task resolution:

```text
python3 ./.trellis/scripts/task.py current --source
=> Current task: .trellis/tasks/10-06-unify-elf-protection-infrastructure
=> Source: session-fallback:pi_01a10d22-c6f7-724e-8a28-995b10217b41
```

Identity and ELF commands (all successful; paths and outputs above):

```sh
readlink -f /usr/lib/aarch64-linux-gnu/libc.so.6
sha256sum /usr/lib/aarch64-linux-gnu/libc.so.6
readelf -nW /usr/lib/aarch64-linux-gnu/libc.so.6
readelf -hW /usr/lib/aarch64-linux-gnu/libc.so.6
readelf -dW /usr/lib/aarch64-linux-gnu/libc.so.6
readlink -f /lib/ld-linux-aarch64.so.1
sha256sum /lib/ld-linux-aarch64.so.1
readelf -nW /lib/ld-linux-aarch64.so.1
readelf --dyn-syms --wide /usr/lib/aarch64-linux-gnu/libc.so.6 | grep -E '_IO_(file|wfile)_jumps'
readelf -SW /usr/lib/aarch64-linux-gnu/libc.so.6
readelf -lW /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -s -j .data.rel.ro --start-address=0x1bf1b8 --stop-address=0x1bf260 /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -s -j .data.rel.ro --start-address=0x1bf3b0 --stop-address=0x1bf458 /usr/lib/aarch64-linux-gnu/libc.so.6
```

The on-disk byte dump used the proven `PT_LOAD` VA-to-file relation and these exact file offsets:

```sh
python3 - <<'PY'
p='/usr/lib/aarch64-linux-gnu/libc.so.6'
for name,off,size in [('_IO_file_jumps',0x1af1b8,168),('_IO_wfile_jumps',0x1af3b0,168)]:
    with open(p,'rb') as f:
        f.seek(off)
        b=f.read(size)
    print(name, hex(off), len(b), b.hex())
PY
```

Runtime range and bytes were read (without invoking the table entries) from the already mapped libc using `ctypes.CDLL`, `dlsym`, `ctypes.string_at`, and `/proc/self/maps`. Runtime identity returned `machine=aarch64`, `python=3.14.4`, `libc_ver=('glibc','2.43')`, `gnu_get_libc_version=2.43`; PID 1195 and exact mappings are included above. No fixture or protection binary was built or executed.

The dynamic-object scan result was:

```text
defined nonzero-size OBJECT dynsym rows=139
symbol lookups=139; unresolved=0
FUNC/IFUNC dynsym rows=2911
.text VA=[0x22600,0x152214)
rows containing 8-byte pointers into .text=3
rows: 77 obstack_alloc_failed_handler; 1158 _IO_file_jumps; 1868 _IO_wfile_jumps
```

The signed-32 symbol-base discovery result was:

```text
defined OBJECT rows checked=139
relative-s32-to-symbol-base sequences with >=2 function-target hits=0
```

The loaded-object scan used `dlsym` for default/unversioned symbols and `dlvsym` for non-default symbol versions, then checked every 8-byte-aligned word against the exact `.text` VA range and every four-byte signed entry relative to the object's `st_value`. These are candidate-discovery checks only; semantic family classification and the limitations above remain explicit.

### Exact runtime and candidate-scan invocations

The mapped-byte command used for the recorded PID/mapping was:

```sh
python3 - <<'PY'
import ctypes, os, platform, re, subprocess
p='/usr/lib/aarch64-linux-gnu/libc.so.6'; lib=ctypes.CDLL(p)
print('pid',os.getpid(),'machine',platform.machine(),'python',platform.python_version(),'libc_ver',platform.libc_ver())
v=lib.gnu_get_libc_version; v.restype=ctypes.c_char_p
print('gnu_get_libc_version',v().decode())
for line in open('/proc/self/maps'):
    if 'libc.so.6' in line or 'ld-linux-aarch64.so.1' in line:
        print(line.rstrip())
maps=[]
for line in open('/proc/self/maps'):
    c=line.rstrip().split(None,5)
    if len(c)>=6 and c[5]==p and int(c[2],16)==0:
        maps.append(int(c[0].split('-')[0],16))
bias=min(maps)
syms=subprocess.check_output(['readelf','--dyn-syms','--wide',p],text=True)
funcs=[]
for line in syms.splitlines():
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$',line)
    if m:
        i,val,size,typ,bind,vis,ndx,name=m.groups()
        if typ in ('FUNC','IFUNC') and ndx not in ('UND','ABS'):
            funcs.append((int(i),int(val,16),int(size),name))
for name,size in [('_IO_file_jumps',168),('_IO_wfile_jumps',168)]:
    address=ctypes.cast(getattr(lib,name),ctypes.c_void_p).value
    raw=ctypes.string_at(address,size)
    print(f'{name}: address=0x{address:x} ELF_VA=0x{address-bias:x} size={size} bytes={raw.hex()}')
    for off in range(0,size,8):
        value=int.from_bytes(raw[off:off+8],'little')
        if not value:
            print(f'  +0x{off:02x}=0')
            continue
        va=value-bias
        names=[n for _,v,s,n in funcs if v<=va<v+max(s,1)]
        print(f'  +0x{off:02x}=0x{value:016x} ELFVA=0x{va:x} {names or "no exported dynsym FUNC/IFUNC extent"}')
PY
```

The successful all-object candidate scan (all 139 lookups resolved) was:

```sh
python3 - <<'PY'
import ctypes,re,subprocess
p='/usr/lib/aarch64-linux-gnu/libc.so.6'; lib=ctypes.CDLL(p)
lines=subprocess.check_output(['readelf','--dyn-syms','--wide',p],text=True).splitlines()
objects=[]; funcs=[]
for line in lines:
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$',line)
    if not m: continue
    i,v,s,t,b,vis,ndx,name=m.groups(); i=int(i); v=int(v,16); s=int(s)
    if ndx in ('UND','ABS') or s==0: continue
    base=name.split('@',1)[0]
    version=(name.split('@@',1)[1].split()[0] if '@@' in name else name.split('@',1)[1].split()[0] if '@' in name else None)
    row=(i,v,s,t,b,vis,ndx,name,base,version)
    if t=='OBJECT': objects.append(row)
    elif t in ('FUNC','IFUNC'): funcs.append(row)
dlsym=lib.dlsym; dlsym.argtypes=[ctypes.c_void_p,ctypes.c_char_p]; dlsym.restype=ctypes.c_void_p
dlvsym=lib.dlvsym; dlvsym.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p]; dlvsym.restype=ctypes.c_void_p
handle=ctypes.c_void_p(lib._handle)
maps=[]
for line in open('/proc/self/maps'):
    cols=line.rstrip().split(None,5)
    if len(cols)>=6 and cols[5]==p and int(cols[2],16)==0:
        maps.append(int(cols[0].split('-')[0],16))
bias=min(maps)
sections=subprocess.check_output(['readelf','-SW',p],text=True)
textrow=next(x for x in sections.splitlines() if re.search(r'\]\s+\.text\s+',x))
sm=re.search(r'\.text\s+\S+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)',textrow)
tlo=int(sm.group(1),16); thi=tlo+int(sm.group(2),16)
pointer_hits=[]; relative_runs=[]; resolved=0
for row in objects:
    idx,value,size,typ,bind,vis,ndx,name,base,version=row
    address=(dlsym(handle,base.encode()) if '@@' in name or version is None
             else dlvsym(handle,base.encode(),version.encode()))
    if not address: raise RuntimeError(f'unresolved dynsym OBJECT row {idx}: {name}')
    resolved+=1
    raw=ctypes.string_at(address,size)
    ph=[]; rh=[]
    for off in range(0,size-7,8):
        target=int.from_bytes(raw[off:off+8],'little')-bias
        if tlo<=target<thi: ph.append((off,target))
    for off in range(0,size-3,4):
        delta=int.from_bytes(raw[off:off+4],'little',signed=True)
        target=value+delta
        if any(f[1]<=target<f[1]+max(f[2],1) for f in funcs): rh.append((off,target))
    if ph: pointer_hits.append((idx,name,ph))
    if len(rh)>=2: relative_runs.append((idx,name,rh))
print(f'defined nonzero-size OBJECT dynsym rows={len(objects)}; symbol lookups={resolved}; unresolved=0; FUNC/IFUNC dynsym rows={len(funcs)}; .text VA=[0x{tlo:x},0x{thi:x})')
print('rows containing aligned 8-byte pointers into .text:',[(i,n) for i,n,_ in pointer_hits])
print('relative-s32-to-symbol-base sequences with >=2 function-target hits:',relative_runs)
PY
```

Result: `defined nonzero-size OBJECT dynsym rows=139; symbol lookups=139; unresolved=0; FUNC/IFUNC dynsym rows=2911; .text VA=[0x22600,0x152214)`; pointer-hit rows were exactly `(77, obstack_alloc_failed_handler@@GLIBC_2.17)`, `(1158, _IO_file_jumps@@GLIBC_2.17)`, `(1868, _IO_wfile_jumps@@GLIBC_2.17)`; signed-32 sequences were `[]`.

The exact disassembly probes used for executable-target sanity were:

```sh
objdump -d --start-address=0x8236c --stop-address=0x8237c /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -d --start-address=0x83068 --stop-address=0x83078 /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -d --start-address=0x83ec0 --stop-address=0x83ed0 /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -d --start-address=0x85660 --stop-address=0x85670 /usr/lib/aarch64-linux-gnu/libc.so.6
objdump -d --start-address=0x86a40 --stop-address=0x86a50 /usr/lib/aarch64-linux-gnu/libc.so.6
```

They returned AArch64 instruction words for all probes; the exported dynsym labels at the first two addresses were `_IO_file_finish` and `_IO_file_overflow`. The other probes were labeled as offsets within nearby exported functions, consistent with the note's limitation that the stripped image does not expose all callback entry identities through dynsym.
