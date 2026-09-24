# P1 Design: Outer AArch64 ELF Wrapper Coverage

## Boundary

P1 extends only the `outer-execveat` profile. The source bytes remain the
authoritative executable image; UrProtect validates, compresses, and recovers
them, while the kernel/native interpreter owns process startup.

## Input classes

Start with stripped and sectionless dynamic PIE images because they exercise
the existing program-header authority without changing process entry semantics.
Then evaluate static PIE and static ET_EXEC as separate classes. A shared object
gets an explicit result until a declared entry profile supplies launch semantics.

Each class needs a validator rule, a fixture producer, a nearest malformed
fixture, and a baseline/wrapped oracle.

## Oracle

The fixture runner records baseline and wrapped status, stdout, stderr, argv,
environment, cwd, signals, and declared file observations. It excludes ASLR
addresses and timing. The wrapper must use the selected native interpreter and
must never fall back to a host architecture, QEMU, or a temporary executable
path.

## Runtime matrix

Use the existing fixture manifest tiers and record glibc, musl, and bionic as
separate runtime facts. A parser pass or a single successful loader invocation
does not promote an outer-wrapper row without the execution oracle and retained
evidence.
