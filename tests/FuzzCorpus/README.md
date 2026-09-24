# Fuzz corpus

The corpus is a deterministic generated-corpus format. The runner creates a
fresh artifact corpus for every invocation, copies these byte fixtures, and
asks `UrProtect.Fuzz --emit-seed` to generate the valid minimal AArch64 ELF
seed through the same named ELF constants used by the parser.

Generated exploratory inputs, minimized crashes, and timeouts are retained
under `.artifacts/fuzz/` by CI. A promoted finding is copied into this tree as
a small binary fixture and gets a named deterministic regression test.
