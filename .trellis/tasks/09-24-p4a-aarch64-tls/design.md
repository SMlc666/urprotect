# P4-A Design: AArch64 TLS Semantics

## Contract

Define a bounded TLS model covering module allocation, TLS relocation, current
thread initialization, new-thread initialization, thread exit, reentrancy,
unload, and release ordering. The contract must state what happens when a live
thread still references an image.

## Evidence

Use a real threaded AArch64 ET_DYN fixture with observable per-thread values,
entry/release events, and deterministic teardown. Static PT_TLS mutations remain
negative boundary tests; they are not a positive support oracle.
