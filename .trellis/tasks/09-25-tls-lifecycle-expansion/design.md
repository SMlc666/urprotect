# Design: TLS and HostContext lifecycle expansion

## Objective

Define image ownership and thread/lifecycle semantics before expanding beyond
the current initial-exec TLS and constructor/destructor evidence.

## Contract questions resolved by each slice

- Which TLS models and AArch64 relocation forms are accepted?
- When is module TLS allocated and initialized for the current thread?
- What happens for a thread created during `urp_entry`?
- Must entry return before image release, or can a supported image retain an
  ownership reference?
- Are constructors before entry and destructors during release guaranteed?
- What happens on constructor failure, entry failure, callback reentrancy, or
  concurrent dispatch?
- When is `release_image` legal and how are live thread users represented?

The first slice should remain deliberately narrow if a full threaded contract
is not yet ready. Capability bits and frame metadata must express requirements
instead of allowing the adapter to guess.

## Ownership model

The native runtime owns the frame dispatch sequence; the HostContext adapter
owns image handles and loader resources; the loaded image owns only declared
entry behavior. A successful release must not race with supported live users.
All failure paths clear handles and retain the original status.

## Test architecture

Use real compiler/linker fixtures with:

- TLS-backed entry values;
- constructor state observed by entry;
- destructor release marker;
- deterministic thread barriers and join/exit behavior;
- invalid capability/order cases;
- repeated/concurrent dispatch where the contract allows it.

Avoid tests that pass only because a particular libc happens to keep a module
mapped. Each claimed runtime needs a retained oracle.

## Rollback

Retain the last validated initial-exec/lifecycle rows and reject dynamic TLS,
new-thread, reentrant, or live-thread unload combinations until their explicit
contract and oracle are complete.
