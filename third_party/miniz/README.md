# miniz tinfl

This directory contains the raw-deflate inflater sources from miniz commit
`77d0dce8627735138c51770d1799a1ef48f2117d`.

UrProtect uses only the low-level tinfl decoder. The compressor, ZIP, stdio,
time, zlib-header, and optional heap APIs are not part of the launcher.
`miniz_export.h` is a project-provided build shim because the upstream build
generates that header from its build system.

The upstream MIT license is in `LICENSE`. File hashes and provenance are
recorded in `native/urprotect-launcher/PROVENANCE.txt` during launcher builds.
