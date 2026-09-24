# Selected public AArch64 sample projects

The registry freezes exactly 20 distinct upstream project identities. The
artifacts are public, versioned, and SHA-256 locked in `manifest.json` and
`candidates.json`. The table is a selection rationale, not a claim that every
project is executable by every UrProtect profile.

| Project | Public artifact | Runtime fact | Selection contribution |
| --- | --- | --- | --- |
| GNU Bash | Debian bookworm arm64 `bash` | glibc | Shell startup and a larger autotools executable |
| BusyBox | Alpine 3.20.3 AArch64 minirootfs | musl | Compact multi-call image and musl rootfs boundary |
| GNU coreutils | Debian `coreutils` (`ls`) | glibc | Common system utility and stripped/dynamic producer |
| curl | Debian `curl` | glibc | Network/TLS dependency shape without executing network activity |
| Git | Debian `git` | glibc | Larger command-line application with multiple shared dependencies |
| OpenSSL | Debian `openssl` | glibc | Cryptographic CLI and symbol/dependency surface |
| Perl | Debian `perl-base` | glibc | Interpreter-style executable and runtime metadata |
| SQLite | Debian `sqlite3` | glibc | Embedded database CLI with a compact dynamic image |
| Vim | Debian `vim-tiny` | glibc | Terminal-oriented application with a different dependency profile |
| GNU nano | Debian `nano` | glibc | Small terminal editor and application metadata |
| jq | Debian `jq` | glibc | Small C application with a distinct producer artifact |
| ripgrep | Debian `ripgrep` | glibc | Rust-produced real distribution executable |
| CMake | Debian `cmake` | glibc | C++ application with a larger dependency and read-only data surface |
| FFmpeg | Debian `ffmpeg` | glibc | Large multimedia dependency graph and dynamic table |
| Nginx | Debian `nginx` | glibc | Server executable and system-service style layout |
| Node.js | Public Termux `nodejs` package | bionic | Android/bionic loader fact and public dynamic-PIE observation |
| CPython | Debian `python3.11-minimal` | glibc | Language runtime executable and an explicit ET_EXEC rejection boundary |
| PostgreSQL | Debian `postgresql-client-15` (`psql`) | glibc | Database client and larger runtime dependency shape |
| Redis | Debian `redis-tools` (`redis-check-rdb`) | glibc | Redis utility executable and package/runtime distinction |
| Caddy | Debian `caddy` | glibc | Go-produced server executable with a different binary profile |

## Coverage notes

- Project identity, not package count, determines the 20 total.
- Debian packages provide immutable archive hashes from public package metadata;
  the CI runner independently verifies the archive and extracted artifact.
- The Alpine rootfs and Termux package are runtime facts, not claims of
  universal musl or Android compatibility.
- The registry compares ELF class, data encoding, machine, type, and
  interpreter against a locked CI-discovery policy. Relocations, TLS, GNU
  property, RELRO, GNU stack, stripped state, dependency names, and feature
  tags are retained as observed evidence; they are not guessed support claims.
- Candidates that duplicate the same producer/runtime shape or lack a stable
  public hash remain in `candidates.json` with a rejected/deferred reason.

## Deliberate boundaries

Normal public programs are `not-applicable` to HostContext because they do not
declare the `urp_entry` ABI. The Termux/bionic Node.js artifact is retained as
a real bionic dynamic-PIE observation; its static validator result is recorded
as accepted without upgrading the bionic fixture lane, outer packaging, or
HostContext claim. The Debian CPython and Caddy artifacts are real ET_EXEC
rejection boundaries because the current product accepts only ET_DYN inputs.

The BusyBox record is the one currently applicable dynamic oracle: its
`executionPolicy.baseline.command` is `["/bin/busybox", "true"]`, and the
runner verifies that the first command element is exactly the declared
extracted `artifactPath` before invoking bubblewrap. It mounts only the
archive-derived rootfs read-only with network disabled. This is not a host
BusyBox fallback. The other 19 records retain explicit dependency-closure,
outer-profile, or HostContext `not-applicable` policies until a reviewed
rootfs/ABI oracle is supplied.
