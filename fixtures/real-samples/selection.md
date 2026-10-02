# Selected public AArch64 sample projects

The locked public CI-only registry contains **100 distinct upstream project identities**. The approved target is 100 and the shortfall is zero. Package, archive, build, libc, and distribution variants remain attributes of one `identityKey`; they never add identities.
Artifacts are public, versioned, and SHA-256 locked in `manifest.json` and `candidates.json`. The registry is ecology evidence, not a claim that every project is executable by every UrProtect profile.

## Reviewed increment

| Increment | Identities | Source/runtime facts |
| --- | ---: | --- |
| Existing approved baseline | 20 | Debian/glibc, Alpine BusyBox/musl, Termux/bionic |
| Promoted deferred candidates | 23 | Debian Bookworm AArch64/glibc |
| New Debian Bookworm projects | 37 | Debian package artifacts/glibc |
| New Alpine APK projects | 20 | Alpine v3.22 AArch64 APK/musl |
| **Total** | **100** | **78 glibc / 21 musl / 1 bionic** |

The Debian index lock is `2ddb1737692e8c45c53e8d57c0ce4cd21c78c5703b830c3226b1423566a06c00`; the Alpine AArch64 APKINDEX lock is `1f7a5be0ef6c857f2aa1013f2be0b678d2c5dd2ad3a4eee5760a184be58bbe20`. The 20 new APKs are independently sourced upstream identities and are not Alpine variants of an existing project.

The execution closure refresh is recorded separately in
`runtime-closures.json`. Its current Alpine resolver index is hash-locked to
`4d5e75508936b08bed7423bb9e9039a669eadc05323189a9c31c90573766ab99`; the
registry observation hash above remains the historical selection evidence.

## Runtime, source, and producer mix

| Dimension | Value | Identities |
| --- | --- | ---: |
| Source | `alpine-minirootfs` | 1 |
| Source | `alpine-v3.22-main-aarch64-apk` | 20 |
| Source | `debian-bookworm-arm64-package` | 78 |
| Source | `termux-package` | 1 |
| Runtime | `bionic` | 1 |
| Runtime | `glibc` | 78 |
| Runtime | `musl` | 21 |
| Loader | `/lib/ld-linux-aarch64.so.1` | 78 |
| Loader | `/lib/ld-musl-aarch64.so.1` | 21 |
| Loader | `/system/bin/linker64` | 1 |
| Producer annotation | `alpine-musl-g++` | 4 |
| Producer annotation | `alpine-musl-gcc` | 17 |
| Producer annotation | `autotools-gcc` | 24 |
| Producer annotation | `cmake-gcc` | 1 |
| Producer annotation | `configure-gcc` | 10 |
| Producer annotation | `debian-bookworm-g++` | 3 |
| Producer annotation | `debian-bookworm-gcc` | 32 |
| Producer annotation | `go` | 3 |
| Producer annotation | `make-gcc` | 4 |
| Producer annotation | `rustc` | 1 |
| Producer annotation | `termux-clang` | 1 |

## Locked selected identities

| Project ID | Upstream identity | Source/archive | Runtime/loader | Declared artifact | Expected static result |
| --- | --- | --- | --- | --- | --- |
| `gnu-bash` | GNU Bash | debian bookworm arm64 package<br>`bash_5.2.15-2+b13_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/bash` | `validated` |
| `busybox` | BusyBox | alpine minirootfs<br>`alpine-minirootfs-3.20.3-aarch64.tar.gz` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `bin/busybox` | `validated` |
| `gnu-coreutils` | GNU coreutils | debian bookworm arm64 package<br>`coreutils_9.1-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/ls` | `validated` |
| `curl` | curl | debian bookworm arm64 package<br>`curl_7.88.1-10+deb12u15_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/curl` | `validated` |
| `git` | Git | debian bookworm arm64 package<br>`git_2.39.5-0+deb12u3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/git` | `validated` |
| `openssl` | OpenSSL | debian bookworm arm64 package<br>`openssl_3.0.20-1~deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/openssl` | `validated` |
| `perl` | Perl | debian bookworm arm64 package<br>`perl-base_5.36.0-7+deb12u3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/perl` | `validated` |
| `sqlite` | SQLite | debian bookworm arm64 package<br>`sqlite3_3.40.1-2+deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/sqlite3` | `validated` |
| `vim` | Vim | debian bookworm arm64 package<br>`vim-tiny_9.0.1378-2+deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/vim.tiny` | `validated` |
| `nano` | GNU nano | debian bookworm arm64 package<br>`nano_7.2-1+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/nano` | `validated` |
| `jq` | jq | debian bookworm arm64 package<br>`jq_1.6-2.1+deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/jq` | `validated` |
| `ripgrep` | ripgrep | debian bookworm arm64 package<br>`ripgrep_13.0.0-4+b2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/rg` | `validated` |
| `cmake` | CMake | debian bookworm arm64 package<br>`cmake_3.25.1-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/cmake` | `validated` |
| `ffmpeg` | FFmpeg | debian bookworm arm64 package<br>`ffmpeg_5.1.9-0+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/ffmpeg` | `validated` |
| `nginx` | nginx | debian bookworm arm64 package<br>`nginx_1.22.1-9+deb12u9_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/sbin/nginx` | `validated` |
| `nodejs` | Node.js | termux package<br>`nodejs_26.4.0-1_aarch64.deb` | `bionic`<br>`/system/bin/linker64` | `data/data/com.termux/files/usr/bin/node` | `validated` |
| `python` | CPython | debian bookworm arm64 package<br>`python3.11-minimal_3.11.2-6+deb12u8_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/python3.11` | `validated` |
| `postgresql` | PostgreSQL | debian bookworm arm64 package<br>`postgresql-client-15_15.18-0+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/lib/postgresql/15/bin/psql` | `validated` |
| `redis` | Redis | debian bookworm arm64 package<br>`redis-tools_7.0.15-1~deb12u7_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/redis-check-rdb` | `validated` |
| `caddy` | Caddy | debian bookworm arm64 package<br>`caddy_2.6.2-5_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/caddy` | `validated` |
| `ruby` | Ruby | debian bookworm arm64 package<br>`ruby3.1_3.1.2-7+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/ruby3.1` | `validated` |
| `gawk` | GNU Awk | debian bookworm arm64 package<br>`gawk_5.2.1-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/gawk` | `validated` |
| `grep` | GNU grep | debian bookworm arm64 package<br>`grep_3.8-5_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/grep` | `validated` |
| `sed` | GNU sed | debian bookworm arm64 package<br>`sed_4.9-1+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/sed` | `validated` |
| `findutils` | GNU Findutils | debian bookworm arm64 package<br>`findutils_4.9.0-4_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/find` | `validated` |
| `gnu-tar` | GNU tar | debian bookworm arm64 package<br>`tar_1.34+dfsg-1.2+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/tar` | `validated` |
| `gnu-gzip` | GNU gzip | debian bookworm arm64 package<br>`gzip_1.12-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/gzip` | `validated` |
| `less` | less | debian bookworm arm64 package<br>`less_590-2.1~deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/less` | `validated` |
| `screen` | GNU Screen | debian bookworm arm64 package<br>`screen_4.9.0-4_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/screen` | `validated` |
| `tmux` | tmux | debian bookworm arm64 package<br>`tmux_3.3a-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/tmux` | `validated` |
| `rsync` | rsync | debian bookworm arm64 package<br>`rsync_3.2.7-1+deb12u6_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/rsync` | `validated` |
| `wget` | GNU Wget | debian bookworm arm64 package<br>`wget_1.21.3-1+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/wget` | `validated` |
| `lua` | Lua | debian bookworm arm64 package<br>`lua5.4_5.4.4-3+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/lua5.4` | `validated` |
| `php` | PHP | debian bookworm arm64 package<br>`php8.2-cli_8.2.32-1~deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/php8.2` | `validated` |
| `graphviz` | Graphviz | debian bookworm arm64 package<br>`graphviz_2.42.2-7+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/dot_builtins` | `validated` |
| `strace` | strace | debian bookworm arm64 package<br>`strace_6.1-0.1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/strace` | `validated` |
| `file` | file | debian bookworm arm64 package<br>`file_5.44-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/file` | `validated` |
| `m4` | GNU M4 | debian bookworm arm64 package<br>`m4_1.4.19-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/m4` | `validated` |
| `bzip2` | bzip2 | debian bookworm arm64 package<br>`bzip2_1.0.8-5+b1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/bzip2` | `validated` |
| `ncdu` | ncdu | debian bookworm arm64 package<br>`ncdu_1.18-0.2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/ncdu` | `validated` |
| `htop` | htop | debian bookworm arm64 package<br>`htop_3.2.2-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/htop` | `validated` |
| `nmap` | Nmap | debian bookworm arm64 package<br>`nmap_7.93+dfsg1-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/nmap` | `validated` |
| `socat` | socat | debian bookworm arm64 package<br>`socat_1.7.4.4-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/socat` | `validated` |
| `zero-ad` | 0 A.D. | debian bookworm arm64 package<br>`0ad_0.0.26-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/games/pyrogenesis` | `validated` |
| `acl` | Linux ACL | debian bookworm arm64 package<br>`acl_2.3.1-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/getfacl` | `validated` |
| `apache2` | Apache HTTP Server | debian bookworm arm64 package<br>`apache2-bin_2.4.68-1~deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/sbin/apache2` | `validated` |
| `aria2` | aria2 | debian bookworm arm64 package<br>`aria2_1.36.0-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/aria2c` | `validated` |
| `attr` | attr | debian bookworm arm64 package<br>`attr_2.5.1-4_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/getfattr` | `validated` |
| `bind9` | BIND | debian bookworm arm64 package<br>`bind9-dnsutils_9.18.49-1~deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/dig` | `validated` |
| `bison` | GNU Bison | debian bookworm arm64 package<br>`bison_3.8.2+dfsg-1+b1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/bison` | `validated` |
| `cpio` | GNU cpio | debian bookworm arm64 package<br>`cpio_2.13+dfsg-7.1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/cpio` | `validated` |
| `dos2unix` | dos2unix | debian bookworm arm64 package<br>`dos2unix_7.4.3-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/dos2unix` | `validated` |
| `flex` | Flex | debian bookworm arm64 package<br>`flex_2.6.4-8.2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/flex` | `validated` |
| `gdb` | GNU Debugger | debian bookworm arm64 package<br>`gdb_13.1-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/gdb` | `validated` |
| `git-lfs` | Git LFS | debian bookworm arm64 package<br>`git-lfs_3.3.0-1+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/git-lfs` | `validated` |
| `imagemagick` | ImageMagick | debian bookworm arm64 package<br>`imagemagick-6.q16_6.9.11.60+dfsg-1.6+deb12u11_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/identify-im6.q16` | `validated` |
| `iperf3` | iPerf3 | debian bookworm arm64 package<br>`iperf3_3.12-1+deb12u2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/iperf3` | `validated` |
| `iproute2` | iproute2 | debian bookworm arm64 package<br>`iproute2_6.1.0-3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `sbin/ip` | `validated` |
| `irssi` | Irssi | debian bookworm arm64 package<br>`irssi_1.4.3-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/irssi` | `validated` |
| `kmod` | kmod | debian bookworm arm64 package<br>`kmod_30+20221128-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/kmod` | `validated` |
| `logrotate` | logrotate | debian bookworm arm64 package<br>`logrotate_3.21.0-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/sbin/logrotate` | `validated` |
| `lsof` | lsof | debian bookworm arm64 package<br>`lsof_4.95.0-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/lsof` | `validated` |
| `man-db` | man-db | debian bookworm arm64 package<br>`man-db_2.11.2-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/man` | `validated` |
| `micro` | micro | debian bookworm arm64 package<br>`micro_2.0.11-2+b1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/micro` | `validated` |
| `minicom` | minicom | debian bookworm arm64 package<br>`minicom_2.8-2_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/minicom` | `validated` |
| `mosh` | Mosh | debian bookworm arm64 package<br>`mosh_1.4.0-1+b1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/mosh-client` | `validated` |
| `mpv` | mpv | debian bookworm arm64 package<br>`mpv_0.35.1-4_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/mpv` | `validated` |
| `neovim` | Neovim | debian bookworm arm64 package<br>`neovim_0.7.2-7_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/nvim` | `validated` |
| `ninja-build` | Ninja | debian bookworm arm64 package<br>`ninja-build_1.11.1-2~deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/ninja` | `validated` |
| `pigz` | pigz | debian bookworm arm64 package<br>`pigz_2.6-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/pigz` | `validated` |
| `squashfs-tools` | Squashfs-tools | debian bookworm arm64 package<br>`squashfs-tools_4.5.1-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/mksquashfs` | `validated` |
| `subversion` | Apache Subversion | debian bookworm arm64 package<br>`subversion_1.14.2-4+deb12u1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/svn` | `validated` |
| `sysstat` | sysstat | debian bookworm arm64 package<br>`sysstat_12.6.1-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/iostat` | `validated` |
| `tcpdump` | tcpdump | debian bookworm arm64 package<br>`tcpdump_4.99.3-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/tcpdump` | `validated` |
| `tig` | tig | debian bookworm arm64 package<br>`tig_2.5.5-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/tig` | `validated` |
| `traceroute` | traceroute | debian bookworm arm64 package<br>`traceroute_2.1.2-1_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/traceroute.db` | `validated` |
| `unzip` | Info-ZIP UnZip | debian bookworm arm64 package<br>`unzip_6.0-28_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/unzip` | `validated` |
| `util-linux` | util-linux | debian bookworm arm64 package<br>`util-linux_2.38.1-5+deb12u3_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `bin/lsblk` | `validated` |
| `whois` | whois | debian bookworm arm64 package<br>`whois_5.5.17_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/whois` | `validated` |
| `zip` | Info-ZIP Zip | debian bookworm arm64 package<br>`zip_3.0-13_arm64.deb` | `glibc`<br>`/lib/ld-linux-aarch64.so.1` | `usr/bin/zip` | `validated` |
| `alpine-7zip` | 7-Zip | alpine v3.22 main aarch64 apk<br>`7zip-24.09-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/7z` | `validated` |
| `alpine-apk-tools` | apk-tools | alpine v3.22 main aarch64 apk<br>`apk-tools-2.14.12-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `sbin/apk` | `validated` |
| `alpine-bc` | GNU bc | alpine v3.22 main aarch64 apk<br>`bc-1.08.2-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/bc` | `validated` |
| `alpine-diffutils` | GNU diffutils | alpine v3.22 main aarch64 apk<br>`diffutils-3.12-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/diff` | `validated` |
| `alpine-dosfstools` | dosfstools | alpine v3.22 main aarch64 apk<br>`dosfstools-4.2-r2.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `sbin/fsck.fat` | `validated` |
| `alpine-ed` | GNU ed | alpine v3.22 main aarch64 apk<br>`ed-1.21-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `bin/ed` | `validated` |
| `alpine-fish` | fish | alpine v3.22 main aarch64 apk<br>`fish-4.0.2-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/fish` | `validated` |
| `alpine-fping` | fping | alpine v3.22 main aarch64 apk<br>`fping-5.3-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/sbin/fping` | `validated` |
| `alpine-fsarchiver` | fsarchiver | alpine v3.22 main aarch64 apk<br>`fsarchiver-0.8.8-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/sbin/fsarchiver` | `validated` |
| `alpine-libarchive` | libarchive | alpine v3.22 main aarch64 apk<br>`libarchive-tools-3.8.3-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/bsdtar` | `validated` |
| `alpine-mandoc` | mandoc | alpine v3.22 main aarch64 apk<br>`mandoc-1.14.6-r13.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/mandoc` | `validated` |
| `alpine-mc` | Midnight Commander | alpine v3.22 main aarch64 apk<br>`mc-4.8.33-r2.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/mc` | `validated` |
| `alpine-memcached` | memcached | alpine v3.22 main aarch64 apk<br>`memcached-1.6.32-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/memcached` | `validated` |
| `alpine-openssh` | OpenSSH | alpine v3.22 main aarch64 apk<br>`openssh-client-default-10.0_p1-r10.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/ssh` | `validated` |
| `alpine-parted` | GNU Parted | alpine v3.22 main aarch64 apk<br>`parted-3.6-r2.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/sbin/parted` | `validated` |
| `alpine-patch` | GNU patch | alpine v3.22 main aarch64 apk<br>`patch-2.8-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/patch` | `validated` |
| `alpine-patchelf` | patchelf | alpine v3.22 main aarch64 apk<br>`patchelf-0.18.0-r3.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/patchelf` | `validated` |
| `alpine-dropbear` | Dropbear | alpine v3.22 main aarch64 apk<br>`dropbear-2025.88-r1.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/sbin/dropbear` | `validated` |
| `alpine-zstd` | Zstandard | alpine v3.22 main aarch64 apk<br>`zstd-1.5.7-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/zstd` | `validated` |
| `alpine-bluez` | BlueZ | alpine v3.22 main aarch64 apk<br>`bluez-deprecated-5.82-r0.apk` | `musl`<br>`/lib/ld-musl-aarch64.so.1` | `usr/bin/hciconfig` | `validated` |

## Review and isolation boundaries

- Every selected entry locks an immutable archive URL, version, archive-relative path, archive SHA-256, package license/source, declared executable path, AArch64 target/runtime/loader facts, expected static result, selection rationale, and all four layer policies.
- The 80-identity increment was locally downloaded to temporary storage, hash-verified, bounded-extracted, checked for an in-root declared AArch64 ELF, inspected with bounded `readelf`, and passed `dotnet validate --no-analysis`. Raw archives, ELF files, extracted roots, and command output remain outside the repository.
- Each pull request, nightly run, and release run executes the same complete 100-project registry. Static evidence is required for every identity. Baseline, outer-wrapper, and HostContext layers remain explicit `not-applicable` unless their reviewed runtime closure/oracle exists.
- The checked-in aggregate is registry metadata only. Native AArch64 CI generates authoritative feature fingerprints, UrProtect reports, result classifications, cleanup markers, and sanitized evidence. Feature frequency does not promote product support.
- BusyBox remains the existing complete Alpine minirootfs baseline witness. The new APK entries provide musl/AArch64 static ecology facts; they do not widen the runtime compatibility contract.
