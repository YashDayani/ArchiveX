# Tests

These tests check ArchiveX against **independent** implementations. The tools below are *test oracles only*:
they are not part of the app, are not in this repository, and are not needed to build or run ArchiveX.

| Oracle | Used for |
|---|---|
| 7-Zip (`7zz`) — <https://www.7-zip.org> | 7z, ZIP (AES), XZ, BZ2, TAR; BCJ / ARM64 / ARM / Delta filters |
| RARLAB `rar` and `unrar` — <https://www.rarlab.com> | creating and extracting RAR 5 archives |
| `zstd` (optional, e.g. from Homebrew) | Zstandard files, tar.zst and zstd-compressed RPM payloads |
| macOS `unzip`, `zip`, `tar` (bsdtar), `gzip`, `bzip2`, `hdiutil` | ZIP, TAR, GZ, BZ2, XZ, CPIO, ISO |

## Engine tests (`CoreTests`)

```bash
swiftc -O -swift-version 5 Sources/Engine.swift Sources/Core/*.swift Tests/CoreTests/main.swift -o /tmp/CoreTests
/tmp/CoreTests <work-dir> <path-to-7zz> <dir-containing-rar-and-unrar> [<dir-with-an-older-rar>]
```

The optional fourth argument enables the RAR 3/4 tests: RAR 7 can no longer create the older RAR 4 format, so
they need a `rar` from the 5.x or 6.x line (for example 5.91) in that folder. Without it those tests are skipped.

Creates a tricky tree (Unicode names, a 120-character path, symlinks, permissions, empty files, random data) and
round-trips it through every format both ways, plus passwords, wrong passwords, selection, overwrite policies,
editing, zip-slip archives, corrupted and truncated files.

## App tests (`AppTests`)

Drives the real `ArchiveModel` (open → list → test → extract → edit) for every creatable format. Needs a work
folder containing `src/` (a sample tree) and `foreign/` (archives made by other tools).
