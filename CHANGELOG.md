## Unreleased

### Improvements
- CA loading (CAFile, CACertificate, CAPath) is now strict and atomic: PEM
  input is validated block by block, every block must be a parseable X.509
  certificate, and any trailing, truncated, or non-certificate data fails the
  entire load instead of being silently dropped.
- CAPath/CAFile inputs are limited to regular files (symlinks to regular
  files are allowed), individual files are capped at 1 MiB, and a single load
  accepts at most 1024 certificates.
- Added `Config.LegacyCompat` to opt back into the previous lenient
  `AppendCertsFromPEM`-based behavior.

### Changes

### Fixed
- Malformed PEM blocks, non-certificate blocks, and truncated content after a
  valid certificate no longer go unnoticed during CA loading.

### Security

## v1.1.0 (2026-10-23)

### Changes
- Minimum Go version raised from 1.12 to 1.26 (go.mod).
- Added copyright and license headers.
- CI: Go 1.26.10 toolchain, golangci-lint v2.14.0, GitHub Actions updates.

### Security
- CI toolchain updated to fix GO-2025-3503 (net/http NO_PROXY bypass). The library does not import net/http.
