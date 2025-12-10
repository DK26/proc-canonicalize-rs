# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2] - 2025-12-10

### Added

- Comprehensive edge case tests for namespace boundary handling:
  - Non-existent files under valid namespace paths
  - Non-existent PIDs
  - Path normalization with `..` components
  - Trailing slashes
  - Deep nested paths under namespaces
  - Symlink resolution within namespaces
  - Permission denied scenarios
- Real PID tests using PID 1 (init/systemd) for realistic container scenarios
- Tests for `/proc/self/cwd` and `/proc/thread-self/root`
- Test verifying `/proc/self/root` vs `/proc/{pid}/root` equivalence

### Changed

- Made `dunce` dependency Windows-only via target-conditional in Cargo.toml
- README improvements:
  - Fixed table formatting
  - Corrected dunce feature description (it preserves `\\?\` when needed for long paths)

## [0.0.1] - 2025-12-09

### Added

- Initial release
- `canonicalize()` function that preserves Linux `/proc/PID/root` and `/proc/PID/cwd` namespace boundaries
- Support for:
  - `/proc/PID/root` and `/proc/PID/root/...` paths
  - `/proc/PID/cwd` and `/proc/PID/cwd/...` paths
  - `/proc/self/root` and `/proc/self/cwd`
  - `/proc/thread-self/root` and `/proc/thread-self/cwd`
- Non-Linux platforms fall back to `std::fs::canonicalize`
- Optional `dunce` feature for Windows path simplification
- Zero runtime dependencies (dunce is optional and Windows-only)
- Comprehensive test suite for namespace boundary detection

[Unreleased]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/DK26/proc-canonicalize-rs/releases/tag/v0.0.1
