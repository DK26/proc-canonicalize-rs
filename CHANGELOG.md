# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-12-15

### Changed

- **Documentation**: Clarified assertion message guidelines (doc examples vs unit tests)
- **Documentation**: Updated version references throughout README

## [0.1.0] - 2025-12-15

### Changed

- **Maturity**: Promoted from alpha (0.0.x) to stable (0.1.0) release
- **Documentation**: Improved examples to demonstrate unique value instead of redundant comparisons
- **Testing**: Refactored all unit tests to be self-documenting with descriptive names and variable names that tell the story
- **Quality**: Enhanced test coverage and documentation quality for production readiness

## [0.0.4] - 2025-12-11

### Security

- **Critical**: Fixed vulnerability where relative symlinks to `/proc` (e.g. `link -> ../proc/self/root`) could bypass namespace protection by resolving through intermediate symlink targets.
- **Critical**: Fixed vulnerability where `..` normalization before symlink detection could hide symlinks pointing to `/proc` magic paths.
- Added comprehensive security test suite with 18 tests covering:
  - Double and triple symlink indirection chains
  - Symlink loops with proc references
  - Relative symlinks with `..` components resolving to /proc
  - Mixed real directories and symlink chains
  - Innocent-looking symlink chains

### Fixed

- **Critical Bug**: Fixed path duplication when canonicalizing paths through `/proc/PID/cwd`
  - Previously, `/proc/self/cwd/file.txt` incorrectly resolved to `/proc/self/cwd/home/user/project/file.txt`
  - Now correctly resolves to `/proc/self/cwd/file.txt`

- **Critical Bug**: Paths escaping namespace via `..` are now handled correctly
  - `/proc/self/cwd/..` now correctly returns the parent directory as an absolute path
  - Detects when paths escape the namespace and returns absolute host path

- Error reporting: Now correctly returns `PermissionDenied` instead of `NotFound` when lacking access to namespace paths

### Added

- Support for task-level namespace boundaries: `/proc/PID/task/TID/root` and `/proc/PID/task/TID/cwd`
- 15 comprehensive edge case regression tests covering:
  - Namespace type symmetry (root vs cwd)
  - Paths through namespaces (not just prefix alone)
  - Namespace escape via `..`
  - Symlink resolution within namespaces
  - Idempotency invariant verification

### Changed

- Rewrote `detect_indirect_proc_magic_link()` to walk path components manually instead of normalizing first
  - Prevents `..` normalization from hiding symlinks to magic paths
  - Follows symlink chains iteratively with proper loop detection
- Documented known limitations in AGENTS.md with clear threat model guidance
- Added "Safe Use Cases" and "Unsafe Use Cases" sections for users

## [0.0.3] - 2025-12-11

### Fixed

- **Security**: Indirect symlinks to `/proc` magic paths now correctly preserve namespace boundaries
  - Previously, a symlink like `/tmp/container -> /proc/self/root` would resolve to `/` instead of `/proc/self/root`
  - This could allow container escape if symlinks outside `/proc` pointed to namespace boundaries
  - Now detects and handles symlink chains (up to 40 levels, matching kernel `MAXSYMLINKS`)

### Changed

- Documentation examples are now tested Rust code with assertions instead of text blocks
- README examples updated to use proper `assert!` macros demonstrating expected behavior

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

[Unreleased]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.4...HEAD
[0.0.4]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/DK26/proc-canonicalize-rs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/DK26/proc-canonicalize-rs/releases/tag/v0.0.1
