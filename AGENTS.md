# AGENTS: AI Contributor Guide

This repo contains a zero-dependency Rust crate that fixes `std::fs::canonicalize` for Linux `/proc/PID/root` and `/proc/PID/cwd` paths. It preserves namespace boundaries that `std::fs::canonicalize` incorrectly resolves to `/`.

Use this guide when proposing changes, refactors, tests, or docs with an automated agent.

## Golden Rules

- Compatibility: Normal paths must behave exactly like `std::fs::canonicalize`.
- Namespace preservation: `/proc/PID/root` and `/proc/PID/cwd` prefixes must be preserved.
- Zero deps: Keep runtime dependencies at 0 (dev-only `tempfile` is allowed in tests).
- Linux-focused: Primary functionality is Linux-specific; other platforms fall back to std.
- MSRV: Keep Minimum Supported Rust Version at `1.70.0` (edition 2021; no unstable features).
- CI clean: `cargo fmt`, `clippy -D warnings`, tests, docs (rustdoc `-D warnings`), and MSRV all pass locally.

## Public Surface (do not break)

- `pub fn canonicalize(path: impl AsRef<std::path::Path>) -> std::io::Result<std::path::PathBuf>`

Do not change signatures or remove items without a clear migration plan and tests.

## Behavioral Invariants

- Normal paths: Return exactly what `std::fs::canonicalize` returns.
- `/proc/PID/root` paths: Preserve the namespace prefix instead of resolving to `/`.
- `/proc/PID/cwd` paths: Preserve the namespace prefix instead of resolving to the actual cwd.
- `/proc/self/root` and `/proc/self/cwd`: Treated as namespace boundaries.
- `/proc/thread-self/root` and `/proc/thread-self/cwd`: Treated as namespace boundaries.
- Non-Linux platforms: Fall back to `std::fs::canonicalize` directly.
- Optional `dunce` feature (Windows only): Simplifies extended-length paths on Windows.

## Repository Layout

- `src/lib.rs`: Core algorithm, Linux/non-Linux branches, helpers, tests.
- `README.md`: User-facing documentation.
- `CHANGELOG.md`: Version history.
- CI helpers: `ci-local.sh` and `ci-local.ps1` replicate GitHub Actions locally.

## Local CI (run before any PR)

- Bash (Linux/macOS/WSL): `bash ci-local.sh`
- PowerShell (Windows): `.\ci-local.ps1`

These scripts:
- Check UTF-8 encodings and BOM for critical files.
- Run `cargo fmt --check`, `clippy -D warnings`, `cargo test --verbose` (includes doctests), and `cargo doc` with `RUSTDOCFLAGS='-D warnings'`.
- Test feature combinations: default features and `--features dunce` on Windows.
- Verify MSRV by building and linting on Rust 1.70.0.

## Coding Guidelines

- Style: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction.
- Error handling: Return meaningful `io::Error` with context when appropriate.
- Allocation: Avoid unnecessary allocations; prefer `PathBuf` and component streaming.
- Platform cfg: Keep Linux/non-Linux branches correct; don't introduce behavioral drift.
- Dependencies: Do not add runtime dependencies. If you believe one is strictly necessary, open an issue first.
- **dunce feature usage (CRITICAL)**: Any code that uses `dunce::` functions MUST be guarded with `#[cfg(all(feature = "dunce", windows))]`. The dunce crate is a Windows-only target-conditional dependency.

## Documentation Examples (CRITICAL)

Documentation examples in `lib.rs` must be **testable and tested**. Claims about behavior must be backed by assertions, not just comments.

**Note**: `README.md` examples are NOT tested by `cargo test --doc`, so they should be clean and readable without hidden test scaffolding. However, they should still use `assert!` macros to demonstrate expected behavior clearly.

### Rules for `lib.rs` Examples

1. **Use `assert!` macros**: When showing behavior, use assertions to prove the claim.
2. **No `no_run` or `ignore`**: Examples must actually execute. These attributes are forbidden.
3. **Platform-gating is allowed**: Use `#[cfg(target_os = "linux")]` to limit tests to relevant platforms.
4. **Examples are tests**: Doc examples are compiled and run by `cargo test --doc`. They must pass.

### Correct Pattern (`lib.rs`)

```rust
//! ```rust
//! # #[cfg(target_os = "linux")]
//! # fn main() -> std::io::Result<()> {
//! use std::path::PathBuf;
//!
//! // Prove the claim with an assertion
//! let resolved = proc_canonicalize::canonicalize("/proc/self/root")?;
//! assert_eq!(resolved, PathBuf::from("/proc/self/root"));
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
```

### Correct Pattern (`README.md`)

README examples are not tested, so keep them clean without hidden scaffolding:

```rust
use proc_canonicalize::canonicalize;
use std::path::PathBuf;

let resolved = canonicalize("/proc/self/root")?;
assert_eq!(resolved, PathBuf::from("/proc/self/root"));
```

### Incorrect Patterns (do NOT use)

```rust
// BAD: Uses no_run - test never executes
//! ```rust,no_run

// BAD: Uses ignore - test is skipped entirely  
//! ```rust,ignore

// BAD: Comment-only claim with no assertion
//! let result = canonicalize(path)?;  // Returns "/proc/self/root"
```

### Why This Matters

- Doc examples are the first thing users see and copy
- Assertions ensure examples stay correct as code evolves
- `cargo test --doc` catches documentation rot automatically
- Comments can lie; assertions cannot

## Tests & Quality Gates

- Run `cargo test` on Linux (primary platform) and optionally Windows/macOS.
- Coverage areas include: namespace boundary detection, PID validation, existing/non-existing paths, permission errors, symlink resolution within namespaces.
- When changing behavior, add focused tests alongside the changed logic.
- Keep tests deterministic and filesystem-safe.

### Bug Fix Methodology (CRITICAL)

When fixing bugs, you **MUST** follow this test-driven process to verify both the bug and the fix:

1. **Write tests first**: Create tests that exercise the buggy behavior.
2. **Verify tests FAIL**: Run the tests and confirm they fail, proving the bug exists.
3. **Implement the fix**: Write the code to address the bug.
4. **Verify tests PASS**: Run the tests again and confirm they now pass.
5. **Run full CI**: Ensure no regressions in existing functionality.

**Why this matters**: If you write tests and fixes simultaneously without step 2, you have no proof that:
- The bug actually exists in the codebase
- Your fix addresses the bug (tests might pass for the wrong reason)

**Example workflow**:
```bash
# 1. Write tests for the bug
# 2. Run tests - they should FAIL
cargo test my_new_bug_tests  # Expect failures

# 3. Implement the fix
# 4. Run tests again - they should PASS
cargo test my_new_bug_tests  # Expect success

# 5. Full CI
bash ci-local.sh
```

**Temporary disable technique**: If you accidentally write the fix first, you can still verify by temporarily commenting out the fix, running the tests (should fail), then re-enabling the fix (should pass).

### Testing on Linux (Required)

Most functionality is Linux-specific. Test primarily on Linux or WSL:
```bash
# From WSL or Linux
cargo test --verbose
```

### Testing on Windows (Optional)

Windows tests verify the fallback behavior and optional dunce feature:
```powershell
cargo test --verbose
cargo test --features dunce --verbose
```

## Common Pitfalls (avoid)

- Breaking namespace detection: Don't change the `find_namespace_boundary` logic without thorough testing.
- Incorrect PID validation: PIDs must be numeric, "self", or "thread-self".
- Over-canonicalizing: Only preserve the namespace prefix; let std handle the actual path resolution within the namespace.
- Dropping error context: Don't return bare `io::Error` without meaningful context.

## PR Checklist (agent self-check)

- Normal path behavior unchanged and equal to `std::fs::canonicalize`.
- Namespace boundary preservation working correctly.
- All CI steps pass locally.
- New/changed logic covered by tests.
- Docs updated (README/lib.rs) if user-visible behavior changed.
- No new runtime dependencies; MSRV respected; no unstable features.

## Quick Commands

- Run all local CI: `bash ci-local.sh` or `.\ci-local.ps1`
- Tests (verbose): `cargo test --verbose`
- Tests on Linux (WSL): `wsl -e bash -ilc "cd /mnt/c/path/to/repo && cargo test"`
- Lints: `cargo clippy --all-targets --all-features -- -D warnings`
- Docs (warnings as errors): `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`

## Releasing (maintainers)

- Tag as `vX.Y.Z` to trigger publish and GitHub Release via workflows.
- Update `CHANGELOG.md` with clear, user-facing notes.

---

If anything in this guide appears to conflict with the existing tests, treat the tests as the source of truth and open an issue to correct the guide.

