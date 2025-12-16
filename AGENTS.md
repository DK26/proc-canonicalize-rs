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

## Security Architecture & Path Resolution

To prevent namespace escapes and ensure security, the library follows a strict resolution order:

1. **Indirect Symlink Detection**: Before processing, we check if the path contains symlinks that point to a `/proc` magic path (e.g., `/tmp/link -> /proc`).
   - *Why*: If we passed `/tmp/link/self/root` directly to `std::fs::canonicalize`, it would resolve the symlink to `/proc`, see it's a magic link, and resolve it to `/` (host root), bypassing our protection.
   - *Rule*: Any path that *resolves* to a magic path must be treated as a magic path.

2. **Prefix Resolution**: When a magic path is found (e.g., `/proc/self/root/etc`), we:
   - Resolve the prefix (`/proc/self/root`) to its absolute host path (e.g., `/proc/1234/root`).
   - Canonicalize the full path (`/proc/1234/root/etc`).
   - Strip the resolved prefix from the full path.
   - Re-attach the original magic prefix.

3. **Escape Detection**: If the stripped path cannot be re-attached (e.g., it resolved to `../../etc`), we return the absolute path. We never return a path that claims to be inside the namespace if it actually escaped it.

## Known Limitations

This library provides best-effort namespace preservation suitable for **cooperative environments**. It is NOT a security boundary against adversarial filesystem manipulation.

### Fundamental Limitations (require API/design changes to fix)

- **TOCTOU After Symlink Scan**: The code detects symlinks into `/proc` before calling `std::fs::canonicalize`, but an attacker who controls the path can swap components to point into `/proc` after the scan and before canonicalization. Avoidable only with `openat`-style, race-free resolution.

- **PID Reuse Race**: Paths like `/proc/<pid>/root/...` are resolved using the live proc entry. If the target process exits and a new process reuses that PID between your initial check and the canonicalize call, the namespace being consulted may silently change.

- **Mount-Namespace Churn**: If the target PID switches mount namespaces mid-resolution (e.g., during container teardown/startup), the resolved path could straddle namespaces unexpectedly. There's no stabilization of the namespace view during canonicalization.

- **Untrusted /proc Mount**: Logic assumes `/proc` is the real procfs. If an attacker controls a bind-mount or chroot that provides a fake `/proc`, the pattern match will treat it as authoritative and could misrepresent a hostile namespace boundary.

### Detection Limitations (pattern-matching constraints)

- **Bind Mounts of /proc**: Paths involving bind mounts (e.g., `mount --bind /proc /mnt/proc`) are not detected as magic paths unless they explicitly use the `/proc` path. The library relies on path pattern matching (`/proc/PID/...`).

- **Non-Standard /proc Mounts**: If `/proc` is mounted at a different location (e.g., `/custom/proc`), it will not be detected.

### Safe Use Cases

- Host-side container monitoring (container cannot modify host filesystem)
- Path canonicalization where users control input strings but not the filesystem
- Best-effort namespace prefix preservation for logging/display

### Unsafe Use Cases

- Security decisions on paths under attacker-controlled directories
- Validation on shared/remote filesystems (NFS, FUSE)
- PID-based validation during process lifecycle transitions

For adversarial environments, use `O_NOFOLLOW` + `openat()` chains and validate via `fstat()` on the opened file descriptor.

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
- **MSRV Compliance**: We support Rust 1.70.0. Run `rustup run 1.70.0 cargo clippy` to catch version-specific lints (e.g., `clippy::needless_borrow` behavior changes between versions).
- **dunce feature usage (CRITICAL)**: Any code that uses `dunce::` functions MUST be guarded with `#[cfg(all(feature = "dunce", windows))]`. The dunce crate is a Windows-only target-conditional dependency.

## Documentation Examples (CRITICAL)

Documentation examples in `lib.rs` must be **testable and tested**. Claims about behavior must be backed by assertions, not just comments.

**Note**: `README.md` examples are NOT tested by `cargo test --doc`, so they should be clean and readable without hidden test scaffolding. However, they should still use `assert!` macros to demonstrate expected behavior clearly.

### Examples Must Demonstrate Unique Value

Don't waste reader time showing that "normal behavior works like std". Examples should show what makes THIS crate different.

**BAD** (adds no value):
```rust
// Normal paths work like std::fs::canonicalize
let our_result = canonicalize(".")?;
let std_result = std::fs::canonicalize(".")?;
assert_eq!(our_result, std_result);
```

**GOOD** (shows why this crate exists):
```rust
// We preserve namespace boundaries that std breaks
let our_result = canonicalize("/proc/self/root")?;
let std_result = std::fs::canonicalize("/proc/self/root")?;
assert_eq!(std_result, PathBuf::from("/"));  // std breaks it
assert_eq!(our_result, PathBuf::from("/proc/self/root"));  // we fix it
```

### Code Example Style for Clarity

1. **Use fully qualified paths when comparing APIs**: Show `std::fs::canonicalize` vs `proc_canonicalize::canonicalize` side-by-side so readers see the difference without mental mapping.
2. **Prefer exact comparisons over partial checks**: Use `assert_eq!(path, Path::new("/proc/self/root"))` instead of `assert!(path.starts_with("/proc/self/root"))`. Exact values reduce cognitive load.
3. **Use `Path::new()` over `PathBuf::from()`**: For assertions, `Path::new("/proc/self/root")` is cleaner than `PathBuf::from("/proc/self/root")` since `PathBuf` derefs to `Path`.
4. **Merge related examples**: When showing problem vs solution, use one code block with both to make the contrast obvious.
5. **Use modern format syntax**: Prefer `format!("/proc/{container_pid}/root")` over `format!("/proc/{}/root", container_pid)`.
6. **Choose information-dense examples**: Use one rich example that demonstrates multiple properties instead of multiple simple examples. For instance, `/proc/self/root/etc` shows both namespace preservation AND path resolution, eliminating the need for separate `/proc/self/root` and `/proc/self/root/etc` examples.

### Rules for `lib.rs` Examples

1. **Use `assert!` macros**: When showing behavior, use assertions to prove the claim.
2. **No `no_run` or `ignore`**: Examples must actually execute. These attributes are forbidden.
3. **Platform-gating is allowed**: Use `#[cfg(target_os = "linux")]` to limit tests to relevant platforms.
4. **Examples are tests**: Doc examples are compiled and run by `cargo test --doc`. They must pass.
5. **No failure messages in doc assertions**: In documentation, the assertion IS the teaching moment. Failure messages are noise.

**BAD** (in documentation):
```rust
assert!(canonical.starts_with(&container_root), "path escapes container boundary");
```

**GOOD** (in documentation):
```rust
// Security: canonical path must stay inside container_root
assert!(canonical.starts_with(&container_root));
```

**Note**: In unit tests (not documentation), failure messages ARE helpful for debugging CI failures:
```rust
// In unit tests, failure messages help diagnose issues quickly
assert!(result.starts_with("/proc/self/root"), "expected /proc prefix, got: {:?}", result);
```

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

### Namespace Testing Guidelines (CRITICAL)

When writing or reviewing tests for `/proc` namespace paths, follow these rules to ensure comprehensive coverage:

#### 1. Namespace Type Symmetry
For every test on `/proc/.../root`, write a parallel test for `/proc/.../cwd`. They behave differently:
- `/proc/self/root` typically resolves to `/` on the host
- `/proc/self/cwd` resolves to the actual working directory (NOT `/`)

**Example of missing symmetry (BAD):**
```rust
// Only tests root - what about cwd?
fn test_canonicalize_proc_self_root() { ... }
```

**Correct approach (GOOD):**
```rust
fn test_canonicalize_proc_self_root() { ... }
fn test_canonicalize_proc_self_cwd() { ... }  // Parallel test
```

#### 2. Test "Paths Through", Not Just "Prefix Alone"
Always test accessing files *through* the namespace, not just the namespace prefix itself:

**Insufficient (BAD):**
```rust
canonicalize("/proc/self/cwd")  // Only tests the prefix
```

**Comprehensive (GOOD):**
```rust
canonicalize("/proc/self/cwd")           // Prefix alone
canonicalize("/proc/self/cwd/file.txt")  // Path THROUGH the namespace
canonicalize("/proc/self/cwd/dir/file")  // Deeper path through
```

#### 3. Test Namespace Escape via `..`
Paths using `..` can escape the namespace. Test both cases:
- `..` that stays inside (e.g., `/proc/self/root/../etc` → still inside because `..` from `/` is `/`)
- `..` that escapes (e.g., `/proc/self/cwd/..` → escapes to parent of cwd)

#### 4. Test Non-Root Namespace Targets
The namespace prefix may not resolve to `/`. Ensure tests cover:
- Direct paths where prefix resolves to `/` (e.g., `/proc/self/root` on host)
- Indirect symlinks that exercise non-`/` prefix resolution
- Container-like scenarios where `/proc/PID/root` is not `/`

#### 5. Invariant Tests
Add property-based tests that verify invariants:
```rust
// Invariant 1: Result is either prefixed OR escaped absolute
// Invariant 2: canonicalize(canonicalize(x)) == canonicalize(x)
```

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

### Self-Documenting Tests (CRITICAL)

Tests should be **self-explanatory through code**, not comments. The code itself must clearly show how the API should or should not be used.

#### Principles

1. **Function names read like sentences**: Use descriptive names that explain what's being tested.
   ```rust
   // GOOD: Name explains the behavior
   fn proc_self_root_preserved_not_resolved_to_slash() { ... }
   fn symlink_to_proc_self_root_preserves_namespace() { ... }
   
   // BAD: Generic or unclear names
   fn test_case_1() { ... }
   fn test_canonicalize() { ... }
   ```

2. **Variable names explain intent**: Names should tell the story.
   ```rust
   // GOOD: Variables explain the scenario
   let container_pid = std::process::id();
   let container_root = format!("/proc/{}/root", container_pid);
   let file_inside_container = format!("{}/etc", container_root);
   let is_inside_container = canonical.starts_with(&container_root);
   
   // BAD: Generic names require mental mapping
   let p = std::process::id();
   let r = format!("/proc/{}/root", p);
   let f = format!("{}/etc", r);
   ```

3. **Tests are copy-able usage examples**: A user should be able to copy test code directly.
   ```rust
   #[test]
   fn reading_container_file_from_host() {
       let container_pid = std::process::id();
       let container_root = format!("/proc/{}/root", container_pid);
       let file_inside_container = format!("{}/etc", container_root);
   
       let canonical_path = canonicalize(file_inside_container).unwrap();
   
       assert!(canonical_path.starts_with(&container_root));
   }
   ```

4. **Show contrast with std when relevant**: Make the difference obvious.
   ```rust
   let our_result = canonicalize(path).unwrap();
   let std_result = std::fs::canonicalize(path).unwrap();
   
   assert_eq!(std_result, PathBuf::from("/"));           // std breaks it
   assert_eq!(our_result, PathBuf::from("/proc/self/root")); // we fix it
   ```

5. **Minimal comments**: If you need a comment to explain what code does, rename the variables instead.
   ```rust
   // BAD: Comment explains what code should say
   let r = canonicalize(p)?;  // Returns the preserved namespace path
   
   // GOOD: Code speaks for itself
   let preserved_namespace_path = canonicalize(container_file)?;
   ```

6. **Section headers organize test modules**: Group related tests under clear headers.
   ```rust
   // ==========================================================================
   // USAGE EXAMPLES: How to use this crate for container monitoring
   // ==========================================================================
   
   // ==========================================================================
   // ERROR CASES: What happens with invalid input
   // ==========================================================================
   ```

#### Why This Matters

- Tests are documentation that can't lie (they compile and run)
- New contributors learn the API by reading tests
- Self-documenting tests don't rot when behavior changes (comments do)
- Copy-able examples reduce user friction

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

### CHANGELOG Guidelines

The CHANGELOG is for **users**, not developers. Only include changes that affect the public API or user experience.

**DO include:**
- Bug fixes that affected user-facing behavior
- New features or API additions
- Breaking changes or deprecations
- Security fixes
- Performance improvements users would notice

**DO NOT include:**
- Internal refactoring
- Test additions or changes
- Documentation updates (unless significant)
- CI/tooling changes
- Code style fixes
- Updates to AGENTS.md or other contributor docs

**Format:**
- Keep entries concise (1-2 sentences)
- Focus on *what changed* for the user, not *how* it was implemented
- Technical root cause details belong in commit messages or PR descriptions, not CHANGELOG

---

If anything in this guide appears to conflict with the existing tests, treat the tests as the source of truth and open an issue to correct the guide.

