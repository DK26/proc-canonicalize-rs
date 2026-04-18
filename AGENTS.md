# AGENTS: AI Contributor Guide

Rules for writing code in this crate. Not a project description, not a changelog, not architectural documentation — read the code for those.

## Maintaining This File

AGENTS.md is read by stateless agents with no memory of prior sessions.
Every rule must stand on its own without session context.

- **General, not reactive.** Do not add rules to address a single past mistake. Only codify patterns that could recur across sessions.
- **Context-free.** No references to specific conversations, resolved issues, commit hashes, or session artifacts. A future agent must understand the rule without knowing what prompted it.
- **Principles over examples.** Prefer abstract guidance. If an example is needed, make it generic — never name a specific module or function as the motivating case.
- **No stale specifics.** If a rule names a concrete item (file, function, feature), it must be because the item is structurally important (e.g. the repository layout table), not because it was the subject of a past debate.
- **Token-efficient.** Do not bloat this file with redundant information an agent can derive by reading the repo — current implementation details, file listings, architectural snapshots, project state, or change history. Every paragraph must teach the agent *how to code*; if it only describes what already exists, cut it.

## Golden Rules

- Compatibility: Normal paths must behave exactly like `std::fs::canonicalize`.
- Namespace preservation: `/proc/PID/root` and `/proc/PID/cwd` prefixes must be preserved.
- Zero mandatory deps: Keep mandatory runtime dependencies at 0. The only optional runtime dependency is `dunce` (Windows-only, feature-gated, target-conditional in `Cargo.toml`). Dev-only `tempfile` is allowed in tests.
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

## Security Rules

- Any path that *resolves* to a `/proc` magic path (e.g. via an intermediate symlink) must be treated as a magic path. Passing such a path unmodified to `std::fs::canonicalize` would let the kernel resolve the magic link to `/` and erase the namespace boundary.
- If a resolved path cannot be re-attached to its original magic prefix (because it escaped via `..` or similar), return the escaped absolute path. Never return a path that falsely claims to be inside a namespace.
- This crate provides best-effort namespace preservation for cooperative environments; it is not a security boundary against adversarial filesystem manipulation. Do not add code that implies it is — no hardening claims in docs, no APIs that suggest race-free guarantees.

## Local CI (run before any PR)

- Bash (Linux/macOS/WSL): `bash ci-local.sh`
- PowerShell (Windows): `.\ci-local.ps1`

These scripts:
- Check UTF-8 encodings and BOM for critical files.
- Run `cargo fmt --check`, `clippy -D warnings`, `cargo test --verbose` (includes doctests), and `cargo doc` with `RUSTDOCFLAGS='-D warnings'`.
- Test feature combinations: default features and `--features dunce` on Windows.
- Verify MSRV by building and linting on Rust 1.70.0.

## Coding Guidelines

- **Style**: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction. Complexity belongs in the problem domain (namespace detection), not in code structure.
- **Error handling**: Return meaningful `io::Error` with context. A bare `ErrorKind::Other` leaves callers no basis to decide whether to retry, log, or surface the error.
- **Allocation**: Prefer borrowed `&Path` / `&OsStr` for read-only inspection; use component iterators to stream over path parts without materializing them into owned values. See Heap Allocation in Hot Paths below.
- **Platform cfg**: Keep Linux and non-Linux branches behaviorally aligned. The non-Linux branch is a delegate to `std`; silent divergence breaks callers who develop on macOS/Windows and deploy on Linux.
- **Dependencies**: Do not add runtime dependencies. Zero-mandatory-deps is a documented guarantee; breaking it increases supply-chain surface for every downstream crate. If one seems strictly necessary, open an issue first.
- **MSRV Compliance**: Run `rustup run 1.70.0 cargo clippy` to catch version-specific lints (e.g. `clippy::needless_borrow` behavior changes between versions). Downstream crates pinned to older toolchains hit breakage we don't see on stable.
- **dunce feature usage (CRITICAL)**: Guard every call into `dunce::` with `#[cfg(all(feature = "dunce", windows))]`. A bare `#[cfg(feature = "dunce")]` compiles on Linux/macOS but links against a missing symbol, because `dunce` is target-gated to Windows in `Cargo.toml`.
- **No `.unwrap()` / `.expect()` in production code**: A panic in a library function aborts the caller's process instead of returning an error they can handle. Use `?`, `.ok_or()`, `.map_err()`, or `.unwrap_or()` in `src/`. Test code may use `.unwrap()` freely.
- **No dead code suppressions**: Do not add `#[allow(dead_code)]` or similar. A helper that was meant to be called but isn't is a logic bug, not a style issue — use it or remove it.

### Safe Indexing — No Direct Indexing in Production Code

Inputs come from the caller — filesystem paths, PID strings, proc entries — whose shapes are not under our control. A crafted or unexpectedly short path component would cause a panic, aborting the calling process rather than returning an error; that is an unrecoverable denial-of-service the caller cannot catch. Production code must not use direct indexing (`data[i]`, `parts[1]`, `slice[start..end]`) on slices, `Vec`, or `str`; all input-derived lengths must go through bounds-checked accessors so failures propagate as `io::Error`.

| Banned               | Replacement                                            |
| -------------------- | ------------------------------------------------------ |
| `parts[i]`          | `parts.get(i).ok_or(…)?` or `parts.get(i).map(…)`     |
| `data[start..end]`  | `data.get(start..end).ok_or(…)?`                       |
| `slice[i..]`        | `slice.get(i..).unwrap_or_default()`                   |

For sequential processing, prefer iterators (`.iter()`, `.enumerate()`, `.windows()`, `.chunks()`, `.split()`) over index-based loops — they are bounds-checked by construction and communicate intent more clearly than offset arithmetic.

Test code (`#[cfg(test)]` blocks, `tests/`) may use direct indexing when the test controls the input and panic-on-bug is acceptable.

### Heap Allocation in Hot Paths

Path component iteration, namespace boundary detection, PID segment validation, and prefix stripping run on every canonicalize call and must not heap-allocate intermediate values. Callers can invoke this crate thousands of times per second; hidden `String::new()` or `.to_owned()` inside helpers is invisible in this crate's own benchmarks but shows up as allocator pressure in the caller's profile.

- Use `&str` / `&Path` / `&OsStr` slices over owned types when the data already lives in the caller's buffer.
- Use iterators (`.components()`, `.split()`, `.bytes()`) to stream over path parts without materializing them.
- Avoid `.to_string()`, `.to_owned()`, `.collect::<Vec<_>>()`, or `format!()` inside loops or frequently-called helpers.
- Do not create a `String` just to pattern-match on it; match on `&str` or `OsStr` bytes directly.

When an allocation is unavoidable (e.g., the output `PathBuf` must own its data):
- Pre-size with `PathBuf::with_capacity(input.as_os_str().len())` or `Vec::with_capacity(known_size)` to avoid reallocation growth.
- Prefer `push` / `extend_from_slice` in a single pass over repeated small appends.
- Leave a one-line comment at the allocation site explaining why it cannot be avoided.

### Type Safety

- **Prefer `Option` / `Result` over sentinel values.** Sentinels are invisible contracts — every caller must know the magic value and check it, whereas `Option`/`Result` make presence/absence explicit in the type system and enforce handling at the call site. Never use empty strings, `-1`, or null-equivalent magic values to signal absence.
- **Prefer `match` over `if let` when handling enums.** Path resolution involves several small state machines (namespace kind, PID kind, resolution outcome); a new variant missed at one `if let` site creates silent behavioral divergence that is very hard to locate at runtime. Adding a new variant should produce a compile error at every unhandled site, not fall through silently.
- **Keep struct fields private when invariants must be enforced.** A public field can be set to any value by any caller; a constructor or setter method is the only place invariants can be checked centrally. Expose transition methods that enforce them.

### Lifetime Naming

Use descriptive lifetime names when a function has two or more input lifetimes or when the output-borrow source would otherwise be ambiguous. `'a` and `'b` tell the reader nothing about which output borrow comes from which input — especially in helpers that borrow across input path, component iterator, prefix slice, and parent-directory reference.

Single-lifetime functions with an unambiguous borrow source may rely on elision per standard Rust idiom.

| Lifetime     | Meaning                                              |
| ------------ | ---------------------------------------------------- |
| `'path`      | Borrows from the input path argument                 |
| `'input`     | Borrows from any generic caller-supplied input       |
| `'buf`       | Borrows from an internal or caller-supplied buffer   |
| `'prefix`    | Borrows from a namespace prefix slice                |
| `'parent`    | Borrows from a parent-directory component            |

```rust
// BAD: 'a tells the reader nothing about where the return value borrows from
fn strip_prefix<'a>(path: &'a Path, prefix: &Path) -> Option<&'a Path> { ... }

// GOOD: 'path makes clear the return borrows from `path`, not `prefix`
fn strip_prefix<'path>(path: &'path Path, prefix: &Path) -> Option<&'path Path> { ... }
```

### RAG / LLM-Friendly File Size

Keep source files under **~600 lines** (production or test) to fit within a single LLM context window and improve RAG retrieval precision.

- When a production file grows past ~600 lines, split into focused submodules (e.g. `foo.rs` → `foo/mod.rs` + `foo/helpers.rs`).
- When a test file grows past ~600 lines, split into thematic files (e.g. `tests_validation.rs`, `tests_security.rs`).
- Favor a stable top-to-bottom layout so any reader knows where to look: module docs → imports → constants → types → impl blocks → functions → tests.

## Coding Session Discipline

### Test-First / Proof-First

- For every non-trivial behavior change, bug fix, or regression fix: **write or update the tests first** so the expected behavior is explicit before implementation changes begin.
- The intended workflow is **red → green → refactor**:
  1. Encode the requirement in a test.
  2. Observe the old implementation fail or lack the behavior.
  3. Implement the change.
  4. Rerun the tests to prove the new behavior.
- If a task is purely structural (rename, move, formatting) and has no behavioral delta, a new failing test is not required.
- Every problem or bug fixed must include a regression test as part of the same change set.

### Evidence Rule

Do not claim a feature or fix is complete without evidence:

- Tests (unit, integration, or doctests) proving the behavior.
- CI output showing clean build + test pass.
- Manual verification notes (if no automation exists yet).

"Implemented" or "fixed" without proof is not acceptable.

## Documentation Examples (CRITICAL)

Doc examples are the first thing users see and copy; comments can lie but assertions cannot, and `cargo test --doc` catches documentation rot automatically as code evolves. Documentation examples in `lib.rs` must therefore be testable and tested, with every behavioral claim backed by an assertion rather than a comment.

`README.md` examples are NOT tested by `cargo test --doc`, so they should be clean and readable without hidden test scaffolding. They should still use `assert!` macros to demonstrate expected behavior clearly — a reader skimming the README gets the same unambiguous picture as a reader running the doctests.

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
2. **Match the assertion to what the test actually asserts**: Use `assert_eq!(path, Path::new("/proc/self/root"))` when the full expected value is deterministic — exact values reduce cognitive load. Use `assert!(path.starts_with(&anchor))` when the test is a containment check and the suffix is system-dependent (e.g., cwd resolution, PID-specific tails). Do not reach for `starts_with` as a cop-out when the full value is knowable.
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

In unit tests (not documentation), failure messages ARE helpful for debugging CI failures where you cannot attach a debugger:
```rust
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

Writing the test and the fix together leaves you with no proof the bug ever existed in the codebase — the test might pass for the wrong reason (e.g., passing against unrelated behavior), and you cannot distinguish a real fix from a test that was wrong all along. Every bug fix must therefore follow this test-driven sequence:

1. Write tests that exercise the buggy behavior.
2. Run them and confirm they FAIL — this proves the bug is real and reachable.
3. Implement the fix.
4. Run the tests again and confirm they now PASS.
5. Run full CI to ensure no regression elsewhere.

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

If you accidentally write the fix first, recover the evidence by temporarily commenting out the fix and running the tests (they should fail), then re-enabling the fix (they should pass).

### Self-Documenting Tests (CRITICAL)

Tests are documentation that cannot lie — they compile and run every CI cycle, so they never rot the way comments do. New contributors learn the API by reading tests, so every test must read like a copy-able usage example. The code must carry the meaning; do not lean on comments to explain what a well-named identifier could say directly.

1. **Function names read like sentences.** The test name should state the behavior under test so a failing test line in CI output is self-describing.
   ```rust
   // GOOD: Name states the behavior
   fn proc_self_root_preserved_not_resolved_to_slash() { ... }
   fn symlink_to_proc_self_root_preserves_namespace() { ... }
   
   // BAD: Generic or unclear names
   fn test_case_1() { ... }
   fn test_canonicalize() { ... }
   ```

2. **Variable names explain intent.** Names should tell the story without a glossary.
   ```rust
   // GOOD: Variables name what the value represents
   let pid = std::process::id();
   let namespace_root = format!("/proc/{pid}/root");
   let file_in_namespace = format!("{namespace_root}/etc");
   let is_inside_namespace = canonical.starts_with(&namespace_root);
   
   // BAD: Generic names require mental mapping
   let p = std::process::id();
   let r = format!("/proc/{}/root", p);
   let f = format!("{}/etc", r);
   ```

3. **Tests are copy-able usage examples.** A user should be able to lift the body directly into their own code.
   ```rust
   #[test]
   fn proc_pid_namespace_prefix_preserved_through_canonicalize() {
       let pid = std::process::id();
       let namespace_root = format!("/proc/{pid}/root");
       let file_in_namespace = format!("{namespace_root}/etc");
   
       let canonical = canonicalize(file_in_namespace).unwrap();
   
       assert!(canonical.starts_with(&namespace_root));
   }
   ```

4. **Show contrast with std when relevant.** Make the behavioral difference obvious side-by-side.
   ```rust
   let our_result = canonicalize(path).unwrap();
   let std_result = std::fs::canonicalize(path).unwrap();
   
   assert_eq!(std_result, PathBuf::from("/"));               // std resolves away
   assert_eq!(our_result, PathBuf::from("/proc/self/root")); // we preserve
   ```

5. **Minimal comments.** If you need a comment to explain what code does, rename variables until the code says it.
   ```rust
   // BAD: Comment explains what the code should say
   let r = canonicalize(p)?;  // Returns the preserved namespace path
   
   // GOOD: The code says it
   let preserved_namespace_path = canonicalize(proc_pid_path)?;
   ```

6. **Section headers organize test modules.** Group related tests so a reader can navigate by intent.
   ```rust
   // ==========================================================================
   // USAGE EXAMPLES: How to use this crate for container monitoring
   // ==========================================================================
   
   // ==========================================================================
   // ERROR CASES: What happens with invalid input
   // ==========================================================================
   ```

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

## Git Usage Policy (CRITICAL for Agents)

The user has context you don't, and uncommitted state (staged files, stashes, untracked work-in-progress) may represent their in-progress work. By default, run only read-only git commands; never modify the working tree, index, or history on your own initiative — not even to "clean up" or "fix" something you just changed.

**Always allowed (read-only):**
- `git status`, `git diff`, `git diff --staged`
- `git log`, `git show`, `git blame`
- `git ls-files`, `git stash list`

**Only on explicit user authorization:**
- `git add`, `git stage`
- `git commit`, `git commit --amend`
- `git reset` (any form), `git restore`, `git checkout -- <file>`
- `git stash`, `git stash pop`
- `git merge`, `git rebase`
- `git push`, `git pull`, `git fetch`
- `git rm`, `git mv`
- `git tag`, `git branch -d`

Authorization is scoped to the operation the user named. "Commit this" is not permission to `push`; "stage my changes" is not permission to `commit`. If a workflow needs further write operations, ask before each one. When the user authorizes a commit, follow the Git Commit Workflow below.

## Git Commit Workflow (when the user authorizes a commit)

This section applies only once the user has explicitly asked you to create a commit. Absent that instruction, the read-only policy above governs.

A commit is a permanent record attached to the user's name; staging the wrong files, or stacking your commit on top of the user's unrelated staged work, creates a mess that is awkward to untangle. Before running `git commit` you must always first inspect what is already staged — the user may have staged files for a different purpose that your commit would silently absorb.

1. Run `git status` to see which files are staged vs. unstaged vs. untracked.
2. Run `git diff --staged --stat` to see exactly what a commit right now would contain.
3. Review the staged changes and confirm they match the scope the user asked you to commit.
4. If unrelated files are staged, either ask the user how to proceed, or (with further explicit authorization) unstage them before committing.

Never run `git add <file>; git commit` blindly — that absorbs any pre-existing staged work into your commit. The commit message must match the staged content; if they diverge, stop and clarify with the user.

```bash
# WRONG - ignores existing staged files and commits them under the wrong message
git add myfile.rs
git commit -m "fix: something"

# CORRECT - inspect first
git status
git diff --staged --stat
# Review output, then if appropriate:
git add myfile.rs
git diff --staged --stat  # Check again after adding
git commit -m "fix: something"
```

## Handling External Feedback & Reviews

Treat feedback as input, not instruction. Validate every claim before acting.

1. **Check against established principles first.** Before applying any fix — whether from a reviewer, from your own analysis, or from a pragmatic shortcut — ask: "Does this change violate a design principle we already settled?" If yes, the change is wrong regardless of how reasonable it sounds. Fix the surrounding code to uphold the principle; never weaken the principle to match the surrounding code.

2. **Use git history to resolve contradictions.** When two representations disagree, run `git log -S "<term>" --oneline -- <file>` on both sides to determine which text is newer. The newer commit represents the more recent design decision. Always upgrade stale text to match the newer decision, never the reverse.

3. **Verify the factual claim.** Read the text being criticized. Is the characterization accurate? Quote the actual text. If the reviewer misread or mischaracterized the code/doc, say so and reject the finding.

4. **Independently assess severity.** Do not accept a reviewer's severity rating at face value. Assign your own and state it if it differs.

5. **Distinguish bugs from preferences.** A factual contradiction or invariant violation is a bug — fix it. "The code could be cleaner" is a preference — evaluate against the cost of the change.

6. **Reject or downgrade with justification.** If a finding is invalid, reject it explicitly and state the reason. Do not implement changes just because someone flagged something.

7. **Check for cascade inconsistencies.** When fixing a confirmed finding, search for the same pattern in other files. Fix all occurrences in one pass — but only where the same error actually exists.

## Common Pitfalls (avoid)

- PID segment validation: a PID segment must be an all-ASCII-digit sequence, `self`, or `thread-self`. Any other shape is not a magic-path PID; do not treat it as one.
- Over-canonicalizing: only preserve the namespace prefix; let `std` handle path resolution inside the namespace.
- Dropping error context: do not return a bare `io::Error` without meaningful context.

## PR Checklist (agent self-check)

- Normal path behavior unchanged and equal to `std::fs::canonicalize`.
- Namespace boundary preservation working correctly.
- All CI steps pass locally (`bash ci-local.sh` or `.\ci-local.ps1`).
- New/changed logic covered by tests (unit, integration, or doctests if public behavior changed).
- Docs updated (README/lib.rs) if user-visible behavior changed.
- No new runtime dependencies; MSRV respected; no unstable features.

## Test Counting

We track test count as the sum of:
- Number of `#[test]` items found under `src/` and `tests/` folders
- Plus the number of Rust doc tests

**Important**: Doc tests must be runnable. Do not use `no_run`, `ignore`, `should_panic`, or other attributes that prevent execution. All doc tests must compile and run successfully as part of `cargo test`.

Commands to count tests:

**PowerShell (Windows):**
```powershell
# Count #[test] in src/ and tests/
$unit = (Get-ChildItem -Recurse -Path src, tests -Include *.rs | Select-String -Pattern '#\s*\[\s*test\s*\]')
$unit.Count

# Count doc tests
(cargo test --doc -- --list | Select-String -Pattern '^test ').Count
```

**Bash (Linux/macOS/WSL):**
```bash
# Count #[test] in src/ and tests/
grep -REo '#[[:space:]]*\[[[:space:]]*test[[:space:]]*\]' src tests | wc -l

# Count doc tests
cargo test --doc -- --list | grep '^test ' | wc -l
```

When documenting test count, use the sum of both numbers.

## Quick Commands

- Run all local CI: `bash ci-local.sh` or `.\ci-local.ps1`
- Tests (verbose): `cargo test --verbose`
- Tests on Linux (WSL): `wsl -e bash -ilc "cd /mnt/c/path/to/repo && cargo test"`
- Lints: `cargo clippy --all-targets --all-features -- -D warnings`
- Docs (warnings as errors): `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`

## One-Shot Prompt for Agents

Use when spinning up an automated change:

"""
Work on proc-canonicalize. Constraints: no new runtime deps (approved optional dep: `dunce`, Windows-only, feature-gated; dev-only `tempfile` is allowed in tests); preserve exact parity with `std::fs::canonicalize` for normal paths; preserve `/proc/PID/root` and `/proc/PID/cwd` namespace boundaries; keep MSRV 1.70.0; pass `clippy -D warnings` and `rustdoc -D warnings`; run `bash ci-local.sh` or `.\ci-local.ps1` before proposing changes. Never remove tests or weaken namespace detection, PID validation, or symlink protections. Add focused tests for any behavior you touch.
"""

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
