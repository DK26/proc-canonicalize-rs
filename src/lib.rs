//! # proc-canonicalize
//!
//! A patch for `std::fs::canonicalize` that preserves Linux `/proc/PID/root` and
//! `/proc/PID/cwd` namespace boundaries.
//!
//! ## The Problem
//!
//! On Linux, `/proc/PID/root` is a "magic symlink" that crosses into a process's
//! mount namespace. However, `std::fs::canonicalize` resolves it to `/`, breaking
//! security boundaries. This crate preserves the `/proc/PID/root` and `/proc/PID/cwd`
//! prefixes:
//!
//! ```rust
//! # #[cfg(target_os = "linux")]
//! # fn main() -> std::io::Result<()> {
//! use std::path::Path;
//!
//! // BROKEN: std::fs::canonicalize loses the namespace prefix!
//! let std_resolved = std::fs::canonicalize("/proc/self/root/etc")?;
//! assert_eq!(std_resolved, Path::new("/etc"));  // Resolves to host's /etc!
//!
//! // FIXED: Namespace prefix is preserved!
//! let resolved = proc_canonicalize::canonicalize("/proc/self/root/etc")?;
//! assert_eq!(resolved, Path::new("/proc/self/root/etc"));
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! ## Platform Support
//!
//! - **Linux**: Full functionality - preserves `/proc/PID/root` and `/proc/PID/cwd`
//! - **Other platforms**: Falls back to `std::fs::canonicalize` (no-op)
//!
//! ## Zero Dependencies
//!
//! This crate has no dependencies beyond the Rust standard library.
//!
//! ## Optional Features
//!
//! - `dunce` (Windows only): Simplifies Windows extended-length paths by removing the `\\?\` prefix
//!   when possible (e.g., `\\?\C:\foo` becomes `C:\foo`). Automatically preserves the prefix when
//!   needed (e.g., for paths longer than 260 characters). Enable with `features = ["dunce"]`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::path::Component;

/// Maximum number of symlinks to follow before giving up (matches kernel MAXSYMLINKS).
#[cfg(target_os = "linux")]
const MAX_SYMLINK_FOLLOWS: u32 = 40;

/// Canonicalize a path, preserving Linux `/proc/PID/root` and `/proc/PID/cwd` boundaries.
///
/// This function behaves like [`std::fs::canonicalize`], except that on Linux it
/// detects and preserves namespace boundary prefixes:
/// - `/proc/PID/root`, `/proc/PID/cwd`
/// - `/proc/PID/task/TID/root`, `/proc/PID/task/TID/cwd`
/// - `/proc/self/root`, `/proc/self/cwd`
/// - `/proc/thread-self/root`, `/proc/thread-self/cwd`
///
/// # Examples
///
/// ```rust
/// # #[cfg(target_os = "linux")]
/// # fn main() -> std::io::Result<()> {
/// use std::path::Path;
/// use proc_canonicalize::canonicalize;
///
/// // On Linux, the namespace prefix is preserved
/// let path = "/proc/self/root";
/// let canonical = canonicalize(path)?;
/// assert_eq!(canonical, Path::new("/proc/self/root"));
/// # Ok(())
/// # }
/// # #[cfg(not(target_os = "linux"))]
/// # fn main() {}
/// ```
///
/// # Why This Matters
///
/// `std::fs::canonicalize("/proc/1234/root")` returns `/` because the kernel's
/// `readlink()` on that magic symlink returns `/`. This breaks security boundaries
/// for container tooling that needs to access container filesystems via `/proc/PID/root`.
///
/// # Platform Behavior
///
/// - **Linux**: Preserves `/proc/PID/root` and `/proc/PID/cwd` prefixes
/// - **Other platforms**: Identical to `std::fs::canonicalize`
///
/// # Errors
///
/// Returns an error if:
/// - The path does not exist
/// - The process lacks permission to access the path
/// - An I/O error occurs during resolution
pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    canonicalize_impl(path.as_ref())
}

#[cfg(target_os = "linux")]
fn canonicalize_impl(path: &Path) -> io::Result<PathBuf> {
    // Check if path contains a /proc namespace boundary
    if let Some((namespace_prefix, remainder)) = find_namespace_boundary(path) {
        // Verify the namespace prefix exists and is accessible
        // We use metadata() to check existence and permissions, which gives better error messages
        // than exists() (e.g. PermissionDenied vs NotFound)
        std::fs::metadata(&namespace_prefix)?;

        if remainder.as_os_str().is_empty() {
            // Path IS the namespace boundary (e.g., "/proc/1234/root")
            Ok(namespace_prefix)
        } else {
            // Path goes through namespace boundary (e.g., "/proc/1234/root/etc/passwd")

            // 1. Resolve the namespace prefix to its absolute path on the host.
            // This is necessary because /proc/PID/root might not be "/" (e.g. in containers),
            // and /proc/PID/cwd is almost certainly not "/".
            let resolved_prefix = std::fs::canonicalize(&namespace_prefix)?;

            // 2. Canonicalize the full path.
            // This traverses the magic link and resolves everything.
            let full_path = namespace_prefix.join(&remainder);
            let canonicalized = std::fs::canonicalize(full_path)?;

            // 3. Try to re-base the canonicalized path onto the namespace prefix.
            // We do this by stripping the resolved prefix from the canonicalized path.
            if let Ok(suffix) = canonicalized.strip_prefix(&resolved_prefix) {
                // The path is within the namespace. Re-attach the prefix.
                Ok(namespace_prefix.join(suffix))
            } else {
                // The path escaped the namespace (e.g. via ".." or symlinks to outside).
                // In this case, we cannot preserve the prefix while being correct.
                // We return the fully resolved path (absolute path on host).
                Ok(canonicalized)
            }
        }
    } else {
        // Check for indirect symlinks to /proc magic paths BEFORE calling std::fs::canonicalize.
        //
        // This handles cases like:
        //   symlink("/proc/self/root", "/tmp/container_link")
        //   canonicalize("/tmp/container_link")        -> should return /proc/self/root, not /
        //   canonicalize("/tmp/container_link/etc")    -> should return /proc/self/root/etc, not /etc
        //
        // We detect symlinks in the path that point to /proc magic paths and handle them
        // the same way we handle direct /proc paths.
        if let Some(magic_path) = detect_indirect_proc_magic_link(path)? {
            // Found an indirect symlink to a /proc magic path
            // Use our namespace-aware canonicalization on the reconstructed path
            return canonicalize_impl(&magic_path);
        }

        // Normal path - use std::fs::canonicalize directly
        std::fs::canonicalize(path)
    }
}

#[cfg(not(target_os = "linux"))]
fn canonicalize_impl(path: &Path) -> io::Result<PathBuf> {
    // On non-Linux platforms, just use std::fs::canonicalize
    #[cfg(all(feature = "dunce", windows))]
    {
        dunce::canonicalize(path)
    }
    #[cfg(not(all(feature = "dunce", windows)))]
    {
        std::fs::canonicalize(path)
    }
}

/// Count the leading components that form a `/proc` namespace-boundary prefix.
///
/// Returns `Some(4)` for `/proc/PID/{root,cwd}` shapes, `Some(6)` for
/// `/proc/PID/task/TID/{root,cwd}` shapes, and `None` if the path does not
/// begin with a valid namespace prefix. Allocation-free — used on every
/// ancestor-walk iteration in the indirect-symlink scanner, where building
/// transient `PathBuf`s just to discard them would dominate allocator cost.
#[cfg(target_os = "linux")]
fn namespace_prefix_len(path: &Path) -> Option<usize> {
    let mut components = path.components();

    if components.next()? != Component::RootDir {
        return None;
    }
    match components.next()? {
        Component::Normal(s) if s == "proc" => {}
        _ => return None,
    }

    let pid = match components.next()? {
        Component::Normal(s) => s,
        _ => return None,
    };
    if !is_valid_pid_segment(pid) {
        return None;
    }

    let next = match components.next()? {
        Component::Normal(s) => s,
        _ => return None,
    };
    if next == "root" || next == "cwd" {
        return Some(4);
    }
    if next != "task" {
        return None;
    }

    let tid = match components.next()? {
        Component::Normal(s) => s,
        _ => return None,
    };
    if !is_numeric_segment(tid) {
        return None;
    }

    match components.next()? {
        Component::Normal(s) if s == "root" || s == "cwd" => Some(6),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn is_valid_pid_segment(s: &std::ffi::OsStr) -> bool {
    // to_str() returns a borrowed &str without allocating; to_string_lossy()
    // would allocate a replacement String when the OsStr is not valid UTF-8.
    match s.to_str() {
        Some("self") | Some("thread-self") => true,
        Some(s) => is_nonempty_ascii_digits(s),
        None => false,
    }
}

#[cfg(target_os = "linux")]
fn is_numeric_segment(s: &std::ffi::OsStr) -> bool {
    match s.to_str() {
        Some(s) => is_nonempty_ascii_digits(s),
        None => false,
    }
}

#[cfg(target_os = "linux")]
fn is_nonempty_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Find a `/proc/PID/root` or `/proc/PID/cwd` namespace boundary in the path.
///
/// Returns `Some((namespace_prefix, remainder))` if found, where:
/// - `namespace_prefix` is the boundary path (e.g., `/proc/1234/root`)
/// - `remainder` is the path after the boundary (e.g., `etc/passwd`)
///
/// Returns `None` if the path doesn't contain a namespace boundary.
#[cfg(target_os = "linux")]
fn find_namespace_boundary(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let prefix_len = namespace_prefix_len(path)?;

    let mut components = path.components();
    let mut prefix = PathBuf::with_capacity(path.as_os_str().len());
    for _ in 0..prefix_len {
        prefix.push(components.next()?.as_os_str());
    }
    let remainder: PathBuf = components.collect();
    Some((prefix, remainder))
}

/// Check if a path is a `/proc` magic path (`/proc/{pid}/root` or `/proc/{pid}/cwd`).
///
/// This checks whether the path matches patterns like:
/// - `/proc/self/root`, `/proc/self/cwd`
/// - `/proc/thread-self/root`, `/proc/thread-self/cwd`
/// - `/proc/{numeric_pid}/root`, `/proc/{numeric_pid}/cwd`
///
/// The path may have additional components after the magic suffix (e.g., `/proc/self/root/etc`).
#[cfg(target_os = "linux")]
fn is_proc_magic_path(path: &Path) -> bool {
    namespace_prefix_len(path).is_some()
}

/// Lexically normalize `.` and `..` components in a path without consulting the filesystem.
///
/// This is purely symbolic — it does NOT follow symlinks. `..` at root is a no-op.
///
/// Used to catch namespace-boundary bypasses where `..` in the prefix defeats
/// lexical matching in [`find_namespace_boundary`], e.g. `/proc/<PID>/../<PID>/root`
/// lexically normalizes to `/proc/<PID>/root`.
#[cfg(target_os = "linux")]
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => result.push(component.as_os_str()),
            Component::Normal(name) => result.push(name),
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            Component::Prefix(_) => unreachable!("Linux paths don't have prefixes"),
        }
    }
    result
}

/// Detect if a path contains an indirect symlink to a `/proc` magic path.
///
/// This walks the ancestor chain of the input path looking for symlinks that
/// point to `/proc/.../root` or `/proc/.../cwd`.
///
/// Returns `Some(magic_path)` with any remaining suffix if found, or `None` otherwise.
#[cfg(target_os = "linux")]
fn detect_indirect_proc_magic_link(path: &Path) -> io::Result<Option<PathBuf>> {
    let mut current_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut iterations = 0;

    // We restart the scan whenever we resolve a symlink
    'scan: loop {
        if iterations >= MAX_SYMLINK_FOLLOWS {
            return Ok(None);
        }

        // We CANNOT blindly normalize_path() here because if we have "symlink/..",
        // normalize_path() will remove "symlink" and "..", completely missing the fact
        // that "symlink" might point to a magic path.
        //
        // Instead, we must walk the components one by one. If we hit a symlink, we resolve it.
        // If we hit "..", we pop from our accumulated path.

        // Check if the path's lexical normalization is magic. This catches two
        // distinct bypasses that plain `is_proc_magic_path(&current_path)` misses:
        //
        // 1. `..` in the PREFIX:  /proc/<PID>/../<PID>/root lexically normalizes
        //    to /proc/<PID>/root. Without this check, the component walk below
        //    reaches /proc/<PID>/root after the `..` pop, sees it is a symlink,
        //    and follows it via `read_link` — which returns "/", dropping the
        //    namespace boundary entirely.
        //
        // 2. `..` in the REMAINDER that lands back on a boundary: after resolving
        //    an indirect symlink to /proc/<PID>, a path like .../cwd/../root has
        //    current_path = /proc/<PID>/cwd/../root, which matches the cwd branch
        //    with remainder `../root`. Returning it as-is sends the caller down
        //    the host-resolution path in canonicalize_impl, which loses the
        //    boundary. Lexical normalization gives /proc/<PID>/root directly.
        let normalized = lexical_normalize(&current_path);
        if is_proc_magic_path(&normalized) {
            return Ok(Some(normalized));
        }

        let mut accumulated = PathBuf::new();
        let mut components = current_path.components().peekable();

        if let Some(Component::RootDir) = components.peek() {
            accumulated.push("/");
            components.next();
        }

        while let Some(component) = components.next() {
            match component {
                Component::RootDir => {
                    accumulated.push("/");
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    accumulated.pop();
                    // After popping, we might be at a magic path (e.g. /proc/self/root/etc/..)
                    if is_proc_magic_path(&accumulated) {
                        // Reconstruct full path from here to preserve the magic prefix
                        let remainder: PathBuf = components.collect();
                        return Ok(Some(accumulated.join(remainder)));
                    }
                }
                Component::Normal(name) => {
                    let next_path = accumulated.join(name);

                    // Check symlink
                    let metadata = match std::fs::symlink_metadata(&next_path) {
                        Ok(m) => m,
                        Err(_) => {
                            accumulated.push(name);
                            continue;
                        }
                    };

                    if metadata.is_symlink() {
                        // Found symlink!
                        iterations += 1;
                        let target = std::fs::read_link(&next_path)?;

                        // Construct new path: accumulated (parent) + target + remainder
                        let parent = next_path.parent().unwrap_or(Path::new("/"));
                        let remainder: PathBuf = components.collect();

                        let resolved = if target.is_relative() {
                            parent.join(target)
                        } else {
                            target
                        };

                        current_path = resolved.join(remainder);
                        continue 'scan; // Restart scan from root of new path
                    }

                    accumulated.push(name);
                }
                Component::Prefix(_) => unreachable!("Linux paths don't have prefixes"),
            }
        }

        // If we reached here, we scanned the whole path and found no symlinks (or no more symlinks).
        // And it wasn't magic (checked at start of loop).
        // One final check on the accumulated path (which is effectively normalized now)
        if is_proc_magic_path(&accumulated) {
            return Ok(Some(accumulated));
        }

        return Ok(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        // ==========================================================================
        // NAMESPACE BOUNDARY DETECTION (find_namespace_boundary)
        // These tests verify the lexical pattern matching that identifies
        // /proc/PID/root and /proc/PID/cwd as namespace boundaries.
        // ==========================================================================

        #[test]
        fn test_find_namespace_boundary_proc_pid_root() {
            // Standard pattern: /proc/<numeric_pid>/root
            // Used by container runtimes to access container filesystems from host
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root/etc/passwd")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            assert_eq!(remainder, PathBuf::from("etc/passwd"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_pid_cwd() {
            // Pattern: /proc/<pid>/cwd - the process's current working directory
            // Less common but equally needs protection
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/5678/cwd/some/file.txt")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/5678/cwd"));
            assert_eq!(remainder, PathBuf::from("some/file.txt"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_self_root() {
            // /proc/self/root - own process's root, resolves to "/" on host
            // Common in self-referential container tooling
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/self/root/etc/passwd")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/self/root"));
            assert_eq!(remainder, PathBuf::from("etc/passwd"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_thread_self_root() {
            // /proc/thread-self/root - per-thread namespace, less common
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/thread-self/root/app/config")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/thread-self/root"));
            assert_eq!(remainder, PathBuf::from("app/config"));
        }

        #[test]
        fn test_find_namespace_boundary_just_prefix_no_remainder() {
            // Accessing just the magic path itself, no subpath
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            assert_eq!(remainder, PathBuf::from(""));
        }

        #[test]
        fn test_find_namespace_boundary_normal_path_returns_none() {
            // Regular paths should NOT match - no namespace treatment needed
            assert!(find_namespace_boundary(Path::new("/home/user/file.txt")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_proc_other_files_not_namespace() {
            // SECURITY: /proc/PID/status, /proc/PID/exe, /proc/PID/fd are NOT namespaces
            // Only "root" and "cwd" are magic symlinks that cross namespace boundaries
            assert!(find_namespace_boundary(Path::new("/proc/1234/status")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/1234/exe")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/1234/fd/0")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_relative_path_rejected() {
            // SECURITY: Only absolute paths can be namespace boundaries
            // "proc/1234/root" without leading "/" is relative, not /proc
            assert!(find_namespace_boundary(Path::new("proc/1234/root")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_invalid_pid_rejected() {
            // SECURITY: PID must be numeric, "self", or "thread-self"
            // Arbitrary strings like "abc" must not match
            assert!(find_namespace_boundary(Path::new("/proc/abc/root")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/123abc/root")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc//root")).is_none());
        }

        // ==========================================================================
        // EDGE CASES FOR BOUNDARY DETECTION
        // ==========================================================================

        #[test]
        fn boundary_detection_handles_trailing_slash() {
            let (prefix, _remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root/")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
        }

        #[test]
        fn boundary_detection_handles_dot_components() {
            let (prefix, _remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root/./etc/../etc")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
        }

        // ==========================================================================
        // PID/TID SEGMENT VALIDATION (private API)
        // Public-API behavior tests live in tests/public_api.rs.
        // ==========================================================================

        #[test]
        fn missing_pid_not_namespace() {
            assert!(find_namespace_boundary(Path::new("/proc/root")).is_none());
        }

        #[test]
        fn invalid_special_names_not_namespace() {
            for name in &["parent", "init", "current", "me"] {
                let path = format!("/proc/{name}/root");
                assert!(find_namespace_boundary(Path::new(&path)).is_none());
            }
        }

        #[test]
        fn long_numeric_pid_accepted() {
            let long_pid = "9".repeat(100);
            let path = format!("/proc/{long_pid}/root");
            assert!(find_namespace_boundary(Path::new(&path)).is_some());
        }

        #[test]
        fn pid_zero_syntactically_valid_but_nonexistent() {
            assert!(find_namespace_boundary(Path::new("/proc/0/root")).is_some());
            assert!(canonicalize("/proc/0/root").is_err()); // But doesn't exist
        }

        #[test]
        fn negative_pid_not_valid() {
            assert!(find_namespace_boundary(Path::new("/proc/-1/root")).is_none());
        }

        #[test]
        fn leading_zeros_in_pid_accepted() {
            assert!(find_namespace_boundary(Path::new("/proc/0001234/root")).is_some());
        }
    }

    #[cfg(not(target_os = "linux"))]
    mod non_linux {
        use super::*;

        #[test]
        fn test_canonicalize_is_std_on_non_linux() {
            // On non-Linux, we just wrap std::fs::canonicalize
            let tmp = std::env::temp_dir();
            let our_result = canonicalize(&tmp).expect("should succeed");
            let std_result = std::fs::canonicalize(&tmp).expect("should succeed");
            // With dunce feature on Windows, our result is simplified but std returns UNC
            #[cfg(all(feature = "dunce", windows))]
            {
                let our_str = our_result.to_string_lossy();
                let std_str = std_result.to_string_lossy();
                // dunce should simplify the path
                assert!(!our_str.starts_with(r"\\?\"), "dunce should simplify path");
                assert!(std_str.starts_with(r"\\?\"), "std returns UNC format");
                // They should match except for the UNC prefix
                assert_eq!(our_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
            }
            // Without dunce (or on non-Windows), they should match exactly
            #[cfg(not(all(feature = "dunce", windows)))]
            {
                assert_eq!(our_result, std_result);
            }
        }
    }
}
