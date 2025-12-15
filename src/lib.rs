//! # proc-canonicalize
//!
//! A patch for `std::fs::canonicalize` that preserves Linux `/proc/PID/root` and
//! `/proc/PID/cwd` namespace boundaries.
//!
//! ## The Problem
//!
//! On Linux, `/proc/PID/root` is a "magic symlink" that crosses into a process's
//! mount namespace. However, `std::fs::canonicalize` resolves it to `/`, losing
//! the namespace context:
//!
//! ```rust
//! # #[cfg(target_os = "linux")]
//! # fn main() -> std::io::Result<()> {
//! // The kernel resolves /proc/self/root to "/" - losing the namespace boundary!
//! let resolved = std::fs::canonicalize("/proc/self/root")?;
//! assert_eq!(resolved, std::path::PathBuf::from("/"));
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! This breaks security tools that use `/proc/PID/root` as a boundary for container
//! filesystem access, because the boundary resolves to the host root!
//!
//! ## The Fix
//!
//! This crate detects `/proc/PID/root` and `/proc/PID/cwd` prefixes and preserves them:
//!
//! ```rust
//! # #[cfg(target_os = "linux")]
//! # fn main() -> std::io::Result<()> {
//! use std::path::PathBuf;
//!
//! // The namespace boundary is preserved!
//! let resolved = proc_canonicalize::canonicalize("/proc/self/root")?;
//! assert_eq!(resolved, PathBuf::from("/proc/self/root"));
//!
//! // Paths through the boundary also preserve the prefix
//! let resolved = proc_canonicalize::canonicalize("/proc/self/root/etc")?;
//! assert!(resolved.starts_with("/proc/self/root"));
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
/// use std::path::PathBuf;
/// use proc_canonicalize::canonicalize;
///
/// // On Linux, the namespace prefix is preserved
/// let path = "/proc/self/root";
/// let canonical = canonicalize(path)?;
/// assert_eq!(canonical, PathBuf::from("/proc/self/root"));
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

/// Find a `/proc/PID/root` or `/proc/PID/cwd` namespace boundary in the path.
///
/// Returns `Some((namespace_prefix, remainder))` if found, where:
/// - `namespace_prefix` is the boundary path (e.g., `/proc/1234/root`)
/// - `remainder` is the path after the boundary (e.g., `etc/passwd`)
///
/// Returns `None` if the path doesn't contain a namespace boundary.
#[cfg(target_os = "linux")]
fn find_namespace_boundary(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut components = path.components();

    // Must start with root "/"
    if components.next() != Some(Component::RootDir) {
        return None;
    }

    // Next must be "proc"
    match components.next() {
        Some(Component::Normal(s)) if s == "proc" => {}
        _ => return None,
    }

    // Next must be a PID (digits), "self", or "thread-self"
    let pid_component = match components.next() {
        Some(Component::Normal(s)) => s,
        _ => return None,
    };

    let pid_str = pid_component.to_string_lossy();
    let is_valid_pid = pid_str == "self"
        || pid_str == "thread-self"
        || (!pid_str.is_empty() && pid_str.chars().all(|c| c.is_ascii_digit()));

    if !is_valid_pid {
        return None;
    }

    // Next component determines if it's a direct namespace or a task namespace
    let next_component = match components.next() {
        Some(Component::Normal(s)) => s,
        _ => return None,
    };

    if next_component == "root" || next_component == "cwd" {
        // /proc/PID/root or /proc/PID/cwd
        let mut prefix = PathBuf::from("/proc");
        prefix.push(pid_component);
        prefix.push(next_component);

        // Collect remaining components as the remainder
        let remainder: PathBuf = components.collect();
        Some((prefix, remainder))
    } else if next_component == "task" {
        // /proc/PID/task/TID/root or /proc/PID/task/TID/cwd

        // Next must be TID (digits)
        let tid_component = match components.next() {
            Some(Component::Normal(s)) => s,
            _ => return None,
        };

        let tid_str = tid_component.to_string_lossy();
        if tid_str.is_empty() || !tid_str.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }

        // Next must be root or cwd
        let ns_type = match components.next() {
            Some(Component::Normal(s)) if s == "root" || s == "cwd" => s,
            _ => return None,
        };

        let mut prefix = PathBuf::from("/proc");
        prefix.push(pid_component);
        prefix.push("task");
        prefix.push(tid_component);
        prefix.push(ns_type);

        // Collect remaining components as the remainder
        let remainder: PathBuf = components.collect();
        Some((prefix, remainder))
    } else {
        None
    }
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
    find_namespace_boundary(path).is_some()
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

        // Check if the path ITSELF is magic (e.g. after resolution)
        // We still check this first because we might have just resolved a symlink to a magic path
        if is_proc_magic_path(&current_path) {
            return Ok(Some(current_path));
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
        // USAGE EXAMPLES: How to use this crate for container monitoring
        // ==========================================================================

        #[test]
        fn reading_container_file_from_host() {
            // Real-world pattern: Host process reads a container's /etc/hostname
            let container_pid = std::process::id(); // In reality, this would be a container's PID
            let container_root = format!("/proc/{}/root", container_pid);
            let file_inside_container = format!("{}/etc", container_root);

            let canonical_path = canonicalize(file_inside_container).unwrap();

            // The path STAYS inside the container namespace
            assert!(canonical_path.starts_with(&container_root));
        }

        #[test]
        fn validating_path_stays_in_container() {
            // Security pattern: Verify a user-provided path doesn't escape container
            let container_pid = std::process::id();
            let container_root = format!("/proc/{}/root", container_pid);
            let user_requested_file = format!("{}/etc/passwd", container_root);

            let canonical = canonicalize(user_requested_file).unwrap();

            // Security check: canonical path must start with container_root
            let is_inside_container = canonical.starts_with(&container_root);
            assert!(is_inside_container);
        }

        #[test]
        fn proc_self_root_preserved_not_resolved_to_slash() {
            let path = "/proc/self/root";

            let our_result = canonicalize(path).unwrap();
            let std_result = std::fs::canonicalize(path).unwrap();

            // std breaks it: returns "/"
            assert_eq!(std_result, PathBuf::from("/"));

            // we fix it: preserves the namespace
            assert_eq!(our_result, PathBuf::from("/proc/self/root"));
        }

        #[test]
        fn proc_self_cwd_preserved() {
            let path = "/proc/self/cwd";

            let result = canonicalize(path).unwrap();

            assert_eq!(result, PathBuf::from("/proc/self/cwd"));
        }

        #[test]
        fn explicit_pid_root_preserved() {
            let my_pid = std::process::id();
            let path = format!("/proc/{}/root", my_pid);

            let our_result = canonicalize(&path).unwrap();
            let std_result = std::fs::canonicalize(&path).unwrap();

            assert_eq!(std_result, PathBuf::from("/"));
            assert_eq!(our_result, PathBuf::from(&path));
        }

        #[test]
        fn subpath_through_namespace_preserves_prefix() {
            let path = "/proc/self/root/etc";

            let result = canonicalize(path).unwrap();

            assert!(result.starts_with("/proc/self/root"));
            assert!(result.ends_with("etc"));
        }

        #[test]
        fn normal_paths_behave_like_std() {
            let path = std::env::temp_dir();

            let our_result = canonicalize(&path).unwrap();
            let std_result = std::fs::canonicalize(&path).unwrap();

            assert_eq!(our_result, std_result);
        }

        // ==========================================================================
        // ERROR CASES: What happens with invalid input
        // ==========================================================================

        #[test]
        fn nonexistent_file_returns_not_found() {
            let path = "/proc/self/root/this_file_does_not_exist_12345";

            let result = canonicalize(path);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn nonexistent_pid_returns_not_found() {
            let path = "/proc/4294967295/root"; // PID that doesn't exist

            let result = canonicalize(path);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn empty_path_returns_error() {
            let result = canonicalize("");

            assert!(result.is_err());
        }

        // ==========================================================================
        // PATH NORMALIZATION: Dots and parent references
        // ==========================================================================

        #[test]
        fn dotdot_stays_inside_root_namespace() {
            let path = "/proc/self/root/tmp/../etc";

            let result = canonicalize(path);

            if let Ok(canonical) = result {
                assert!(canonical.starts_with("/proc/self/root"));
            }
        }

        #[test]
        fn dot_is_normalized_out() {
            let path = "/proc/self/root/./etc";

            let result = canonicalize(path);

            if let Ok(canonical) = result {
                assert!(canonical.starts_with("/proc/self/root"));
                assert!(!canonical.to_string_lossy().contains("/./"));
            }
        }

        #[test]
        fn deep_path_preserves_namespace() {
            let path = "/proc/self/root/usr/share/doc";

            let result = canonicalize(path);

            if let Ok(canonical) = result {
                assert!(canonical.starts_with("/proc/self/root"));
            }
        }

        #[test]
        fn trailing_slash_works() {
            let with_slash = canonicalize("/proc/self/root/");
            let without_slash = canonicalize("/proc/self/root");

            if let (Ok(a), Ok(b)) = (with_slash, without_slash) {
                assert!(a.starts_with("/proc/self/root"));
                assert!(b.starts_with("/proc/self/root"));
            }
        }

        #[test]
        fn thread_self_root_preserved() {
            let path = "/proc/thread-self/root";

            if let Ok(result) = canonicalize(path) {
                assert_eq!(result, PathBuf::from("/proc/thread-self/root"));
            }
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
        // ACCESSING OTHER PROCESSES (requires permissions)
        // ==========================================================================

        #[test]
        fn pid_1_root_requires_permission_or_preserves_prefix() {
            let path = "/proc/1/root";

            match canonicalize(path) {
                Ok(result) => {
                    // If accessible, prefix must be preserved
                    assert_eq!(result, PathBuf::from("/proc/1/root"));
                    // And std would have broken it
                    assert_eq!(std::fs::canonicalize(path).unwrap(), PathBuf::from("/"));
                }
                Err(e) => {
                    // Permission denied or not found is acceptable
                    assert!(matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                    ));
                }
            }
        }

        #[test]
        fn pid_1_subpath_preserves_prefix_when_accessible() {
            let path = "/proc/1/root/etc/hostname";

            match canonicalize(path) {
                Ok(result) => {
                    assert!(
                        result.starts_with("/proc/1/root"),
                        "must preserve /proc/1/root prefix, got: {:?}",
                        result
                    );
                }
                Err(e) => {
                    assert!(matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                    ));
                }
            }
        }

        #[test]
        fn pid_1_cwd_preserves_prefix_when_accessible() {
            let path = "/proc/1/cwd";

            match canonicalize(path) {
                Ok(result) => assert_eq!(result, PathBuf::from("/proc/1/cwd")),
                Err(e) => {
                    assert!(matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                    ));
                }
            }
        }

        #[test]
        fn self_and_explicit_pid_both_work() {
            let my_pid = std::process::id();

            let self_result = canonicalize("/proc/self/root").unwrap();
            let pid_result = canonicalize(format!("/proc/{}/root", my_pid)).unwrap();

            assert_eq!(self_result, PathBuf::from("/proc/self/root"));
            assert_eq!(pid_result, PathBuf::from(format!("/proc/{}/root", my_pid)));
        }

        // ==========================================================================
        // INDIRECT SYMLINKS: Symlinks outside /proc pointing TO /proc magic paths
        // ==========================================================================

        mod indirect_symlink_tests {
            use super::*;
            use std::os::unix::fs::symlink;

            #[test]
            fn symlink_to_proc_self_root_preserves_namespace() {
                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("link");

                symlink("/proc/self/root", &link).unwrap();

                let result = canonicalize(&link).unwrap();

                assert_ne!(result, PathBuf::from("/")); // NOT the broken behavior
                assert_eq!(result, PathBuf::from("/proc/self/root"));
            }

            #[test]
            fn symlink_then_subpath_preserves_namespace() {
                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("container");

                symlink("/proc/self/root", &link).unwrap();

                let result = canonicalize(link.join("etc")).unwrap();

                assert!(result.starts_with("/proc/self/root"));
            }

            #[test]
            fn chained_symlinks_all_followed() {
                let temp = tempfile::tempdir().unwrap();
                let link1 = temp.path().join("link1");
                let link2 = temp.path().join("link2");

                symlink("/proc/self/root", &link2).unwrap();
                symlink(&link2, &link1).unwrap();

                let result = canonicalize(&link1).unwrap();

                assert_eq!(result, PathBuf::from("/proc/self/root"));
            }

            #[test]
            fn symlink_to_explicit_pid_root_preserved() {
                let my_pid = std::process::id();
                let target = format!("/proc/{}/root", my_pid);
                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("link");

                symlink(&target, &link).unwrap();

                let result = canonicalize(&link).unwrap();

                assert_ne!(result, PathBuf::from("/"));
                assert_eq!(result, PathBuf::from(&target));
            }

            #[test]
            fn symlink_to_cwd_preserved() {
                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("link");

                symlink("/proc/self/cwd", &link).unwrap();

                let result = canonicalize(&link).unwrap();

                assert!(result.starts_with("/proc/self/cwd"));
            }

            #[test]
            fn normal_symlinks_work_like_std() {
                let temp = tempfile::tempdir().unwrap();
                let target = temp.path().join("target");
                let link = temp.path().join("link");

                std::fs::create_dir(&target).unwrap();
                symlink(&target, &link).unwrap();

                let our_result = canonicalize(&link).unwrap();
                let std_result = std::fs::canonicalize(&link).unwrap();

                assert_eq!(our_result, std_result);
            }

            #[test]
            fn symlink_loop_returns_error_not_hang() {
                let temp = tempfile::tempdir().unwrap();
                let link_a = temp.path().join("a");
                let link_b = temp.path().join("b");

                symlink(&link_b, &link_a).unwrap();
                symlink(&link_a, &link_b).unwrap();

                let result = canonicalize(&link_a);

                assert!(result.is_err());
            }

            #[test]
            fn symlink_to_thread_self_root_preserved() {
                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("thread_link");

                symlink("/proc/thread-self/root", &link).unwrap();

                // thread-self might not exist on all systems
                if let Ok(result) = canonicalize(&link) {
                    assert!(result.starts_with("/proc/thread-self/root"));
                }
            }
        }

        // ==========================================================================
        // SECURITY EDGE CASES
        // ==========================================================================

        mod security_tests {
            use super::*;

            #[test]
            fn excessive_dotdot_cannot_escape_root_namespace() {
                let path = "/proc/self/root/../../../../../../../etc/passwd";

                if let Ok(result) = canonicalize(path) {
                    assert!(result.starts_with("/proc/self/root"));
                }
            }

            #[test]
            fn idempotent_canonicalization() {
                let paths = ["/proc/self/root", "/proc/self/root/etc", "/proc/self/cwd"];

                for path in &paths {
                    if let Ok(first) = canonicalize(path) {
                        if let Ok(second) = canonicalize(&first) {
                            assert_eq!(first, second);
                        }
                    }
                }
            }

            #[test]
            fn uppercase_proc_not_magic() {
                let result = canonicalize("/PROC/self/root");

                match result {
                    Ok(path) => assert!(!path.starts_with("/proc/")),
                    Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
                }
            }

            #[test]
            fn double_slashes_normalized() {
                if let Ok(normal) = canonicalize("/proc/self/root") {
                    if let Ok(doubled) = canonicalize("//proc//self//root") {
                        assert_eq!(normal, doubled);
                    }
                }
            }

            #[test]
            fn relative_proc_path_not_magic() {
                // "proc/self/root" (no leading /) is relative, not magic
                let _ = canonicalize("proc/self/root"); // Just shouldn't panic
            }

            #[test]
            fn missing_pid_not_namespace() {
                let result = find_namespace_boundary(Path::new("/proc/root"));
                assert!(result.is_none());
            }

            #[test]
            fn invalid_special_names_not_namespace() {
                for name in &["parent", "init", "current", "me"] {
                    let path = format!("/proc/{}/root", name);
                    assert!(find_namespace_boundary(Path::new(&path)).is_none());
                }
            }

            #[test]
            fn long_numeric_pid_accepted() {
                let long_pid = "9".repeat(100);
                let path = format!("/proc/{}/root", long_pid);
                assert!(find_namespace_boundary(Path::new(&path)).is_some());
            }

            #[test]
            fn pid_zero_syntactically_valid() {
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

            #[test]
            fn symlink_to_deep_proc_path_preserves_prefix() {
                use std::os::unix::fs::symlink;

                let temp = tempfile::tempdir().unwrap();
                let link = temp.path().join("link");

                symlink("/proc/self/root/etc", &link).unwrap();

                if let Ok(result) = canonicalize(&link) {
                    assert!(result.starts_with("/proc/self/root"));
                }
            }

            #[test]
            fn relative_symlink_looking_like_proc_not_magic() {
                use std::os::unix::fs::symlink;

                let temp = tempfile::tempdir().unwrap();
                let fake_proc = temp.path().join("proc/self/root");
                std::fs::create_dir_all(fake_proc).unwrap();

                let link = temp.path().join("link");
                symlink("proc/self/root", &link).unwrap();

                let result = canonicalize(&link).unwrap();

                assert!(!result.starts_with("/proc/self/root"));
                assert!(result.starts_with(temp.path()));
            }

            #[test]
            fn relative_symlink_escape_behaves_like_std() {
                // Normal symlink (not to /proc) that attempts path traversal escape
                // Must behave exactly like std::fs::canonicalize
                use std::os::unix::fs::symlink;

                let temp = tempfile::tempdir().unwrap();
                let subdir = temp.path().join("subdir");
                std::fs::create_dir(&subdir).unwrap();

                let escape_link = subdir.join("escape");
                symlink("../../../../../../etc", &escape_link).unwrap();

                let our_result = canonicalize(&escape_link);
                let std_result = std::fs::canonicalize(&escape_link);

                match (our_result, std_result) {
                    (Ok(ours), Ok(stds)) => assert_eq!(ours, stds),
                    (Err(_), Err(_)) => {} // Both error is fine
                    _ => panic!("Behavior should match std"),
                }
            }
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
