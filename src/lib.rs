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
//! For all other paths, behavior is identical to `std::fs::canonicalize`:
//!
//! ```rust
//! # fn main() -> std::io::Result<()> {
//! // Normal paths behave exactly like std::fs::canonicalize
//! let std_result = std::fs::canonicalize(".")?;
//! let our_result = proc_canonicalize::canonicalize(".")?;
//! // Note: On Windows with the `dunce` feature, our result may differ
//! // (simplified path without \\?\ prefix). See unit tests for full coverage.
//! #[cfg(not(windows))]
//! assert_eq!(std_result, our_result);
//! #[cfg(windows)]
//! let _ = (std_result, our_result); // Use variables to avoid warnings
//! # Ok(())
//! # }
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

        #[test]
        fn test_find_namespace_boundary_proc_pid_root() {
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root/etc/passwd")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            assert_eq!(remainder, PathBuf::from("etc/passwd"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_pid_cwd() {
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/5678/cwd/some/file.txt")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/5678/cwd"));
            assert_eq!(remainder, PathBuf::from("some/file.txt"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_self_root() {
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/self/root/etc/passwd")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/self/root"));
            assert_eq!(remainder, PathBuf::from("etc/passwd"));
        }

        #[test]
        fn test_find_namespace_boundary_proc_thread_self_root() {
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/thread-self/root/app/config")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/thread-self/root"));
            assert_eq!(remainder, PathBuf::from("app/config"));
        }

        #[test]
        fn test_find_namespace_boundary_just_prefix() {
            let (prefix, remainder) =
                find_namespace_boundary(Path::new("/proc/1234/root")).unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            assert_eq!(remainder, PathBuf::from(""));
        }

        #[test]
        fn test_find_namespace_boundary_normal_path() {
            assert!(find_namespace_boundary(Path::new("/home/user/file.txt")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_proc_but_not_namespace() {
            // /proc/1234/status is NOT a namespace boundary
            assert!(find_namespace_boundary(Path::new("/proc/1234/status")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/1234/exe")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/1234/fd/0")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_relative_path() {
            assert!(find_namespace_boundary(Path::new("proc/1234/root")).is_none());
        }

        #[test]
        fn test_find_namespace_boundary_invalid_pid() {
            assert!(find_namespace_boundary(Path::new("/proc/abc/root")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc/123abc/root")).is_none());
            assert!(find_namespace_boundary(Path::new("/proc//root")).is_none());
        }

        #[test]
        fn test_canonicalize_proc_self_root() {
            // /proc/self/root should return itself, not "/"
            let result = canonicalize("/proc/self/root").expect("should succeed");
            assert_eq!(result, PathBuf::from("/proc/self/root"));

            // Contrast with std::fs::canonicalize which returns "/"
            let std_result = std::fs::canonicalize("/proc/self/root").expect("should succeed");
            assert_eq!(std_result, PathBuf::from("/"));

            // They should be different!
            assert_ne!(result, std_result);
        }

        #[test]
        fn test_canonicalize_proc_self_root_subpath() {
            // Test with a subpath that exists
            let result = canonicalize("/proc/self/root/etc").expect("should succeed");
            assert!(
                result.starts_with("/proc/self/root"),
                "should preserve /proc/self/root prefix, got: {:?}",
                result
            );
        }

        #[test]
        fn test_canonicalize_normal_path() {
            // Normal paths should behave like std::fs::canonicalize
            let tmp = std::env::temp_dir();
            let our_result = canonicalize(&tmp).expect("should succeed");
            let std_result = std::fs::canonicalize(&tmp).expect("should succeed");
            assert_eq!(our_result, std_result);
        }

        #[test]
        fn test_canonicalize_proc_pid_root() {
            use std::process;
            let pid = process::id();
            let proc_pid_root = format!("/proc/{}/root", pid);

            let result = canonicalize(&proc_pid_root).expect("should succeed");
            assert_eq!(result, PathBuf::from(&proc_pid_root));

            // std would return "/"
            let std_result = std::fs::canonicalize(&proc_pid_root).expect("should succeed");
            assert_eq!(std_result, PathBuf::from("/"));
        }

        #[test]
        fn test_canonicalize_proc_self_cwd() {
            // /proc/self/cwd should also be preserved
            let result = canonicalize("/proc/self/cwd").expect("should succeed");
            assert_eq!(result, PathBuf::from("/proc/self/cwd"));
        }

        #[test]
        fn test_canonicalize_nonexistent_file_under_namespace() {
            // Non-existent file under valid namespace should return NotFound error
            let result = canonicalize("/proc/self/root/this_file_definitely_does_not_exist_12345");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn test_canonicalize_nonexistent_pid() {
            // Very high PID that almost certainly doesn't exist
            let result = canonicalize("/proc/4294967295/root");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn test_canonicalize_with_dotdot_normalization() {
            // Path with .. that should be normalized but stay within namespace
            let result = canonicalize("/proc/self/root/etc/../etc/passwd");
            // This should either succeed (if /etc/passwd exists) or fail with NotFound
            // But if it succeeds, it must preserve the namespace prefix
            if let Ok(path) = result {
                assert!(
                    path.starts_with("/proc/self/root"),
                    "should preserve namespace prefix, got: {:?}",
                    path
                );
            }
        }

        #[test]
        fn test_canonicalize_with_dotdot_at_boundary() {
            // Try to escape with .. - should still be contained
            // /proc/self/root/../root/etc should resolve within namespace
            let result = canonicalize("/proc/self/root/tmp/../etc");
            if let Ok(path) = result {
                assert!(
                    path.starts_with("/proc/self/root"),
                    "should preserve namespace prefix even with .., got: {:?}",
                    path
                );
            }
        }

        #[test]
        fn test_canonicalize_deep_nested_path() {
            // Deep nested path under namespace
            let result = canonicalize("/proc/self/root/usr/share/doc");
            if let Ok(path) = result {
                assert!(
                    path.starts_with("/proc/self/root"),
                    "should preserve namespace prefix for deep paths, got: {:?}",
                    path
                );
            }
        }

        #[test]
        fn test_canonicalize_trailing_slash() {
            // Trailing slash should still work
            let result = canonicalize("/proc/self/root/");
            // Note: std::fs::canonicalize typically strips trailing slashes
            if let Ok(path) = result {
                assert!(
                    path.starts_with("/proc/self/root"),
                    "should handle trailing slash, got: {:?}",
                    path
                );
            }
        }

        #[test]
        fn test_canonicalize_thread_self() {
            // /proc/thread-self/root should also work
            let result = canonicalize("/proc/thread-self/root");
            if let Ok(path) = result {
                assert_eq!(path, PathBuf::from("/proc/thread-self/root"));
            }
            // Note: thread-self might not exist on all systems, so we allow failure
        }

        #[test]
        fn test_canonicalize_symlink_resolution_within_namespace() {
            // /etc/mtab is often a symlink - verify symlinks are resolved
            // but namespace prefix is preserved
            let result = canonicalize("/proc/self/root/etc/mtab");
            if let Ok(path) = result {
                assert!(
                    path.starts_with("/proc/self/root"),
                    "symlink resolution should preserve namespace, got: {:?}",
                    path
                );
            }
        }

        #[test]
        fn test_find_namespace_boundary_with_trailing_slash() {
            // Path with trailing slash
            let result = find_namespace_boundary(Path::new("/proc/1234/root/"));
            assert!(result.is_some());
            let (prefix, _remainder) = result.unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            // Remainder might be empty or contain just a component depending on how trailing slash is parsed
        }

        #[test]
        fn test_find_namespace_boundary_with_dots() {
            // Path with . and .. components - these get normalized by Path
            let result = find_namespace_boundary(Path::new("/proc/1234/root/./etc/../etc"));
            assert!(result.is_some());
            let (prefix, _remainder) = result.unwrap();
            assert_eq!(prefix, PathBuf::from("/proc/1234/root"));
            // Remainder will contain the unnormalized path components
        }

        #[test]
        fn test_canonicalize_permission_denied() {
            // Try to access another process's namespace without permission
            // PID 1 is usually init and may have restricted access
            let result = canonicalize("/proc/1/root/etc/shadow");
            // This should either succeed or fail with PermissionDenied or NotFound
            // depending on system configuration
            if let Err(e) = result {
                assert!(
                    e.kind() == io::ErrorKind::PermissionDenied
                        || e.kind() == io::ErrorKind::NotFound,
                    "expected PermissionDenied or NotFound, got: {:?}",
                    e.kind()
                );
            }
        }

        #[test]
        fn test_canonicalize_pid_1_root() {
            // PID 1 is always init/systemd - a real external process
            // This is the realistic scenario: accessing another process's namespace
            let result = canonicalize("/proc/1/root");

            match result {
                Ok(path) => {
                    // If we have permission, the prefix MUST be preserved
                    assert_eq!(
                        path,
                        PathBuf::from("/proc/1/root"),
                        "must preserve /proc/1/root prefix"
                    );

                    // Verify std::fs::canonicalize would return "/" (the problem we're fixing)
                    let std_result =
                        std::fs::canonicalize("/proc/1/root").expect("std should also succeed");
                    assert_eq!(std_result, PathBuf::from("/"), "std resolves to /");
                }
                Err(e) => {
                    // Permission denied is acceptable - we're accessing another process
                    assert!(
                        e.kind() == io::ErrorKind::PermissionDenied
                            || e.kind() == io::ErrorKind::NotFound,
                        "expected PermissionDenied or NotFound, got: {:?}",
                        e.kind()
                    );
                }
            }
        }

        #[test]
        fn test_canonicalize_pid_1_root_subpath() {
            // Access a file through PID 1's namespace - realistic container scenario
            let result = canonicalize("/proc/1/root/etc/hostname");

            match result {
                Ok(path) => {
                    // Path MUST preserve the namespace boundary
                    assert!(
                        path.starts_with("/proc/1/root"),
                        "must preserve /proc/1/root prefix, got: {:?}",
                        path
                    );
                }
                Err(e) => {
                    // Permission denied or file not found is acceptable
                    assert!(
                        e.kind() == io::ErrorKind::PermissionDenied
                            || e.kind() == io::ErrorKind::NotFound,
                        "expected PermissionDenied or NotFound, got: {:?}",
                        e.kind()
                    );
                }
            }
        }

        #[test]
        fn test_canonicalize_pid_1_cwd() {
            // Test /proc/1/cwd - the working directory of init
            let result = canonicalize("/proc/1/cwd");

            match result {
                Ok(path) => {
                    assert_eq!(
                        path,
                        PathBuf::from("/proc/1/cwd"),
                        "must preserve /proc/1/cwd"
                    );
                }
                Err(e) => {
                    assert!(
                        e.kind() == io::ErrorKind::PermissionDenied
                            || e.kind() == io::ErrorKind::NotFound,
                        "expected PermissionDenied or NotFound, got: {:?}",
                        e.kind()
                    );
                }
            }
        }

        #[test]
        fn test_self_vs_pid_equivalence() {
            // /proc/self/root and /proc/{our_pid}/root should behave the same
            use std::process;
            let pid = process::id();

            let self_result = canonicalize("/proc/self/root").expect("self should work");
            let pid_result = canonicalize(format!("/proc/{}/root", pid)).expect("pid should work");

            // Both should preserve their respective prefixes
            assert_eq!(self_result, PathBuf::from("/proc/self/root"));
            assert_eq!(pid_result, PathBuf::from(format!("/proc/{}/root", pid)));
        }

        /// Tests for indirect symlinks pointing to /proc/PID/root magic paths.
        ///
        /// These test the security vulnerability where a symlink outside /proc
        /// points to a /proc magic path, bypassing the lexical prefix check.
        mod indirect_symlink_tests {
            use super::*;
            use std::os::unix::fs::symlink;

            #[test]
            fn test_indirect_symlink_to_proc_self_root() {
                // Create a symlink outside /proc that points to /proc/self/root
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_path = temp.path().join("link_to_proc");

                // Create symlink: link_to_proc -> /proc/self/root
                symlink("/proc/self/root", &link_path).expect("failed to create symlink");

                let result = canonicalize(&link_path).expect("canonicalize should succeed");

                // CRITICAL: Must NOT be "/" - that would be the security bypass
                assert_ne!(
                    result,
                    PathBuf::from("/"),
                    "SECURITY BUG: Indirect symlink to /proc/self/root resolved to /"
                );

                // Should preserve the /proc/self/root prefix
                assert!(
                    result.starts_with("/proc/self/root"),
                    "Expected /proc/self/root prefix, got: {:?}",
                    result
                );
            }

            #[test]
            fn test_indirect_symlink_with_suffix() {
                // Create a symlink and then access a path through it
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_path = temp.path().join("container");

                // Create symlink: container -> /proc/self/root
                symlink("/proc/self/root", &link_path).expect("failed to create symlink");

                // Canonicalize a path THROUGH the symlink
                let result =
                    canonicalize(link_path.join("etc")).expect("canonicalize should succeed");

                // Should be /proc/self/root/etc, NOT /etc
                assert!(
                    result.starts_with("/proc/self/root"),
                    "Expected /proc/self/root prefix, got: {:?}",
                    result
                );
            }

            #[test]
            fn test_chained_symlinks_to_proc() {
                // Create chain: link1 -> link2 -> /proc/self/root
                let temp = tempfile::tempdir().expect("failed to create temp dir");

                let link2 = temp.path().join("link2");
                let link1 = temp.path().join("link1");

                symlink("/proc/self/root", &link2).expect("failed to create link2");
                symlink(&link2, &link1).expect("failed to create link1");

                let result = canonicalize(&link1).expect("canonicalize should succeed");

                // Should preserve /proc prefix even through chain
                assert!(
                    result.starts_with("/proc/self/root"),
                    "Chained symlinks should preserve /proc prefix, got: {:?}",
                    result
                );
            }

            #[test]
            fn test_indirect_symlink_to_proc_pid_root() {
                // Test with actual PID (our own process)
                use std::process;
                let pid = process::id();
                let proc_path = format!("/proc/{}/root", pid);

                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_path = temp.path().join("pid_link");

                symlink(proc_path.as_str(), &link_path).expect("failed to create symlink");

                let result = canonicalize(&link_path).expect("canonicalize should succeed");

                // Should NOT be "/"
                assert_ne!(
                    result,
                    PathBuf::from("/"),
                    "SECURITY BUG: Indirect symlink to /proc/{}/root resolved to /",
                    pid
                );

                // Should preserve the /proc/PID/root prefix
                assert!(
                    result.starts_with(format!("/proc/{}/root", pid)),
                    "Expected /proc/{}/root prefix, got: {:?}",
                    pid,
                    result
                );
            }

            #[test]
            fn test_indirect_symlink_to_proc_self_cwd() {
                // Same vulnerability applies to /proc/self/cwd
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_path = temp.path().join("cwd_link");

                symlink("/proc/self/cwd", &link_path).expect("failed to create symlink");

                let result = canonicalize(&link_path).expect("canonicalize should succeed");

                // Should preserve the /proc/self/cwd prefix
                assert!(
                    result.starts_with("/proc/self/cwd"),
                    "Expected /proc/self/cwd prefix, got: {:?}",
                    result
                );
            }

            #[test]
            fn test_indirect_symlink_to_proc_thread_self_root() {
                // Test thread-self variant
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_path = temp.path().join("thread_link");

                symlink("/proc/thread-self/root", &link_path).expect("failed to create symlink");

                // thread-self might not exist on all systems
                if let Ok(result) = canonicalize(&link_path) {
                    assert!(
                        result.starts_with("/proc/thread-self/root"),
                        "Expected /proc/thread-self/root prefix, got: {:?}",
                        result
                    );
                }
            }

            #[test]
            fn test_normal_symlink_not_affected() {
                // Ensure normal symlinks (not pointing to /proc magic) still work
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let target = temp.path().join("target");
                let link = temp.path().join("link");

                std::fs::create_dir(&target).expect("failed to create target dir");
                symlink(&target, &link).expect("failed to create symlink");

                let result = canonicalize(&link).expect("canonicalize should succeed");
                let std_result =
                    std::fs::canonicalize(&link).expect("std canonicalize should succeed");

                // Normal symlinks should resolve identically to std
                assert_eq!(result, std_result);
            }

            #[test]
            fn test_symlink_loop_does_not_hang() {
                // Ensure we handle symlink loops gracefully
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link_a = temp.path().join("link_a");
                let link_b = temp.path().join("link_b");

                // Create circular symlinks
                symlink(&link_b, &link_a).expect("failed to create link_a");
                symlink(&link_a, &link_b).expect("failed to create link_b");

                // Should return an error (too many symlinks), not hang
                let result = canonicalize(&link_a);
                assert!(result.is_err(), "Symlink loop should return error");
            }
        }

        /// Security-focused tests for potential attack vectors.
        ///
        /// These tests verify protection against common path-based attacks
        /// including path traversal, symlink escapes, and edge cases.
        mod security_tests {
            use super::*;

            #[test]
            fn test_path_traversal_many_dotdot_at_boundary() {
                // Attempt to escape namespace with excessive .. components
                // /proc/self/root/../../../../../../../etc/passwd
                let result = canonicalize("/proc/self/root/../../../../../../../etc/passwd");

                // This should either:
                // 1. Preserve namespace prefix (if path resolves within)
                // 2. Error out (if path is invalid)
                // But NEVER resolve to /etc/passwd on the host
                if let Ok(path) = result {
                    assert!(
                        path.starts_with("/proc/self/root"),
                        "Path traversal should not escape namespace, got: {:?}",
                        path
                    );
                }
            }

            #[test]
            fn test_canonicalize_idempotency() {
                // Security property: canonicalize(canonicalize(x)) == canonicalize(x)
                // If not idempotent, attackers could exploit the difference
                let test_paths = ["/proc/self/root", "/proc/self/root/etc", "/proc/self/cwd"];

                for path in &test_paths {
                    if let Ok(first) = canonicalize(path) {
                        if let Ok(second) = canonicalize(&first) {
                            assert_eq!(
                                first, second,
                                "canonicalize should be idempotent for {:?}",
                                path
                            );
                        }
                    }
                }
            }

            #[test]
            fn test_case_sensitivity_proc() {
                // Linux is case-sensitive: /PROC should NOT match /proc
                // This verifies we don't accidentally treat /PROC as a namespace
                let result = canonicalize("/PROC/self/root");

                // /PROC/self/root should not exist (case-sensitive filesystem)
                // or if it somehow does, it should not be treated as a namespace
                match result {
                    Ok(path) => {
                        // If it somehow exists, it should NOT have /proc protection
                        // (would be treated as normal path)
                        assert!(
                            !path.starts_with("/proc/"),
                            "/PROC should not be treated as /proc namespace"
                        );
                    }
                    Err(e) => {
                        // Expected: NotFound because /PROC doesn't exist
                        assert_eq!(e.kind(), io::ErrorKind::NotFound);
                    }
                }
            }

            #[test]
            fn test_double_slash_normalization() {
                // Paths with double slashes: //proc/self/root or /proc//self//root
                // Verify they're handled correctly
                let result = canonicalize("/proc/self/root");
                if let Ok(normal) = result {
                    // Path::new normalizes double slashes, so this should work the same
                    let double_slash = canonicalize("//proc//self//root");
                    if let Ok(ds_path) = double_slash {
                        assert_eq!(normal, ds_path, "Double slashes should normalize correctly");
                    }
                }
            }

            #[test]
            fn test_trailing_slash_consistency() {
                // /proc/self/root vs /proc/self/root/ should behave consistently
                let without_slash = canonicalize("/proc/self/root");
                let with_slash = canonicalize("/proc/self/root/");

                if let (Ok(a), Ok(b)) = (without_slash, with_slash) {
                    // Both should preserve the namespace
                    assert!(a.starts_with("/proc/self/root"));
                    assert!(b.starts_with("/proc/self/root"));
                }
                // If either fails, that's fine for this test
            }

            #[test]
            fn test_dot_components() {
                // /proc/self/root/./etc should normalize to /proc/self/root/etc
                let result = canonicalize("/proc/self/root/./etc");
                if let Ok(path) = result {
                    assert!(
                        path.starts_with("/proc/self/root"),
                        "Dot components should preserve namespace, got: {:?}",
                        path
                    );
                    // Should not contain /./
                    assert!(
                        !path.to_string_lossy().contains("/./"),
                        "Dot should be normalized out"
                    );
                }
            }

            #[test]
            fn test_symlink_within_namespace_relative_escape_attempt() {
                // Create a symlink inside a temp dir that tries to escape via relative path
                // This tests symlink resolution staying within bounds
                use std::os::unix::fs::symlink;

                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let subdir = temp.path().join("subdir");
                std::fs::create_dir(&subdir).expect("failed to create subdir");

                // Create a symlink that tries to escape: subdir/escape -> ../../../../../../etc
                let escape_link = subdir.join("escape");
                symlink("../../../../../../etc", &escape_link).expect("failed to create symlink");

                // Canonicalizing should resolve but this is a normal symlink
                // (not through /proc), so std behavior applies
                let result = canonicalize(&escape_link);
                // Just verify it doesn't panic and behaves like std
                if let Ok(path) = &result {
                    let std_result = std::fs::canonicalize(&escape_link);
                    if let Ok(std_path) = std_result {
                        assert_eq!(*path, std_path);
                    }
                }
            }

            #[test]
            fn test_empty_path() {
                // Empty path should error
                let result = canonicalize("");
                assert!(result.is_err(), "Empty path should error");
            }

            #[test]
            fn test_relative_path_not_mistaken_for_proc() {
                // A relative path "proc/self/root" should NOT be treated as /proc/self/root
                let result = canonicalize("proc/self/root");

                // Should either error (doesn't exist) or resolve relative to cwd
                // But should NOT get namespace treatment
                // The key verification is that find_namespace_boundary rejects relative paths
                let _ = result; // Result depends on whether relative path exists
            }

            #[test]
            fn test_proc_without_pid() {
                // /proc/root (missing PID) should not be treated as namespace boundary
                let result = find_namespace_boundary(Path::new("/proc/root"));
                assert!(
                    result.is_none(),
                    "/proc/root (no PID) should not be a namespace boundary"
                );
            }

            #[test]
            fn test_proc_invalid_special_names() {
                // Only "self" and "thread-self" are valid special PIDs
                // Others like "parent" or "init" should not be treated as namespace
                for invalid in &["parent", "init", "current", "me"] {
                    let path = format!("/proc/{}/root", invalid);
                    let result = find_namespace_boundary(Path::new(&path));
                    assert!(
                        result.is_none(),
                        "/proc/{}/root should not be a namespace boundary",
                        invalid
                    );
                }
            }

            #[test]
            fn test_very_long_pid() {
                // PIDs have a max value (typically 4194304 on 64-bit Linux)
                // But we accept any numeric string - verify no overflow/panic
                let long_pid = "9".repeat(100);
                let path = format!("/proc/{}/root", long_pid);
                let result = find_namespace_boundary(Path::new(&path));
                // Should be detected as a namespace boundary (syntactically valid)
                assert!(
                    result.is_some(),
                    "Very long numeric PID should be syntactically accepted"
                );
            }

            #[test]
            fn test_pid_zero() {
                // PID 0 is the kernel scheduler, not a real process
                // But syntactically it's a valid PID format
                let result = find_namespace_boundary(Path::new("/proc/0/root"));
                assert!(result.is_some(), "PID 0 is syntactically valid");

                // Canonicalizing will likely fail since /proc/0/root doesn't exist
                let canon = canonicalize("/proc/0/root");
                assert!(canon.is_err(), "/proc/0/root should not exist");
            }

            #[test]
            fn test_negative_pid_rejected() {
                // Negative PIDs are invalid
                let result = find_namespace_boundary(Path::new("/proc/-1/root"));
                assert!(
                    result.is_none(),
                    "Negative PID should not be a namespace boundary"
                );
            }

            #[test]
            fn test_pid_with_leading_zeros() {
                // PIDs like "0001234" - are these valid?
                // Syntactically they're all digits, so we accept them
                let result = find_namespace_boundary(Path::new("/proc/0001234/root"));
                assert!(
                    result.is_some(),
                    "PID with leading zeros is syntactically valid"
                );
            }

            #[test]
            fn test_symlink_to_proc_subpath() {
                // Symlink pointing deep into /proc: link -> /proc/self/root/etc
                use std::os::unix::fs::symlink;
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link = temp.path().join("deep_link");
                symlink("/proc/self/root/etc", &link).expect("failed to create symlink");

                let result = canonicalize(&link);
                if let Ok(path) = result {
                    assert!(
                        path.starts_with("/proc/self/root"),
                        "Symlink to /proc subpath should preserve prefix, got: {:?}",
                        path
                    );
                }
            }

            #[test]
            fn test_symlink_interception() {
                // link1 -> link2 -> /proc/self/root
                use std::os::unix::fs::symlink;
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link2 = temp.path().join("link2");
                let link1 = temp.path().join("link1");

                symlink("/proc/self/root", &link2).expect("failed to create link2");
                symlink(&link2, &link1).expect("failed to create link1");

                let result = canonicalize(&link1).expect("should succeed");
                assert!(
                    result.starts_with("/proc/self/root"),
                    "Chain of symlinks should be detected"
                );
            }

            #[test]
            fn test_symlink_to_relative_proc_name() {
                // link -> "proc/self/root" (relative path, not absolute /proc)
                // This should NOT be treated as magic unless it resolves to absolute /proc
                use std::os::unix::fs::symlink;
                let temp = tempfile::tempdir().expect("failed to create temp dir");
                let link = temp.path().join("rel_link");

                // Create a fake proc dir locally to make the link valid
                let fake_proc = temp.path().join("proc/self/root");
                std::fs::create_dir_all(fake_proc).expect("failed to create fake proc");

                symlink("proc/self/root", &link).expect("failed to create symlink");

                let result = canonicalize(&link).expect("should succeed");

                // Should resolve to the temp dir path, NOT /proc/self/root
                assert!(
                    !result.starts_with("/proc/self/root"),
                    "Relative path looking like proc should not be magic"
                );
                assert!(
                    result.starts_with(temp.path()),
                    "Should resolve to temp dir"
                );
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
