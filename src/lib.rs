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
//! ```text
//! std::fs::canonicalize("/proc/1234/root")           -> "/"
//! std::fs::canonicalize("/proc/1234/root/etc/passwd") -> "/etc/passwd"
//! ```
//!
//! This breaks security tools that use `/proc/PID/root` as a boundary for container
//! filesystem access, because the boundary resolves to the host root!
//!
//! ## The Fix
//!
//! This crate detects `/proc/PID/root` and `/proc/PID/cwd` prefixes and preserves them:
//!
//! ```text
//! proc_canonicalize::canonicalize("/proc/1234/root")           -> "/proc/1234/root"
//! proc_canonicalize::canonicalize("/proc/1234/root/etc/passwd") -> "/proc/1234/root/etc/passwd"
//! ```
//!
//! For all other paths, behavior is identical to `std::fs::canonicalize`.
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

/// Canonicalize a path, preserving Linux `/proc/PID/root` and `/proc/PID/cwd` boundaries.
///
/// This function behaves like [`std::fs::canonicalize`], except that on Linux it
/// detects and preserves namespace boundary prefixes (`/proc/PID/root`, `/proc/PID/cwd`,
/// `/proc/self/root`, `/proc/self/cwd`, `/proc/thread-self/root`, `/proc/thread-self/cwd`).
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
        if !namespace_prefix.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "namespace path does not exist: {}",
                    namespace_prefix.display()
                ),
            ));
        }

        if remainder.as_os_str().is_empty() {
            // Path IS the namespace boundary (e.g., "/proc/1234/root")
            Ok(namespace_prefix)
        } else {
            // Path goes through namespace boundary (e.g., "/proc/1234/root/etc/passwd")
            // Canonicalize the full path, then re-attach the namespace prefix
            let full_path = namespace_prefix.join(&remainder);

            // Use std::fs::canonicalize on the full path - this will traverse
            // through /proc/PID/root correctly, but return a path without the prefix
            let canonicalized = std::fs::canonicalize(&full_path)?;

            // The result will be something like "/etc/passwd" (the container's view)
            // We need to re-attach the namespace prefix
            Ok(namespace_prefix.join(canonicalized.strip_prefix("/").unwrap_or(&canonicalized)))
        }
    } else {
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

    // Next must be "root" or "cwd"
    let ns_type = match components.next() {
        Some(Component::Normal(s)) if s == "root" || s == "cwd" => s,
        _ => return None,
    };

    // Build the namespace prefix: /proc/{pid}/{root|cwd}
    let mut prefix = PathBuf::from("/proc");
    prefix.push(pid_component);
    prefix.push(ns_type);

    // Collect remaining components as the remainder
    let remainder: PathBuf = components.collect();

    Some((prefix, remainder))
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
