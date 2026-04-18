#![cfg(target_os = "linux")]

//! Integration tests exercising the public `canonicalize` API.
//!
//! Tests that reach into crate-private helpers (`find_namespace_boundary`,
//! `namespace_prefix_len`) live inline in `src/lib.rs` — integration-test
//! crates cannot see those symbols.

use proc_canonicalize::canonicalize;
use std::io;
use std::path::{Path, PathBuf};

// ==========================================================================
// USAGE EXAMPLES: Reading through a /proc/PID namespace boundary
// ==========================================================================

#[test]
fn reading_file_through_proc_pid_namespace() {
    let pid = std::process::id();
    let namespace_root = format!("/proc/{pid}/root");
    let file_in_namespace = format!("{namespace_root}/etc");

    let canonical_path = canonicalize(file_in_namespace).unwrap();

    assert!(canonical_path.starts_with(&namespace_root));
}

#[test]
fn canonicalized_path_stays_inside_proc_pid_namespace() {
    let pid = std::process::id();
    let namespace_root = format!("/proc/{pid}/root");
    let requested_file = format!("{namespace_root}/etc/passwd");

    let canonical = canonicalize(requested_file).unwrap();

    assert!(canonical.starts_with(&namespace_root));
}

#[test]
fn proc_self_root_preserved_not_resolved_to_slash() {
    let path = "/proc/self/root";

    let our_result = canonicalize(path).unwrap();
    let std_result = std::fs::canonicalize(path).unwrap();

    // std breaks it: returns "/"
    assert_eq!(std_result, Path::new("/"));

    // we fix it: preserves the namespace
    assert_eq!(our_result, Path::new("/proc/self/root"));
}

#[test]
fn proc_self_cwd_preserved() {
    let path = "/proc/self/cwd";

    let result = canonicalize(path).unwrap();

    assert_eq!(result, Path::new("/proc/self/cwd"));
}

#[test]
fn explicit_pid_root_preserved() {
    let my_pid = std::process::id();
    let path = format!("/proc/{my_pid}/root");

    let our_result = canonicalize(&path).unwrap();
    let std_result = std::fs::canonicalize(&path).unwrap();

    assert_eq!(std_result, Path::new("/"));
    assert_eq!(our_result, Path::new(&path));
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
    let pid_result = canonicalize(format!("/proc/{my_pid}/root")).unwrap();

    assert_eq!(self_result, Path::new("/proc/self/root"));
    assert_eq!(pid_result, Path::new(&format!("/proc/{my_pid}/root")));
}

// ==========================================================================
// INDIRECT SYMLINKS: Symlinks outside /proc pointing TO /proc magic paths
// ==========================================================================

mod indirect_symlinks {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlink_to_proc_self_root_preserves_namespace() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("link");

        symlink("/proc/self/root", &link).unwrap();

        let result = canonicalize(&link).unwrap();

        assert_ne!(result, Path::new("/")); // NOT the broken behavior
        assert_eq!(result, Path::new("/proc/self/root"));
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

        assert_eq!(result, Path::new("/proc/self/root"));
    }

    #[test]
    fn symlink_to_explicit_pid_root_preserved() {
        let my_pid = std::process::id();
        let target = format!("/proc/{my_pid}/root");
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("link");

        symlink(&target, &link).unwrap();

        let result = canonicalize(&link).unwrap();

        assert_ne!(result, Path::new("/"));
        assert_eq!(result, Path::new(&target));
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
// SECURITY EDGE CASES (public-API only)
// ==========================================================================

mod security {
    use super::*;
    use std::os::unix::fs::symlink;

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
    fn symlink_to_deep_proc_path_preserves_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("link");

        symlink("/proc/self/root/etc", &link).unwrap();

        if let Ok(result) = canonicalize(&link) {
            assert!(result.starts_with("/proc/self/root"));
        }
    }

    #[test]
    fn relative_symlink_looking_like_proc_not_magic() {
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
        // Normal symlink (not to /proc) attempting path-traversal escape must
        // behave exactly like std::fs::canonicalize.
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
