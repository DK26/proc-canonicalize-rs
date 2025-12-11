#[cfg(target_os = "linux")]
mod linux_edge_cases {
    use proc_canonicalize::canonicalize;
    use std::path::PathBuf;

    // ==========================================================================
    // NAMESPACE TYPE SYMMETRY TESTS
    // For every test on /proc/self/root, there should be a parallel for /proc/self/cwd
    // ==========================================================================

    #[test]
    fn test_task_level_root() {
        // /proc/self/task/<tid>/root
        let pid = std::process::id();
        let task_dir = std::path::Path::new("/proc/self/task");

        if let Ok(entries) = std::fs::read_dir(task_dir) {
            if let Some(Ok(entry)) = entries.into_iter().next() {
                let tid = entry.file_name();
                let tid_str = tid.to_string_lossy();

                let path = format!("/proc/{}/task/{}/root", pid, tid_str);
                let result = canonicalize(path.as_str());

                if let Ok(p) = result {
                    assert_eq!(p, PathBuf::from(&path), "Should preserve task-level root");
                }
            }
        }
    }

    #[test]
    fn test_task_level_cwd() {
        // Symmetry test: /proc/self/task/<tid>/cwd (parallel to test_task_level_root)
        let pid = std::process::id();
        let task_dir = std::path::Path::new("/proc/self/task");

        if let Ok(entries) = std::fs::read_dir(task_dir) {
            if let Some(Ok(entry)) = entries.into_iter().next() {
                let tid = entry.file_name();
                let tid_str = tid.to_string_lossy();

                let path = format!("/proc/{}/task/{}/cwd", pid, tid_str);
                let result = canonicalize(path.as_str());

                if let Ok(p) = result {
                    assert_eq!(p, PathBuf::from(&path), "Should preserve task-level cwd");
                }
            }
        }
    }

    // ==========================================================================
    // "PATHS THROUGH" TESTS
    // Test accessing files THROUGH the namespace, not just the prefix alone
    // ==========================================================================

    #[test]
    fn test_cwd_preservation() {
        // Test the fix for the "cwd bug"
        // /proc/self/cwd/README.md should resolve to /proc/self/cwd/README.md
        // NOT /proc/self/cwd/<absolute_path>/README.md

        // We need a file that exists in CWD.
        let file_name = "test_cwd_preservation.tmp";
        std::fs::write(file_name, "test").unwrap();

        let path = format!("/proc/self/cwd/{}", file_name);
        let result = canonicalize(path.as_str());

        std::fs::remove_file(file_name).unwrap();

        let resolved = result.expect("Should succeed");
        assert_eq!(resolved, PathBuf::from(path));
    }

    #[test]
    fn test_root_subpath_preservation() {
        // Symmetry test: /proc/self/root/etc should preserve prefix
        // This was already tested elsewhere but we include it for completeness
        let result = canonicalize("/proc/self/root/etc");
        if let Ok(p) = result {
            assert!(
                p.starts_with("/proc/self/root"),
                "Should preserve /proc/self/root prefix for subpaths, got: {:?}",
                p
            );
        }
    }

    #[test]
    fn test_cwd_subdir_preservation() {
        // Create a subdirectory and test path through cwd
        let dir_name = "test_cwd_subdir_preservation";
        std::fs::create_dir_all(dir_name).unwrap();
        let file_path = format!("{}/file.txt", dir_name);
        std::fs::write(file_path, "test").unwrap();

        let path = format!("/proc/self/cwd/{}/file.txt", dir_name);
        let result = canonicalize(path);

        std::fs::remove_dir_all(dir_name).unwrap();

        let resolved = result.expect("Should succeed");
        assert_eq!(
            resolved,
            PathBuf::from(format!("/proc/self/cwd/{}/file.txt", dir_name))
        );
    }

    // ==========================================================================
    // NAMESPACE ESCAPE TESTS
    // Test behavior when paths traverse OUT of the namespace via ..
    // ==========================================================================

    #[test]
    fn test_cwd_with_dotdot_escape() {
        // Test escaping cwd via ..
        // /proc/self/cwd/.. should resolve to the absolute path, NOT /proc/self/cwd/...

        let path = "/proc/self/cwd/..";
        let result = canonicalize(path).expect("Should succeed");

        // Result should be an absolute path, NOT starting with /proc/self/cwd
        assert!(
            !result.starts_with("/proc/self/cwd"),
            "Should escape cwd namespace"
        );
        assert!(result.is_absolute());
    }

    #[test]
    fn test_root_with_dotdot_stays_inside() {
        // /proc/self/root/../etc should stay INSIDE the namespace
        // because .. from / is still /
        let result = canonicalize("/proc/self/root/../etc");
        if let Ok(p) = result {
            assert!(
                p.starts_with("/proc/self/root"),
                "/proc/self/root/../etc should stay in namespace, got: {:?}",
                p
            );
        }
    }

    // ==========================================================================
    // SYMLINK THROUGH NAMESPACE TESTS
    // Test symlink resolution within namespaces
    // ==========================================================================

    #[test]
    fn test_symlink_within_cwd_namespace() {
        use std::os::unix::fs::symlink;

        // Create: file.txt and link.txt -> file.txt
        let file_name = "test_symlink_cwd_file.txt";
        let link_name = "test_symlink_cwd_link.txt";

        std::fs::write(file_name, "test").unwrap();
        let _ = std::fs::remove_file(link_name); // Clean up if exists
        symlink(file_name, link_name).unwrap();

        let path = format!("/proc/self/cwd/{}", link_name);
        let result = canonicalize(path);

        std::fs::remove_file(link_name).unwrap();
        std::fs::remove_file(file_name).unwrap();

        let resolved = result.expect("Should succeed");
        // Should resolve to the target file, but still within namespace
        assert_eq!(
            resolved,
            PathBuf::from(format!("/proc/self/cwd/{}", file_name))
        );
    }

    #[test]
    fn test_symlink_inside_namespace_pointing_outside() {
        // CRITICAL SECURITY TEST:
        // A symlink INSIDE the namespace that points to an absolute path OUTSIDE.
        // Example: /proc/self/cwd/escape_link -> /etc/passwd
        //
        // This tests what happens when following a symlink escapes the namespace.
        // The canonicalized result should be the absolute host path (escaped).
        use std::os::unix::fs::symlink;

        let link_name = "test_escape_symlink.tmp";
        let _ = std::fs::remove_file(link_name);

        // Create symlink in cwd pointing to absolute path outside namespace
        symlink("/etc/hostname", link_name).expect("failed to create symlink");

        let path = format!("/proc/self/cwd/{}", link_name);
        let result = canonicalize(path);

        std::fs::remove_file(link_name).unwrap();

        // This should resolve to the actual /etc/hostname (escaped the namespace)
        // NOT /proc/self/cwd/etc/hostname
        if let Ok(resolved) = result {
            assert!(
                !resolved.starts_with("/proc/self/cwd"),
                "Symlink to outside should escape namespace, got: {:?}",
                resolved
            );
            // Should resolve to /etc/hostname or a path it symlinks to
            assert!(resolved.is_absolute());
        }
        // If /etc/hostname doesn't exist, the test may error - that's ok
    }

    #[test]
    fn test_symlink_inside_root_namespace_pointing_outside() {
        // Same test but for /proc/self/root
        // A symlink at /proc/self/root/tmp/link -> /some/host/path
        // This is tricky because on the host, /proc/self/root IS /
        // So the symlink is actually at /tmp/link
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let link_in_tmp = temp.path().join("escape_link");

        // Create symlink pointing to an absolute path
        symlink("/etc/hostname", &link_in_tmp).expect("failed to create symlink");

        // Access through /proc/self/root
        let path = format!("/proc/self/root{}", link_in_tmp.to_string_lossy());
        let result = canonicalize(path);

        // For /proc/self/root on host, /etc/hostname IS inside the namespace (it's /)
        // So this should stay within the namespace
        if let Ok(resolved) = result {
            assert!(
                resolved.starts_with("/proc/self/root"),
                "On host, /etc/hostname is inside /proc/self/root namespace, got: {:?}",
                resolved
            );
        }
    }

    // ==========================================================================
    // NON-ROOT NAMESPACE TARGET SIMULATION
    // These tests verify behavior when namespace prefix doesn't resolve to "/"
    // ==========================================================================

    #[test]
    fn test_indirect_symlink_to_cwd_with_subpath() {
        // This simulates a container-like scenario where the namespace
        // doesn't resolve to /
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let link_path = temp.path().join("cwd_link");

        // Create symlink: cwd_link -> /proc/self/cwd
        symlink("/proc/self/cwd", &link_path).expect("failed to create symlink");

        // Create a file in cwd
        let file_name = "test_indirect_cwd.tmp";
        std::fs::write(file_name, "test").unwrap();

        // Access file through the indirect symlink
        let result = canonicalize(link_path.join(file_name));

        std::fs::remove_file(file_name).unwrap();

        let resolved = result.expect("Should succeed");
        // Should preserve /proc/self/cwd prefix
        assert!(
            resolved.starts_with("/proc/self/cwd"),
            "Indirect symlink to cwd should preserve prefix, got: {:?}",
            resolved
        );
        assert_eq!(
            resolved,
            PathBuf::from(format!("/proc/self/cwd/{}", file_name))
        );
    }

    // ==========================================================================
    // INVARIANT TESTS
    // Property-based checks that should always hold
    // ==========================================================================

    #[test]
    fn test_invariant_prefix_or_absolute() {
        // INVARIANT: For any /proc/.../root or /proc/.../cwd path,
        // the result is either:
        // 1. Starts with the same prefix (path stayed inside namespace)
        // 2. Is an absolute path not starting with /proc (path escaped)

        let test_cases = ["/proc/self/root", "/proc/self/root/etc", "/proc/self/cwd"];

        for input in &test_cases {
            if let Ok(result) = canonicalize(input) {
                let is_prefixed =
                    result.starts_with("/proc/self/root") || result.starts_with("/proc/self/cwd");
                let is_escaped_absolute =
                    result.is_absolute() && !result.starts_with("/proc/self/");

                assert!(
                    is_prefixed || is_escaped_absolute,
                    "Invariant violated for {}: result {:?} is neither prefixed nor escaped absolute",
                    input,
                    result
                );
            }
        }
    }

    #[test]
    fn test_invariant_idempotency() {
        // INVARIANT: canonicalize(canonicalize(x)) == canonicalize(x)

        let file_name = "test_idempotency.tmp";
        std::fs::write(file_name, "test").unwrap();

        let test_cases = [
            "/proc/self/root".to_string(),
            "/proc/self/root/etc".to_string(),
            "/proc/self/cwd".to_string(),
            format!("/proc/self/cwd/{}", file_name),
        ];

        for input in &test_cases {
            if let Ok(first) = canonicalize(input) {
                if let Ok(second) = canonicalize(&first) {
                    assert_eq!(
                        first, second,
                        "Idempotency violated for {}: first={:?}, second={:?}",
                        input, first, second
                    );
                }
            }
        }

        std::fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_symlink_to_proc_parent_vulnerability() {
        // Regression test for vulnerability where symlink to /proc caused fallback to std::fs::canonicalize
        // resulting in resolution to / instead of preserving namespace.
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create symlink /tmp/.../myproc -> /proc
        let myproc = temp.path().join("myproc");
        symlink("/proc", &myproc).expect("failed to create symlink");

        // Construct path: /tmp/.../myproc/self/root
        let path = myproc.join("self/root");

        // Canonicalize
        let result = canonicalize(path).expect("canonicalize failed");

        // It should NOT be / (host root)
        assert_ne!(
            result,
            std::path::Path::new("/"),
            "VULNERABILITY: Resolved /proc/self/root to / via parent symlink"
        );

        // It SHOULD be /proc/self/root
        assert_eq!(result, std::path::Path::new("/proc/self/root"));
    }

    #[test]
    fn test_relative_symlink_to_proc_vulnerability() {
        // Vulnerability: A relative symlink pointing to /proc (e.g. via ..)
        // might trick the detection logic if it doesn't normalize the path
        // before checking for the /proc prefix.
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create directory structure: /tmp/dir
        let dir = temp.path().join("dir");
        std::fs::create_dir(&dir).expect("failed to create dir");

        // /tmp/proc_link -> /proc
        let proc_link = temp.path().join("proc_link");
        symlink("/proc", proc_link).expect("failed to create proc_link");

        // /tmp/dir/link -> ../proc_link/self/root
        let link = dir.join("link");
        symlink("../proc_link/self/root", &link).expect("failed to create link");

        // Canonicalize
        let result = canonicalize(&link).expect("canonicalize failed");

        // It should NOT be / (host root)
        assert_ne!(
            result,
            std::path::Path::new("/"),
            "VULNERABILITY: Resolved relative symlink to /proc/self/root to /"
        );

        assert!(result.starts_with("/proc/self/root"));
    }
}
