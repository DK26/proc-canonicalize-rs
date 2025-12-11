//! Additional security tests for edge cases and potential vulnerabilities

#[cfg(target_os = "linux")]
mod additional_security_tests {
    use proc_canonicalize::canonicalize;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    #[test]
    fn test_symlink_resolution_with_dotdot_normalization_bypass() {
        // Vulnerability: "normalize_path" at start of loop blindly removes "component/.."
        // If "component" is a symlink to a magic path, we miss it.
        //
        // Setup:
        // /tmp/magic -> /proc/self/root
        // /tmp/innocent -> /tmp/magic/subdir
        // Path: /tmp/innocent/..
        //
        // Lexical normalization: /tmp
        // Actual resolution: /proc/self/root

        let temp_dir = tempfile::TempDir::new().unwrap();
        let root = temp_dir.path().to_path_buf();

        // 1. Create /tmp/magic -> /proc/self/root
        let magic_link = root.join("magic");
        symlink("/proc/self/root", &magic_link).unwrap();

        // 2. Create /tmp/innocent -> /tmp/magic/etc
        // We use "etc" because it exists inside /proc/self/root
        let innocent_link = root.join("innocent");
        symlink(magic_link.join("etc"), &innocent_link).unwrap();

        // 3. Path to test: /tmp/innocent/..
        // This should resolve to /proc/self/root/etc/.. -> /proc/self/root
        let attack_path = innocent_link.join(std::path::Component::ParentDir.as_os_str());

        let result = canonicalize(attack_path).unwrap();

        // We expect the result to be /proc/self/root
        assert_eq!(result, PathBuf::from("/proc/self/root"));
    }

    #[test]
    fn test_double_symlink_indirection() {
        // /tmp/a -> /tmp/b -> /proc/self/root
        // Both symlinks should be followed and detected
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        let link_b = temp.path().join("link_b");
        let link_a = temp.path().join("link_a");

        symlink("/proc/self/root", &link_b).expect("failed to create link_b");
        symlink(&link_b, &link_a).expect("failed to create link_a");

        let result = canonicalize(&link_a).expect("canonicalize failed");

        assert_ne!(
            result,
            PathBuf::from("/"),
            "Double indirection should not resolve to /"
        );
        assert!(
            result.starts_with("/proc/self/root")
                || result == std::path::Path::new("/proc/self/root")
        );
    }

    #[test]
    fn test_triple_symlink_chain() {
        // /tmp/a -> /tmp/b -> /tmp/c -> /proc/self/root
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        let link_c = temp.path().join("link_c");
        let link_b = temp.path().join("link_b");
        let link_a = temp.path().join("link_a");

        symlink("/proc/self/root", &link_c).expect("failed to create link_c");
        symlink(&link_c, &link_b).expect("failed to create link_b");
        symlink(&link_b, &link_a).expect("failed to create link_a");

        let result = canonicalize(&link_a).expect("canonicalize failed");

        assert_ne!(
            result,
            PathBuf::from("/"),
            "Triple chain should not resolve to /"
        );
        assert!(result.starts_with("/proc/self/root"));
    }

    #[test]
    fn test_relative_path_resolving_to_proc() {
        // From a temp dir, create a path that when made absolute resolves through /proc
        // This is tricky - we need a symlink that when followed lands in /proc
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create /tmp/.../proc_link -> /proc
        let proc_link = temp.path().join("proc_link");
        symlink("/proc", &proc_link).expect("failed to create proc_link");

        // Now if we're "in" temp dir and access "proc_link/self/root"
        // it should still be detected
        let relative_ish = proc_link.join("self/root");

        let result = canonicalize(relative_ish).expect("canonicalize failed");

        assert_ne!(result, PathBuf::from("/"));
        assert_eq!(result, PathBuf::from("/proc/self/root"));
    }

    #[test]
    fn test_fd_symlink_to_proc_namespace() {
        // /proc/self/fd/N where fd N points to /proc/PID/root
        // This is hard to set up without actually opening /proc/PID/root
        // But we can test that /proc/self/fd paths themselves aren't mistaken for namespaces

        // /proc/self/fd is NOT a namespace boundary (it's a directory of file descriptors)
        let result = canonicalize("/proc/self/fd");

        // Should succeed (it exists) and NOT be treated as namespace
        if let Ok(path) = result {
            // fd is a real directory, should resolve normally
            // The path might be /proc/self/fd or /proc/<pid>/fd
            assert!(path.to_string_lossy().contains("/proc/"));
            assert!(path.to_string_lossy().contains("/fd"));
        }
        // If it errors, that's also fine (permission issues)
    }

    #[test]
    fn test_nested_proc_access() {
        // /proc/self/root/proc/self/root - accessing proc inside namespace
        // First /proc/self/root is our namespace boundary
        // Inside that, /proc/self/root would be the container's view

        let result = canonicalize("/proc/self/root/proc/self/root");

        // This path may or may not exist depending on whether /proc is mounted inside
        // But if it does exist, it should preserve the OUTER namespace prefix
        if let Ok(path) = result {
            assert!(path.starts_with("/proc/self/root"));
        }
        // Error is also acceptable (path doesn't exist)
    }

    #[test]
    fn test_symlink_with_dotdot_escaping_to_proc() {
        // /tmp/dir/escape -> ../../proc/self/root
        // Tricky because the .. must resolve correctly

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let subdir = temp.path().join("subdir");
        std::fs::create_dir(&subdir).expect("failed to create subdir");

        // Calculate how many .. we need to get to /
        // From /tmp/xxx/subdir, we need ../../../ to get to /
        // Then proc/self/root

        let escape = subdir.join("escape");
        symlink("../../../proc/self/root", &escape).expect("failed to create escape symlink");

        let result = canonicalize(&escape);

        // If the symlink resolves to /proc/self/root, we should detect it
        if let Ok(path) = result {
            assert_ne!(
                path,
                PathBuf::from("/"),
                "Escaped symlink should not resolve to /"
            );
            // It should either be /proc/self/root or an error
            if path != std::path::Path::new("/proc/self/root") {
                // Might resolve to something else if .. doesn't land exactly on /
                // That's okay as long as it's not /
                println!("Resolved to: {:?}", path);
            }
        }
        // Error is acceptable if the path doesn't resolve correctly
    }

    #[test]
    fn test_symlink_to_proc_with_trailing_components() {
        // /tmp/link -> /proc
        // then access /tmp/link/self/root/etc/passwd

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let proc_link = temp.path().join("proc_link");
        symlink("/proc", &proc_link).expect("failed to create symlink");

        let path = proc_link.join("self/root/etc/passwd");

        let result = canonicalize(path);

        if let Ok(resolved) = result {
            // Should preserve /proc/self/root prefix
            assert!(
                resolved.starts_with("/proc/self/root"),
                "Should preserve namespace: {:?}",
                resolved
            );
        }
        // Error is acceptable if file doesn't exist
    }

    #[test]
    fn test_symlink_loop_with_proc() {
        // /tmp/a -> /tmp/b
        // /tmp/b -> /tmp/a/proc (doesn't exist, but tests loop detection)
        // This shouldn't hang

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let link_a = temp.path().join("link_a");
        let link_b = temp.path().join("link_b");

        // Create a loop
        symlink(&link_b, &link_a).expect("failed to create link_a");
        symlink(&link_a, &link_b).expect("failed to create link_b");

        // This should not hang - should either error or return after max iterations
        let result = canonicalize(&link_a);

        // Should error (loop detected or ELOOP from kernel)
        assert!(result.is_err(), "Symlink loop should error, not hang");
    }

    #[test]
    fn test_mixed_symlinks_and_real_dirs() {
        // /tmp/real_dir/link -> /proc/self/root
        // Ensure we handle mixed real dirs and symlinks

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let real_dir = temp.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("failed to create real_dir");

        let link = real_dir.join("link");
        symlink("/proc/self/root", &link).expect("failed to create symlink");

        let result = canonicalize(&link).expect("canonicalize failed");

        assert_ne!(result, PathBuf::from("/"));
        assert_eq!(result, PathBuf::from("/proc/self/root"));
    }

    #[test]
    fn test_symlink_to_proc_thread_self() {
        // Ensure /proc/thread-self paths are also protected via symlinks
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let link = temp.path().join("thread_link");
        symlink("/proc/thread-self/root", &link).expect("failed to create symlink");

        let result = canonicalize(&link).expect("canonicalize failed");

        // thread-self/root resolves to / on the host, but we should preserve it
        assert_ne!(result, PathBuf::from("/"));
        assert!(
            result.starts_with("/proc/thread-self/root")
                || result.starts_with("/proc/") && result.to_string_lossy().contains("/root")
        );
    }

    // =========================================================================
    // Symlink target resolution edge cases
    // =========================================================================

    #[test]
    fn test_symlink_target_with_dotdot_resolving_to_proc() {
        // Setup:
        // /tmp/subdir/link -> ../proc_link/self/root
        // /tmp/proc_link -> /proc
        //
        // When we access /tmp/subdir/link:
        // 1. Resolve symlink: ../proc_link/self/root (relative to /tmp/subdir)
        // 2. Becomes: /tmp/proc_link/self/root
        // 3. proc_link is symlink to /proc
        // 4. Becomes: /proc/self/root
        // 5. Should be detected as magic

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        // Create /tmp/proc_link -> /proc
        let proc_link = root.join("proc_link");
        symlink("/proc", proc_link.as_path()).expect("create proc_link");

        // Create /tmp/subdir/
        let subdir = root.join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");

        // Create /tmp/subdir/link -> ../proc_link/self/root
        let link = subdir.join("link");
        symlink("../proc_link/self/root", &link).expect("create link");

        let result = canonicalize(&link).unwrap();

        assert_eq!(
            result,
            PathBuf::from("/proc/self/root"),
            "Symlink target with .. should resolve to magic path"
        );
    }

    #[test]
    fn test_multiple_dotdot_after_symlink_to_deep_path() {
        // Setup:
        // /tmp/link -> /proc/self/root/usr/share/doc
        // Then access /tmp/link/../../../
        // Should resolve to /proc/self/root

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        // /proc/self/root/usr/share/doc exists on most systems
        let link = root.join("link");
        symlink("/proc/self/root/usr/share/doc", &link).expect("create link");

        // Access link/../../.. -> should be /proc/self/root
        let path = link.join("../../..");

        let result = canonicalize(path);

        if let Ok(resolved) = result {
            assert_eq!(
                resolved,
                PathBuf::from("/proc/self/root"),
                "Multiple .. should pop back to namespace root"
            );
        }
        // May error if /usr/share/doc doesn't exist, that's OK
    }

    #[test]
    fn test_directory_symlink_then_dotdot() {
        // Setup:
        // /tmp/dir_link -> /proc/self/root/etc
        // Access: /tmp/dir_link/..
        // Should resolve to /proc/self/root (the parent of /etc inside namespace)

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        let dir_link = root.join("dir_link");
        symlink("/proc/self/root/etc", &dir_link).expect("create dir_link");

        let path = dir_link.join("..");

        let result = canonicalize(path);

        if let Ok(resolved) = result {
            assert_eq!(
                resolved,
                PathBuf::from("/proc/self/root"),
                ".. after symlink to subdir should pop to namespace root"
            );
        }
    }

    #[test]
    fn test_symlink_chain_with_dotdot_in_middle() {
        // Setup:
        // /tmp/a/link_a -> ../b/link_b
        // /tmp/b/link_b -> /proc/self/root
        //
        // Access /tmp/a/link_a should resolve to /proc/self/root

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        let dir_a = root.join("a");
        let dir_b = root.join("b");
        std::fs::create_dir(&dir_a).expect("create dir_a");
        std::fs::create_dir(&dir_b).expect("create dir_b");

        let link_b = dir_b.join("link_b");
        symlink("/proc/self/root", link_b.as_path()).expect("create link_b");

        let link_a = dir_a.join("link_a");
        symlink("../b/link_b", &link_a).expect("create link_a");

        let result = canonicalize(&link_a).unwrap();

        assert_eq!(
            result,
            PathBuf::from("/proc/self/root"),
            "Chain with .. in middle should still detect magic"
        );
    }

    #[test]
    fn test_cwd_symlink_with_escape_via_dotdot() {
        // /proc/self/cwd points to current working directory
        // If cwd is /home/user, then /proc/self/cwd/.. should escape to /home
        // We need to return the escaped absolute path, not claim it's inside namespace

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        let link = root.join("link");
        symlink("/proc/self/cwd", &link).expect("create link");

        let path = link.join("..");

        let result = canonicalize(path);

        if let Ok(resolved) = result {
            // Get actual parent of cwd for comparison
            let cwd = std::env::current_dir().unwrap();
            if let Some(parent) = cwd.parent() {
                // Either it matches the actual parent, or it's the same as cwd (if cwd is /)
                assert!(
                    resolved == parent
                        || resolved == cwd
                        || !resolved.starts_with("/proc/self/cwd"),
                    "Should either resolve to parent or not claim namespace prefix"
                );
            }
        }
    }

    #[test]
    fn test_dot_components_with_symlink_to_proc() {
        // /tmp/./link/./self/./root where link -> /proc
        // All the . should be ignored

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        let link = root.join("link");
        symlink("/proc", link.as_path()).expect("create link");

        // Build path with . components
        let path = root
            .join(".")
            .join("link")
            .join(".")
            .join("self")
            .join(".")
            .join("root");

        let result = canonicalize(path).unwrap();

        assert_eq!(
            result,
            PathBuf::from("/proc/self/root"),
            ". components should be ignored"
        );
    }

    #[test]
    fn test_innocent_looking_symlink_chain() {
        // /tmp/data -> /tmp/storage
        // /tmp/storage -> /tmp/backup
        // /tmp/backup -> /proc/self/root
        //
        // The first two symlinks look innocent

        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp.path();

        let backup = root.join("backup");
        symlink("/proc/self/root", &backup).expect("create backup");

        let storage = root.join("storage");
        symlink(&backup, &storage).expect("create storage");

        let data = root.join("data");
        symlink(&storage, &data).expect("create data");

        let result = canonicalize(&data).unwrap();

        assert_eq!(
            result,
            PathBuf::from("/proc/self/root"),
            "Innocent-looking chain should still be detected"
        );
    }

    // =========================================================================
    // KNOWN LIMITATIONS (documented, not vulnerabilities per se)
    // =========================================================================

    // NOTE: Bind mounts are NOT detected by this library.
    // If someone does: mount --bind /proc /mnt/proc
    // Then /mnt/proc/self/root will NOT be protected.
    // This is because:
    // 1. Bind mounts are not symlinks - they're mount points
    // 2. Detecting bind mounts requires reading /proc/self/mountinfo
    // 3. This would add complexity and another TOCTOU window
    // 4. Bind mounts require root to create, limiting the attack surface
    //
    // If your threat model includes malicious bind mounts, you should:
    // 1. Restrict mount capabilities in your container/sandbox
    // 2. Use mount namespaces
    // 3. Audit /proc/self/mountinfo before trusting paths
}
