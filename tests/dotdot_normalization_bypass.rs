//! Failing tests proving a namespace-boundary bypass via `..` in the prefix.
//!
//! `find_namespace_boundary` does lexical matching on `path.components()` but
//! never normalizes `..`. As a result, paths like `/proc/<PID>/../<PID>/root`
//! lexically normalize to `/proc/<PID>/root` (a magic boundary) yet fail
//! detection. The fallback then hits `std::fs::canonicalize`, which follows the
//! magic symlink and silently drops the namespace prefix.
//!
//! A secondary bug also covered here: inside `detect_indirect_proc_magic_link`,
//! a symlink at `next_path` is resolved via `read_link` without first checking
//! whether `next_path` itself is a magic `/proc/.../root|cwd`. This is what
//! loses the boundary for the `..`-prefix cases after the scan reassembles
//! `/proc/<PID>/root` at the component walker.
//!
//! These tests should FAIL on the current implementation and PASS once the bug
//! is fixed (e.g. by lexically normalizing `..` in `find_namespace_boundary`
//! and/or by checking `is_proc_magic_path(&next_path)` in
//! `detect_indirect_proc_magic_link` before resolving a magic symlink).

#[cfg(target_os = "linux")]
mod dotdot_bypass {
    use proc_canonicalize::canonicalize;
    use std::path::{Path, PathBuf};

    #[test]
    fn dotdot_in_pid_prefix_preserves_root_namespace() {
        // /proc/<PID>/../<PID>/root  -- lexically equivalent to /proc/<PID>/root.
        // std::fs::canonicalize follows the magic symlink and returns "/", so
        // a buggy implementation will return "/" here too.
        let pid = std::process::id();
        let path = format!("/proc/{pid}/../{pid}/root");

        let result = canonicalize(path).expect("canonicalize should succeed");

        assert_ne!(
            result,
            Path::new("/"),
            "namespace boundary lost: /proc/{pid}/../{pid}/root resolved to host '/'"
        );
        assert_eq!(
            result,
            PathBuf::from(format!("/proc/{pid}/root")),
            "namespace prefix must be preserved through `..` normalization"
        );
    }

    #[test]
    fn dotdot_in_pid_prefix_with_subpath_preserves_root_namespace() {
        // Same vulnerability with a subpath. Reads /etc on the host instead of
        // through the namespace boundary.
        let pid = std::process::id();
        let path = format!("/proc/{pid}/../{pid}/root/etc");

        let result = canonicalize(path).expect("canonicalize should succeed");

        assert!(
            result.starts_with(format!("/proc/{pid}/root")),
            "namespace prefix lost for subpath: got {:?}",
            result
        );
    }

    #[test]
    fn dotdot_in_pid_prefix_preserves_cwd_namespace() {
        // Same bug for /proc/<PID>/cwd. A buggy implementation returns the
        // actual host cwd instead of the namespace-bounded path.
        let pid = std::process::id();
        let path = format!("/proc/{pid}/../{pid}/cwd");

        let result = canonicalize(path).expect("canonicalize should succeed");

        let host_cwd = std::env::current_dir().expect("get cwd");
        assert_ne!(
            result, host_cwd,
            "cwd namespace boundary lost: resolved to actual host cwd"
        );
        assert_eq!(
            result,
            PathBuf::from(format!("/proc/{pid}/cwd")),
            "cwd namespace prefix must be preserved through `..` normalization"
        );
    }

    #[test]
    fn dotdot_in_task_prefix_preserves_namespace() {
        // /proc/<PID>/task/<TID>/../<TID>/root  -- lexically equivalent to
        // /proc/<PID>/task/<TID>/root, but `..` after the TID defeats the
        // lexical matcher in find_namespace_boundary.
        let pid = std::process::id();
        let task_dir = Path::new("/proc/self/task");
        let entry = std::fs::read_dir(task_dir)
            .expect("read /proc/self/task")
            .next()
            .expect("at least one tid")
            .expect("entry ok");
        let tid = entry.file_name();
        let tid_str = tid.to_string_lossy();

        let path = format!("/proc/{pid}/task/{tid_str}/../{tid_str}/root");

        let result = canonicalize(path).expect("canonicalize should succeed");

        assert_ne!(
            result,
            Path::new("/"),
            "task-level namespace boundary lost: resolved to host '/'"
        );
        assert_eq!(
            result,
            PathBuf::from(format!("/proc/{pid}/task/{tid_str}/root")),
            "task-level namespace prefix must be preserved through `..` normalization"
        );
    }

    #[test]
    fn dotdot_in_self_prefix_preserves_namespace() {
        // Variant using `self`, which is itself a magic symlink. After resolving
        // `self` to the numeric PID, the same `..` bypass applies.
        //
        // NOTE: on the current code this one actually PASSES today, because the
        // `self` symlink resolution in detect_indirect_proc_magic_link leaves
        // the scan with /proc/<PID>/../self/root, and a second symlink resolution
        // re-lands on /proc/<PID>/root which is then caught by is_proc_magic_path.
        // It is kept as a regression guard so that any future refactor of the
        // `..` handling does not accidentally break this working case.
        let path = "/proc/self/../self/root";

        let result = canonicalize(path).expect("canonicalize should succeed");

        assert_ne!(
            result,
            Path::new("/"),
            "namespace boundary lost via self/.. /self pattern"
        );
        // The library may legitimately return either /proc/self/root or
        // /proc/<PID>/root after resolving `self`. Both preserve the boundary.
        let s = result.to_string_lossy();
        assert!(
            s.starts_with("/proc/") && s.ends_with("/root"),
            "expected a /proc/.../root path, got {:?}",
            result
        );
    }

    #[test]
    fn indirect_symlink_through_dotdot_preserves_namespace() {
        // Independent indirect path that exercises the same root cause through
        // detect_indirect_proc_magic_link: a symlink to /proc/<PID>, accessed
        // with a trailing `root` segment via `..` games inside the prefix.
        //
        //   /tmp/.../procdir -> /proc/<PID>          (real directory, not magic)
        //   access: /tmp/.../procdir/cwd/../root
        //
        // On entering detect_indirect, after resolving `procdir`, current_path
        // becomes /proc/<PID>/cwd/../root. find_namespace_boundary then matches
        // the cwd branch (with remainder ../root) and re-bases on the *host*
        // resolution of cwd, dropping the magic boundary at /proc/<PID>/root.
        use std::os::unix::fs::symlink;

        let pid = std::process::id();
        let temp = tempfile::tempdir().expect("tempdir");
        let procdir = temp.path().join("procdir");
        symlink(format!("/proc/{pid}"), &procdir).expect("create procdir symlink");

        let attack = procdir.join("cwd/../root");

        let result = canonicalize(attack).expect("canonicalize should succeed");

        let host_cwd_parent = std::env::current_dir()
            .expect("cwd")
            .parent()
            .map(Path::to_path_buf);
        if let Some(parent) = host_cwd_parent {
            assert_ne!(
                result.join(""), // normalize trailing-slash differences
                parent.join("root"),
                "namespace boundary lost: resolved to host parent-of-cwd path"
            );
        }
        assert_ne!(
            result,
            Path::new("/"),
            "namespace boundary lost: resolved to host '/'"
        );
        assert!(
            result.starts_with(format!("/proc/{pid}/root"))
                || result.starts_with(format!("/proc/{pid}/cwd")),
            "expected namespace prefix preserved, got {:?}",
            result
        );
    }
}
