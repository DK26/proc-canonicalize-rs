# proc-canonicalize

[![Crates.io](https://img.shields.io/crates/v/proc-canonicalize.svg)](https://crates.io/crates/proc-canonicalize)
[![Documentation](https://docs.rs/proc-canonicalize/badge.svg)](https://docs.rs/proc-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

**A patch for `std::fs::canonicalize` that preserves Linux `/proc/PID/root` namespace boundaries.**

## The Problem

On Linux, `/proc/PID/root` is a "magic symlink" that crosses into a process's mount namespace. When you access files through it, you're accessing the container's filesystem:

```bash
# Reading a container's file from the host:
cat /proc/1234/root/etc/os-release  # Shows container's OS, not host's!
```

However, `std::fs::canonicalize` resolves this magic symlink to `/`, **breaking security boundaries**:

```rust
// BROKEN: std::fs::canonicalize loses the namespace prefix!
std::fs::canonicalize("/proc/1234/root")?           // Returns "/" 
std::fs::canonicalize("/proc/1234/root/etc/passwd")? // Returns "/etc/passwd"

// Security tools using this as a boundary are now checking against "/" (host root)!
```

## The Fix

This crate preserves the `/proc/PID/root` and `/proc/PID/cwd` prefixes:

```rust
use proc_canonicalize::canonicalize;

// FIXED: Namespace prefix is preserved!
canonicalize("/proc/1234/root")?           // Returns "/proc/1234/root"
canonicalize("/proc/1234/root/etc/passwd")? // Returns "/proc/1234/root/etc/passwd"

// Normal paths work exactly like std::fs::canonicalize:
canonicalize("/home/user/../user/file.txt")? // Returns "/home/user/file.txt"
```

## Use Case

Container monitoring and security tools that need to:

1. Access container filesystems from the host via `/proc/PID/root`
2. Validate that paths stay within the container boundary
3. Prevent container escape vulnerabilities

```rust
use proc_canonicalize::canonicalize;

fn read_container_file(container_pid: u32, path: &str) -> std::io::Result<Vec<u8>> {
    let container_root = format!("/proc/{}/root", container_pid);
    let full_path = format!("{}{}", container_root, path);
    
    // Canonicalize preserves the container boundary
    let canonical = canonicalize(&full_path)?;
    
    // Security check: ensure path is still within container
    if !canonical.starts_with(&container_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path escapes container boundary"
        ));
    }
    
    std::fs::read(&canonical)
}
```

## Supported Paths

| Path Pattern             | Preserved                       |
| ------------------------ | ------------------------------- |
| `/proc/PID/root`         | ✅                               |
| `/proc/PID/root/...`     | ✅                               |
| `/proc/PID/cwd`          | ✅                               |
| `/proc/PID/cwd/...`      | ✅                               |
| `/proc/self/root`        | ✅                               |
| `/proc/self/cwd`         | ✅                               |
| `/proc/thread-self/root` | ✅                               |
| `/proc/thread-self/cwd`  | ✅                               |
| All other paths          | Same as `std::fs::canonicalize` |

## Platform Support

- **Linux**: Full functionality
- **Other platforms**: Falls back to `std::fs::canonicalize` (no-op)

## Optional Features

### `dunce` (Windows Only)

Simplifies Windows extended-length paths by removing the `\\?\` prefix when possible:

```toml
[dependencies]
proc-canonicalize = { version = "0.1", features = ["dunce"] }
```

**Behavior:**
- Without `dunce`: Returns `\\?\C:\Users\Alice\file.txt` (Windows extended-length format)
- With `dunce`: Returns `C:\Users\Alice\file.txt` (simplified format)

**Benefits:**
- ✅ More readable paths in logs and user output
- ✅ Automatically preserves `\\?\` prefix when needed (e.g., for paths longer than 260 characters)

## Zero Dependencies

This crate has **no dependencies** beyond the Rust standard library.

## Installation

```toml
[dependencies]
proc-canonicalize = "0.1"
```

## License

MIT OR Apache-2.0
