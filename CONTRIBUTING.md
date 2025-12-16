# Contributing

Thanks for your interest in contributing! 🦀

## Quick Start

1. Fork & clone the repository
2. Test locally: `bash ci-local.sh` or `.\ci-local.ps1`
3. Submit a pull request

## How to Contribute

- **🐛 Bug reports**: [Open an issue](https://github.com/DK26/proc-canonicalize-rs/issues) with reproduction steps
- **💡 Features**: Discuss in an issue before implementing
- **📝 Docs**: Fix typos, add examples, improve clarity
- **🔧 Code**: Bug fixes and improvements welcome

## Guidelines

- Zero runtime dependencies
- Linux or WSL required for testing
- Match `std::fs::canonicalize` behavior for normal paths
- Preserve `/proc/PID/root` and `/proc/PID/cwd` namespace prefixes

## License

Contributions licensed under **MIT OR Apache-2.0**.

---

Every contribution matters! 🚀
