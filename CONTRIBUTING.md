# Contributing to NullStrike

First off, thank you for considering contributing to NullStrike! It's people like you that make NullStrike such a great tool for the community.

## How Can I Contribute?

### Reporting Bugs
If you find a bug, please create an issue on GitHub. Include as much detail as possible:
- Your operating system and Rust version.
- The `playbook.yaml` you were using.
- The exact error output or unexpected behavior.

### Suggesting Enhancements
Have an idea for a new Auditor module (e.g., Azure Active Directory scanning, Kubernetes RBAC validation)? Open an issue to discuss it before you start writing code!

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation in `README.md`.
4. Ensure the test suite passes by running `cargo test` and `cargo check`.
5. Issue a pull request!

## Architecture Overview
- **`app.rs`**: Manages the core TUI state and tracks simulation progress.
- **`auditor.rs`**: Defines the extensible `Auditor` trait and the `SecurityEvent` payloads.
- **`playbook.rs`**: The YAML parser and validation engine.
- **`cloud_engine.rs`**, **`network_engine.rs`**, **`host_engine.rs`**: The concrete simulation engines.
- **`ui.rs`** and **`report.rs`**: Handles rendering the Ratatui interface and the comfy-table stdout summaries.

We look forward to your contributions!
