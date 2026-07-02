# NullStrike ⚡️

NullStrike is a highly concurrent, zero-footprint **Breach and Attack Simulation (BAS)** CLI tool written entirely in Rust. Designed for ultra-fast, non-destructive security auditing, it leverages `tokio` for massively parallel execution and `ratatui` for a beautiful, real-time terminal UI.

## Features

- **Blazing Fast Concurrency**: Built on `tokio`, NullStrike spawns lightweight worker pools to simulate thousands of checks per second without breaking a sweat.
- **YAML Playbooks**: Define infrastructure-as-code security tests. From IAM blast-radius simulations to Kubernetes ephemeral port sweeps, everything is driven by a thread-safe `playbook.yaml`.
- **Zero-Footprint Execution**: Evaluates internal port availability without establishing full socket handshakes (minimizing connection exhaustion) and inspects host layers with zero-allocation memory management.
- **Destructive-Safe Protocol**: Guaranteed safety constraints built into the parsing layer ensure that simulations don't modify critical infrastructure or disrupt services.
- **Advanced Post-Simulation Analytics**: Shifts seamlessly from the real-time TUI to a rich stdout summary report powered by `comfy-table`, complete with severity bar charts.
- **Actionable Remediation**: Automatically dumps a `report.json` payload and a beautifully structured `report.md` artifact loaded with specific remediation code blocks designed for CI/CD or Splunk integration.

## Installation

Ensure you have Rust and Cargo installed, then clone the repository:

```bash
git clone https://github.com/Aryan-Protein-Vala/NullStrike.git
cd NullStrike
cargo build --release
```

## Usage

Simply run the compiled binary:

```bash
cargo run --release
```

If a `playbook.yaml` does not exist in the current directory, NullStrike will automatically generate a default configuration demonstrating Cloud IAM chaining, Ephemeral Port Sweeps, and Host File Inspection. 

Sit back and watch the TUI stream the execution logs, and when the audit finishes, review your detailed terminal report!

## Configuration

NullStrike is driven by the `playbook.yaml`. Here is an example of what it looks like:

```yaml
name: Default Security Sweep
description: A standard mock check
targets:
  - 10.0.0.5
  - kube-pod-1
checks:
  - type: IamRoleAssumption
    role_arn: arn:aws:iam::123456789012:role/worker
  - type: EphemeralPortSweep
    ports:
      - 22
      - 80
      - 443
      - 8080
  - type: HostFileInspector
    path: /etc/shadow
```

## Contributing

We welcome contributions from the community! Check out our [CONTRIBUTING.md](CONTRIBUTING.md) to see how you can get involved. If you find a bug or have a feature request, please open an issue.

## License

This project is licensed under the [MIT License](LICENSE).
