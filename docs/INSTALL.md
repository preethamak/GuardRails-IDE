# Install and run GuardRails IDE

GuardRails IDE currently ships as a local application that serves its bundled UI only
on `127.0.0.1`. The repository, Rust security services, HTML, CSS, and JavaScript are
compiled or embedded into one `guardrails-ide` executable. No Node.js installation is
required.

## macOS, Linux, and Windows prerequisites

1. Install Git.
2. Install the stable Rust toolchain from <https://rustup.rs>.
3. Clone this repository.

## Install from a clone

On macOS or Linux:

```bash
git clone <your-guardrails-repository-url>
cd GuardRails-IDE
./scripts/install.sh
guardrails-ide --workspace /path/to/your/project
```

On Windows PowerShell:

```powershell
git clone <your-guardrails-repository-url>
cd GuardRails-IDE
cargo install --locked --path crates/guardrails-ide
guardrails-ide --workspace C:\path\to\your\project
```

Open <http://127.0.0.1:43110> in a browser. Use `--port 43111` if the default port is
already occupied. Stop the application with **Ctrl+C**.

## Run without installing

```bash
./scripts/run-dev.sh /path/to/your/project
```

or on every supported platform:

```bash
cargo run --locked -p guardrails-ide -- --workspace /path/to/your/project
```

## What this runnable version provides

- a VS Code-inspired workspace shell;
- Git-ignore-aware repository indexing with hidden paths excluded;
- UTF-8 source viewing through the capability policy and filesystem broker;
- a live security audit panel;
- localhost-only listening, CSP, and content-type protection;
- configurable 2 MiB per-file read limits;
- no Node.js, extension host, terminal, network agent, or inherited secret access.

This version is deliberately read-only. It is installable and useful for securely
viewing repositories, but it is not yet a full Code-OSS replacement. Editing, terminal
execution, agents, and extensions remain disabled until their enforcing brokers and
sandbox tests exist; the UI must not imply that unfinished controls are available.
