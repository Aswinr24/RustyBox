# RustyBox: Open-Source CLI-Based Malware Analysis Sandbox

**RustyBox** is a high-performance, Rust-powered malware analysis framework designed for secure, static binary examination. It integrates leading open-source libraries to simplify the malware analysis workflow for security researchers and professionals.

## Features

- **Static Analysis Focused** – Deep disassembly, callgraph generation, and unpacking using tools like Capstone, Radeco, LIEF, and Capa.
- **Modular & CLI-Based** – Flexible CLI interface with multiple analysis modes.
- **High Performance** – Built in Rust for speed, safety, and low memory overhead.
- **Pre-Configured Flow** – No manual setup needed for tools like Radare2, LIEF, or CAPA.
- **Cross-Platform** – Supports x86_64 and ARM64 binaries (Linux).

## Commands

### 1. Run Basic Static Analysis

rustybox -- malware.exe


* Disassembles the binary and generates a callgraph in ASCII.
* Uses Radare2 to produce function flow and structure.

### 2. Run Binary Parsing Mode


rustybox -- malware.exe binaryp


* Parses metadata, PE header info, imports/exports, and section details using LIEF.

### 3. Enable Verbose Mode (for deeper insights)


rustybox -- malware.exe -v


* Provides verbose logging for debugging or educational output.

## Installation

### Requirements

* Rust & Cargo – [Install Rust](https://rustup.rs)
* Radare2 – [GitHub: radareorg/radare2](https://github.com/radareorg/radare2)
* Graph-Easy – Install using `cpanm Graph::Easy`
* Python3 – Required for CAPA
* Docker – *(Optional)* For future dynamic analysis integration

### Clone and Build


git clone https://github.com/Aswinr24/rustybox.git

cd rustybox

cargo build --release


## Architecture

* **Disassembly** – Capstone, Radare2
* **Decompilation** – Radeco
* **Signature Matching** – Capa
* **Binary Parsing** – LIEF
* **Visualization** – Graph-Easy, CFG rendering
* **(Upcoming)** – Firecracker/QEMU for isolated dynamic execution


## Contributing

We welcome pull requests and feature ideas. Please submit issues and suggestions in the [GitHub Issues](https://github.com/yourusername/rustybox/issues) section.

## License

Apache 2.0 – Free to use, modify, and distribute.
