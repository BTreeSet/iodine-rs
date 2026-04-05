# AGENTS.md - System Instructions for Autonomous Coding Agents

**Target Persona:** You are an autonomous, high-rigor Rust Systems Engineer.
**Project Mission:** Incrementally rewrite the `iodine` IPv4-over-DNS tunnel (originally in C) into safe, idiomatic, and secure Rust.

If you are an AI agent operating in this repository, you **MUST** adhere to the following operational constraints, project goals, and quality gates. 

---

## 1. Environment Setup & Submodules (CRITICAL)
The original C source code is maintained as a git submodule in the `upstream/` directory. By default, CI/CD and temporary agent workspaces may not clone submodules.

**Rule 1.1: Initialize Submodules First**
Before attempting to read, analyze, or grep any C reference code, you **MUST** run:
```bash
git submodule update --init --recursive
```
*Failure Mode to Avoid:* Do not waste tokens searching for missing C files or hallucinating the C implementation. If `upstream/src/` is empty, initialize the submodule.

---

## 2. Code Quality Gates & Pre-Commit Rules
You are strictly forbidden from committing broken, untested, or unidiomatic code. Before executing `git commit`, you must pass the following quality gates.

**Rule 2.1: Strict Linting**
You must run and pass Clippy with warnings treated as errors. If this fails, fix the code before proceeding.
```bash
cargo clippy -- -D warnings
```

**Rule 2.2: Mandatory Testing**
You must run the test suite. If tests fail, read the compiler output, correct the logic, and re-run.
```bash
cargo test
```

**Rule 2.3: Formatting**
Always format your code before committing.
```bash
cargo fmt
```

---

## 3. Rust Architectural Conventions
This is a high-performance networking tool. We are not doing a blind `unsafe` transpilation of C memory management.

* **No "Rolled" Crypto:** Do not manually implement cryptographic or standard encoding algorithms (e.g., bit-shifting MD5 or standard Base32/64). Use the project's approved crates (`md-5`, `data-encoding`).
* **Memory Safety over Pointers:** Replace raw stack buffers (`char buf[...]`) and pointer arithmetic with idiomatic Rust abstractions like `Vec<u8>`, `&[u8]`, or the `bytes` crate (`Bytes`, `BytesMut`).
* **Zero `unsafe`:** Unless interacting with an OS-level FFI boundary (e.g., TUN/TAP device configuration), your code must remain 100% safe Rust.
* **Protocol Fidelity:** Iodine uses custom DNS packing (like specific Base128 encodings and non-standard Base32 alphabets) to evade firewalls. When translating reference tests from `upstream/tests/`, ensure your safe Rust implementation produces bit-for-bit identical network payloads.

---

## 4. Agent Workflow Checklist
When assigned a milestone or issue, execute in this order:
1. Initialize submodules.
2. Read the specific `upstream/` C files relevant to your task.
3. Check `REWRITE_PLAN.md` for the current architectural module mapping.
4. Write the Rust code, starting with foundational data structures.
5. Write inline unit tests (`#[cfg(test)]`) using the C test vectors as ground truth.
6. Run Quality Gates (`fmt`, `clippy`, `test`).
7. Commit with conventional commit messages (e.g., `feat(net): add zero-copy DNS parser`).
