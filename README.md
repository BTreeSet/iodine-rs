# iodine-rs - DNS Tunneling Software

`iodine-rs` is a progressive rewrite of the original [iodine](https://code.kryo.se/iodine) DNS tunneling software in Rust, aiming to be compatible with the iodine project as of commit [517d729](https://github.com/yarrick/iodine/tree/517d7298b084fdb82d35ded4ed26bbc00673118a). This software allows IPv4 data tunneling through DNS servers, useful in scenarios where internet access is firewalled, but DNS queries are allowed.

## Current Status & Features

The project is actively being ported from C to safe, idiomatic, and secure Rust using the `tokio` async runtime. Current implemented capabilities include:

- **Unified CLI**: Execution mode dispatch for both client (`iodine`) and server (`iodined`) logic.
- **Async TUN Integration**: Cross-platform, asynchronous packet reading/writing to OS-level TUN devices.
- **DNS Protocol Parsing**: Custom, zero-copy parsing and serialization of DNS headers, questions, and resource records.
- **Protocol Encodings**: Full Rust implementations of the iodine protocol's custom Base32, Base64, and Base128 encodings, alongside domain-name packing utilities.
- **Cryptography**: Integrated MD5 challenge/response authentication logic.
- **Server State Management**: Virtual IP pooling, user authentication, downstream packet queues, and an LRU-based DNS cache.

## Why iodine-rs?

- **Incremental Rewriting**: The C codebase is progressively rewritten in Rust, ensuring that the project compiles at every step.
- **Intended Compatibility**: Maintains compatibility with the iodine protocol and aims to offer the same functionality in a more secure and modern language.
- **Safety and Performance**: Leverages Rust's memory safety guarantees and high-performance asynchronous networking, moving away from raw stack buffers and manual pointer arithmetic.

## Goals

1. **Maintain Compatibility**: Ensure `iodine-rs` maintains compatibility with legacy iodine clients and servers.
2. **Progressive Migration**: Modules will be progressively rewritten in Rust from the original C codebase, ensuring continuous compilation.
3. **Enhanced Safety**: Introduce Rust's memory safety and concurrency features to reduce vulnerabilities present in C.

## Contribution

Feel free to contribute to the project by opening issues, submitting pull requests, or offering feedback. Please refer to `AGENTS.md` and `REWRITE_PLAN.md` for architectural guidelines, strict linting rules, and the current migration roadmap.

## Contact

For any questions or suggestions, reach out to the maintainer at `iodine-rs@oss.joefang.org`.
