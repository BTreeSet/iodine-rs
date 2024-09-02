# iodine-rs - DNS Tunneling Software

`iodine-rs` is a progressive rewrite of the original [iodine](https://code.kryo.se/iodine) DNS tunneling software in Rust, aiming to be compatible with the iodine project as of commit [68b0a7b](https://github.com/yarrick/iodine/commit/68b0a7b16e214f0b50a6a849fc30756d580b480a) on September 1, 2024. This software allows IPv4 data tunneling through DNS servers, useful in scenarios where internet access is firewalled, but DNS queries are allowed.

## Why iodine-rs?

- **Incremental Rewriting**: The C codebase is progressively rewritten in Rust, ensuring that the project compiles at every step.
- **Intended Compatibility**: Maintains compatibility with the iodine protocol and aims to offer the same functionality in a more secure and modern language.
- **Safety and Performance**: Leverages Rust's safety guarantees and performance benefits.

## Goals

1. **Maintain Compatibility**: Ensure `iodine-rs` maintains compatibility with iodine clients and servers.
2. **Progressive Migration**: Modules will be progressively rewritten in Rust from the original C codebase, ensuring continuous compilation.
3. **Enhanced Safety**: Introduce Rust's memory safety and concurrency features to reduce vulnerabilities present in C.

## Contribution

Feel free to contribute to the project by opening issues, submitting pull requests, or offering feedback.

## Contact

For any questions or suggestions, reach out to the maintainer at `iodine-rs@oss.joefang.org`.
