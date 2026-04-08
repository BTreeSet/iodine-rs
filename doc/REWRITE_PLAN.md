# iodine-rs Rewrite Plan (Milestone 1)

## Scope
This milestone establishes an updated C reference mirror, an architectural map, and a compile-ready Rust scaffold. It intentionally avoids porting runtime logic.

## C → Rust module mapping

### Entry points and runtime orchestration
- `src-c/iodine.c` (client executable entrypoint) → `src/main.rs` mode dispatch + `src/client.rs`
- `src-c/iodined.c` (server executable entrypoint + tunnel orchestration) → `src/main.rs` mode dispatch + `src/server.rs`

### DNS packet and tunnel protocol handling
- `src-c/dns.c` / `src-c/dns.h` → `src/dns.rs`
- `src-c/encoding.c` / `src-c/base32.c` / `src-c/base64.c` / `src-c/base128.c` → future `src/encoding/` module tree
- `src-c/read.c` and packet read helpers → future `src/protocol/` and/or `src/dns.rs` parser helpers

### TUN device and OS integration
- `src-c/tun.c` / `src-c/tun.h` → `src/tun/mod.rs` (with platform split in future)
- platform-specific routines currently in `tun.c` (Linux/BSD/macOS/Windows branches) → future `src/tun/linux.rs`, `src/tun/bsd.rs`, `src/tun/macos.rs`, `src/tun/windows.rs`

### Authentication and crypto
- `src-c/login.c` / `src-c/login.h` → `src/login.rs`
- `src-c/md5.c` / `src-c/md5.h` → `src/crypto/md5.rs` and `src/crypto/mod.rs`

### User/session state and server packet queues
- `src-c/user.c` / `src-c/user.h` and user/session data in `iodined.c` → future `src/server/` state modules (session/user/outbound queue/cache)

### Shared utilities
- `src-c/common.c` / `src-c/common.h`, `src-c/util.c` / `src-c/util.h`, `src-c/fw_query.c` / `src-c/fw_query.h` → future `src/common/` and `src/net/` modules

## Architectural observations from key C files

### `iodine.c` (client)
- Handles CLI parsing, privilege/chroot setup, nameserver/topdomain validation, tunnel setup, and hands execution to client handshake + tunnel loop.
- Rust direction: keep `main.rs` as mode selector; move client lifecycle to `client.rs`.

### `iodined.c` (server)
- Central state machine for DNS request handling, user authentication state, packet fragmentation/reassembly, duplicate suppression, caching, and TUN forwarding.
- Rust direction: isolate mutable shared state into typed structs and explicit state containers in `server.rs` and submodules.

### `tun.c`
- Strongly platform-conditional implementation for device open/read/write/IP/MTU setup.
- Rust direction: `tun` module boundary with per-platform backends selected by `cfg`.

### `dns.c`
- Contains packet encode/decode and response synthesis for A/CNAME/MX/SRV/TXT/NULL/NS/NXDOMAIN paths.
- Rust direction: parser/encoder APIs over owned byte buffers and typed packet structs.

### `login.c`
- Challenge/response based on password material and MD5.
- Rust direction: small pure function module (`login.rs`, `crypto/md5.rs`) with explicit input/output types.

## Core data structures to replace with safe Rust equivalents

- Raw stack buffers (`char buf[...], packet[...]`) → `Vec<u8>` / `bytes::BytesMut`.
- Pointer arithmetic over packet payloads (`char *p`, manual bounds checks) → cursor-based parsing/encoding APIs with checked indexing.
- C strings and manual truncation (`strncpy`, `snprintf`) → `String`, `&str`, and fixed-capacity wrappers only where protocol requires it.
- Address unions (`sockaddr_storage`, casts to v4/v6) → `std::net::SocketAddr` and enum-backed address abstractions.
- Global mutable state in `iodined.c` (`running`, user arrays, caches) → owned structs managed by server runtime context.
- Per-user packet queues/cache arrays with manual indexes → `VecDeque`, ring-buffer abstractions, and typed cache entries.
- Integer flags/options (`int` booleans and mode flags) → enums/bitflags/newtypes for protocol and transport modes.
- OS resource handles (`int fd`, `HANDLE`) → RAII wrappers and runtime-managed I/O objects.

## Milestone 1 scaffold boundaries
- Provide modules and entrypoint wiring only.
- Provide CLI mode selection between client (`iodine`) and server (`iodined`).
- Keep runtime execution paths as `unimplemented!()` placeholders.
- Avoid `unsafe` in all Rust scaffolding.
