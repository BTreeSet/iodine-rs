# iodine DNS tunnel protocol notes (from upstream C)

This document is derived from:

- `upstream/src/common.h`
- `upstream/src/encoding.c`
- `upstream/src/client.c`
- `upstream/src/iodined.c`
- `upstream/src/dns.c`

## 1) DNS upstream DATA query layout (client -> server)

In DNS mode, upstream DATA is **not** `(type<<4)|userid` raw bytes.  
That nibble format (`RAW_HDR_CMD_*`) is for **raw UDP mode**, not DNS QNAME data mode.

For DNS DATA queries (`client.c::send_chunk`, `iodined.c` DATA branch):

1. QNAME prefix starts with **5 ASCII header chars**, then encoded payload, then `.topdomain`.
2. Header bytes are:
   - `in[0]`: user id hex ASCII (`0-9a-fA-F`)
   - `in[1]`: `b32_5to8(((up_seq & 7) << 2) | ((up_frag & 15) >> 2))`
   - `in[2]`: `b32_5to8(((up_frag & 3) << 3) | (down_ack_seq & 7))`
   - `in[3]`: `b32_5to8(((down_ack_frag & 15) << 1) | last_frag_bit)`
   - `in[4]`: data CMC (`a-z0-9`, rotating)
3. Encoded payload starts at `in[5]` and is decoded with the negotiated codec.
4. Dot separators inserted in hostnames must be removed before decode (`inline_undotify` behavior).

Server decode in C (`iodined.c`) confirms:

- `up_seq = (b32_8to5(in[1]) >> 2) & 7`
- `up_frag = ((b32_8to5(in[1]) & 3) << 2) | ((b32_8to5(in[2]) >> 3) & 3)`
- `dn_seq = b32_8to5(in[2]) & 7`
- `dn_frag = b32_8to5(in[3]) >> 1`
- `lastfrag = b32_8to5(in[3]) & 1`

## 2) DNS upstream PING query layout (client -> server)

PING query name starts with `p`/`P` followed by Base32-encoded binary (`client.c::send_ping`):

- decoded byte0: `userid`
- decoded byte1: `((down_ack_seq & 7) << 4) | (down_ack_frag & 15)`
- decoded byte2..3: random seed (not part of ACK extraction logic)

Server (`iodined.c`) uses byte1 to process downstream ACK state.

## 3) Upstream packet body semantics

For DATA queries, the decoded payload bytes are compressed fragment bytes only.  
Per-fragment protocol header (seq/frag/ack/last/cmc) is in QNAME chars, not inside decoded payload.

Server reassembles fragments by seq/frag; when `lastfrag` is set, concatenated compressed bytes are zlib-uncompressed and forwarded.

## 4) Downstream packet layout (server -> client, NULL/TXT payload after decode)

Downstream tunnel packet bytes (`iodined.c::send_chunk_or_dataless`) are:

- byte0: `(1<<7) | ((up_ack_seq & 7) << 4) | (up_ack_frag & 15)`
  - bit7: compression flag (set to 1 in upstream C)
  - bits6..4: ACK for client upstream seq
  - bits3..0: ACK for client upstream frag
- byte1: `((down_seq & 7) << 5) | ((down_frag & 15) << 1) | last_bit`
  - bits7..5: downstream packet seq
  - bits4..1: downstream frag
  - bit0: last fragment
- byte2..: compressed fragment payload (may be empty for dataless ACK/ping reply)

## 5) DNS RR encoding for downstream packets

`write_dns` (`iodined.c`) wraps downstream bytes into RR data based on query type:

- `NULL`: raw binary downstream bytes as-is.
- `TXT`: one-byte codec marker + encoded stream:
  - `t` base32
  - `s` base64
  - `u` base64u
  - `v` base128
  - `r` raw bytes
- `CNAME`/`A`/`MX`/`SRV`: hostname/name-encoded forms (`h/i/j/k` markers and name packing).

Client-side parser (`client.c::dns_namedec`) decodes those marker-prefixed forms back to the binary downstream packet format above before interpreting the 2-byte tunnel header.
