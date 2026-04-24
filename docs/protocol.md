# BSV Shard — Wire Protocol Specification

## 1. Overview

The BSV sharding pipeline transports raw BSV transactions over IPv6 UDP (or TCP
for reliable delivery) using a compact binary frame format. Every frame begins
with the BSV mainnet P2P network magic so that standard firewall rules and
network monitors already configured for BSV traffic classify shard datagrams
correctly.

## 2. BRC-122 Frame Format (current)

**Header size:** 92 bytes.  
**Byte order:** big-endian for all multi-byte integers.

```text
Offset  Size  Align  Field                 Value / notes
------  ----  -----  -----                 -------------
     0     4   —     Network magic         0xE3E1F3E8 (BSV mainnet P2P magic)
     4     2   —     Protocol ver          0x02BF = 703
     6     1   —     Frame version         0x02 (BRC-122)
     7     1   —     Reserved              0x00
     8    32   8B    Transaction ID        raw 256-bit txid (internal byte order)
    40     4   8B    Sender ID             CRC32c of IPv6; 0 = unset
    44     4   —     Sequence ID           uint32 BE; random flow identifier; 0 = unset
    48     4   8B    Shard Sequence Number uint32 BE; monotonic counter; 0 = unset
    52     4   —     Reserved              padding; must be 0x00000000
    56    32   8B    Subtree ID            32-byte batch identifier; zeros = unset
    88     4   8B    Payload length        uint32; max 10 MiB
    92     *   —     BSV tx payload        raw serialised transaction bytes
```

**Alignment verification:**
| Field | Offset | Offset % 8 |
|---|---|---|
| TXID | 8 | 0 ✓ |
| SenderID | 40 | 0 ✓ |
| SequenceID | 44 | 4 |
| ShardSeqNum | 48 | 0 ✓ |
| Reserved | 52 | 4 |
| SubtreeID | 56 | 0 ✓ |
| PayLen | 88 | 0 ✓ |

### 2.1 Fields

**Network magic (0:4)** — `0xE3E1F3E8`. The BSV mainnet P2P network magic.
Frames that do not start with this value are rejected.

**Protocol version (4:6)** — `0x02BF` (703). The BSV node protocol version
baseline that introduced the large-block policy. This field is informational;
receivers do not validate it.

**Frame version (6)** — `0x02` for BRC-122, `0x01` for v1 (see §3). Any other
value is rejected. Both v1 and BRC-122 frames are forwarded verbatim.

**Reserved (7)** — Must be `0x00`. Reserved for future use.

**Transaction ID (8:40)** — 32 bytes. The raw 256-bit txid in internal byte
order as used in the BSV P2P protocol — **not** the reversed display order
shown by block explorers. The top bits of `txid[0:4]` are used by the shard
engine to derive the multicast group index.

**Sender ID (40:44)** — `uint32` big-endian. CRC32c (Castagnoli polynomial)
of the original BSV sender's IPv6 address. The proxy stamps this field
**in-place** before forwarding. Collision risk is minimal on realistic BSV
networks (~1,000 mining nodes, ~12-20 core transaction processors). `0` means unset.

**Sequence ID (44:48)** — `uint32` big-endian. A random flow identifier assigned
by the sender. Combined with SenderID and ShardSeqNum, it uniquely identifies a
sequenced flow for retransmission requests. Senders reset this value periodically
(e.g., by packet count or time ~10 minutes). `0` means unset.

**Shard Sequence Number (48:52)** — `uint32` big-endian. A monotonic counter assigned
by the sender. `0` means unset. Passed through unchanged by the proxy.

**Reserved (52:56)** — `uint32`. Padding for alignment; must be `0x00000000`.

**Subtree ID (56:88)** — 32 bytes. An opaque batch identifier assigned by the
transaction processor. All-zero bytes mean the field is unset. Passed through
unchanged by the proxy.

**Payload length (88:92)** — `uint32` big-endian. The number of payload bytes
immediately following the header. The application determines the maximum accepted size.

**Payload (92+)** — Raw serialised BSV transaction. Same format as the BSV P2P
`tx` message payload (version LE32 + inputs + outputs + locktime LE32). No P2P
message envelope wraps it.

---

## 3. Legacy BRC-12 Frame Format (v1)

Legacy v1 frames use a 44-byte header and carry no BRC-122 fields.
The proxy accepts them and forwards them verbatim without modification.

```text
Offset  Size  Field
------  ----  -----
     0     4  Network magic    0xE3E1F3E8
     4     2  Protocol ver     0x02BF
     6     1  Frame version    0x01
     7     1  Reserved         0x00
     8    32  Transaction ID
    40     4  Payload length
    44     *  Payload
```

**TCP ingress:** the TCP reader reads 44 bytes first to detect the version, then
completes the header read if BRC-122 (48 more bytes). No separate port is needed
for v1 and BRC-122 — both versions share the same listener.

---

## 4. Subtree Model

A *subtree* is an ordered set of related transactions sharing a common batch
context. The `SubtreeID` field allows downstream subscribers to associate
frames with a named batch:

- **`SubtreeID`** — 32-byte opaque batch identifier; all-zero means unset.

This field is optional. The proxy passes it through unchanged.

---

## 5. Shard Derivation

The multicast group for a frame is derived from its `TxID`:

```
groupIndex = (txid[0:4] as uint32 BE) >> (32 - shardBits)
```

where `shardBits` is the configured `-shard-bits` value (default 2, range
1–24). The group index maps to an IPv6 multicast address:

```
[FFsc::groupIndex]
```

where `sc` is the two-nibble scope code (e.g. `FF05` for site-local). The
group index occupies the three lowest bytes of the address.

**Consistent-hashing property:** increasing `shardBits` by 1 splits every
existing group into exactly two child groups. Subscribers need only join
additional groups; no existing subscriptions become invalid.

---

## 6. Proxy Forward Rules

The proxy processes each incoming datagram in two steps:

1. **Decode** — parse the frame header (v1 or BRC-122); drop with a debug log on
   bad magic, unsupported version, oversized payload, or truncated datagram.
   The TxID is extracted to derive the destination multicast group.

2. **Forward** — for BRC-122 frames, overwrite `raw[40:44]` in-place with the
   CRC32c of the ingress source IPv6 address (`SenderID`) before forwarding.
   Write the raw bytes to every configured egress interface via `IPV6_MULTICAST_IF`.
   v1 frames are forwarded verbatim without modification.

---

## 7. TCP Ingress

When `-tcp-listen-port` is non-zero, the proxy also accepts TCP connections for
reliable frame delivery. The TCP wire format is identical to UDP: v1 or BRC-122
frames concatenated end-to-end with no additional envelope.

**Read sequence per frame:**
1. Read 44 bytes (minimum header, sufficient for both v1 and the start of BRC-122).
2. Inspect `FrameVer` at byte 6.
   - **v1:** header is complete; `PayLen` is at bytes 40–43.
   - **BRC-122:** read 48 more bytes to complete the 92-byte header;
     `PayLen` is at bytes 88–91.
3. Read exactly `PayLen` bytes (the payload).
4. Forward the reassembled raw bytes (SenderID stamped at 40–43 for BRC-122).

The proxy closes the TCP connection on any protocol violation (bad magic,
unsupported version byte, or read error).

---

## 8. Error Handling

| Condition | UDP | TCP |
|---|---|---|
| Bad magic | datagram silently dropped | connection closed |
| Unknown frame version (not v1/BRC-122) | datagram silently dropped | connection closed |
| Truncated datagram | datagram silently dropped | read error → connection closed |
| Egress write error | logged; next interface attempted | logged; next interface attempted |

All drops are counted in the `bsp_packets_dropped_total` Prometheus metric with
a `reason` label (`decode_error`, `write_error`, or `truncated`).

---

## 9. Constants Reference

| Name | Value | Notes |
|---|---|---|
| `MagicBSV` | `0xE3E1F3E8` | BSV mainnet P2P magic |
| `ProtoVer` | `0x02BF` | Protocol version 703 |
| `FrameVerV1` | `0x01` | Legacy BRC-12; accepted, forwarded verbatim |
| `FrameVerBRC122` | `0x02` | Current (BRC-122) |
| `HeaderSizeLegacy` | `44` | Legacy v1 header bytes |
| `HeaderSize` | `92` | BRC-122 header bytes |

