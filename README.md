# bitcoin-shard-common

[![CI](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml/badge.svg)](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml)

Shared protocol primitives for the BSV transaction sharding pipeline.

## Packages

- **`frame`** — v1/v2 BSV-over-UDP wire format: `Encode`, `Decode`, constants, and sentinel errors. See [docs/protocol.md](docs/protocol.md) for the full wire format specification.
- **`shard`** — Deterministic txid → IPv6 multicast group address derivation. Given a txid and a configured bit width, `Engine` derives a consistent-hash group index and the corresponding `net.UDPAddr`. Also provides `ControlGroupAddr` for BRC-126 control-plane multicast groups (beacon, control).
- **`sequence`** — Per-shard monotonic sequence counters backed by `sync/atomic`. One independent `atomic.Uint64` per shard group; zero allocation and no contention between shards.

## Consumers

| Repo | Uses |
|-------------------------------------------------------------------------------------------|------------------------------|
| [`bitcoin-shard-proxy`](https://github.com/lightwebinc/bitcoin-shard-proxy) | `frame`, `shard`, `sequence` |
| [`bitcoin-shard-listener`](https://github.com/lightwebinc/bitcoin-shard-listener) | `frame`, `shard` |
| [`bitcoin-retry-endpoint`](https://github.com/lightwebinc/bitcoin-retry-endpoint) | `frame`, `shard` |

## Requirements

- Go 1.25 or later

## License

Apache 2.0 — see [LICENSE](LICENSE).
