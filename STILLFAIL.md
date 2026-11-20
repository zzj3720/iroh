# still.fail's iroh

The `stillfail` branch is iroh as still.fail ([AFK-surf/still.fail](https://github.com/AFK-surf/still.fail)) builds it:
upstream's release (`v1.0.3` now) and one commit for each change of ours on top, each marked `ember:` in the source.
still.fail takes the `iroh` crate from here by commit (`[patch.crates-io]` in its `client/Cargo.toml` and
`station/native/mesh/Cargo.toml`).

- A change: a commit here, its tests green (`.github/workflows/stillfail.yml`), then still.fail's pin moved to it.
- A new upstream release: this branch rebased onto its tag.
- A change upstream takes in a release: its commit dropped at the rebase.

macOS guests identified by Apple's `VirtualMac` hardware model bound the relay TCP carrier's unsent data to one
segment. In a bridged guest, all 35 captured multi-segment offloaded sends were lost, while 223 normal segments
arrived; disabling system TSO confirmed the dependency. The client workaround changes only its own socket:
`TCP_NOTSENT_LOWAT=1`, current MSS minus one byte per write, and a real writability check before each send. The
one-byte reserve includes the unsent byte macOS permits at the low-water mark. The flight window is
not restricted. TLS and HTTP proxies use this carrier too; a local proxy's loopback hop uses ordinary Tokio I/O.

This does not diagnose every virtual Mac as broken. It is a conservative compatibility path for this virtual hardware
class, with extra per-segment syscall cost. Physical Macs and other platforms keep ordinary batching and vectored I/O.
Removing the guest guard made a healthy Mac's 384 MiB loopback transfer take 393–407 ms instead of 264–282 ms, so
it is deliberately not a general macOS default. No system settings are written, no administrator privilege is used,
and no hardware identity is sent anywhere. The guest workaround should be reconsidered when the underlying
virtual-network offload defect can be reliably distinguished from a working path.

`Builder::relay_allowlist` optionally fixes the relay URLs an endpoint may use for its lifetime. The default is
unrestricted, as before; an empty allowlist leaves IP and custom transports available. A relay learned from a
peer, address lookup or cached path cannot expand this ceiling, nor can `insert_relay` or forwarding-entrance
updates. The send boundary and relay-actor connection boundary enforce it; home selection and net-report use
filtered maps detached from caller mutations. Per-remote disabled sets can further restrict the ceiling.
Changing the ceiling requires a new endpoint, so a policy-scoped underlay cannot silently widen after binding.

Selectors may request `PathSelection::close` only for explicitly withdrawn custom paths.
Retirement waits until every connection using that remote address has a different selected,
open path with a same-path RTT, then closes and forgets the withdrawn address to prevent
automatic reopening. This is not RTT tuning: IP/relay paths and merely slower alternatives
are unaffected, and noq retains its last-open-path guard.

Custom selectors can compare `PathSelectionData::connection()` weak identities together
with noq's path generation, same-path RTT epoch and actual ACK sample sequence. Snapshot
reads and initial PATH_RESPONSE estimates are not sustained quality evidence.

Alternate relay-entrance probes (`ActiveRelayActor::start_entry_probes`) back off exponentially from 30 s up to 5 min
(`30 -> 60 -> 120 -> 240 -> 300` s) whenever a round finds no candidate and none is being observed. Observing a
candidate, switching entrances, updating `entries`, reconnecting after a failure, or receiving a major network-change
connection check (`ActiveRelayMessage::CheckConnection`) resets the interval to 30 s; connection failures and major
network changes also wake an immediate probe round. Probes keep ephemeral identities, require an alternate entrance to
be strictly more than 20% faster and at least 10 ms faster (`ENTRY_MIN_GAIN`) — switching immediately on the first
comparison after startup or `update_entries` and requiring two consecutive rounds thereafter — so loopback or scheduling
jitter cannot reset backoff or churn sockets, and stay within the configured `[url, ...entries]` ceiling.

Per-remote disabled relay addresses (`Endpoint::set_disabled_relays`, `ConnectOptions::with_disabled_relays`) are
shelved inside `RemotePathState` instead of erased: while disabled, no further datagrams are handed to relay transports
and active or opening paths through disabled relays are closed; when `set_disabled_relays` allows a shelved relay again,
its address returns to `paths`, its per-relay `relay_lost` counter is cleared (within `RELAY_CONN_LOST_MAX`), and
existing client connections immediately reopen paths through it without redialing or address lookup. Likewise,
`Endpoint::remove_relay` and `Endpoint::insert_relay` serialize map, tombstone, transport, and remote-actor updates
through the socket actor: `remove_relay` closes established paths at once without falling back to another transport,
canceling unestablished opening paths accounts toward `RELAY_CONN_LOST_MAX`, and `insert_relay` reopens client paths
once that inserted relay connects while leaving ordinary home-relay reconnects unchanged. `Builder::relay_allowlist`
remains an immutable ceiling, and per-remote `disabled_relays` continues to override `insert_relay`.
