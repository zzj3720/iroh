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
